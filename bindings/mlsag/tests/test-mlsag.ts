// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

// to run tests we need web build
//  wasm-pack build -t web bindings/mlsag
// deno test -A bindings/mlsag/tests/test-mlsag.ts

import { assert, assertEquals, assertFalse, assertThrows } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { RistrettoPoint } from "https://esm.sh/@noble/curves@1.9.7/ed25519";

import initMlsag, {
    fillRing,
    KeygenSession,
    Keyshare,
    Message,
    SignInput,
    SignSession,
    verifySignature,
} from "../pkg/mlsag_wasm_ll.js";

const PARTICIPANTS = 3;
const THRESHOLD = 2;
const MESSAGE = new TextEncoder().encode("threshold-mlsag/deno-test");
const VALUE = 9n;

// Ristretto group order.
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

export const test = (name: string, f: any) => {
    Deno.test(name, async (t) => {
        await initMlsag();
        return f(t);
    });
};

export function concatBytes(chunks: Uint8Array[]): Uint8Array {
    const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
    let offset = 0;
    for (const chunk of chunks) {
        out.set(chunk, offset);
        offset += chunk.length;
    }
    return out;
}

function cloneAll(messages: Message[]): Message[] {
    return messages.map((msg) => msg.clone());
}

function bytesToScalar(bytes: Uint8Array): bigint {
    let value = 0n;
    for (let i = bytes.length - 1; i >= 0; i--) {
        value = (value << 8n) | BigInt(bytes[i]);
    }
    return value % L;
}

function scalarToBytes(scalar: bigint): Uint8Array {
    const out = new Uint8Array(32);
    let value = ((scalar % L) + L) % L;
    for (let i = 0; i < 32; i++) {
        out[i] = Number(value & 0xffn);
        value >>= 8n;
    }
    return out;
}

function randomScalar(): bigint {
    for (;;) {
        const scalar = bytesToScalar(crypto.getRandomValues(new Uint8Array(64)));
        if (scalar !== 0n) {
            return scalar;
        }
    }
}

function randomPoint(): Uint8Array {
    return RistrettoPoint.BASE.multiply(randomScalar()).toRawBytes();
}

/// Ring with the spent output at `realIndex` and random decoys. The real
/// input and the output commit to the same value, so `z = y_out - y_in`.
type RingFixture = {
    ring: Uint8Array;
    realIndex: number;
    outputCommitment: Uint8Array;
    z: Uint8Array;
};

function ringFixture(publicKey: Uint8Array, realIndex: number, size: number): RingFixture {
    const h = RistrettoPoint.hashToCurve(new Uint8Array(64).fill(0x42));
    const commit = (blinding: bigint) =>
        h.multiply(VALUE).add(RistrettoPoint.BASE.multiply(blinding)).toRawBytes();
    const yIn = randomScalar();
    const yOut = randomScalar();

    const members: Uint8Array[] = [];
    for (let i = 0; i < size; i++) {
        if (i === realIndex) {
            members.push(publicKey, commit(yIn));
        } else {
            members.push(randomPoint(), randomPoint());
        }
    }

    return {
        ring: concatBytes(members),
        realIndex,
        outputCommitment: commit(yOut),
        z: scalarToBytes(yOut - yIn),
    };
}

function signInput(fixture: RingFixture, message: Uint8Array = MESSAGE): SignInput {
    return new SignInput(message, fixture.ring, fixture.realIndex, fixture.outputCommitment);
}

export function runDkgMessageQueue(parties: KeygenSession[], roundtrip = false): void {
    const queue: Message[] = parties.map((p) => p.createFirstMessage());

    let steps = 0;
    while (queue.length > 0) {
        if (++steps > 10_000) {
            throw new Error("dkg session exceeded step limit");
        }

        const msg = queue.shift()!;
        const sender = msg.sender();
        const receiver = msg.receiver();

        const receivers = receiver === undefined
            ? parties.map((_, p) => p).filter((p) => p !== sender)
            : receiver === sender
            ? []
            : [receiver];

        for (const p of receivers) {
            queue.push(...parties[p].receiveMessage(msg.clone()));
            if (roundtrip) {
                parties[p] = KeygenSession.fromBytes(parties[p].toBytes());
            }
        }
    }

    for (const party of parties) {
        assert(party.isFinished(), "dkg session stalled before completion");
        assertEquals(party.error(), undefined);
    }
}

export function dkg(participants: number, threshold: number, roundtrip = false): Keyshare[] {
    const parties: KeygenSession[] = [];
    for (let i = 0; i < participants; i++) {
        parties.push(new KeygenSession(participants, threshold, i, undefined));
    }

    runDkgMessageQueue(parties, roundtrip);
    return parties.map((party) => party.keyshare());
}

export function dsg(
    shares: Keyshare[],
    quorum: number[],
    fixture: RingFixture,
    roundtrip = false,
): Uint8Array {
    const pids = new Uint8Array(quorum);
    let sessions = quorum.map((pid) =>
        new SignSession(shares[pid], pids, signInput(fixture), undefined)
    );
    const maybeRoundtrip = () => {
        if (roundtrip) {
            sessions = sessions.map((s) => SignSession.fromBytes(s.toBytes()));
        }
    };

    maybeRoundtrip();
    const round1 = sessions.map((s) => s.createFirstMessage());
    maybeRoundtrip();
    const round2 = sessions.flatMap((s) => s.handleMessages(cloneAll(round1)));
    maybeRoundtrip();
    for (const s of sessions) {
        assertEquals(s.handleMessages(cloneAll(round2)).length, 0);
    }
    maybeRoundtrip();

    const nonceCommit = sessions[0].nonceCommit();
    for (const s of sessions) {
        assertEquals(s.nonceCommit(), nonceCommit);
    }

    const tour = fillRing(
        signInput(fixture),
        shares[quorum[0]].keyImage,
        nonceCommit,
        fixture.z,
        undefined,
    );

    const round3 = sessions.map((s) => s.handleRingTour(tour));
    maybeRoundtrip();
    for (const s of sessions) {
        assertEquals(s.handleMessages(cloneAll(round3)).length, 0);
    }
    maybeRoundtrip();

    const signatures = sessions.map((s) => s.signature());
    for (const signature of signatures) {
        assertEquals(signature, signatures[0]);
    }
    return signatures[0];
}

test("MLSAG DKG 2x3", () => {
    const shares = dkg(PARTICIPANTS, THRESHOLD);

    assertEquals(shares.length, PARTICIPANTS);
    shares.forEach((share, partyId) => {
        assertEquals(share.threshold, THRESHOLD);
        assertEquals(share.participants, PARTICIPANTS);
        assertEquals(share.partyId, partyId);
        assertEquals(share.publicKey, shares[0].publicKey);
        assertEquals(share.keyImage, shares[0].keyImage);
        assertEquals(share.keyId, shares[0].keyId);
        assertEquals(share.rootChainCode, shares[0].rootChainCode);
    });
});

test("MLSAG DSG 2x3 every quorum verifies", () => {
    const shares = dkg(PARTICIPANTS, THRESHOLD);
    const ringSize = 4;
    const fixture = ringFixture(shares[0].publicKey, 2, ringSize);

    for (const quorum of [[0, 1], [1, 2], [0, 2]]) {
        const signature = dsg(shares, quorum, fixture);

        assertEquals(signature.length, 32 * (2 * ringSize + 2));
        assertEquals(signature.slice(-32), shares[0].keyImage);
        assert(verifySignature(signature, signInput(fixture)));
        assertFalse(
            verifySignature(signature, signInput(fixture, new TextEncoder().encode("other"))),
        );
    }
});

test("MLSAG DSG 3x3 with every party", () => {
    const shares = dkg(3, 3);
    const fixture = ringFixture(shares[0].publicKey, 0, 3);

    const signature = dsg(shares, [0, 1, 2], fixture);

    assert(verifySignature(signature, signInput(fixture)));
});

test("MLSAG sessions and keyshares survive CBOR roundtrip", () => {
    const shares = dkg(PARTICIPANTS, THRESHOLD, true)
        .map((share) => Keyshare.fromBytes(share.toBytes()));
    const fixture = ringFixture(shares[0].publicKey, 1, 3);

    const signature = dsg(shares, [0, 2], fixture, true);

    assert(verifySignature(signature, signInput(fixture)));
});

test("MLSAG sign rejects a ring whose real slot is not the key", () => {
    const shares = dkg(PARTICIPANTS, THRESHOLD);
    const fixture = ringFixture(randomPoint(), 1, 3);

    assertThrows(
        () => new SignSession(shares[0], new Uint8Array([0, 1]), signInput(fixture), undefined),
        Error,
        "ring onetime key does not match keyshare",
    );
});

test("MLSAG fillRing rejects an unbalanced amount", () => {
    const shares = dkg(PARTICIPANTS, THRESHOLD);
    const fixture = ringFixture(shares[0].publicKey, 1, 3);
    const pids = new Uint8Array([0, 1]);
    const sessions = [0, 1].map((pid) =>
        new SignSession(shares[pid], pids, signInput(fixture), undefined)
    );

    const round1 = sessions.map((s) => s.createFirstMessage());
    const round2 = sessions.flatMap((s) => s.handleMessages(cloneAll(round1)));
    sessions.forEach((s) => s.handleMessages(cloneAll(round2)));

    assertThrows(
        () =>
            fillRing(
                signInput(fixture),
                shares[0].keyImage,
                sessions[0].nonceCommit(),
                scalarToBytes(randomScalar()),
                undefined,
            ),
        Error,
        "input and output amounts are not equal",
    );
});
