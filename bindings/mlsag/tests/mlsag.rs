// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! MLSAG DKG + threshold signing (wasm_bindgen_test / wasm-pack test).

use std::collections::VecDeque;

use curve25519_dalek::{RistrettoPoint, Scalar};
use rand::RngCore;
use wasm_bindgen_test::wasm_bindgen_test;

use mlsag_wasm_ll::{
    fill_ring, verify_signature, KeygenSession, Keyshare, Message, SignInput, SignSession,
};

const PARTICIPANTS: u8 = 3;
const THRESHOLD: u8 = 2;
const MESSAGE: &[u8] = b"threshold-mlsag/wasm-test";
const VALUE: u64 = 9;

#[wasm_bindgen_test]
pub fn mlsag_dkg_2x3() {
    let shares = run_dkg(PARTICIPANTS, THRESHOLD);

    assert_eq!(shares.len(), PARTICIPANTS as usize);
    for (party_id, share) in shares.iter().enumerate() {
        assert_eq!(share.threshold(), THRESHOLD);
        assert_eq!(share.participants(), PARTICIPANTS);
        assert_eq!(share.party_id(), party_id as u8);
        assert_eq!(share.public_key(), shares[0].public_key());
        assert_eq!(share.key_image(), shares[0].key_image());
        assert_eq!(share.key_id(), shares[0].key_id());
        assert_eq!(share.root_chain_code(), shares[0].root_chain_code());
    }
}

#[wasm_bindgen_test]
pub fn mlsag_sign_2x3_every_quorum_verifies() {
    let shares = run_dkg(PARTICIPANTS, THRESHOLD);
    let ring = RingFixture::new(&shares[0].public_key(), 1, 4);

    for quorum in [[0u8, 1], [1, 2], [0, 2]] {
        let signature = run_sign(&shares, &quorum, &ring);

        assert!(verify_signature(signature.clone(), &ring.input(MESSAGE)));
        assert!(!verify_signature(signature.clone(), &ring.input(b"other")));
        assert_eq!(signature[signature.len() - 32..], shares[0].key_image());
    }
}

#[wasm_bindgen_test]
pub fn mlsag_keyshare_roundtrip_still_signs() {
    let shares: Vec<Keyshare> = run_dkg(PARTICIPANTS, THRESHOLD)
        .into_iter()
        .map(|share| Keyshare::from_bytes(share.to_bytes()).unwrap())
        .collect();
    let ring = RingFixture::new(&shares[0].public_key(), 0, 3);

    let signature = run_sign(&shares, &[0, 2], &ring);

    assert!(verify_signature(signature, &ring.input(MESSAGE)));
}

#[wasm_bindgen_test]
pub fn mlsag_every_session_draws_fresh_randomness() {
    let first_keygen = |party_id| {
        KeygenSession::new(PARTICIPANTS, THRESHOLD, party_id)
            .create_first_message()
            .payload()
    };
    assert_ne!(first_keygen(0), first_keygen(0));

    let shares = run_dkg(PARTICIPANTS, THRESHOLD);
    let ring = RingFixture::new(&shares[0].public_key(), 1, 3);
    let input = ring.input(MESSAGE);
    let first_sign = || {
        SignSession::new(&shares[0], vec![0, 1], &input)
            .create_first_message()
            .payload()
    };
    assert_ne!(first_sign(), first_sign());
}

fn run_dkg(participants: u8, threshold: u8) -> Vec<Keyshare> {
    let mut sessions: Vec<KeygenSession> = (0..participants)
        .map(|party_id| KeygenSession::new(participants, threshold, party_id))
        .collect();

    let mut queue = VecDeque::new();
    for session in sessions.iter_mut() {
        queue.push_back(session.create_first_message());
    }

    let mut steps = 0usize;
    while let Some(msg) = queue.pop_front() {
        steps += 1;
        assert!(steps <= 10_000, "dkg session exceeded step limit");

        let receivers: Vec<usize> = match msg.receiver() {
            Some(receiver) if receiver == msg.sender() => continue,
            Some(receiver) => vec![receiver as usize],
            None => (0..sessions.len())
                .filter(|party_id| *party_id != msg.sender() as usize)
                .collect(),
        };

        for receiver in receivers {
            queue.extend(sessions[receiver].recv_message(msg.clone_message()));
        }
    }

    assert!(
        sessions.iter().all(|session| session.is_finished()),
        "dkg session stalled before completion"
    );

    sessions
        .into_iter()
        .map(|session| session.into_keyshare())
        .collect()
}

fn run_sign(shares: &[Keyshare], quorum: &[u8], ring: &RingFixture) -> Vec<u8> {
    let input = ring.input(MESSAGE);

    let mut sessions: Vec<SignSession> = quorum
        .iter()
        .map(|&party_id| SignSession::new(&shares[party_id as usize], quorum.to_vec(), &input))
        .collect();

    let round1: Vec<Message> = sessions
        .iter_mut()
        .map(|session| session.create_first_message())
        .collect();

    let round2: Vec<Message> = sessions
        .iter_mut()
        .flat_map(|session| session.handle_messages(clone_all(&round1)))
        .collect();

    for session in sessions.iter_mut() {
        assert!(session.handle_messages(clone_all(&round2)).is_empty());
    }

    let nonce_commit = sessions[0].nonce_commit();
    assert!(sessions
        .iter()
        .all(|session| session.nonce_commit() == nonce_commit));

    let tour = fill_ring(
        &input,
        shares[quorum[0] as usize].key_image(),
        nonce_commit,
        ring.z.as_bytes().to_vec(),
    );

    let round3: Vec<Message> = sessions
        .iter_mut()
        .map(|session| session.handle_ring_tour(tour.clone()))
        .collect();

    for session in sessions.iter_mut() {
        assert!(session.handle_messages(clone_all(&round3)).is_empty());
    }

    let signatures: Vec<Vec<u8>> = sessions
        .into_iter()
        .map(|session| session.into_signature())
        .collect();
    assert!(signatures.iter().all(|sig| *sig == signatures[0]));
    signatures.into_iter().next().unwrap()
}

fn clone_all(messages: &[Message]) -> Vec<Message> {
    messages.iter().map(Message::clone_message).collect()
}

/// Ring with the spent output at `real_index` and random decoys. The real
/// input and the output commit to the same value, so `z = y_out - y_in`.
struct RingFixture {
    ring: Vec<u8>,
    real_index: u32,
    output_commitment: Vec<u8>,
    z: Scalar,
}

impl RingFixture {
    fn new(public_key: &[u8], real_index: u32, len: u32) -> Self {
        let h = RistrettoPoint::from_uniform_bytes(&[0x42; 64]);
        let value = Scalar::from(VALUE);
        let y_in = random_scalar();
        let y_out = random_scalar();

        let mut ring = Vec::new();
        for index in 0..len {
            if index == real_index {
                ring.extend_from_slice(public_key);
                ring.extend_from_slice(
                    (h * value + RistrettoPoint::mul_base(&y_in))
                        .compress()
                        .as_bytes(),
                );
            } else {
                for _ in 0..2 {
                    ring.extend_from_slice(
                        RistrettoPoint::mul_base(&random_scalar())
                            .compress()
                            .as_bytes(),
                    );
                }
            }
        }

        RingFixture {
            ring,
            real_index,
            output_commitment: (h * value + RistrettoPoint::mul_base(&y_out))
                .compress()
                .to_bytes()
                .to_vec(),
            z: y_out - y_in,
        }
    }

    fn input(&self, message: &[u8]) -> SignInput {
        SignInput::new(
            message.to_vec(),
            self.ring.clone(),
            self.real_index,
            self.output_commitment.clone(),
        )
    }
}

fn random_scalar() -> Scalar {
    let mut wide = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}
