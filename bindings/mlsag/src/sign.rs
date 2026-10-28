// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    Scalar,
};
use js_sys::Error;
use rand::rngs::OsRng;
use wasm_bindgen::{prelude::*, throw_str, UnwrapThrowExt};

use sl_mpc_mlsag::{
    sign::{StateClosed, StateInit, StateNonces, StateOpened, StateRound1Sent},
    KeyImage, MlsagError, MlsagSignContext, RingMLSAG, RingMember, RingTour, SignMsg1, SignMsg2,
    SignMsg3, SignPublicInput,
};

use crate::{keyshare::Keyshare, message::Message};

const POINT_SIZE: usize = 32;
const RING_MEMBER_SIZE: usize = 2 * POINT_SIZE;

/// Public MLSAG signing input: message, ring, real index and output
/// commitment.
///
/// `ring` is the concatenation of every ring member as
/// `onetime_public (32 bytes) || commitment (32 bytes)`, each a compressed
/// Ristretto point. The ring length `M` is `ring.length / 64`.
#[wasm_bindgen]
pub struct SignInput {
    inner: SignPublicInput,
}

#[wasm_bindgen]
impl SignInput {
    #[wasm_bindgen(constructor)]
    pub fn new(
        message: Vec<u8>,
        ring: Vec<u8>,
        real_index: u32,
        output_commitment: Vec<u8>,
    ) -> SignInput {
        if ring.is_empty() || !ring.len().is_multiple_of(RING_MEMBER_SIZE) {
            throw_str(&format!("ring length mismatch {}", ring.len()));
        }

        let ring = ring
            .chunks(RING_MEMBER_SIZE)
            .map(|member| RingMember {
                onetime_public: compressed_point(&member[..POINT_SIZE]),
                commitment: compressed_point(&member[POINT_SIZE..]),
            })
            .collect();

        SignInput {
            inner: SignPublicInput {
                message,
                ring,
                real_index: real_index as usize,
                output_commitment: compressed_point(&output_commitment),
            },
        }
    }
}

#[allow(clippy::large_enum_variant)]
enum SignRound {
    Init(MlsagSignContext<StateInit>),
    WaitMsg1(MlsagSignContext<StateRound1Sent>),
    WaitMsg2(MlsagSignContext<StateOpened>),
    WaitRingTour {
        party: MlsagSignContext<StateNonces>,
        l0: [u8; 32],
        r0: [u8; 32],
    },
    WaitMsg3 {
        party: MlsagSignContext<StateClosed>,
        tour: RingTour,
    },
    Finished(Vec<u8>),
    Failed {
        reason: String,
    },
}

/// One party's MLSAG signing session.
///
/// The session lives in memory only and cannot be serialised. After
/// `createFirstMessage` it holds this party's spend nonce, and answering two
/// different challenges from one copy of that state reveals the key share.
/// If a session is lost, every signer aborts and starts a new one.
#[wasm_bindgen]
pub struct SignSession {
    round: SignRound,
}

#[wasm_bindgen]
impl SignSession {
    /// Creates a new signer for the provided key share and signing
    /// input. `participating_party_ids` is the signing quorum: at least
    /// `threshold` ids including this party. `input.ring[realIndex]` must
    /// carry this key share's public key.
    #[wasm_bindgen(constructor)]
    pub fn new(
        keyshare: &Keyshare,
        participating_party_ids: Vec<u8>,
        input: &SignInput,
    ) -> SignSession {
        let party = MlsagSignContext::new(
            keyshare.as_inner().clone(),
            participating_party_ids,
            input.inner.clone(),
        );

        let party = match party {
            Ok(party) => party,
            Err(err) => throw_str(&err.to_string()),
        };

        SignSession {
            round: SignRound::Init(party),
        }
    }

    /// Returns the failure that caused the session to abort, if any.
    #[wasm_bindgen(js_name = error)]
    pub fn error(&self) -> Option<Error> {
        match &self.round {
            SignRound::Failed { reason } => Some(Error::new(reason)),
            _ => None,
        }
    }

    /// Starts the signing protocol and returns the first broadcast
    /// message: a commitment to this party's session id and spend nonce.
    #[wasm_bindgen(js_name = createFirstMessage)]
    pub fn create_first_message(&mut self) -> Message {
        let party = match core::mem::replace(
            &mut self.round,
            SignRound::Failed {
                reason: "invalid state".into(),
            },
        ) {
            SignRound::Init(party) => party,
            SignRound::Failed { reason } => {
                self.round = SignRound::Failed { reason };
                throw_str("failed");
            }
            other => {
                self.round = other;
                throw_str("invalid state");
            }
        };

        match party.round1_out(&mut OsRng) {
            Ok((next, msg)) => {
                self.round = SignRound::WaitMsg1(next);
                Message::encode(msg)
            }
            Err(err) => self.fail(err),
        }
    }

    /// Processes the full batch of messages for the current round,
    /// including this party's own, and returns the next messages that
    /// need to be forwarded to peers.
    ///
    /// After the round-2 batch the session returns no message and waits for
    /// the ring tour; see [`handle_ring_tour`](Self::handle_ring_tour).
    #[wasm_bindgen(js_name = handleMessages)]
    pub fn handle_messages(&mut self, messages: Vec<Message>) -> Vec<Message> {
        match core::mem::replace(
            &mut self.round,
            SignRound::Failed {
                reason: "invalid state".into(),
            },
        ) {
            SignRound::WaitMsg1(party) => {
                let msgs = Message::decode_vec::<SignMsg1>(&messages);
                let party = match party.round1_in(msgs) {
                    Ok((party, _session_id)) => party,
                    Err(err) => self.fail(err),
                };
                match party.round2_out() {
                    Ok((next, msg)) => {
                        self.round = SignRound::WaitMsg2(next);
                        vec![Message::encode(msg)]
                    }
                    Err(err) => self.fail(err),
                }
            }

            SignRound::WaitMsg2(party) => {
                let msgs = Message::decode_vec::<SignMsg2>(&messages);
                match party.round2_in(msgs) {
                    Ok((next, nonce)) => {
                        self.round = SignRound::WaitRingTour {
                            party: next,
                            l0: nonce.l0.compress().to_bytes(),
                            r0: nonce.r0.compress().to_bytes(),
                        };
                        vec![]
                    }
                    Err(err) => self.fail(err),
                }
            }

            SignRound::WaitMsg3 { party, tour } => {
                let msgs = Message::decode_vec::<SignMsg3>(&messages);
                match party.round3_in(msgs, &tour) {
                    Ok(signature) => {
                        self.round = SignRound::Finished(signature_to_bytes(&signature));
                        vec![]
                    }
                    Err(err) => self.fail(err),
                }
            }

            SignRound::Failed { reason } => {
                self.round = SignRound::Failed { reason };
                throw_str("failed")
            }

            other => {
                self.round = other;
                throw_str("invalid state")
            }
        }
    }

    /// Returns the summed spend nonce `L0 || R0` (two compressed points)
    /// once the round-2 batch has been processed. Input to
    /// [`fill_ring`].
    #[wasm_bindgen(js_name = nonceCommit)]
    pub fn nonce_commit(&self) -> Vec<u8> {
        match &self.round {
            SignRound::WaitRingTour { l0, r0, .. } => [*l0, *r0].concat(),
            SignRound::Failed { .. } => throw_str("failed"),
            _ => throw_str("invalid state"),
        }
    }

    /// Closes this party's spend response against the ring tour from
    /// [`fill_ring`] and returns the round-3 broadcast message. Every
    /// signer must receive the same tour bytes.
    #[wasm_bindgen(js_name = handleRingTour)]
    pub fn handle_ring_tour(&mut self, tour: Vec<u8>) -> Message {
        let party = match core::mem::replace(
            &mut self.round,
            SignRound::Failed {
                reason: "invalid state".into(),
            },
        ) {
            SignRound::WaitRingTour { party, .. } => party,
            SignRound::Failed { reason } => {
                self.round = SignRound::Failed { reason };
                throw_str("failed");
            }
            other => {
                self.round = other;
                throw_str("invalid state");
            }
        };

        let tour: RingTour =
            ciborium::from_reader(tour.as_slice()).expect_throw("CBOR decode failure");

        match party.round3_out(&tour) {
            Ok((next, msg)) => {
                self.round = SignRound::WaitMsg3 { party: next, tour };
                Message::encode(msg)
            }
            Err(err) => self.fail(err),
        }
    }

    /// Consumes the session and returns the signature bytes
    /// `c_zero || r_{0,0} || r_{0,1} || ... || r_{M-1,1} || key_image`,
    /// each 32 bytes. Calling this before the protocol completes results
    /// in an error.
    #[wasm_bindgen(js_name = signature)]
    pub fn into_signature(self) -> Vec<u8> {
        match self.round {
            SignRound::Finished(signature) => signature,
            _ => throw_str("invalid state"),
        }
    }
}

impl SignSession {
    fn fail(&mut self, err: MlsagError) -> ! {
        let reason = err.to_string();
        self.round = SignRound::Failed { reason };
        throw_str(&err.to_string())
    }
}

/// Builds the ring tour: decoy responses, the amount-layer response and
/// `L1`. Called once by whoever knows the blinding difference
/// `z = y_out - y_in` (32-byte canonical scalar). `nonce_commit` is
/// [`SignSession::nonce_commit`] and `key_image` is the key share's key
/// image.
///
/// Returns the CBOR-encoded tour. Send the same bytes to every signer and
/// keep them inside the quorum: the unset spend slot identifies the real
/// index.
#[wasm_bindgen(js_name = fillRing)]
pub fn fill_ring(
    input: &SignInput,
    key_image: Vec<u8>,
    nonce_commit: Vec<u8>,
    z: Vec<u8>,
) -> Vec<u8> {
    let key_image = match <[u8; 32]>::try_from(key_image.as_slice())
        .ok()
        .and_then(|bytes| KeyImage::try_from(bytes).ok())
    {
        Some(key_image) => key_image,
        None => throw_str("invalid key image"),
    };

    if nonce_commit.len() != 2 * POINT_SIZE {
        throw_str("invalid nonce commit");
    }
    let l0 = decompress_point(&nonce_commit[..POINT_SIZE]);
    let r0 = decompress_point(&nonce_commit[POINT_SIZE..]);
    let z = canonical_scalar(&z);

    let tour = match sl_mpc_mlsag::fill_ring(&input.inner, &key_image, &l0, &r0, &z, &mut OsRng) {
        Ok(tour) => tour,
        Err(err) => throw_str(&err.to_string()),
    };

    let mut buffer = vec![];
    ciborium::into_writer(&tour, &mut buffer).expect_throw("CBOR serialization failure");
    buffer
}

/// Verifies signature bytes produced by [`SignSession::into_signature`]
/// against `input`. Verification does not use `input.realIndex`.
#[wasm_bindgen(js_name = verifySignature)]
pub fn verify_signature(signature: Vec<u8>, input: &SignInput) -> bool {
    match signature_from_bytes(&signature) {
        Some(signature) => signature.verify(&input.inner).is_ok(),
        None => false,
    }
}

fn signature_to_bytes(signature: &RingMLSAG) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(POINT_SIZE * (signature.responses.len() + 2));
    bytes.extend_from_slice(signature.c_zero.as_bytes());
    for response in &signature.responses {
        bytes.extend_from_slice(response.as_bytes());
    }
    bytes.extend_from_slice(signature.key_image.as_bytes());
    bytes
}

fn signature_from_bytes(bytes: &[u8]) -> Option<RingMLSAG> {
    if bytes.len() < 2 * POINT_SIZE || !bytes.len().is_multiple_of(POINT_SIZE) {
        return None;
    }

    let mut scalars = bytes[..bytes.len() - POINT_SIZE]
        .chunks(POINT_SIZE)
        .map(|chunk| Option::from(Scalar::from_canonical_bytes(chunk.try_into().ok()?)))
        .collect::<Option<Vec<Scalar>>>()?;
    let c_zero = scalars.remove(0);
    let key_image =
        KeyImage::try_from(<[u8; 32]>::try_from(&bytes[bytes.len() - POINT_SIZE..]).ok()?).ok()?;

    Some(RingMLSAG {
        c_zero,
        responses: scalars,
        key_image,
    })
}

fn compressed_point(bytes: &[u8]) -> CompressedRistretto {
    match CompressedRistretto::from_slice(bytes) {
        Ok(point) => point,
        Err(_) => throw_str("invalid point length"),
    }
}

fn decompress_point(bytes: &[u8]) -> RistrettoPoint {
    match compressed_point(bytes).decompress() {
        Some(point) => point,
        None => throw_str("invalid point"),
    }
}

fn canonical_scalar(bytes: &[u8]) -> Scalar {
    match <[u8; 32]>::try_from(bytes)
        .ok()
        .and_then(|bytes| Option::from(Scalar::from_canonical_bytes(bytes)))
    {
        Some(scalar) => scalar,
        None => throw_str("invalid scalar"),
    }
}
