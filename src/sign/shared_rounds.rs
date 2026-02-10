// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! This module contains the shared round logic (first 2 rounds) for all signing protocols.
//! The logic is generic over the elliptic curve group.
//! Since the final signing is done differently for different schemes, that part is not generic and
//! is implemented as specific modules. (e.g `taproot.rs` and `eddsa.rs`)
//!
use std::sync::Arc;

use crypto_bigint::subtle::ConstantTimeEq;
use derivation_path::DerivationPath;
use elliptic_curve::{group::GroupEncoding, Group};

use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

#[cfg(feature = "eddsa")]
use curve25519_dalek::EdwardsPoint;

#[cfg(feature = "redpallas")]
use crate::common::redpallas::RedPallasPoint;
#[cfg(feature = "redpallas")]
use ff::{Field, PrimeField};

use crate::{
    common::{
        get_lagrange_coeff,
        traits::{GroupElem, Round, ScalarReduce},
        utils::{calculate_final_session_id, HashBytes, SessionId},
        DLogProof,
    },
    keygen::Keyshare,
    sign::validate_input_messages,
};

#[cfg(feature = "serde")]
use crate::common::ser::Serializable;

#[cfg(feature = "serde")]
use crate::common::utils::serde_point;

use super::{
    messages::{SignMsg1, SignMsg2},
    types::{SignEntropy, SignError},
};

#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "G::Scalar: Serializable",
        deserialize = "G::Scalar: Serializable"
    ))
)]
struct Params<G>
where
    G: Group + GroupEncoding,
{
    party_id: u8,
    threshold: u8,
    total_parties: u8,
    message: Vec<u8>,
    additive_offset: G::Scalar,
    #[cfg_attr(feature = "serde", serde(with = "serde_point"))]
    derived_public_key: G,
    shamir_share: G::Scalar,
}

/// Signer party
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "T: serde::Serialize, G::Scalar: Serializable",
        deserialize = "T: serde::Deserialize<'de>, G::Scalar: Serializable"
    ))
)]
pub struct SignerParty<T, G>
where
    G: Group + GroupEncoding,
{
    params: Params<G>,
    pub(crate) rand_params: SignEntropy<G>,
    pub(crate) state: T,
    #[cfg(feature = "keyshare-session-id")]
    final_session_id: [u8; 32],
}

/// Initial state of a round based protocol.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct R0;

/// Round 1 state of Signer party
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct R1<G: Group + GroupEncoding> {
    #[cfg_attr(feature = "serde", serde(with = "serde_point"))]
    big_r_i: G,
    commitment_r_i: [u8; 32],
}

/// Round 2 state of Signer party
/// State before processing all SignMsg2 messages
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct R2<G: Group + GroupEncoding> {
    final_session_id: SessionId,
    #[cfg_attr(feature = "serde", serde(with = "serde_point"))]
    big_r_i: G,
    commitment_list: Vec<[u8; 32]>,
    sid_list: Vec<SessionId>,
    pid_list: Vec<u8>,
}

/// State of Signer party after processing all SignMsg2 messages.
/// Party is ready to sign a message
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "G: Group + GroupEncoding, G::Scalar: Serializable",
        deserialize = "G: Group + GroupEncoding, G::Scalar: Serializable"
    ))
)]
pub struct SignReady<G: Group> {
    pub session_id: SessionId,
    #[cfg_attr(feature = "serde", serde(with = "serde_point"))]
    pub(crate) big_r: G,
    pub(crate) d_i: G::Scalar,
    pub pid_list: Vec<u8>,
    #[cfg_attr(feature = "serde", serde(with = "serde_point"))]
    pub public_key: G,
    pub message: Vec<u8>,
    pub(crate) k_i: G::Scalar,
    pub party_id: u8,
}

/// State of Signer party after processing all SignMsg3 messages
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "G: Group + GroupEncoding, G::Scalar: Serializable",
        deserialize = "G: Group + GroupEncoding, G::Scalar: Serializable"
    ))
)]
pub struct PartialSign<G: Group> {
    pub party_id: u8,
    pub(crate) session_id: SessionId,
    #[cfg_attr(feature = "serde", serde(with = "serde_point"))]
    pub(crate) big_r: G,
    #[cfg_attr(feature = "serde", serde(with = "serde_point"))]
    pub public_key: G,
    pub(crate) s_i: G::Scalar,
    pub(crate) msg_to_sign: Vec<u8>,
    pub(crate) pid_list: Vec<u8>,
}

#[cfg(feature = "eddsa")]
impl SignerParty<R0, EdwardsPoint> {
    /// Create a new signer party with the given keyshare
    pub fn new<R: CryptoRng + RngCore>(
        keyshare: Arc<Keyshare<EdwardsPoint>>,
        message: Vec<u8>,
        derivation_path: DerivationPath,
        rng: &mut R,
    ) -> Self {
        let (additive_offset, derived_public_key) =
            keyshare.derive_with_offset(&derivation_path).unwrap();

        Self {
            params: Params {
                party_id: keyshare.party_id(),
                threshold: keyshare.threshold,
                total_parties: keyshare.total_parties,
                additive_offset,
                derived_public_key,
                shamir_share: *keyshare.shamir_share(),
                message,
            },
            #[cfg(feature = "keyshare-session-id")]
            final_session_id: keyshare.final_session_id,
            rand_params: SignEntropy::generate(rng),
            state: R0,
        }
    }
}

#[cfg(feature = "taproot")]
impl SignerParty<R0, k256::ProjectivePoint> {
    /// Create a new signer party with the given keyshare
    pub fn new<R: CryptoRng + RngCore>(
        keyshare: Arc<Keyshare<k256::ProjectivePoint>>,
        message: [u8; 32],
        derivation_path: DerivationPath,
        rng: &mut R,
    ) -> Self {
        let (additive_offset, derived_public_key) =
            keyshare.derive_with_offset(&derivation_path).unwrap();

        Self {
            params: Params {
                party_id: keyshare.party_id(),
                threshold: keyshare.threshold,
                total_parties: keyshare.total_parties,
                additive_offset,
                derived_public_key,
                shamir_share: *keyshare.shamir_share(),
                message: message.to_vec(),
            },
            #[cfg(feature = "keyshare-session-id")]
            final_session_id: keyshare.final_session_id,
            rand_params: SignEntropy::generate(rng),
            state: R0,
        }
    }
}

#[cfg(feature = "redpallas")]
impl SignerParty<R0, RedPallasPoint> {
    /// Create a new signer party with the given keyshare (RedDSA / RedPallas)
    pub fn new<R: CryptoRng + RngCore>(
        keyshare: Arc<Keyshare<RedPallasPoint>>,
        message: Vec<u8>,
        derivation_path: DerivationPath,
        rng: &mut R,
    ) -> Self {
        let (additive_offset, derived_public_key) =
            keyshare.derive_with_offset(&derivation_path).unwrap();

        Self {
            params: Params {
                party_id: keyshare.party_id(),
                threshold: keyshare.threshold,
                total_parties: keyshare.total_parties,
                additive_offset,
                derived_public_key,
                shamir_share: *keyshare.shamir_share(),
                message,
            },
            #[cfg(feature = "keyshare-session-id")]
            final_session_id: keyshare.final_session_id,
            rand_params: SignEntropy::generate(rng),
            state: R0,
        }
    }
}

// Protocol 11 from https://eprint.iacr.org/2022/374.pdf
impl<G> Round for SignerParty<R0, G>
where
    G: GroupElem,
{
    type InputMessage = ();
    type Input = ();
    type Error = SignError;
    type Output = (SignerParty<R1<G>, G>, SignMsg1);

    fn process(self, _: ()) -> Result<Self::Output, Self::Error> {
        let big_r_i = G::generator() * self.rand_params.k_i;
        let commitment_r_i = hash_commitment_r_i(
            &self.rand_params.session_id,
            self.params.party_id,
            &big_r_i,
            &self.rand_params.blind_factor,
        );

        let msg1 = SignMsg1 {
            from_party: self.params.party_id,
            session_id: self.rand_params.session_id,
            commitment_r_i,
        };

        let next_state = SignerParty {
            params: self.params,
            rand_params: self.rand_params,
            state: R1 {
                big_r_i,
                commitment_r_i,
            },
            #[cfg(feature = "keyshare-session-id")]
            final_session_id: self.final_session_id,
        };

        Ok((next_state, msg1))
    }
}

impl<G> Round for SignerParty<R1<G>, G>
where
    G: GroupElem,
    G::Scalar: ScalarReduce<[u8; 32]>,
{
    type InputMessage = SignMsg1;
    type Input = Vec<SignMsg1>;
    type Error = SignError;
    type Output = (SignerParty<R2<G>, G>, SignMsg2<G>);

    fn process(self, mut msgs: Self::Input) -> Result<Self::Output, Self::Error> {
        let mut commitment_list = Vec::with_capacity(self.params.threshold as usize);
        let mut sid_list = Vec::with_capacity(self.params.threshold as usize);
        let mut party_ids = Vec::with_capacity(self.params.threshold as usize);

        msgs.sort_by_key(|m| m.from_party);

        for msg in &msgs {
            commitment_list.push(msg.commitment_r_i);
            sid_list.push(msg.session_id);
            party_ids.push(msg.from_party);
        }

        // check if the input commitments match
        msgs.iter()
            .any(|msg| {
                msg.from_party == self.params.party_id
                    && msg.commitment_r_i == self.state.commitment_r_i
            })
            .then_some(())
            .ok_or(SignError::InvalidParticipantSet)?;

        // check sids are included
        if !sid_list.contains(&self.rand_params.session_id) {
            return Err(SignError::InvalidParticipantSet);
        }

        // Check for duplicate party ids
        let num_parties = party_ids.len();
        party_ids.dedup();

        if party_ids.len() != num_parties || !party_ids.contains(&self.params.party_id) {
            return Err(SignError::InvalidParticipantSet);
        }

        // Check if the number of parties is within the threshold
        if party_ids.len() < self.params.threshold as usize
            || party_ids.len() > self.params.total_parties as usize
        {
            return Err(SignError::InvalidParticipantSet);
        }

        let final_sid = calculate_final_session_id(
            party_ids.iter().copied(),
            &sid_list,
            #[cfg(feature = "keyshare-session-id")]
            &[&self.params.message, &self.final_session_id],
            #[cfg(not(feature = "keyshare-session-id"))]
            &[&self.params.message],
        );

        use sha2::digest::Update;
        let dlog_sid = Sha256::new()
            .chain(b"SL-EDDSA-SIGN")
            .chain(final_sid)
            .chain((self.params.party_id as u32).to_be_bytes())
            .chain(b"DLOG-SID")
            .finalize()
            .into();

        let mut rng = ChaCha20Rng::from_seed(self.rand_params.seed);
        let dlog_proof = DLogProof::prove(&dlog_sid, &self.rand_params.k_i, &mut rng);

        let msg2 = SignMsg2 {
            from_party: self.params.party_id,
            session_id: final_sid,
            dlog_proof,
            blind_factor: self.rand_params.blind_factor,
            big_r_i: self.state.big_r_i.to_bytes().as_ref().to_vec(),
        };

        let next = SignerParty {
            params: self.params,
            rand_params: self.rand_params,
            state: R2 {
                final_session_id: final_sid,
                commitment_list,
                sid_list,
                big_r_i: self.state.big_r_i,
                pid_list: party_ids,
            },
            #[cfg(feature = "keyshare-session-id")]
            final_session_id: self.final_session_id,
        };

        Ok((next, msg2))
    }
}
#[cfg(feature = "eddsa")]
impl Round for SignerParty<R2<EdwardsPoint>, EdwardsPoint> {
    type InputMessage = SignMsg2<EdwardsPoint>;
    type Input = Vec<SignMsg2<EdwardsPoint>>;
    type Error = SignError;
    type Output = SignReady<EdwardsPoint>;

    fn process(self, msgs: Self::Input) -> Result<Self::Output, Self::Error> {
        let msgs = validate_input_messages(msgs, &self.state.pid_list)?;

        let mut big_r_i = self.state.big_r_i;
        let participants = msgs.len();

        for (idx, msg) in msgs.iter().enumerate() {
            if msg.from_party == self.params.party_id {
                continue;
            }

            let mut encoding = <EdwardsPoint as GroupEncoding>::Repr::default();
            if encoding.as_ref().len() != msg.big_r_i.len() {
                return Err(SignError::InvalidBigRi);
            }
            encoding.as_mut().copy_from_slice(&msg.big_r_i);

            let msg_big_r_i = EdwardsPoint::from_bytes(&encoding)
                .into_option()
                .ok_or(SignError::InvalidBigRi)?;
            if msg_big_r_i.is_identity().into() {
                return Err(SignError::InvalidBigRi);
            }

            if !verify_commitment_r_i(
                &self.state.sid_list[idx],
                msg.from_party,
                &msg_big_r_i,
                &msg.blind_factor,
                &self.state.commitment_list[idx],
            ) {
                return Err(SignError::InvalidCommitment(msg.from_party));
            }

            let mut h = Sha256::new();
            h.update(b"SL-EDDSA-SIGN");
            h.update(self.state.final_session_id.as_ref());
            h.update((msg.from_party as u32).to_be_bytes());
            h.update(b"DLOG-SID");

            let dlog_sid = h.finalize().into();

            msg.dlog_proof
                .verify(&dlog_sid, &msg_big_r_i)
                .then_some(())
                .ok_or(SignError::InvalidDLogProof(msg.from_party))?;

            big_r_i += msg_big_r_i;
        }

        let coeff = get_lagrange_coeff::<EdwardsPoint>(
            &self.params.party_id,
            self.state.pid_list.iter().copied(),
        );

        let d_i = coeff * self.params.shamir_share;

        let threshold_inv = curve25519_dalek::Scalar::from(participants as u64).invert();

        let additive_offset = self.params.additive_offset * threshold_inv;

        //tweak the secret key share by the computed additive offset
        let d_i = d_i + additive_offset;

        let next = SignReady {
            big_r: big_r_i,
            d_i,
            pid_list: self.state.pid_list,
            public_key: self.params.derived_public_key,
            session_id: self.state.final_session_id,
            message: self.params.message,
            k_i: self.rand_params.k_i,
            party_id: self.params.party_id,
        };

        Ok(next)
    }
}

#[cfg(feature = "taproot")]
impl Round for SignerParty<R2<k256::ProjectivePoint>, k256::ProjectivePoint> {
    type InputMessage = SignMsg2<k256::ProjectivePoint>;
    type Input = Vec<SignMsg2<k256::ProjectivePoint>>;
    type Error = SignError;
    type Output = SignReady<k256::ProjectivePoint>;

    fn process(self, msgs: Self::Input) -> Result<Self::Output, Self::Error> {
        let msgs = validate_input_messages(msgs, &self.state.pid_list)?;

        let mut big_r_i = self.state.big_r_i;
        let participants = msgs.len();

        for (idx, msg) in msgs.iter().enumerate() {
            if msg.from_party == self.params.party_id {
                continue;
            }

            let mut encoding: <k256::ProjectivePoint as GroupEncoding>::Repr = Default::default();
            if encoding.len() != msg.big_r_i.len() {
                return Err(SignError::InvalidBigRi);
            }
            encoding[..].copy_from_slice(&msg.big_r_i);

            let msg_big_r_i = k256::ProjectivePoint::from_bytes(&encoding)
                .into_option()
                .ok_or(SignError::InvalidBigRi)?;
            if msg_big_r_i.is_identity().into() {
                return Err(SignError::InvalidBigRi);
            }

            if !verify_commitment_r_i(
                &self.state.sid_list[idx],
                msg.from_party,
                &msg_big_r_i,
                &msg.blind_factor,
                &self.state.commitment_list[idx],
            ) {
                return Err(SignError::InvalidCommitment(msg.from_party));
            }

            let mut h = Sha256::new();
            h.update(b"SL-EDDSA-SIGN");
            h.update(self.state.final_session_id.as_ref());
            h.update((msg.from_party as u32).to_be_bytes());
            h.update(b"DLOG-SID");

            let dlog_sid = h.finalize().into();

            msg.dlog_proof
                .verify(&dlog_sid, &msg_big_r_i)
                .then_some(())
                .ok_or(SignError::InvalidDLogProof(msg.from_party))?;

            big_r_i += msg_big_r_i;
        }

        let coeff = get_lagrange_coeff::<k256::ProjectivePoint>(
            &self.params.party_id,
            self.state.pid_list.iter().copied(),
        );

        let d_i = coeff * self.params.shamir_share;

        let scalar = k256::Scalar::from(participants as u64);
        let threshold_inv: k256::Scalar =
            Option::from(scalar.invert()).ok_or(SignError::InvalidThreshold)?;

        let additive_offset = self.params.additive_offset * threshold_inv;

        //tweak the secret key share by the computed additive offset
        let d_i = d_i + additive_offset;

        let next = SignReady {
            big_r: big_r_i,
            d_i,
            pid_list: self.state.pid_list,
            public_key: self.params.derived_public_key,
            session_id: self.state.final_session_id,
            message: self.params.message,
            k_i: self.rand_params.k_i,
            party_id: self.params.party_id,
        };

        Ok(next)
    }
}

#[cfg(feature = "redpallas")]
impl Round for SignerParty<R2<RedPallasPoint>, RedPallasPoint> {
    type InputMessage = SignMsg2<RedPallasPoint>;
    type Input = Vec<SignMsg2<RedPallasPoint>>;
    type Error = SignError;
    type Output = SignReady<RedPallasPoint>;

    fn process(self, msgs: Self::Input) -> Result<Self::Output, Self::Error> {
        let msgs = validate_input_messages(msgs, &self.state.pid_list)?;

        let mut big_r_i = self.state.big_r_i;
        let participants = msgs.len();
        // Use commitment hashes as randomizer source (each party's commitment is bound in round 1)
        let commitment_r_i = hash_commitment_r_i(
            &self.rand_params.session_id,
            self.params.party_id,
            &big_r_i,
            &self.rand_params.blind_factor,
        );
        let mut randomizer_i =
            <pasta_curves::Fq as ScalarReduce<[u8; 32]>>::reduce_from_bytes(&commitment_r_i);

        for (idx, msg) in msgs.iter().enumerate() {
            if msg.from_party == self.params.party_id {
                continue;
            }

            let mut encoding = <RedPallasPoint as GroupEncoding>::Repr::default();
            if encoding.as_ref().len() != msg.big_r_i.len() {
                return Err(SignError::InvalidBigRi);
            }
            encoding.as_mut().copy_from_slice(&msg.big_r_i);

            let msg_big_r_i = RedPallasPoint::from_bytes(&encoding)
                .into_option()
                .ok_or(SignError::InvalidBigRi)?;
            if msg_big_r_i.is_identity().into() {
                return Err(SignError::InvalidBigRi);
            }

            if !verify_commitment_r_i(
                &self.state.sid_list[idx],
                msg.from_party,
                &msg_big_r_i,
                &msg.blind_factor,
                &self.state.commitment_list[idx],
            ) {
                return Err(SignError::InvalidCommitment(msg.from_party));
            }

            let mut h = Sha256::new();
            h.update(b"SL-EDDSA-SIGN");
            h.update(self.state.final_session_id.as_ref());
            h.update((msg.from_party as u32).to_be_bytes());
            h.update(b"DLOG-SID");

            let dlog_sid = h.finalize().into();

            msg.dlog_proof
                .verify(&dlog_sid, &msg_big_r_i)
                .then_some(())
                .ok_or(SignError::InvalidDLogProof(msg.from_party))?;

            big_r_i += msg_big_r_i;
            //add randomness from commitment_r_i to the randomizer
            randomizer_i += <pasta_curves::Fq as ScalarReduce<[u8; 32]>>::reduce_from_bytes(
                &self.state.commitment_list[idx],
            );
        }

        let coeff = get_lagrange_coeff::<RedPallasPoint>(
            &self.params.party_id,
            self.state.pid_list.iter().copied(),
        );

        let d_i = coeff * self.params.shamir_share;

        let scalar = <RedPallasPoint as Group>::Scalar::from(participants as u64);
        let threshold_inv: pasta_curves::Fq =
            Option::from(scalar.invert()).ok_or(SignError::InvalidThreshold)?;

        let additive_offset = self.params.additive_offset * threshold_inv;

        let rand_offset = randomizer_i;
        //hash the randomizer to get a scalar
        let rand_offset_hashed = RedPallasPoint::hash_randomizer(rand_offset.to_repr().as_ref());

        let d_i = d_i + additive_offset + rand_offset_hashed;

        let next = SignReady {
            big_r: big_r_i,
            d_i,
            pid_list: self.state.pid_list,
            public_key: self.params.derived_public_key
                + (RedPallasPoint::generator()
                    * (rand_offset_hashed * pasta_curves::Fq::from(participants as u64))),
            session_id: self.state.final_session_id,
            message: self.params.message,
            k_i: self.rand_params.k_i,
            party_id: self.params.party_id,
        };

        Ok(next)
    }
}

fn hash_commitment_r_i<G: Group + GroupEncoding>(
    session_id: &SessionId,
    party_id: u8,
    big_r_i: &G,
    blind_factor: &[u8; 32],
) -> HashBytes {
    use sha2::digest::Update;
    Sha256::new()
        .chain(session_id.as_ref())
        .chain((party_id as u32).to_be_bytes())
        .chain(big_r_i.to_bytes())
        .chain(blind_factor)
        .finalize()
        .into()
}

fn verify_commitment_r_i<G: Group + GroupEncoding>(
    sid: &SessionId,
    pid: u8,
    big_r_i: &G,
    blind_factor: &[u8; 32],
    commitment: &HashBytes,
) -> bool {
    let compare_commitment = hash_commitment_r_i(sid, pid, big_r_i, blind_factor);
    commitment.ct_eq(&compare_commitment).into()
}
