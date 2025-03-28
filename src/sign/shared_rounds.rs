//! This module contains the shared round logic (first 2 rounds) for all signing protocols.
//! The logic is generic over the elliptic curve group.
//! Since the final signing is done differently for different schemes, that part is not generic and
//! is implemented as specific modules. (e.g `taproot.rs` and `eddsa.rs`)
//!
use std::sync::Arc;

use super::{
    messages::{SignMsg1, SignMsg2},
    types::{SignEntropy, SignError},
};
use crate::common::traits::OrderMachine;
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
use crypto_bigint::subtle::ConstantTimeEq;
use curve25519_dalek::EdwardsPoint;
use derivation_path::DerivationPath;
use elliptic_curve::{group::GroupEncoding, Group};
use ff::Field;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

/// Signer party
pub struct SignerParty<T, G>
where
    G: Group + GroupEncoding,
{
    pub party_id: u8,
    pub message: Vec<u8>,
    pub derivation_path: DerivationPath,
    pub(crate) keyshare: Arc<Keyshare<G>>,
    pub(crate) rand_params: SignEntropy<G>,
    pub(crate) seed: [u8; 32],
    pub(crate) state: T,
}

/// Initial state of a round based protocol.
pub struct R0;

/// Round 1 state of Signer party
pub struct R1<G> {
    big_r_i: G,
    commitment_r_i: [u8; 32],
}

/// Round 2 state of Signer party
/// State before processing all SignMsg2 messages
pub struct R2<G> {
    final_session_id: SessionId,
    big_r_i: G,
    commitment_list: Vec<[u8; 32]>,
    sid_list: Vec<SessionId>,
    pid_list: Vec<u8>,
}

/// State of Signer party after processing all SignMsg2 messages.
/// Party is ready to sign a message
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SignReady<G: Group> {
    pub session_id: SessionId,
    pub(crate) big_r: G,
    pub(crate) d_i: G::Scalar,
    pub pid_list: Vec<u8>,
    pub threshold: u8,
    pub public_key: G,
    pub message: Vec<u8>,
    pub key_id: [u8; 32],
    pub(crate) k_i: G::Scalar,
    pub party_id: u8,
}
/// State of Signer party after processing all SignMsg3 messages
pub struct PartialSign<G: Group> {
    pub party_id: u8,
    pub(crate) session_id: SessionId,
    pub threshold: u8,
    pub(crate) big_r: G,
    pub public_key: G,
    pub(crate) s_i: G::Scalar,
    pub(crate) msg_to_sign: Vec<u8>,
    pub(crate) pid_list: Vec<u8>,
}

impl SignerParty<R0, EdwardsPoint> {
    /// Create a new signer party with the given keyshare
    pub fn new<R: CryptoRng + RngCore>(
        keyshare: Arc<Keyshare<EdwardsPoint>>,
        message: Vec<u8>,
        derivation_path: DerivationPath,
        rng: &mut R,
    ) -> Self {
        Self {
            party_id: keyshare.party_id(),
            message,
            keyshare,
            derivation_path,
            rand_params: SignEntropy::generate(rng),
            seed: rng.gen(),
            state: R0,
        }
    }
}

#[cfg(any(feature = "taproot", test))]
impl SignerParty<R0, k256::ProjectivePoint> {
    /// Create a new signer party with the given keyshare
    pub fn new<R: CryptoRng + RngCore>(
        keyshare: Arc<Keyshare<k256::ProjectivePoint>>,
        message: [u8; 32],
        derivation_path: DerivationPath,
        rng: &mut R,
    ) -> Self {
        Self {
            party_id: keyshare.party_id(),
            message: message.to_vec(),
            keyshare,
            derivation_path,
            rand_params: SignEntropy::generate(rng),
            seed: rng.gen(),
            state: R0,
        }
    }
}

// Protocol 11 from https://eprint.iacr.org/2022/374.pdf
impl<G: Group + GroupEncoding> Round for SignerParty<R0, G> {
    type Input = ();

    type Output = Result<(SignerParty<R1<G>, G>, SignMsg1), SignError>;

    fn process(self, _: ()) -> Self::Output {
        let big_r_i = G::generator() * self.rand_params.k_i;
        let commitment_r_i = hash_commitment_r_i(
            &self.rand_params.session_id,
            self.party_id,
            &big_r_i,
            &self.rand_params.blind_factor,
        );

        let msg1 = SignMsg1 {
            from_party: self.keyshare.party_id(),
            session_id: self.rand_params.session_id,
            commitment_r_i,
        };

        let next_state = SignerParty {
            party_id: self.party_id,
            message: self.message,
            derivation_path: self.derivation_path,
            keyshare: self.keyshare,
            rand_params: self.rand_params,
            state: R1 {
                big_r_i,
                commitment_r_i,
            },
            seed: self.seed,
        };

        Ok((next_state, msg1))
    }
}

impl<G: GroupElem> Round for SignerParty<R1<G>, G>
where
    G: ConstantTimeEq,
    G::Scalar: ScalarReduce<[u8; 32]>,
{
    type Input = Vec<SignMsg1>;

    type Output = Result<(SignerParty<R2<G>, G>, SignMsg2<G>), SignError>;

    fn process(self, mut msgs: Self::Input) -> Self::Output {
        let mut commitment_list = Vec::with_capacity(self.keyshare.threshold as usize);
        let mut sid_list = Vec::with_capacity(self.keyshare.threshold as usize);
        let mut party_ids = Vec::with_capacity(self.keyshare.threshold as usize);

        msgs.sort_by_key(|m| m.from_party);

        for msg in &msgs {
            commitment_list.push(msg.commitment_r_i);
            sid_list.push(msg.session_id);
            party_ids.push(msg.from_party);
        }

        //check if the input commitments match
        msgs.iter()
            .any(|msg| {
                msg.from_party == self.party_id && msg.commitment_r_i == self.state.commitment_r_i
            })
            .then_some(())
            .ok_or(SignError::InvalidParticipantSet)?;

        //check sids are included
        if !sid_list.contains(&self.rand_params.session_id) {
            return Err(SignError::InvalidParticipantSet);
        }

        // Check for duplicate party ids
        let num_parties = party_ids.len();
        party_ids.dedup();

        if party_ids.len() != num_parties || !party_ids.contains(&self.party_id) {
            return Err(SignError::InvalidParticipantSet);
        }

        // Check if the number of parties is within the threshold
        if party_ids.len() < self.keyshare.threshold as usize
            || party_ids.len() > self.keyshare.total_parties as usize
        {
            return Err(SignError::InvalidParticipantSet);
        }

        let final_sid =
            calculate_final_session_id(party_ids.iter().copied(), &sid_list, Some(&self.message));

        use sha2::digest::Update;
        let dlog_sid = Sha256::new()
            .chain(b"SL-EDDSA-SIGN")
            .chain(final_sid.as_ref())
            .chain((self.party_id as u32).to_be_bytes())
            .chain(b"DLOG-SID")
            .finalize()
            .into();

        let mut rng = ChaCha20Rng::from_seed(self.seed);
        let dlog_proof = DLogProof::prove(&dlog_sid, &self.rand_params.k_i, &mut rng);

        let msg2 = SignMsg2 {
            from_party: self.keyshare.party_id(),
            session_id: final_sid,
            dlog_proof,
            blind_factor: self.rand_params.blind_factor,
            big_r_i: self.state.big_r_i.to_bytes().as_ref().to_vec(),
        };

        let next = SignerParty {
            party_id: self.party_id,
            message: self.message,
            derivation_path: self.derivation_path,
            keyshare: self.keyshare,
            rand_params: self.rand_params,
            state: R2 {
                final_session_id: final_sid,
                commitment_list,
                sid_list,
                big_r_i: self.state.big_r_i,
                pid_list: party_ids,
            },
            seed: rng.gen(),
        };

        Ok((next, msg2))
    }
}

impl<G: GroupElem> Round for SignerParty<R2<G>, G>
where
    G: ConstantTimeEq,
    G::Scalar: ScalarReduce<[u8; 32]> + OrderMachine<[u8; 32]>,
{
    type Input = Vec<SignMsg2<G>>;

    type Output = Result<SignReady<G>, SignError>;

    fn process(self, msgs: Self::Input) -> Self::Output {
        let msgs = validate_input_messages(msgs, &self.state.pid_list)?;

        let mut big_r_i = self.state.big_r_i;
        let mut participants: u32 = 0;

        for (idx, msg) in msgs.iter().enumerate() {
            if msg.from_party == self.keyshare.party_id() {
                continue;
            }

            let mut encoding = G::Repr::default();
            if encoding.as_ref().len() != msg.big_r_i.len() {
                return Err(SignError::InvalidBigRi);
            }
            encoding.as_mut().copy_from_slice(&msg.big_r_i);
            let msg_big_r_i = G::from_bytes(&encoding);
            let msg_big_r_i = if msg_big_r_i.is_some().into() {
                msg_big_r_i.unwrap()
            } else {
                return Err(SignError::InvalidBigRi);
            };
            if msg_big_r_i.is_identity().into() {
                return Err(SignError::InvalidBigRi);
            }

            let sid = self.state.sid_list[idx];
            let commitment = self.state.commitment_list[idx];

            verify_commitment_r_i(
                &sid,
                msg.from_party,
                &msg_big_r_i,
                &msg.blind_factor,
                &commitment,
            )
            .then_some(())
            .ok_or(SignError::InvalidCommitment(msg.from_party))?;

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
            participants += 1_u32;
        }
        //total participants = |message I received| + 1
        participants += 1_u32;

        // FIXME: do we need copied?
        let coeff = get_lagrange_coeff::<G>(&self.party_id, self.state.pid_list.iter().copied());

        let d_i = coeff * self.keyshare.shamir_share();

        let (additive_offset, derived_public_key) = self
            .keyshare
            .derive_with_offset(&self.derivation_path)
            .map_err(|_| SignError::InvalidKeyDerivation)?;
        let threshold_inv = <G as Group>::Scalar::from(participants as u64)
            .invert()
            .unwrap();
        let additive_offset = additive_offset * threshold_inv;

        //tweak the secret key share by the computed additive offset
        let d_i = d_i + additive_offset;

        let next = SignReady {
            key_id: self.keyshare.key_id,
            threshold: self.keyshare.threshold,
            big_r: big_r_i,
            d_i,
            pid_list: self.state.pid_list,
            public_key: derived_public_key, //replase the public key for that signature with the tweaked public key
            session_id: self.state.final_session_id,
            message: self.message,
            k_i: self.rand_params.k_i,
            party_id: self.party_id,
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
