// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! RedPallas keyshare rerandomization: distributed or orchestrator-sampled alpha.
//!
//! # Distributed path ([`RerandParty`])
//!
//! Three rounds:
//! 1. Each party samples `(session_id, randomizer_i, blind_factor)`, commits to
//!    `(party_id, session_id, randomizer_i)`, and broadcasts the commitment.
//! 2. After the same participant-set checks as DSG round 1 (no DLOG), parties
//!    compute `final_sid` and open by sending `blind_factor` and `randomizer_i`.
//! 3. Commitments are checked; each party adds `alpha = H(∑ randomizer_i)` to its
//!    shamir share and `G·alpha` to the public key, then outputs the new keyshare
//!    together with `alpha`.
//!
//! # Orchestrator-sampled path
//!
//! A trusted orchestrator (e.g. wallet-platform) samples a canonical non-zero
//! [`Fq`] alpha and delivers it to each signer. Callers then use
//! [`apply_alpha`] / [`apply_alpha_bytes`] (and optionally [`verify_rk`]) before
//! DSG. Both paths produce the same share tweak: `d' = d + α`, `rk = ak + G·α`.

use alloc::vec::Vec;

use crypto_bigint::subtle::ConstantTimeEq;
use elliptic_curve::Group;
use ff::{Field, PrimeField};
use group::GroupEncoding;
use pasta_curves::Fq;
use rand::{CryptoRng, Rng, RngCore};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    common::{
        redpallas::RedPallasPoint,
        traits::Round,
        utils::{calculate_final_session_id, BaseMessage, HashBytes, SessionId},
    },
    keygen::Keyshare,
};

/// Errors for the RedPallas keyshare rerandomization protocol.
#[derive(Debug, Error)]
pub enum RerandError {
    #[error("Invalid party ids on messages list")]
    InvalidParticipantSet,
    #[error("Invalid input message count")]
    InvalidMsgCount,
    #[error("Received duplicate party id")]
    DuplicatePartyId,
    #[error("Invalid party ids")]
    InvalidMsgPartyId,
    #[error("Invalid commitment from party {0}")]
    InvalidCommitment(u8),
    #[error("Alpha must be a non-zero scalar")]
    ZeroAlpha,
    #[error("Rerandomized public key must not be the identity")]
    IdentityRk,
    #[error("Alpha encoding is not a canonical Fq")]
    InvalidAlphaEncoding,
    #[error("Claimed rk does not equal ak + alpha·G")]
    RkMismatch,
}

/// Round-1 message: commitment to `(party_id, session_id, randomizer_i)`.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone)]
pub struct RerandMsg1 {
    pub from_party: u8,
    pub session_id: SessionId,
    pub commitment: [u8; 32],
}

/// Round-2 message: opening of the round-1 commitment.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone)]
pub struct RerandMsg2 {
    pub from_party: u8,
    pub session_id: SessionId,
    pub blind_factor: [u8; 32],
    pub randomizer_i: Fq,
}

impl BaseMessage for RerandMsg2 {
    fn party_id(&self) -> u8 {
        self.from_party
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
struct RerandEntropy {
    session_id: SessionId,
    randomizer_i: Fq,
    blind_factor: [u8; 32],
}

impl RerandEntropy {
    fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Self {
            session_id: rng.gen(),
            randomizer_i: Fq::random(&mut *rng),
            blind_factor: rng.gen(),
        }
    }
}

/// Rerandomization party.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RerandParty<S> {
    keyshare: Keyshare<RedPallasPoint>,
    entropy: RerandEntropy,
    state: S,
}

/// Initial state.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RerandR0;

/// After broadcasting the commitment.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RerandR1 {
    commitment: [u8; 32],
}

/// After validating round-1 messages; ready to open.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RerandR2 {
    final_session_id: SessionId,
    commitment_list: Vec<[u8; 32]>,
    sid_list: Vec<SessionId>,
    pid_list: Vec<u8>,
}

impl RerandParty<RerandR0> {
    /// Start rerandomization from an existing RedPallas keyshare.
    pub fn new<R: CryptoRng + RngCore>(keyshare: Keyshare<RedPallasPoint>, rng: &mut R) -> Self {
        Self {
            keyshare,
            entropy: RerandEntropy::generate(rng),
            state: RerandR0,
        }
    }
}

/// Decode a canonical little-endian 32-byte `Fq` encoding.
pub fn decode_alpha(alpha_le: &[u8; 32]) -> Result<Fq, RerandError> {
    let mut repr = <Fq as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(alpha_le);
    Option::<Fq>::from(Fq::from_repr(repr)).ok_or(RerandError::InvalidAlphaEncoding)
}

/// `rk = ak + α·G`. Rejects zero α and the identity point.
pub fn derive_rk(ak: &RedPallasPoint, alpha: &Fq) -> Result<RedPallasPoint, RerandError> {
    if bool::from(alpha.is_zero()) {
        return Err(RerandError::ZeroAlpha);
    }
    let rk = *ak + RedPallasPoint::generator() * *alpha;
    if bool::from(rk.is_identity()) {
        return Err(RerandError::IdentityRk);
    }
    Ok(rk)
}

/// Check that `claimed_rk == ak + α·G` (and that α / rk pass [`derive_rk`] checks).
pub fn verify_rk(
    ak: &RedPallasPoint,
    alpha: &Fq,
    claimed_rk: &RedPallasPoint,
) -> Result<(), RerandError> {
    let rk = derive_rk(ak, alpha)?;
    if bool::from(rk.ct_eq(claimed_rk)) {
        Ok(())
    } else {
        Err(RerandError::RkMismatch)
    }
}

/// Locally tweak a RedPallas keyshare with an externally supplied α.
///
/// Sets `d' = d + α` and `public_key' = ak + G·α`. Used by the orchestrator-
/// sampled path; the distributed [`RerandParty`] path also ends here after
/// deriving `α = H(∑ randomizer_i)`.
pub fn apply_alpha(
    mut keyshare: Keyshare<RedPallasPoint>,
    alpha: Fq,
) -> Result<(Keyshare<RedPallasPoint>, Fq), RerandError> {
    let rk = derive_rk(&keyshare.public_key, &alpha)?;
    keyshare.d_i += alpha;
    keyshare.public_key = rk;
    Ok((keyshare, alpha))
}

/// [`apply_alpha`] with a canonical 32-byte little-endian α encoding.
pub fn apply_alpha_bytes(
    keyshare: Keyshare<RedPallasPoint>,
    alpha_le: &[u8; 32],
) -> Result<(Keyshare<RedPallasPoint>, Fq), RerandError> {
    let alpha = decode_alpha(alpha_le)?;
    apply_alpha(keyshare, alpha)
}

fn hash_commitment_randomizer(
    session_id: &SessionId,
    party_id: u8,
    randomizer: &Fq,
    blind_factor: &[u8; 32],
) -> HashBytes {
    use sha2::digest::Update;
    Sha256::new()
        .chain(session_id.as_ref())
        .chain((party_id as u32).to_be_bytes())
        .chain(randomizer.to_repr().as_ref())
        .chain(blind_factor)
        .finalize()
        .into()
}

fn verify_commitment_randomizer(
    sid: &SessionId,
    pid: u8,
    randomizer: &Fq,
    blind_factor: &[u8; 32],
    commitment: &HashBytes,
) -> bool {
    let compare = hash_commitment_randomizer(sid, pid, randomizer, blind_factor);
    commitment.ct_eq(&compare).into()
}

fn validate_input_messages(
    mut msgs: Vec<RerandMsg2>,
    party_id_list: &[u8],
) -> Result<Vec<RerandMsg2>, RerandError> {
    if msgs.len() != party_id_list.len() {
        return Err(RerandError::InvalidMsgCount);
    }

    let mut party_ids = msgs.iter().map(|msg| msg.party_id()).collect::<Vec<_>>();
    party_ids.sort_unstable();
    party_ids.dedup();

    if party_ids.len() != party_id_list.len() {
        return Err(RerandError::DuplicatePartyId);
    }

    for pid in party_id_list {
        if !party_ids.contains(pid) {
            return Err(RerandError::InvalidMsgPartyId);
        }
    }

    msgs.sort_by_key(BaseMessage::party_id);
    Ok(msgs)
}

impl Round for RerandParty<RerandR0> {
    type InputMessage = ();
    type Input = ();
    type Error = RerandError;
    type Output = (RerandParty<RerandR1>, RerandMsg1);

    fn process(self, _: Self::Input) -> Result<Self::Output, Self::Error> {
        let commitment = hash_commitment_randomizer(
            &self.entropy.session_id,
            self.keyshare.party_id(),
            &self.entropy.randomizer_i,
            &self.entropy.blind_factor,
        );

        let msg = RerandMsg1 {
            from_party: self.keyshare.party_id(),
            session_id: self.entropy.session_id,
            commitment,
        };

        let next = RerandParty {
            keyshare: self.keyshare,
            entropy: self.entropy,
            state: RerandR1 { commitment },
        };

        Ok((next, msg))
    }
}

impl Round for RerandParty<RerandR1> {
    type InputMessage = RerandMsg1;
    type Input = Vec<RerandMsg1>;
    type Error = RerandError;
    type Output = (RerandParty<RerandR2>, RerandMsg2);

    fn process(self, mut msgs: Self::Input) -> Result<Self::Output, Self::Error> {
        let mut commitment_list = Vec::with_capacity(self.keyshare.threshold as usize);
        let mut sid_list = Vec::with_capacity(self.keyshare.threshold as usize);
        let mut party_ids = Vec::with_capacity(self.keyshare.threshold as usize);

        msgs.sort_by_key(|m| m.from_party);

        for msg in &msgs {
            commitment_list.push(msg.commitment);
            sid_list.push(msg.session_id);
            party_ids.push(msg.from_party);
        }

        msgs.iter()
            .any(|msg| {
                msg.from_party == self.keyshare.party_id()
                    && msg.commitment == self.state.commitment
            })
            .then_some(())
            .ok_or(RerandError::InvalidParticipantSet)?;

        if !sid_list.contains(&self.entropy.session_id) {
            return Err(RerandError::InvalidParticipantSet);
        }

        let num_parties = party_ids.len();
        party_ids.dedup();

        if party_ids.len() != num_parties || !party_ids.contains(&self.keyshare.party_id()) {
            return Err(RerandError::InvalidParticipantSet);
        }

        if party_ids.len() < self.keyshare.threshold as usize
            || party_ids.len() > self.keyshare.total_parties as usize
        {
            return Err(RerandError::InvalidParticipantSet);
        }

        let pk_bytes = self.keyshare.public_key.to_bytes();
        let final_sid =
            calculate_final_session_id(party_ids.iter().copied(), &sid_list, &[pk_bytes.as_ref()]);

        let msg2 = RerandMsg2 {
            from_party: self.keyshare.party_id(),
            session_id: final_sid,
            blind_factor: self.entropy.blind_factor,
            randomizer_i: self.entropy.randomizer_i,
        };

        let next = RerandParty {
            keyshare: self.keyshare,
            entropy: self.entropy,
            state: RerandR2 {
                final_session_id: final_sid,
                commitment_list,
                sid_list,
                pid_list: party_ids,
            },
        };

        Ok((next, msg2))
    }
}

impl Round for RerandParty<RerandR2> {
    type InputMessage = RerandMsg2;
    type Input = Vec<RerandMsg2>;
    type Error = RerandError;
    type Output = (Keyshare<RedPallasPoint>, Fq);

    fn process(self, msgs: Self::Input) -> Result<Self::Output, Self::Error> {
        let msgs = validate_input_messages(msgs, &self.state.pid_list)?;

        let mut randomizer_sum = self.entropy.randomizer_i;

        for (idx, msg) in msgs.iter().enumerate() {
            if msg.session_id != self.state.final_session_id {
                return Err(RerandError::InvalidParticipantSet);
            }

            if msg.from_party == self.keyshare.party_id() {
                continue;
            }

            if !verify_commitment_randomizer(
                &self.state.sid_list[idx],
                msg.from_party,
                &msg.randomizer_i,
                &msg.blind_factor,
                &self.state.commitment_list[idx],
            ) {
                return Err(RerandError::InvalidCommitment(msg.from_party));
            }

            randomizer_sum += msg.randomizer_i;
        }

        let alpha = RedPallasPoint::hash_randomizer(randomizer_sum.to_repr().as_ref());
        apply_alpha(self.keyshare, alpha)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::utils::support::{run_keygen, run_round};

    fn run_rerand(shares: Vec<Keyshare<RedPallasPoint>>) -> Vec<(Keyshare<RedPallasPoint>, Fq)> {
        let mut rng = rand::thread_rng();
        let parties: Vec<_> = shares
            .into_iter()
            .map(|ks| RerandParty::new(ks, &mut rng))
            .collect();

        let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, ()).into_iter().unzip();
        let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, msgs).into_iter().unzip();
        run_round(parties, msgs)
    }

    #[test]
    fn rerand_2_of_3_tweaks_pk_consistently() {
        let shares = run_keygen::<2, 3, RedPallasPoint>();
        let old_pk = shares[0].public_key;
        for s in &shares {
            assert_eq!(s.public_key, old_pk);
        }

        let subset: Vec<_> = shares.into_iter().take(2).collect();
        let old_shares: Vec<_> = subset.clone();
        let (new_shares, alphas): (Vec<_>, Vec<_>) = run_rerand(subset).into_iter().unzip();

        assert_eq!(alphas[0], alphas[1]);
        assert_eq!(new_shares[0].public_key, new_shares[1].public_key);
        assert_ne!(new_shares[0].public_key, old_pk);

        // d' = d + α, pk' = pk + G·α
        let delta_share_0 = new_shares[0].d_i - old_shares[0].d_i;
        let delta_share_1 = new_shares[1].d_i - old_shares[1].d_i;
        assert_eq!(delta_share_0, delta_share_1);
        assert_eq!(delta_share_0, alphas[0]);
        assert_eq!(
            new_shares[0].public_key - old_pk,
            RedPallasPoint::generator() * alphas[0]
        );
    }

    #[test]
    fn rerand_then_sign_verifies() {
        use std::sync::Arc;

        use reddsa::orchard::SpendAuth;
        use reddsa::{Signature, VerificationKey};

        use crate::sign::{SignerParty, R0};

        let shares = run_keygen::<2, 3, RedPallasPoint>();
        let subset: Vec<_> = shares.into_iter().take(2).collect();
        let (new_shares, alphas): (Vec<_>, Vec<_>) = run_rerand(subset).into_iter().unzip();
        assert_eq!(alphas[0], alphas[1]);
        let vk_bytes: [u8; 32] = new_shares[0]
            .public_key
            .to_bytes()
            .as_ref()
            .try_into()
            .unwrap();

        let msg = b"rerand then sign";
        let path: derivation_path::DerivationPath = "m".parse().unwrap();
        let mut rng = rand::thread_rng();
        let parties: Vec<SignerParty<R0, RedPallasPoint>> = new_shares
            .into_iter()
            .map(Arc::new)
            .map(|ks| {
                SignerParty::<_, RedPallasPoint>::new(ks, msg.to_vec(), path.clone(), &mut rng)
            })
            .collect();

        let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, ()).into_iter().unzip();
        let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, msgs).into_iter().unzip();
        let ready_parties: Vec<_> = run_round(parties, msgs);
        assert_eq!(ready_parties[0].public_key.to_bytes().as_ref(), &vk_bytes);

        let (parties, partial_sigs): (Vec<_>, Vec<_>) =
            run_round(ready_parties, ()).into_iter().unzip();
        let (signatures, _): (Vec<_>, Vec<_>) =
            run_round(parties, partial_sigs).into_iter().unzip();

        let vk = VerificationKey::<SpendAuth>::try_from(vk_bytes).unwrap();
        let sig = Signature::<SpendAuth>::from(signatures[0]);
        vk.verify(msg, &sig).expect("signature must verify");
    }

    fn sign_and_verify(shares: Vec<Keyshare<RedPallasPoint>>, msg: &[u8]) {
        use std::sync::Arc;

        use reddsa::orchard::SpendAuth;
        use reddsa::{Signature, VerificationKey};

        use crate::sign::{SignerParty, R0};

        let vk_bytes: [u8; 32] = shares[0]
            .public_key
            .to_bytes()
            .as_ref()
            .try_into()
            .unwrap();
        let path: derivation_path::DerivationPath = "m".parse().unwrap();
        let mut rng = rand::thread_rng();
        let parties: Vec<SignerParty<R0, RedPallasPoint>> = shares
            .into_iter()
            .map(Arc::new)
            .map(|ks| {
                SignerParty::<_, RedPallasPoint>::new(ks, msg.to_vec(), path.clone(), &mut rng)
            })
            .collect();

        let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, ()).into_iter().unzip();
        let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, msgs).into_iter().unzip();
        let ready_parties: Vec<_> = run_round(parties, msgs);
        let (parties, partial_sigs): (Vec<_>, Vec<_>) =
            run_round(ready_parties, ()).into_iter().unzip();
        let (signatures, _): (Vec<_>, Vec<_>) =
            run_round(parties, partial_sigs).into_iter().unzip();

        let vk = VerificationKey::<SpendAuth>::try_from(vk_bytes).unwrap();
        let sig = Signature::<SpendAuth>::from(signatures[0]);
        vk.verify(msg, &sig).expect("signature must verify");
    }

    #[test]
    fn apply_alpha_local_then_sign_verifies() {
        let shares = run_keygen::<2, 3, RedPallasPoint>();
        let subset: Vec<_> = shares.into_iter().take(2).collect();
        let ak = subset[0].public_key;
        let alpha = Fq::random(&mut rand::thread_rng());
        let rk = derive_rk(&ak, &alpha).unwrap();

        let old = subset.clone();
        let tweaked: Vec<_> = subset
            .into_iter()
            .map(|ks| {
                verify_rk(&ak, &alpha, &rk).unwrap();
                let (ks, a) = apply_alpha(ks, alpha).unwrap();
                assert_eq!(a, alpha);
                assert_eq!(ks.public_key, rk);
                ks
            })
            .collect();

        assert_eq!(tweaked[0].d_i - old[0].d_i, alpha);
        assert_eq!(tweaked[1].d_i - old[1].d_i, alpha);
        assert_eq!(tweaked[0].public_key, tweaked[1].public_key);

        sign_and_verify(tweaked, b"orchestrator alpha then sign");
    }

    #[test]
    fn apply_alpha_matches_distributed_alpha() {
        let shares = run_keygen::<2, 3, RedPallasPoint>();
        let subset: Vec<_> = shares.into_iter().take(2).collect();
        let originals = subset.clone();
        let (distributed, alphas): (Vec<_>, Vec<_>) = run_rerand(subset).into_iter().unzip();
        assert_eq!(alphas[0], alphas[1]);

        let (local0, _) = apply_alpha(originals[0].clone(), alphas[0]).unwrap();
        let (local1, _) = apply_alpha(originals[1].clone(), alphas[0]).unwrap();
        assert_eq!(local0.public_key, distributed[0].public_key);
        assert_eq!(local0.d_i, distributed[0].d_i);
        assert_eq!(local1.d_i, distributed[1].d_i);
    }

    #[test]
    fn apply_alpha_rejects_zero_and_bad_encoding() {
        let shares = run_keygen::<2, 3, RedPallasPoint>();
        let ks = shares[0].clone();
        assert!(matches!(
            apply_alpha(ks.clone(), Fq::ZERO),
            Err(RerandError::ZeroAlpha)
        ));

        // Non-canonical: Fq modulus bits set high enough that from_repr fails.
        let bad = [0xff; 32];
        assert!(matches!(
            apply_alpha_bytes(ks.clone(), &bad),
            Err(RerandError::InvalidAlphaEncoding)
        ));

        let alpha = Fq::ONE;
        let rk = derive_rk(&ks.public_key, &alpha).unwrap();
        let wrong = rk + RedPallasPoint::generator();
        assert!(matches!(
            verify_rk(&ks.public_key, &alpha, &wrong),
            Err(RerandError::RkMismatch)
        ));

        // α = −ask cancels ak → identity rk.
        let shares = run_keygen::<2, 3, RedPallasPoint>();
        let pids = vec![shares[0].party_id(), shares[1].party_id()];
        let ask = shares[0].scalar_share_interpolate(pids.clone())
            + shares[1].scalar_share_interpolate(pids);
        let ak = shares[0].public_key;
        assert_eq!(RedPallasPoint::generator() * ask, ak);
        assert!(matches!(
            derive_rk(&ak, &(-ask)),
            Err(RerandError::IdentityRk)
        ));
        assert!(matches!(
            apply_alpha(shares[0].clone(), -ask),
            Err(RerandError::IdentityRk)
        ));
    }
}
