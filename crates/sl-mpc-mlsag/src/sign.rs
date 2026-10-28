// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Threshold MLSAG signing (spend layer only).
//!
//! Each signer samples its own session id and commits to that id together with
//! its spend nonce. The next message opens the nonce and proves the DH tuple
//! under the session id obtained by hashing every individual id. Whoever knows
//! the blinding difference `z` then calls [`crate::fill_ring`] once. That call
//! is not a method on [`MlsagSignContext`]. Signers jointly sample `α₀` and
//! close `r_{π,0} = α₀ − c_π · x` from [`crate::MlsagKeyshare`] shares. They
//! never see `z`.

use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use elliptic_curve::subtle::ConstantTimeEq;
use elliptic_curve::Group;
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use sl_mpc_derive::math::{get_lagrange_coeff, participant_public_share};
use sl_mpc_vrf::{dh_tuple_transcript, DhTuplePoints, DhTupleProof, SessionId};

use crate::{
    error::MlsagError,
    hash_to_point::hash_to_point,
    messages::MlsagKeyshare,
    ring_mlsag::{
        assemble_ring_mlsag, open_sign_input, scalar_is_canonical, signing_challenges, RingMLSAG,
        RingTour, SignPublicInput,
    },
};

const SIGN_SID_LABEL: &[u8] = b"SL-MLSAG-SIGN";

/// Round 1: this party's random session id, and a commitment to that id together
/// with `(L0, R0)` and a blind.
///
/// Delivery: broadcast to the signing quorum, signed only.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignMsg1 {
    pub from_party: u8,
    pub session_id: SessionId,
    pub commitment: [u8; 32],
}

/// Round 2: opening of the round-1 commitment, plus a DH-tuple proof of
/// `(L0, R0)` under the combined session id.
///
/// Delivery: broadcast to the signing quorum, signed only.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignMsg2 {
    pub from_party: u8,
    pub session_id: SessionId,
    pub blind_factor: [u8; 32],
    pub l0: [u8; 32],
    pub r0: [u8; 32],
    pub pi: DhTupleProof,
}

/// Round 3: partial spend response `α₀,j − c_π · k_j`.
///
/// Delivery: broadcast to the signing quorum, signed only.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignMsg3 {
    pub from_party: u8,
    pub session_id: SessionId,
    pub r_pi_0: Scalar,
}

/// Summed spend-layer nonce from the round-2 openings. Input to [`crate::fill_ring`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NonceCommit {
    pub l0: RistrettoPoint,
    pub r0: RistrettoPoint,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone)]
struct PartyCommit {
    party_id: u8,
    session_id: SessionId,
    commitment: [u8; 32],
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StateInit;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StateRound1Sent {
    individual_sid: SessionId,
    alpha0: Scalar,
    blind_factor: [u8; 32],
    seed: [u8; 32],
    l0: RistrettoPoint,
    r0: RistrettoPoint,
    commitment: [u8; 32],
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StateReadyToOpen {
    alpha0: Scalar,
    blind_factor: [u8; 32],
    seed: [u8; 32],
    l0: RistrettoPoint,
    r0: RistrettoPoint,
    final_session_id: SessionId,
    commits: Vec<PartyCommit>,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StateOpened {
    alpha0: Scalar,
    final_session_id: SessionId,
    commits: Vec<PartyCommit>,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug)]
pub struct StateNonces {
    alpha0: Scalar,
    final_session_id: SessionId,
    l0: RistrettoPoint,
    r0: RistrettoPoint,
    party_l0: Vec<(u8, RistrettoPoint)>,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StateClosed {
    final_session_id: SessionId,
    l0: RistrettoPoint,
    r0: RistrettoPoint,
    party_l0: Vec<(u8, RistrettoPoint)>,
    c_pi: Scalar,
    tour_binding: [u8; 32],
}

/// One party's MLSAG signing session.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug)]
pub struct MlsagSignContext<T> {
    party_id: u8,
    keyshare: MlsagKeyshare,
    pid_list: Vec<u8>,
    /// Hash of the public signing inputs. Mixed into the combined session id.
    binding: SessionId,
    input: SignPublicInput,
    /// Lagrange-weighted additive share of the onetime secret over `pid_list`.
    k_j: Scalar,
    hp: RistrettoPoint,
    state: T,
}

/// Public-input binding mixed into the combined signing session id.
///
/// This is not the session id carried on [`SignMsg2`] and [`SignMsg3`].
/// That id is the hash of this binding with every party's fresh session id.
pub fn sign_session_id(
    keyshare: &MlsagKeyshare,
    pid_list: &[u8],
    input: &SignPublicInput,
) -> SessionId {
    let mut hasher = Sha256::new();
    hasher.update(SIGN_SID_LABEL);
    hasher.update(keyshare.keyshare_session_id);
    hasher.update(keyshare.key_image.as_bytes());
    hasher.update([pid_list.len() as u8]);
    hasher.update(pid_list);
    hasher.update((input.real_index as u64).to_le_bytes());
    hasher.update((input.message.len() as u64).to_le_bytes());
    hasher.update(&input.message);
    hasher.update(input.output_commitment.as_bytes());
    hasher.update((input.ring.len() as u64).to_le_bytes());
    for member in &input.ring {
        hasher.update(member.onetime_public.as_bytes());
        hasher.update(member.commitment.as_bytes());
    }
    hasher.finalize().into()
}

fn hash_nonce_commitment(
    session_id: &SessionId,
    party_id: u8,
    l0: &RistrettoPoint,
    r0: &RistrettoPoint,
    blind_factor: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(session_id);
    hasher.update((party_id as u32).to_be_bytes());
    hasher.update(l0.compress().as_bytes());
    hasher.update(r0.compress().as_bytes());
    hasher.update(blind_factor);
    hasher.finalize().into()
}

fn combined_session_id(binding: &SessionId, commits: &[PartyCommit]) -> SessionId {
    let mut hasher = Sha256::new();
    hasher.update(binding);
    for commit in commits {
        hasher.update((commit.party_id as u32).to_be_bytes());
    }
    for commit in commits {
        hasher.update(commit.session_id);
    }
    hasher.finalize().into()
}

fn commitment_matches(left: &[u8; 32], right: &[u8; 32]) -> bool {
    bool::from(left.ct_eq(right))
}

fn normalize_pids(pid_list: Vec<u8>, keyshare: &MlsagKeyshare) -> Result<Vec<u8>, MlsagError> {
    if keyshare.party_public_shares().len() != keyshare.total_parties as usize {
        return Err(MlsagError::InvalidKeyshare);
    }
    if pid_list.len() < keyshare.threshold as usize {
        return Err(MlsagError::InvalidThreshold);
    }
    if pid_list.len() > keyshare.total_parties as usize {
        return Err(MlsagError::InvalidParticipantSet);
    }
    let mut pid_list = pid_list;
    pid_list.sort_unstable();
    pid_list.dedup();
    if pid_list.len() < keyshare.threshold as usize {
        return Err(MlsagError::InvalidThreshold);
    }
    if !pid_list.contains(&keyshare.party_id) {
        return Err(MlsagError::InvalidParticipantSet);
    }
    for &pid in &pid_list {
        if pid >= keyshare.total_parties {
            return Err(MlsagError::InvalidMsgPartyId);
        }
    }
    Ok(pid_list)
}

fn bind_tour(tour: &RingTour) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(tour.l1.compress().as_bytes());
    hasher.update((tour.responses.len() as u64).to_le_bytes());
    for response in &tour.responses {
        hasher.update(response.as_bytes());
    }
    hasher.finalize().into()
}

fn decompress_nonce(bytes: [u8; 32], party: u8) -> Result<RistrettoPoint, MlsagError> {
    CompressedRistretto(bytes)
        .decompress()
        .filter(|p| !bool::from(p.is_identity()))
        .ok_or(MlsagError::InvalidDhProof(party))
}

fn collect_commits(
    messages: Vec<SignMsg1>,
    pid_list: &[u8],
    party_id: u8,
    individual_sid: &SessionId,
    commitment: &[u8; 32],
) -> Result<Vec<PartyCommit>, MlsagError> {
    if messages.len() != pid_list.len() {
        return Err(MlsagError::InvalidMsgCount);
    }
    let mut messages = messages;
    messages.sort_by_key(|msg| msg.from_party);
    let mut party_ids: Vec<u8> = messages.iter().map(|msg| msg.from_party).collect();
    let received = party_ids.len();
    party_ids.dedup();
    if party_ids.len() != received {
        return Err(MlsagError::DuplicatePartyId);
    }
    if party_ids != pid_list {
        return Err(MlsagError::InvalidParticipantSet);
    }
    let own = messages
        .iter()
        .find(|msg| msg.from_party == party_id)
        .ok_or(MlsagError::InvalidParticipantSet)?;
    if own.session_id != *individual_sid || !commitment_matches(&own.commitment, commitment) {
        return Err(MlsagError::InvalidNonceCommitment(party_id));
    }
    Ok(messages
        .into_iter()
        .map(|msg| PartyCommit {
            party_id: msg.from_party,
            session_id: msg.session_id,
            commitment: msg.commitment,
        })
        .collect())
}

impl<T> MlsagSignContext<T> {
    pub fn party_id(&self) -> u8 {
        self.party_id
    }
}

impl MlsagSignContext<StateInit> {
    /// Start signing. `participating_party_ids` is any set of size at least `t` that includes this party.
    /// `input.ring[real_index]` must be this keyshare's onetime public key.
    pub fn new(
        keyshare: MlsagKeyshare,
        participating_party_ids: Vec<u8>,
        input: SignPublicInput,
    ) -> Result<Self, MlsagError> {
        let pid_list = normalize_pids(participating_party_ids, &keyshare)?;
        let opened = open_sign_input(&input)?;
        if opened.members[input.real_index]
            .0
            .ct_ne(&keyshare.public_key)
            .into()
        {
            return Err(MlsagError::PublicKeyMismatch);
        }
        if bool::from(keyshare.public_key.is_identity())
            || keyshare
                .key_image
                .decompress()
                .filter(|p| !bool::from(p.is_identity()))
                .is_none()
        {
            return Err(MlsagError::InvalidKeyImage);
        }
        let k_j =
            get_lagrange_coeff::<RistrettoPoint>(&keyshare.party_id, pid_list.iter().copied())
                * *keyshare.shamir_share();
        let binding = sign_session_id(&keyshare, &pid_list, &input);
        let hp = hash_to_point(&keyshare.public_key);
        Ok(Self {
            party_id: keyshare.party_id,
            keyshare,
            pid_list,
            binding,
            input,
            k_j,
            hp,
            state: StateInit,
        })
    }

    /// Sample a fresh session id and spend nonce, and publish the commitment.
    ///
    /// The commitment is
    /// `SHA256(session_id || party_id_be || compress(L0) || compress(R0) || blind)`.
    /// `L0` and `R0` stay local until [`round2_out`](Self::round2_out).
    ///
    /// Delivery: broadcast to the signing quorum, signed only.
    pub fn round1_out<R: CryptoRng + RngCore>(
        self,
        rng: &mut R,
    ) -> Result<(MlsagSignContext<StateRound1Sent>, SignMsg1), MlsagError> {
        let mut individual_sid = [0u8; 32];
        let mut blind_factor = [0u8; 32];
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut individual_sid);
        rng.fill_bytes(&mut blind_factor);
        rng.fill_bytes(&mut seed);
        let alpha0 = Scalar::random(&mut *rng);
        let l0 = RistrettoPoint::generator() * alpha0;
        let r0 = self.hp * alpha0;
        let commitment =
            hash_nonce_commitment(&individual_sid, self.party_id, &l0, &r0, &blind_factor);

        let next_state = MlsagSignContext {
            party_id: self.party_id,
            keyshare: self.keyshare,
            pid_list: self.pid_list,
            binding: self.binding,
            input: self.input,
            k_j: self.k_j,
            hp: self.hp,
            state: StateRound1Sent {
                individual_sid,
                alpha0,
                blind_factor,
                seed,
                l0,
                r0,
                commitment,
            },
        };
        let msg1 = SignMsg1 {
            from_party: self.party_id,
            session_id: individual_sid,
            commitment,
        };

        Ok((next_state, msg1))
    }
}

impl MlsagSignContext<StateRound1Sent> {
    /// Check the round-1 commitments and hash them into the combined session id.
    ///
    /// The return value is local. [`round2_out`](Self::round2_out) puts the same
    /// id on the opening message. Inbound `messages` are the signed round-1 broadcast.
    pub fn round1_in(
        self,
        messages: Vec<SignMsg1>,
    ) -> Result<(MlsagSignContext<StateReadyToOpen>, SessionId), MlsagError> {
        let StateRound1Sent {
            individual_sid,
            alpha0,
            blind_factor,
            seed,
            l0,
            r0,
            commitment,
        } = self.state;

        let commits = collect_commits(
            messages,
            &self.pid_list,
            self.party_id,
            &individual_sid,
            &commitment,
        )?;
        let final_session_id = combined_session_id(&self.binding, &commits);

        let next_state = MlsagSignContext {
            party_id: self.party_id,
            keyshare: self.keyshare,
            pid_list: self.pid_list,
            binding: self.binding,
            input: self.input,
            k_j: self.k_j,
            hp: self.hp,
            state: StateReadyToOpen {
                alpha0,
                blind_factor,
                seed,
                l0,
                r0,
                final_session_id,
                commits,
            },
        };

        Ok((next_state, final_session_id))
    }
}

impl MlsagSignContext<StateReadyToOpen> {
    /// Prove knowledge of `α₀` under the combined session id and open the nonce.
    ///
    /// The DH-tuple transcript session id is the combined id from
    /// [`round1_in`](Self::round1_in). The proof's randomness comes from the seed
    /// sampled in [`round1_out`](Self::round1_out).
    ///
    /// Delivery: broadcast to the signing quorum, signed only.
    pub fn round2_out(self) -> Result<(MlsagSignContext<StateOpened>, SignMsg2), MlsagError> {
        let StateReadyToOpen {
            alpha0,
            blind_factor,
            seed,
            l0,
            r0,
            final_session_id,
            commits,
        } = self.state;

        let mut proof_rng = ChaCha20Rng::from_seed(seed);
        let aux = (self.party_id as u32).to_be_bytes();
        let mut transcript = dh_tuple_transcript(&final_session_id, &aux);
        let pi = DhTupleProof::prove(
            DhTuplePoints {
                g: &RistrettoPoint::generator(),
                q: &self.hp,
                a: &l0,
                b: &r0,
            },
            &alpha0,
            &mut transcript,
            &mut proof_rng,
        );

        let next_state = MlsagSignContext {
            party_id: self.party_id,
            keyshare: self.keyshare,
            pid_list: self.pid_list,
            binding: self.binding,
            input: self.input,
            k_j: self.k_j,
            hp: self.hp,
            state: StateOpened {
                alpha0,
                final_session_id,
                commits,
            },
        };

        let msg2 = SignMsg2 {
            from_party: self.party_id,
            session_id: final_session_id,
            blind_factor,
            l0: l0.compress().to_bytes(),
            r0: r0.compress().to_bytes(),
            pi,
        };

        Ok((next_state, msg2))
    }

    pub fn session_id(&self) -> SessionId {
        self.state.final_session_id
    }
}

impl MlsagSignContext<StateOpened> {
    /// Check each opening against its round-1 commitment and return the summed `(L0, R0)`.
    ///
    /// Inbound `messages` are the signed round-2 broadcast. The sum is local:
    /// whoever calls [`crate::fill_ring`] reads that same broadcast and does not
    /// get a separate message.
    pub fn round2_in(
        self,
        messages: Vec<SignMsg2>,
    ) -> Result<(MlsagSignContext<StateNonces>, NonceCommit), MlsagError> {
        let StateOpened {
            alpha0,
            final_session_id,
            commits,
        } = self.state;

        if messages.len() != commits.len() {
            return Err(MlsagError::InvalidMsgCount);
        }
        let mut party_ids: Vec<u8> = messages.iter().map(|msg| msg.from_party).collect();
        party_ids.sort_unstable();
        let received = party_ids.len();
        party_ids.dedup();
        if party_ids.len() != received {
            return Err(MlsagError::DuplicatePartyId);
        }
        if party_ids != self.pid_list {
            return Err(MlsagError::InvalidParticipantSet);
        }

        let g = RistrettoPoint::generator();
        let mut l0_sum = RistrettoPoint::identity();
        let mut r0_sum = RistrettoPoint::identity();
        let mut party_l0 = Vec::with_capacity(messages.len());
        for msg in &messages {
            if msg.session_id != final_session_id {
                return Err(MlsagError::InvalidParticipantSet);
            }
            let stored = commits
                .iter()
                .find(|commit| commit.party_id == msg.from_party)
                .ok_or(MlsagError::InvalidParticipantSet)?;
            let l0 = decompress_nonce(msg.l0, msg.from_party)?;
            let r0 = decompress_nonce(msg.r0, msg.from_party)?;
            let opened = hash_nonce_commitment(
                &stored.session_id,
                msg.from_party,
                &l0,
                &r0,
                &msg.blind_factor,
            );
            if !commitment_matches(&opened, &stored.commitment) {
                return Err(MlsagError::InvalidNonceCommitment(msg.from_party));
            }
            let aux = (msg.from_party as u32).to_be_bytes();
            let mut transcript = dh_tuple_transcript(&final_session_id, &aux);
            if !msg.pi.verify(
                DhTuplePoints {
                    g: &g,
                    q: &self.hp,
                    a: &l0,
                    b: &r0,
                },
                &mut transcript,
            ) {
                return Err(MlsagError::InvalidDhProof(msg.from_party));
            }
            l0_sum += l0;
            r0_sum += r0;
            party_l0.push((msg.from_party, l0));
        }
        party_l0.sort_by_key(|(pid, _)| *pid);

        let next_state = MlsagSignContext {
            party_id: self.party_id,
            keyshare: self.keyshare,
            pid_list: self.pid_list,
            binding: self.binding,
            input: self.input,
            k_j: self.k_j,
            hp: self.hp,
            state: StateNonces {
                alpha0,
                final_session_id,
                l0: l0_sum,
                r0: r0_sum,
                party_l0,
            },
        };

        let nonce_commit = NonceCommit {
            l0: l0_sum,
            r0: r0_sum,
        };

        Ok((next_state, nonce_commit))
    }

    pub fn session_id(&self) -> SessionId {
        self.state.final_session_id
    }
}

impl MlsagSignContext<StateNonces> {
    /// Close this party's spend response against the ring tour.
    ///
    /// `tour` is broadcast to the quorum, signed only (not encrypted). Every
    /// signer must receive the same bytes. Do not publish it outside the
    /// quorum: the unset spend slot is zero and identifies `real_index`.
    /// `c_π` is recomputed from the tour, summed nonce, and this session's public input.
    ///
    /// The returned partial response is broadcast to the quorum, signed only.
    pub fn round3_out(
        self,
        tour: &RingTour,
    ) -> Result<(MlsagSignContext<StateClosed>, SignMsg3), MlsagError> {
        let StateNonces {
            alpha0,
            final_session_id,
            l0,
            r0,
            party_l0,
        } = self.state;

        let challenges = signing_challenges(&self.input, &self.keyshare.key_image, &l0, &r0, tour)?;
        let c_pi = challenges[self.input.real_index];
        let r_pi_0 = alpha0 - c_pi * self.k_j;

        let next_state = MlsagSignContext {
            party_id: self.party_id,
            keyshare: self.keyshare,
            pid_list: self.pid_list,
            binding: self.binding,
            input: self.input,
            k_j: self.k_j,
            hp: self.hp,
            state: StateClosed {
                final_session_id,
                l0,
                r0,
                party_l0,
                c_pi,
                tour_binding: bind_tour(tour),
            },
        };

        let msg3 = SignMsg3 {
            from_party: self.party_id,
            session_id: final_session_id,
            r_pi_0,
        };

        Ok((next_state, msg3))
    }

    pub fn session_id(&self) -> SessionId {
        self.state.final_session_id
    }
}

impl MlsagSignContext<StateClosed> {
    /// Sum spend responses, check each against the opened nonce, and emit [`RingMLSAG`].
    ///
    /// Inbound `messages` are the signed round-3 broadcast. `tour` must be the
    /// same signed broadcast this party used in [`round3_out`](Self::round3_out).
    pub fn round3_in(
        self,
        messages: Vec<SignMsg3>,
        tour: &RingTour,
    ) -> Result<RingMLSAG, MlsagError> {
        let StateClosed {
            final_session_id,
            l0,
            r0,
            party_l0,
            c_pi,
            tour_binding,
        } = self.state;

        if bind_tour(tour) != tour_binding {
            return Err(MlsagError::InvalidChallenge);
        }
        if messages.len() != self.pid_list.len() {
            return Err(MlsagError::InvalidMsgCount);
        }
        let mut party_ids: Vec<u8> = messages.iter().map(|m| m.from_party).collect();
        party_ids.sort_unstable();
        party_ids.dedup();
        if party_ids != self.pid_list {
            return Err(MlsagError::InvalidParticipantSet);
        }

        let g = RistrettoPoint::generator();
        let mut r_sum = Scalar::ZERO;
        for msg in &messages {
            if msg.session_id != final_session_id || !scalar_is_canonical(&msg.r_pi_0) {
                return Err(MlsagError::InvalidParticipantSet);
            }
            let l0_j = party_l0
                .iter()
                .find(|(pid, _)| *pid == msg.from_party)
                .map(|(_, point)| *point)
                .ok_or(MlsagError::InvalidParticipantSet)?;
            let k_pub = participant_public_share::<RistrettoPoint>(
                &self.keyshare.party_public_shares()[msg.from_party as usize],
                msg.from_party,
                self.keyshare.total_parties,
                self.pid_list.iter().copied(),
            );
            if (g * msg.r_pi_0 + k_pub * c_pi).ct_ne(&l0_j).into() {
                return Err(MlsagError::InvalidResponse(msg.from_party));
            }
            r_sum += msg.r_pi_0;
        }

        assemble_ring_mlsag(&self.input, &self.keyshare.key_image, &l0, &r0, tour, r_sum)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::run_mlsag_dkg;
    use crate::ring_mlsag::{fill_ring, RingMember};
    use blake2::Digest;

    fn pedersen_h() -> RistrettoPoint {
        let mut hasher = blake2::Blake2b512::new();
        hasher.update(b"sl-mlsag-test-pedersen-h");
        RistrettoPoint::from_hash(hasher)
    }

    fn input_for_key(
        pk: &RistrettoPoint,
        message: &[u8],
        real_index: usize,
        value: u64,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> (SignPublicInput, Scalar) {
        let y_in = Scalar::random(rng);
        let y_out = Scalar::random(rng);
        let z = y_out - y_in;
        let h = pedersen_h();
        let value = Scalar::from(value);
        let g = RistrettoPoint::generator();
        let ring_len = (real_index + 1).max(3);
        let ring = (0..ring_len)
            .map(|i| {
                if i == real_index {
                    RingMember {
                        onetime_public: pk.compress(),
                        commitment: (h * value + g * y_in).compress(),
                    }
                } else {
                    RingMember {
                        onetime_public: RistrettoPoint::mul_base(&Scalar::random(&mut *rng))
                            .compress(),
                        commitment: RistrettoPoint::mul_base(&Scalar::random(&mut *rng)).compress(),
                    }
                }
            })
            .collect();
        let input = SignPublicInput {
            message: message.to_vec(),
            ring,
            real_index,
            output_commitment: (h * value + g * y_out).compress(),
        };
        (input, z)
    }

    fn run_sign(
        shares: &[MlsagKeyshare],
        pids: &[u8],
        input: &SignPublicInput,
        z: &Scalar,
    ) -> RingMLSAG {
        let mut rng = rand::thread_rng();
        let parties: Vec<_> = pids
            .iter()
            .map(|&pid| {
                MlsagSignContext::new(shares[pid as usize].clone(), pids.to_vec(), input.clone())
                    .unwrap()
            })
            .collect();

        let mut next_states = Vec::new();
        let mut messages1 = Vec::new();
        for p in parties {
            let (next_state, msg1) = p.round1_out(&mut rng).unwrap();
            next_states.push(next_state);
            messages1.push(msg1);
        }
        let parties = next_states;

        let mut next_states = Vec::new();
        let mut sids = Vec::new();
        for p in parties {
            let (next_state, sid) = p.round1_in(messages1.clone()).unwrap();
            next_states.push(next_state);
            sids.push(sid);
        }
        assert!(sids.iter().all(|sid| *sid == sids[0]));
        let parties = next_states;

        let mut next_states = Vec::new();
        let mut messages2 = Vec::new();
        for p in parties {
            let (next_state, msg2) = p.round2_out().unwrap();
            next_states.push(next_state);
            messages2.push(msg2);
        }
        let parties = next_states;

        let mut next_states = Vec::new();
        let mut commits = Vec::new();
        for p in parties {
            let (next_state, c) = p.round2_in(messages2.clone()).unwrap();
            next_states.push(next_state);
            commits.push(c);
        }
        for commit in &commits[1..] {
            assert_eq!(*commit, commits[0]);
        }
        let tour = fill_ring(
            input,
            shares[0].key_image(),
            &commits[0].l0,
            &commits[0].r0,
            z,
            &mut rng,
        )
        .unwrap();
        let parties = next_states;

        let mut next_states = Vec::new();
        let mut messages3 = Vec::new();
        for p in parties {
            let (next_state, msg3) = p.round3_out(&tour).unwrap();
            next_states.push(next_state);
            messages3.push(msg3);
        }
        let parties = next_states;

        let mut signatures = Vec::new();
        for p in parties {
            let signature = p.round3_in(messages3.clone(), &tour).unwrap();
            signatures.push(signature);
        }
        for signature in &signatures[1..] {
            assert_eq!(*signature, signatures[0]);
        }
        signatures.into_iter().next().unwrap()
    }

    #[test]
    fn threshold_sign_2_of_3_verifies() {
        let shares = run_mlsag_dkg(3, 2);
        let mut rng = rand::thread_rng();
        let (input, z) = input_for_key(shares[0].public_key(), b"threshold-mlsag", 1, 9, &mut rng);
        let signature = run_sign(&shares, &[0, 1], &input, &z);
        signature.verify(&input).unwrap();

        let other = run_sign(&shares, &[1, 2], &input, &z);
        other.verify(&input).unwrap();
        assert_eq!(signature.key_image, other.key_image);
        assert_eq!(signature.key_image, shares[0].key_image);
    }

    #[test]
    fn round2_rejects_a_nonce_that_does_not_open_the_commitment() {
        let shares = run_mlsag_dkg(3, 2);
        let mut rng = rand::thread_rng();
        let (input, _z) = input_for_key(shares[0].public_key(), b"threshold-mlsag", 1, 9, &mut rng);
        let pids = [0u8, 1];
        let parties: Vec<_> = pids
            .iter()
            .map(|&pid| {
                MlsagSignContext::new(shares[pid as usize].clone(), pids.to_vec(), input.clone())
                    .unwrap()
            })
            .collect();

        let mut next_states = Vec::new();
        let mut messages1 = Vec::new();
        for p in parties {
            let (next_state, msg1) = p.round1_out(&mut rng).unwrap();
            next_states.push(next_state);
            messages1.push(msg1);
        }
        let parties = next_states;

        let mut next_states = Vec::new();
        let mut sids = Vec::new();
        for p in parties {
            let (next_state, sid) = p.round1_in(messages1.clone()).unwrap();
            next_states.push(next_state);
            sids.push(sid);
        }
        assert!(sids.iter().all(|sid| *sid == sids[0]));
        let parties = next_states;

        let mut next_states = Vec::new();
        let mut messages2 = Vec::new();
        for p in parties {
            let (next_state, msg2) = p.round2_out().unwrap();
            next_states.push(next_state);
            messages2.push(msg2);
        }
        let parties = next_states;

        messages2[0].blind_factor[0] ^= 0xff;

        for p in parties {
            let err = p.round2_in(messages2.clone()).unwrap_err();
            assert_eq!(err, MlsagError::InvalidNonceCommitment(0));
        }
    }
}
