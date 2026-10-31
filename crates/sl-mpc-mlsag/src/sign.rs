// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Threshold MLSAG signing (spend layer only).
//!
//! DKG produces shares of the root spend key `b` with `B = b·G`. Each output
//! is spent with the one-time key `x = b + t` and `P = B + t·G`, where the
//! public tweak `t` comes from whoever holds the view key. Signers check that
//! `P` is the real ring member and bind `t` and `P` into the session id.
//!
//! Each signer samples its own session id and commits to that id together with
//! its spend nonce. The next message opens the nonce, proves the DH tuple
//! under the session id obtained by hashing every individual id, and carries
//! this party's share `I_j` of the output's key image `I = x · H_p(P)` with
//! its own DH-tuple proof. Whoever knows the blinding difference `z` then
//! calls [`crate::fill_ring`] once. That call is not a method on
//! [`MlsagSignContext`]. Signers jointly sample `α₀` and close
//! `r_{π,0} = α₀ − c_π · x` from [`crate::MlsagKeyshare`] shares. They never
//! see `z`.

use crate::{
    error::MlsagError,
    hash_to_point::hash_to_point,
    key_image::KeyImage,
    messages::MlsagKeyshare,
    mlsag::{dh_tuple_transcript, DhTuplePoints, DhTupleProof, SessionId},
    ring_mlsag::{
        assemble_ring_mlsag, open_sign_input, scalar_is_canonical, signing_challenges, RingMLSAG,
        RingTour, SignPublicInput,
    },
};
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use elliptic_curve::subtle::ConstantTimeEq;
use elliptic_curve::Group;
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use sl_mpc_derive::math::{get_lagrange_coeff, participant_public_share};

const SIGN_SID_LABEL: &[u8] = b"SL-MLSAG-SIGN";
const KEY_IMAGE_AUX_LABEL: &[u8] = b"SL-MLSAG-SIGN-KEY-IMAGE";
const KEY_IMAGE_PROOF_SEED_LABEL: &[u8] = b"SL-MLSAG-SIGN-KEY-IMAGE-PROOF-SEED";

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
/// `(L0, R0)` under the combined session id, and this party's key-image share.
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
    /// Compressed `I_j = k_j · H_p(P)`.
    pub i_j: [u8; 32],
    /// DH-tuple proof of `(G, H_p(P), k_j·G, I_j)`.
    pub key_image_pi: DhTupleProof,
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

/// Summed spend-layer nonce and the output's key image from the round-2
/// openings. Input to [`crate::fill_ring`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NonceCommit {
    pub l0: RistrettoPoint,
    pub r0: RistrettoPoint,
    /// `I = x · H_p(P)` for this output.
    pub key_image: KeyImage,
}

#[derive(Clone)]
struct PartyCommit {
    party_id: u8,
    session_id: SessionId,
    commitment: [u8; 32],
}

struct StateInit;

struct StateRound1Sent {
    individual_sid: SessionId,
    alpha0: Scalar,
    blind_factor: [u8; 32],
    seed: [u8; 32],
    key_image_seed: [u8; 32],
    l0: RistrettoPoint,
    r0: RistrettoPoint,
    commitment: [u8; 32],
}

struct StateReadyToOpen {
    alpha0: Scalar,
    blind_factor: [u8; 32],
    seed: [u8; 32],
    key_image_seed: [u8; 32],
    l0: RistrettoPoint,
    r0: RistrettoPoint,
    final_session_id: SessionId,
    commits: Vec<PartyCommit>,
}

struct StateOpened {
    alpha0: Scalar,
    final_session_id: SessionId,
    commits: Vec<PartyCommit>,
}

#[derive(Debug)]
struct StateNonces {
    alpha0: Scalar,
    final_session_id: SessionId,
    l0: RistrettoPoint,
    r0: RistrettoPoint,
    key_image: KeyImage,
    party_l0: Vec<(u8, RistrettoPoint)>,
}

struct StateClosed {
    final_session_id: SessionId,
    l0: RistrettoPoint,
    r0: RistrettoPoint,
    key_image: KeyImage,
    party_l0: Vec<(u8, RistrettoPoint)>,
    c_pi: Scalar,
    tour_binding: [u8; 32],
}

/// One party's MLSAG signing session.
#[derive(Debug)]
pub struct MlsagSignContext<T> {
    party_id: u8,
    keyshare: MlsagKeyshare,
    pid_list: Vec<u8>,
    /// Hash of the public signing inputs. Mixed into the combined session id.
    binding: SessionId,
    input: SignPublicInput,
    /// Public per-output tweak `t`: the one-time key is `x = b + t`.
    tweak: Scalar,
    /// Lagrange-weighted additive share `λ_j · (b_j + t)` of the one-time
    /// secret over `pid_list`.
    k_j: Scalar,
    /// `H_p(P)` with `P = B + t·G`.
    hp: RistrettoPoint,
    state: T,
}

/// Public-input binding mixed into the combined signing session id.
///
/// This is not the session id carried on [`SignMsg2`] and [`SignMsg3`].
/// That id is the hash of this binding with every party's fresh session id.
/// It binds the root key `B`, the tweak `t` and the one-time key `P = B + t·G`.
pub fn sign_session_id(
    keyshare: &MlsagKeyshare,
    pid_list: &[u8],
    input: &SignPublicInput,
    tweak: &Scalar,
) -> SessionId {
    let onetime_public = keyshare.public_key + RistrettoPoint::generator() * tweak;
    let mut hasher = Sha256::new();
    hasher.update(SIGN_SID_LABEL);
    hasher.update(keyshare.keyshare_session_id);
    hasher.update(keyshare.public_key.compress().as_bytes());
    hasher.update(tweak.as_bytes());
    hasher.update(onetime_public.compress().as_bytes());
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

/// DH-tuple transcript aux for a key-image share, distinct from the nonce
/// proof's aux so the two proofs cannot be swapped.
fn key_image_aux(party_id: u8) -> [u8; KEY_IMAGE_AUX_LABEL.len() + 4] {
    let mut aux = [0u8; KEY_IMAGE_AUX_LABEL.len() + 4];
    aux[..KEY_IMAGE_AUX_LABEL.len()].copy_from_slice(KEY_IMAGE_AUX_LABEL);
    aux[KEY_IMAGE_AUX_LABEL.len()..].copy_from_slice(&(party_id as u32).to_be_bytes());
    aux
}

/// Randomness for the key-image share proof. Independent of the nonce proof's
/// seed, and bound to the session id and the statement it proves.
fn key_image_proof_seed(
    seed: &[u8; 32],
    session_id: &SessionId,
    party_id: u8,
    party_k: &RistrettoPoint,
    i_j: &RistrettoPoint,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(KEY_IMAGE_PROOF_SEED_LABEL);
    hasher.update(seed);
    hasher.update(session_id);
    hasher.update((party_id as u32).to_be_bytes());
    hasher.update(party_k.compress().as_bytes());
    hasher.update(i_j.compress().as_bytes());
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

/// `k_j · G` for party `pid`, from its stored DKG public share and the tweak.
fn tweaked_public_share(
    keyshare: &MlsagKeyshare,
    pid_list: &[u8],
    tweak: &Scalar,
    pid: u8,
) -> RistrettoPoint {
    let share = participant_public_share::<RistrettoPoint>(
        &keyshare.party_public_shares()[pid as usize],
        pid,
        keyshare.total_parties,
        pid_list.iter().copied(),
    );
    let lambda = get_lagrange_coeff::<RistrettoPoint>(&pid, pid_list.iter().copied());
    share + RistrettoPoint::generator() * (lambda * tweak)
}

impl MlsagSignContext<StateInit> {
    /// Start signing the output with one-time key `P = B + tweak·G`, where `B` is
    /// the DKG public key and `tweak` the public per-output scalar `t`.
    ///
    /// `participating_party_ids` is any set of size at least `t` that includes
    /// this party. `input.ring[real_index]` must be `P`.
    pub fn new(
        keyshare: MlsagKeyshare,
        participating_party_ids: Vec<u8>,
        input: SignPublicInput,
        tweak: Scalar,
    ) -> Result<Self, MlsagError> {
        let pid_list = normalize_pids(participating_party_ids, &keyshare)?;
        if bool::from(keyshare.public_key.is_identity()) {
            return Err(MlsagError::InvalidKeyshare);
        }
        if !scalar_is_canonical(&tweak) {
            return Err(MlsagError::InvalidTweak);
        }
        let onetime_public = keyshare.public_key + RistrettoPoint::generator() * tweak;
        if bool::from(onetime_public.is_identity()) {
            return Err(MlsagError::InvalidTweak);
        }
        let opened = open_sign_input(&input)?;
        if opened.members[input.real_index]
            .0
            .ct_ne(&onetime_public)
            .into()
        {
            return Err(MlsagError::PublicKeyMismatch);
        }
        let k_j =
            get_lagrange_coeff::<RistrettoPoint>(&keyshare.party_id, pid_list.iter().copied())
                * (*keyshare.shamir_share() + tweak);
        let binding = sign_session_id(&keyshare, &pid_list, &input, &tweak);
        let hp = hash_to_point(&onetime_public);
        Ok(Self {
            party_id: keyshare.party_id,
            keyshare,
            pid_list,
            binding,
            input,
            tweak,
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
        let mut key_image_seed = [0u8; 32];
        rng.fill_bytes(&mut individual_sid);
        rng.fill_bytes(&mut blind_factor);
        rng.fill_bytes(&mut seed);
        rng.fill_bytes(&mut key_image_seed);
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
            tweak: self.tweak,
            k_j: self.k_j,
            hp: self.hp,
            state: StateRound1Sent {
                individual_sid,
                alpha0,
                blind_factor,
                seed,
                key_image_seed,
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
            key_image_seed,
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
            tweak: self.tweak,
            k_j: self.k_j,
            hp: self.hp,
            state: StateReadyToOpen {
                alpha0,
                blind_factor,
                seed,
                key_image_seed,
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
    /// Also publish this party's key-image share `I_j = k_j · H_p(P)` with a
    /// DH-tuple proof against `k_j · G`.
    ///
    /// Both DH-tuple transcripts use the combined id from
    /// [`round1_in`](Self::round1_in). The proofs' randomness comes from
    /// separate seeds sampled in [`round1_out`](Self::round1_out).
    ///
    /// Delivery: broadcast to the signing quorum, signed only.
    pub fn round2_out(self) -> Result<(MlsagSignContext<StateOpened>, SignMsg2), MlsagError> {
        let StateReadyToOpen {
            alpha0,
            blind_factor,
            seed,
            key_image_seed,
            l0,
            r0,
            final_session_id,
            commits,
        } = self.state;

        let g = RistrettoPoint::generator();
        let mut proof_rng = ChaCha20Rng::from_seed(seed);
        let aux = (self.party_id as u32).to_be_bytes();
        let mut transcript = dh_tuple_transcript(&final_session_id, &aux);
        let pi = DhTupleProof::prove(
            DhTuplePoints {
                g: &g,
                q: &self.hp,
                a: &l0,
                b: &r0,
            },
            &alpha0,
            &mut transcript,
            &mut proof_rng,
        );

        let party_k = g * self.k_j;
        let i_j = self.hp * self.k_j;
        let mut key_image_rng = ChaCha20Rng::from_seed(key_image_proof_seed(
            &key_image_seed,
            &final_session_id,
            self.party_id,
            &party_k,
            &i_j,
        ));
        let mut transcript = dh_tuple_transcript(&final_session_id, &key_image_aux(self.party_id));
        let key_image_pi = DhTupleProof::prove(
            DhTuplePoints {
                g: &g,
                q: &self.hp,
                a: &party_k,
                b: &i_j,
            },
            &self.k_j,
            &mut transcript,
            &mut key_image_rng,
        );

        let next_state = MlsagSignContext {
            party_id: self.party_id,
            keyshare: self.keyshare,
            pid_list: self.pid_list,
            binding: self.binding,
            input: self.input,
            tweak: self.tweak,
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
            i_j: i_j.compress().to_bytes(),
            key_image_pi,
        };

        Ok((next_state, msg2))
    }

    pub fn session_id(&self) -> SessionId {
        self.state.final_session_id
    }
}

impl MlsagSignContext<StateOpened> {
    /// Check each opening against its round-1 commitment and each key-image
    /// share against that party's tweaked public share, then return the summed
    /// `(L0, R0)` and the output's key image `I = Σ I_j = x · H_p(P)`.
    ///
    /// Inbound `messages` are the signed round-2 broadcast. The sums are local:
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
        let mut image_sum = RistrettoPoint::identity();
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

            let i_j = CompressedRistretto(msg.i_j)
                .decompress()
                .filter(|p| !bool::from(p.is_identity()))
                .ok_or(MlsagError::InvalidKeyImagePoint(msg.from_party))?;
            let party_k =
                tweaked_public_share(&self.keyshare, &self.pid_list, &self.tweak, msg.from_party);
            let mut transcript =
                dh_tuple_transcript(&final_session_id, &key_image_aux(msg.from_party));
            if !msg.key_image_pi.verify(
                DhTuplePoints {
                    g: &g,
                    q: &self.hp,
                    a: &party_k,
                    b: &i_j,
                },
                &mut transcript,
            ) {
                return Err(MlsagError::InvalidDhProof(msg.from_party));
            }

            l0_sum += l0;
            r0_sum += r0;
            image_sum += i_j;
            party_l0.push((msg.from_party, l0));
        }
        party_l0.sort_by_key(|(pid, _)| *pid);
        if bool::from(image_sum.is_identity()) {
            return Err(MlsagError::InvalidKeyImage);
        }
        let key_image = KeyImage {
            point: image_sum.compress(),
        };

        let next_state = MlsagSignContext {
            party_id: self.party_id,
            keyshare: self.keyshare,
            pid_list: self.pid_list,
            binding: self.binding,
            input: self.input,
            tweak: self.tweak,
            k_j: self.k_j,
            hp: self.hp,
            state: StateNonces {
                alpha0,
                final_session_id,
                l0: l0_sum,
                r0: r0_sum,
                key_image,
                party_l0,
            },
        };

        let nonce_commit = NonceCommit {
            l0: l0_sum,
            r0: r0_sum,
            key_image,
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
            key_image,
            party_l0,
        } = self.state;

        let challenges = signing_challenges(&self.input, &key_image, &l0, &r0, tour)?;
        let c_pi = challenges[self.input.real_index];
        let r_pi_0 = alpha0 - c_pi * self.k_j;

        let next_state = MlsagSignContext {
            party_id: self.party_id,
            keyshare: self.keyshare,
            pid_list: self.pid_list,
            binding: self.binding,
            input: self.input,
            tweak: self.tweak,
            k_j: self.k_j,
            hp: self.hp,
            state: StateClosed {
                final_session_id,
                l0,
                r0,
                key_image,
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
            key_image,
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
            let k_pub =
                tweaked_public_share(&self.keyshare, &self.pid_list, &self.tweak, msg.from_party);
            if (g * msg.r_pi_0 + k_pub * c_pi).ct_ne(&l0_j).into() {
                return Err(MlsagError::InvalidResponse(msg.from_party));
            }
            r_sum += msg.r_pi_0;
        }

        assemble_ring_mlsag(&self.input, &key_image, &l0, &r0, tour, r_sum)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::run_mlsag_dkg;
    use crate::ring_mlsag::{fill_ring, sign_with_scalar, RingMember};
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

    /// Root spend key `b`, reconstructed from every share.
    fn root_secret(shares: &[MlsagKeyshare]) -> Scalar {
        let n = shares.len() as u8;
        (0..n)
            .map(|pid| {
                get_lagrange_coeff::<RistrettoPoint>(&pid, 0..n)
                    * *shares[pid as usize].shamir_share()
            })
            .sum()
    }

    fn onetime_public(shares: &[MlsagKeyshare], tweak: &Scalar) -> RistrettoPoint {
        *shares[0].public_key() + RistrettoPoint::generator() * tweak
    }

    /// Run signing up to the round-2 broadcast.
    fn open_round2(
        shares: &[MlsagKeyshare],
        pids: &[u8],
        input: &SignPublicInput,
        tweak: Scalar,
    ) -> (Vec<MlsagSignContext<StateOpened>>, Vec<SignMsg2>) {
        let mut rng = rand::thread_rng();
        let parties: Vec<_> = pids
            .iter()
            .map(|&pid| {
                MlsagSignContext::new(
                    shares[pid as usize].clone(),
                    pids.to_vec(),
                    input.clone(),
                    tweak,
                )
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
        (next_states, messages2)
    }

    fn run_sign(
        shares: &[MlsagKeyshare],
        pids: &[u8],
        input: &SignPublicInput,
        z: &Scalar,
        tweak: Scalar,
    ) -> RingMLSAG {
        let mut rng = rand::thread_rng();
        let (parties, messages2) = open_round2(shares, pids, input, tweak);

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
            &commits[0].key_image,
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
    fn tweaked_sign_every_quorum_verifies_with_the_output_key_image() {
        let shares = run_mlsag_dkg(3, 2);
        let mut rng = rand::thread_rng();
        let tweak = Scalar::random(&mut rng);
        let p = onetime_public(&shares, &tweak);
        let (input, z) = input_for_key(&p, b"threshold-mlsag", 1, 9, &mut rng);
        let x = root_secret(&shares) + tweak;
        assert_eq!(RistrettoPoint::mul_base(&x), p);

        for pids in [[0u8, 1], [1, 2], [0, 2]] {
            let signature = run_sign(&shares, &pids, &input, &z, tweak);
            signature.verify(&input).unwrap();
            assert_eq!(signature.key_image, KeyImage::from_scalar(&x));
        }

        let signature = run_sign(&shares, &[0, 1, 2], &input, &z, tweak);
        signature.verify(&input).unwrap();
        assert_eq!(signature.key_image, KeyImage::from_scalar(&x));
    }

    #[test]
    fn tweaked_key_image_matches_single_party_signer() {
        let shares = run_mlsag_dkg(3, 2);
        let mut rng = rand::thread_rng();
        let tweak = Scalar::random(&mut rng);
        let (input, z) = input_for_key(
            &onetime_public(&shares, &tweak),
            b"threshold-mlsag",
            2,
            9,
            &mut rng,
        );
        let x = root_secret(&shares) + tweak;

        let threshold = run_sign(&shares, &[0, 2], &input, &z, tweak);
        let single = sign_with_scalar(&input, &x, &z, &mut rng).unwrap();

        threshold.verify(&input).unwrap();
        single.verify(&input).unwrap();
        assert_eq!(threshold.key_image, single.key_image);
    }

    #[test]
    fn zero_tweak_signs_for_the_root_key_with_the_dkg_key_image() {
        let shares = run_mlsag_dkg(3, 2);
        let mut rng = rand::thread_rng();
        let (input, z) = input_for_key(shares[0].public_key(), b"threshold-mlsag", 1, 9, &mut rng);

        let signature = run_sign(&shares, &[0, 1], &input, &z, Scalar::ZERO);

        signature.verify(&input).unwrap();
        assert_eq!(signature.key_image, shares[0].key_image);
    }

    #[test]
    fn key_image_is_per_output() {
        let shares = run_mlsag_dkg(3, 2);
        let mut rng = rand::thread_rng();
        let mut images = Vec::new();
        for _ in 0..2 {
            let tweak = Scalar::random(&mut rng);
            let (input, z) = input_for_key(
                &onetime_public(&shares, &tweak),
                b"threshold-mlsag",
                0,
                9,
                &mut rng,
            );
            let signature = run_sign(&shares, &[1, 2], &input, &z, tweak);
            signature.verify(&input).unwrap();
            images.push(signature.key_image);
        }
        assert_ne!(images[0], images[1]);
        assert_ne!(images[0], shares[0].key_image);
    }

    #[test]
    fn session_binding_depends_on_the_tweak() {
        let shares = run_mlsag_dkg(3, 2);
        let mut rng = rand::thread_rng();
        let (input, _z) = input_for_key(shares[0].public_key(), b"threshold-mlsag", 1, 9, &mut rng);
        let pids = [0u8, 1];

        assert_ne!(
            sign_session_id(&shares[0], &pids, &input, &Scalar::ZERO),
            sign_session_id(&shares[0], &pids, &input, &Scalar::ONE),
        );
    }

    #[test]
    fn new_rejects_a_ring_member_that_is_not_the_tweaked_key() {
        let shares = run_mlsag_dkg(3, 2);
        let mut rng = rand::thread_rng();
        let tweak = Scalar::random(&mut rng);
        let (input, _z) = input_for_key(
            &onetime_public(&shares, &tweak),
            b"threshold-mlsag",
            1,
            9,
            &mut rng,
        );

        for wrong in [Scalar::ZERO, tweak + Scalar::ONE] {
            let err = MlsagSignContext::new(shares[0].clone(), vec![0, 1], input.clone(), wrong)
                .err()
                .unwrap();
            assert_eq!(err, MlsagError::PublicKeyMismatch);
        }
    }

    #[test]
    fn new_rejects_a_tweak_that_cancels_the_root_key() {
        let shares = run_mlsag_dkg(3, 2);
        let mut rng = rand::thread_rng();
        let (input, _z) = input_for_key(shares[0].public_key(), b"threshold-mlsag", 1, 9, &mut rng);
        let tweak = -root_secret(&shares);

        let err = MlsagSignContext::new(shares[0].clone(), vec![0, 1], input, tweak)
            .err()
            .unwrap();
        assert_eq!(err, MlsagError::InvalidTweak);
    }

    #[test]
    fn round2_rejects_a_key_image_share_that_does_not_match_the_proof() {
        let shares = run_mlsag_dkg(3, 2);
        let mut rng = rand::thread_rng();
        let tweak = Scalar::random(&mut rng);
        let (input, _z) = input_for_key(
            &onetime_public(&shares, &tweak),
            b"threshold-mlsag",
            1,
            9,
            &mut rng,
        );

        let (parties, mut messages2) = open_round2(&shares, &[0, 1], &input, tweak);
        messages2[0].i_j = RistrettoPoint::mul_base(&Scalar::random(&mut rng))
            .compress()
            .to_bytes();

        for p in parties {
            let err = p.round2_in(messages2.clone()).unwrap_err();
            assert_eq!(err, MlsagError::InvalidDhProof(0));
        }
    }

    #[test]
    fn round2_rejects_a_key_image_proof_replayed_from_another_session() {
        let shares = run_mlsag_dkg(3, 2);
        let mut rng = rand::thread_rng();
        let tweak = Scalar::random(&mut rng);
        let (input, _z) = input_for_key(
            &onetime_public(&shares, &tweak),
            b"threshold-mlsag",
            1,
            9,
            &mut rng,
        );

        let (parties, mut messages2) = open_round2(&shares, &[0, 1], &input, tweak);
        let (_, other_session) = open_round2(&shares, &[0, 1], &input, tweak);
        assert_eq!(messages2[1].i_j, other_session[1].i_j);
        messages2[1].key_image_pi = other_session[1].key_image_pi.clone();

        for p in parties {
            let err = p.round2_in(messages2.clone()).unwrap_err();
            assert_eq!(err, MlsagError::InvalidDhProof(1));
        }
    }

    #[test]
    fn round2_rejects_a_key_image_share_that_is_not_a_point() {
        let shares = run_mlsag_dkg(3, 2);
        let mut rng = rand::thread_rng();
        let tweak = Scalar::random(&mut rng);
        let (input, _z) = input_for_key(
            &onetime_public(&shares, &tweak),
            b"threshold-mlsag",
            1,
            9,
            &mut rng,
        );

        let (parties, mut messages2) = open_round2(&shares, &[0, 1], &input, tweak);
        messages2[1].i_j = [0xff; 32];

        for p in parties {
            let err = p.round2_in(messages2.clone()).unwrap_err();
            assert_eq!(err, MlsagError::InvalidKeyImagePoint(1));
        }
    }

    #[test]
    fn round2_rejects_a_nonce_that_does_not_open_the_commitment() {
        let shares = run_mlsag_dkg(3, 2);
        let mut rng = rand::thread_rng();
        let tweak = Scalar::random(&mut rng);
        let (input, _z) = input_for_key(
            &onetime_public(&shares, &tweak),
            b"threshold-mlsag",
            1,
            9,
            &mut rng,
        );

        let (parties, mut messages2) = open_round2(&shares, &[0, 1], &input, tweak);
        messages2[0].blind_factor[0] ^= 0xff;

        for p in parties {
            let err = p.round2_in(messages2.clone()).unwrap_err();
            assert_eq!(err, MlsagError::InvalidNonceCommitment(0));
        }
    }
}
