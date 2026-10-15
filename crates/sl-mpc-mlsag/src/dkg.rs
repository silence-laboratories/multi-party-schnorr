// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! End-to-end MLSAG DKG: Feldman–Shamir keygen + all-party key image `I = x · H_p(P)`.

use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint};
use elliptic_curve::Group;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use sl_mpc_derive::math::{get_lagrange_coeff, participant_public_share};
use sl_mpc_vrf::{
    dh_tuple_transcript, DhTuplePoints, DhTupleProof, SessionId, VrfDkgContext, VrfDkgParty,
    VrfKeygenMsg1, VrfKeygenMsg2, VrfKeyshare,
};

use crate::{
    error::MlsagError,
    hash_to_point::hash_to_point,
    key_image::KeyImage,
    messages::{KeyshareMsg, MlsagKeyshare},
};

const KEYSHARE_SID_LABEL: &[u8] = b"SL-MLSAG-KEYIMAGE";

/// Party metadata for MLSAG DKG (same layout as Ristretto VRF DKG).
pub type MlsagDkgParty = VrfDkgParty;

/// Build Fiat–Shamir session id for the key-image round from DKG sid + quorum.
pub fn keyshare_session_id(dkg_session_id: &SessionId, pid_list: &[u8]) -> SessionId {
    let mut hasher = Sha256::new();
    hasher.update(KEYSHARE_SID_LABEL);
    hasher.update(dkg_session_id);
    for pid in pid_list {
        hasher.update([*pid]);
    }
    hasher.finalize().into()
}

enum Phase {
    Dkg(Box<VrfDkgContext>),
    Image(Box<KeyshareContext>),
}

/// End-to-end MLSAG DKG for one party.
///
/// Rounds:
/// 1. `round1_out` / `round1_in` — Feldman–Shamir commitments (broadcast, signed
///    only) and openings (P2P, encrypted to the recipient and signed by the sender)
/// 2. `round2_in` — finish Shamir shares and emit this party's `I_j` (broadcast,
///    signed only; all `n` parties)
/// 3. `round3_in` — verify all `I_j`, output [`MlsagKeyshare`] with shared `I`
pub struct MlsagDkgContext {
    party_id: u8,
    phase: Option<Phase>,
}

impl MlsagDkgContext {
    pub fn new<R: CryptoRng + RngCore>(
        party: MlsagDkgParty,
        rng: &mut R,
    ) -> Result<Self, MlsagError> {
        let party_id = party.party_id;
        Ok(Self {
            party_id,
            phase: Some(Phase::Dkg(Box::new(VrfDkgContext::new(party, rng)?))),
        })
    }

    pub fn party_id(&self) -> u8 {
        self.party_id
    }

    /// Round 1 outbound: polynomial commitments.
    ///
    /// Delivery: broadcast, signed only.
    pub fn round1_out<R: CryptoRng + RngCore>(
        &mut self,
        rng: &mut R,
    ) -> Result<VrfKeygenMsg1, MlsagError> {
        match self.phase.as_mut() {
            Some(Phase::Dkg(c)) => Ok(c.round1_out(rng)?),
            _ => Err(MlsagError::InvalidState),
        }
    }

    /// Round 1 inbound: collect the signed broadcast commitments.
    ///
    /// Returns one opening per party. Each opening is peer-to-peer: encrypt it
    /// to that recipient and sign it as this sender. It carries that party's
    /// Shamir share.
    pub fn round1_in<R: CryptoRng + RngCore>(
        &mut self,
        rng: &mut R,
        messages: Vec<VrfKeygenMsg1>,
    ) -> Result<Vec<VrfKeygenMsg2>, MlsagError> {
        match self.phase.as_mut() {
            Some(Phase::Dkg(c)) => Ok(c.round1_in(rng, messages)?),
            _ => Err(MlsagError::InvalidState),
        }
    }

    /// Round 2: finish Shamir DKG from the encrypted peer-to-peer openings, then
    /// emit this party's key-image contribution.
    ///
    /// The returned [`KeyshareMsg`] is broadcast, signed only. The key-image
    /// quorum is always all `n` parties (`0..n`).
    pub fn round2_in<R: CryptoRng + RngCore>(
        &mut self,
        rng: &mut R,
        messages: Vec<VrfKeygenMsg2>,
    ) -> Result<KeyshareMsg, MlsagError> {
        let Phase::Dkg(mut vrf) = self.phase.take().ok_or(MlsagError::InvalidState)? else {
            return Err(MlsagError::InvalidState);
        };

        let share = match vrf.round2_in(messages) {
            Ok(s) => s,
            Err(e) => {
                self.phase = Some(Phase::Dkg(vrf));
                return Err(e.into());
            }
        };

        let pid_list: Vec<u8> = (0..share.total_parties).collect();
        let mut image = KeyshareContext::new(share, pid_list, rng)?;
        let msg = image.round_out()?;
        self.phase = Some(Phase::Image(Box::new(image)));
        Ok(msg)
    }

    /// Round 3: verify the signed broadcast of every `I_j` and output [`MlsagKeyshare`].
    pub fn round3_in(self, messages: Vec<KeyshareMsg>) -> Result<MlsagKeyshare, MlsagError> {
        match self.phase {
            Some(Phase::Image(ctx)) => (*ctx).round_in(messages),
            _ => Err(MlsagError::InvalidState),
        }
    }
}

/// Key-image assembly for a fixed quorum (used by [`MlsagDkgContext`] with all parties).
pub struct KeyshareContext {
    keyshare: VrfKeyshare,
    pid_list: Vec<u8>,
    session_id: SessionId,
    hp: RistrettoPoint,
    seed: [u8; 32],
    round_complete: bool,
}

impl KeyshareContext {
    /// Start key-image assembly for `participating_party_ids` (`|S| ≥ t`, includes this party).
    pub fn new<R: CryptoRng + RngCore>(
        keyshare: VrfKeyshare,
        participating_party_ids: Vec<u8>,
        rng: &mut R,
    ) -> Result<Self, MlsagError> {
        if keyshare.party_public_shares().len() != keyshare.total_parties as usize {
            return Err(MlsagError::InvalidKeyshare);
        }
        if participating_party_ids.len() < keyshare.threshold as usize {
            return Err(MlsagError::InvalidThreshold);
        }
        if participating_party_ids.len() > keyshare.total_parties as usize {
            return Err(MlsagError::InvalidParticipantSet);
        }

        let mut pid_list = participating_party_ids;
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

        let session_id = keyshare_session_id(&keyshare.final_session_id, &pid_list);
        let hp = hash_to_point(keyshare.public_key());

        Ok(Self {
            keyshare,
            pid_list,
            session_id,
            hp,
            seed: rng.gen(),
            round_complete: false,
        })
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn pid_list(&self) -> &[u8] {
        &self.pid_list
    }

    /// Produce this party's `(I_j, proof)`.
    ///
    /// Delivery: broadcast, signed only.
    pub fn round_out(&mut self) -> Result<KeyshareMsg, MlsagError> {
        if self.round_complete {
            return Err(MlsagError::InvalidState);
        }

        let coeff = get_lagrange_coeff::<RistrettoPoint>(
            &self.keyshare.party_id,
            self.pid_list.iter().copied(),
        );
        let k_j = coeff * *self.keyshare.shamir_share();
        let party_kj = RistrettoPoint::generator() * k_j;
        let i_j = self.hp * k_j;

        let aux = (self.keyshare.party_id as u32).to_be_bytes();
        let mut proof_rng = ChaCha20Rng::from_seed(self.seed);
        let mut transcript = dh_tuple_transcript(&self.session_id, &aux);
        let pi = DhTupleProof::prove(
            DhTuplePoints {
                g: &RistrettoPoint::generator(),
                q: &self.hp,
                a: &party_kj,
                b: &i_j,
            },
            &k_j,
            &mut transcript,
            &mut proof_rng,
        );

        self.round_complete = true;

        Ok(KeyshareMsg {
            from_party: self.keyshare.party_id,
            session_id: self.session_id,
            i_j: i_j.compress().to_bytes(),
            pi,
        })
    }

    /// Verify all quorum messages and output [`MlsagKeyshare`].
    pub fn round_in(self, messages: Vec<KeyshareMsg>) -> Result<MlsagKeyshare, MlsagError> {
        if !self.round_complete {
            return Err(MlsagError::InvalidState);
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
        let mut image_point = RistrettoPoint::identity();

        for msg in &messages {
            if msg.session_id != self.session_id {
                return Err(MlsagError::InvalidParticipantSet);
            }

            let i_j = CompressedRistretto(msg.i_j)
                .decompress()
                .ok_or(MlsagError::InvalidKeyImagePoint(msg.from_party))?;
            if bool::from(i_j.is_identity()) {
                return Err(MlsagError::InvalidKeyImagePoint(msg.from_party));
            }

            let k_j = participant_public_share(
                &self.keyshare.party_public_shares()[msg.from_party as usize],
                msg.from_party,
                self.keyshare.total_parties,
                self.pid_list.iter().copied(),
            );

            let aux = (msg.from_party as u32).to_be_bytes();
            let mut transcript = dh_tuple_transcript(&self.session_id, &aux);
            if !msg.pi.verify(
                DhTuplePoints {
                    g: &g,
                    q: &self.hp,
                    a: &k_j,
                    b: &i_j,
                },
                &mut transcript,
            ) {
                return Err(MlsagError::InvalidDhProof(msg.from_party));
            }

            image_point += i_j;
        }

        if bool::from(image_point.is_identity()) {
            return Err(MlsagError::InvalidKeyImage);
        }
        let key_image = KeyImage {
            point: image_point.compress(),
        };

        Ok(MlsagKeyshare::from_vrf_keyshare(
            &self.keyshare,
            key_image,
            self.session_id,
            self.pid_list,
        ))
    }
}

/// Drive full MLSAG DKG for `n` parties; each output has share + shared `I`.
#[cfg(test)]
pub(crate) fn run_mlsag_dkg(n: u8, t: u8) -> Vec<MlsagKeyshare> {
    let mut rng = rand::thread_rng();
    let mut parties: Vec<MlsagDkgContext> = (0..n)
        .map(|id| MlsagDkgContext::new(MlsagDkgParty::new(n, t, id), &mut rng).unwrap())
        .collect();

    let msg1: Vec<_> = parties
        .iter_mut()
        .map(|p| p.round1_out(&mut rng).unwrap())
        .collect();

    let msg2: Vec<_> = parties
        .iter_mut()
        .flat_map(|party| {
            let mut messages: Vec<_> = msg1
                .iter()
                .filter(|m| m.from_party != party.party_id())
                .cloned()
                .collect();
            let own = *msg1
                .iter()
                .find(|m| m.from_party == party.party_id())
                .unwrap();
            messages.push(own);
            party.round1_in(&mut rng, messages).unwrap()
        })
        .collect();

    let msg3: Vec<_> = parties
        .iter_mut()
        .map(|party| {
            let batch: Vec<_> = msg2
                .iter()
                .filter(|m| m.to_party == party.party_id())
                .cloned()
                .collect();
            party.round2_in(&mut rng, batch).unwrap()
        })
        .collect();

    parties
        .into_iter()
        .map(|party| party.round3_in(msg3.clone()).unwrap())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::Scalar;

    #[test]
    fn mlsag_dkg_2_of_3_share_and_key_image() {
        let shares = run_mlsag_dkg(3, 2);
        let pk = *shares[0].public_key();
        let image = shares[0].key_image;
        for s in &shares {
            assert_eq!(*s.public_key(), pk);
            assert_eq!(s.key_image, image);
            assert_eq!(s.keyshare_pid_list, vec![0, 1, 2]);
        }

        let x: Scalar = (0..3u8)
            .map(|pid| {
                let lam = get_lagrange_coeff::<RistrettoPoint>(&pid, 0..3u8);
                lam * *shares[pid as usize].shamir_share()
            })
            .sum();
        assert_eq!(RistrettoPoint::mul_base(&x), pk);
        assert_eq!(shares[0].key_image, KeyImage::from_scalar(&x));
    }
}
