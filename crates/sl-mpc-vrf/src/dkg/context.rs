// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use curve25519_dalek::{RistrettoPoint, Scalar};
use elliptic_curve::Group;
use rand::{CryptoRng, Rng, RngCore};
use sha2::{Digest, Sha256};
use sl_mpc_mate::math::{GroupPolynomial, Polynomial};

use crate::crypto::calculate_final_session_id_pairs;

use super::{
    crypto::{
        compute_additive_public_shares, hash_commitment, validate_input_messages,
        verify_dlog_proofs, DLogProof, P2pShare, P2P_SHARE_SIZE,
    },
    error::VrfKeygenError,
    messages::{VrfKeygenMsg1, VrfKeygenMsg2, VrfKeyshare},
};

/// Party metadata for VRF DKG (zero ranks, evaluation points `party_id + 1`).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Party {
    pub t: u8,
    pub party_id: u8,
    pub total_parties: u8,
}

impl Party {
    pub fn new(total_parties: u8, t: u8, party_id: u8) -> Self {
        Self {
            t,
            party_id,
            total_parties,
        }
    }
}

/// Key material and round state for Shamir VRF DKG on Ristretto (Protocol 12).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Context {
    party: Party,

    session_id: [u8; 32],
    polynomial: Polynomial<RistrettoPoint>,
    r_i: [u8; 32],
    chain_code_id: [u8; 32],

    big_a_i: GroupPolynomial<RistrettoPoint>,
    c_i_j: Vec<P2pShare>,
    commitment: [u8; 32],

    final_session_id: [u8; 32],
    commitment_list: Vec<[u8; 32]>,
    sid_i_list: Vec<[u8; 32]>,

    msg1_generated: bool,
    round1_complete: bool,
}

impl Context {
    pub fn new<R: RngCore + CryptoRng>(
        party: Party,
        rng: &mut R,
    ) -> Result<Self, VrfKeygenError> {
        if party.party_id >= party.total_parties {
            return Err(VrfKeygenError::InvalidPid);
        }
        if party.t < 2 || party.t > party.total_parties {
            return Err(VrfKeygenError::InvalidT);
        }

        let t = party.t;
        Ok(Self {
            party,
            session_id: rng.gen(),
            polynomial: Polynomial::random(rng, (t - 1) as usize),
            r_i: rng.gen(),
            chain_code_id: rng.gen(),
            big_a_i: GroupPolynomial::new(vec![]),
            c_i_j: Vec::new(),
            commitment: [0u8; 32],
            final_session_id: [0u8; 32],
            commitment_list: Vec::new(),
            sid_i_list: Vec::new(),
            msg1_generated: false,
            round1_complete: false,
        })
    }

    pub fn party_id(&self) -> u8 {
        self.party.party_id
    }

    /// Round 1 outbound: sample polynomial commitments and plaintext P2P shares.
    pub fn round1_out<R: RngCore + CryptoRng>(
        &mut self,
        _rng: &mut R,
    ) -> Result<VrfKeygenMsg1, VrfKeygenError> {
        let big_a_i = self.polynomial.commit();
        let n = self.party.total_parties;

        let c_i_j = (0..n)
            .map(|receiver_pid| {
                let d_i = self
                    .polynomial
                    .evaluate_at(&Scalar::from((receiver_pid + 1) as u64));

                let mut data = [0u8; P2P_SHARE_SIZE];
                data[..32].copy_from_slice(d_i.as_bytes());
                data[32..].copy_from_slice(&self.chain_code_id);

                Ok(P2pShare::new(self.party.party_id, receiver_pid, data))
            })
            .collect::<Result<Vec<_>, VrfKeygenError>>()?;

        let commitment = hash_commitment(
            &self.session_id,
            self.party.party_id,
            &big_a_i.coeffs,
            &c_i_j,
            &self.r_i,
        );

        self.big_a_i = big_a_i;
        self.c_i_j = c_i_j;
        self.commitment = commitment;
        self.msg1_generated = true;

        Ok(VrfKeygenMsg1 {
            from_party: self.party.party_id,
            session_id: self.session_id,
            commitment,
        })
    }

    /// Round 1 inbound: `messages` must include this party's round-1 message.
    pub fn round1_in<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        messages: Vec<VrfKeygenMsg1>,
    ) -> Result<VrfKeygenMsg2, VrfKeygenError> {
        if !self.msg1_generated {
            return Err(VrfKeygenError::InvalidState);
        }
        if messages.len() != self.party.total_parties as usize {
            return Err(VrfKeygenError::InvalidMsgCount);
        }

        let messages = validate_input_messages(messages, self.party.total_parties)?;
        let n = self.party.total_parties as usize;

        let mut sid_i_list = Vec::with_capacity(n);
        let mut commitment_list = Vec::with_capacity(n);

        for message in &messages {
            if message.from_party == self.party.party_id
                && (self.session_id != message.session_id || self.commitment != message.commitment)
            {
                return Err(VrfKeygenError::Abort("invalid own round-1 message"));
            }
            sid_i_list.push(message.session_id);
            commitment_list.push(message.commitment);
        }

        let pairs: Vec<_> = messages
            .iter()
            .map(|m| (m.from_party, m.session_id))
            .collect();
        let final_sid = calculate_final_session_id_pairs(pairs, &[]);

        let dlog_sid: [u8; 32] = Sha256::new()
            .chain_update(b"SL-EDDSA-DLOG-PROOF")
            .chain_update(final_sid)
            .chain_update((self.party.party_id as u32).to_be_bytes())
            .chain_update(b"DLOG-PROOF-1-SID")
            .finalize()
            .into();

        let dlog_proofs = self
            .polynomial
            .iter()
            .map(|coeff| DLogProof::prove(&dlog_sid, coeff, rng))
            .collect();

        self.final_session_id = final_sid;
        self.commitment_list = commitment_list;
        self.sid_i_list = sid_i_list;
        self.round1_complete = true;

        Ok(VrfKeygenMsg2 {
            from_party: self.party.party_id,
            session_id: final_sid,
            r_i: self.r_i,
            big_a_i_poly: self.big_a_i.coeffs.clone(),
            c_i_list: self.c_i_j.clone(),
            dlog_proofs_i: dlog_proofs,
        })
    }

    /// Round 2 inbound: verify openings and derive the VRF key share.
    pub fn round2_in(
        &mut self,
        messages: Vec<VrfKeygenMsg2>,
    ) -> Result<VrfKeyshare, VrfKeygenError> {
        if !self.round1_complete {
            return Err(VrfKeygenError::InvalidState);
        }
        let messages = validate_input_messages(messages, self.party.total_parties)?;

        for msg in &messages {
            if msg.session_id != self.final_session_id {
                return Err(VrfKeygenError::InvalidParticipantSet);
            }

            let party_id = msg.from_party;
            let sid = self.sid_i_list[party_id as usize];
            let commitment = self.commitment_list[party_id as usize];
            let commit_hash =
                hash_commitment(&sid, party_id, &msg.big_a_i_poly, &msg.c_i_list, &msg.r_i);
            if commit_hash != commitment {
                return Err(VrfKeygenError::ProofError);
            }

            let dlog_sid: [u8; 32] = Sha256::new()
                .chain_update(b"SL-EDDSA-DLOG-PROOF")
                .chain_update(self.final_session_id)
                .chain_update((party_id as u32).to_be_bytes())
                .chain_update(b"DLOG-PROOF-1-SID")
                .finalize()
                .into();

            if !verify_dlog_proofs(
                &msg.dlog_proofs_i,
                &msg.big_a_i_poly,
                &dlog_sid,
                self.party.t,
            ) {
                return Err(VrfKeygenError::ProofError);
            }
        }

        let mut d_i_vals = Vec::with_capacity(messages.len());
        let mut chain_code_sids: Vec<[u8; 32]> = Vec::with_capacity(messages.len());

        for msg in &messages {
            let share = &msg.c_i_list[self.party.party_id as usize];
            if share.sender_pid != msg.from_party || share.receiver_pid != self.party.party_id {
                return Err(VrfKeygenError::InvalidParticipantSet);
            }

            let plaintext = share.data;
            let mut scalar_bytes = [0u8; 32];
            scalar_bytes.copy_from_slice(&plaintext[..32]);
            let d_i = Option::from(Scalar::from_canonical_bytes(scalar_bytes))
                .ok_or(VrfKeygenError::InvalidDiPlaintext)?;

            d_i_vals.push(d_i);
            chain_code_sids.push(plaintext[32..].try_into().unwrap());
        }

        let d_i_share: Scalar = d_i_vals.iter().sum();

        let mut chain_hasher = Sha256::new();
        chain_hasher.update(b"SL-Keygen-ChainCode");
        for sid in chain_code_sids {
            chain_hasher.update(sid);
        }
        let root_chain_code: [u8; 32] = chain_hasher.finalize().into();

        let empty_poly = (0..self.party.t)
            .map(|_| RistrettoPoint::identity())
            .collect();
        let mut big_a_poly = GroupPolynomial::new(empty_poly);

        for msg in &messages {
            big_a_poly.add_mut(&msg.big_a_i_poly);

            let d_i = d_i_vals[msg.from_party as usize];
            let expected = RistrettoPoint::mul_base(&d_i);
            let calc = GroupPolynomial::new(msg.big_a_i_poly.clone())
                .evaluate_at(&Scalar::from((self.party.party_id + 1) as u64));

            if expected != calc {
                return Err(VrfKeygenError::Abort(
                    "invalid d_i share for sender polynomial",
                ));
            }
        }

        let public_key = big_a_poly.get_constant();
        let party_public_shares =
            compute_additive_public_shares(&big_a_poly, self.party.total_parties);

        let expected = RistrettoPoint::mul_base(&d_i_share);
        let calc = big_a_poly.evaluate_at(&Scalar::from((self.party.party_id + 1) as u64));
        if expected != calc {
            return Err(VrfKeygenError::Abort("invalid combined d_i share"));
        }

        let key_id: [u8; 32] = Sha256::digest(public_key.compress().as_bytes()).into();

        Ok(VrfKeyshare {
            threshold: self.party.t,
            total_parties: self.party.total_parties,
            party_id: self.party.party_id,
            d_i: d_i_share,
            public_key,
            party_public_shares,
            key_id,
            root_chain_code,
            final_session_id: self.final_session_id,
        })
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub fn init_states(n: u8, t: u8) -> Vec<Context> {
        let mut rng = rand::thread_rng();
        (0..n)
            .map(|party_id| {
                Context::new(Party::new(n, t, party_id), &mut rng).unwrap()
            })
            .collect()
    }

    pub fn vrf_dkg_inner(mut parties: Vec<Context>) -> Vec<VrfKeyshare> {
        let mut rng = rand::thread_rng();

        let msg1: Vec<VrfKeygenMsg1> = parties
            .iter_mut()
            .map(|p| p.round1_out(&mut rng).unwrap())
            .collect();

        let msg2: Vec<VrfKeygenMsg2> = parties
            .iter_mut()
            .map(|party| {
                let mut messages: Vec<VrfKeygenMsg1> = msg1
                    .iter()
                    .filter(|msg| msg.from_party != party.party_id())
                    .cloned()
                    .collect();
                let own = msg1
                    .iter()
                    .find(|m| m.from_party == party.party_id())
                    .unwrap()
                    .clone();
                messages.push(own);
                party.round1_in(&mut rng, messages).unwrap()
            })
            .collect();

        parties
            .iter_mut()
            .map(|party| party.round2_in(msg2.clone()).unwrap())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::RistrettoPoint;

    use super::test_support::{init_states, vrf_dkg_inner};
    use super::VrfKeyshare;

    fn assert_shared_vrf_state(shares: &[VrfKeyshare]) {
        let reference = &shares[0];
        let pk = reference.public_key();
        let chain = reference.root_chain_code;
        let key_id = reference.key_id;
        let final_sid = reference.final_session_id;
        let additive_shares = reference.party_public_shares();

        for share in &shares[1..] {
            assert_eq!(share.public_key(), pk);
            assert_eq!(share.root_chain_code, chain);
            assert_eq!(share.key_id, key_id);
            assert_eq!(share.final_session_id, final_sid);
            assert_eq!(share.party_public_shares(), additive_shares);
        }

        let sum: RistrettoPoint = additive_shares.iter().sum();
        assert_eq!(sum, *pk);
    }

    #[test]
    fn vrf_dkg_3_out_of_3() {
        let shares = vrf_dkg_inner(init_states(3, 3));
        assert_eq!(shares.len(), 3);
        assert_shared_vrf_state(&shares);
    }

    #[test]
    fn vrf_dkg_2_out_of_3() {
        let shares = vrf_dkg_inner(init_states(3, 2));
        assert_eq!(shares.len(), 3);
        assert_shared_vrf_state(&shares);
    }
}
