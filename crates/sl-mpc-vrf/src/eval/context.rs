// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use curve25519_dalek::{RistrettoPoint, Scalar};
use elliptic_curve::{group::GroupEncoding, subtle::ConstantTimeEq, Group};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sl_mpc_derive::{
    impls::ristretto::VrfGroup,
    math::{get_lagrange_coeff, participant_public_share},
    ro_hash_string, ED25519_VRF_OUTPUT_BITS,
};

use crate::{
    crypto::{calculate_final_session_id_pairs, hash_consistency, validate_input_messages},
    dh_tuple::{dh_tuple_transcript, DhTuplePoints, DhTupleProof},
    messages::{VrfMsg0, VrfMsg1},
    types::{SessionId, VrfError},
};

/// Output of a successful MPC VRF evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfOutput {
    pub output: Vec<u8>,
    pub session_id: SessionId,
    pub pid_list: Vec<u8>,
}

/// Key material and round state for MPC VRF evaluation.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone)]
pub struct Context {
    party_id: u8,
    threshold: u8,
    total_parties: u8,
    message: Vec<u8>,
    output_bits: usize,
    shamir_share: Scalar,
    public_key: RistrettoPoint,
    party_public_shares: Vec<RistrettoPoint>,

    session_id: SessionId,
    seed: [u8; 32],
    /// When set (e.g. `keyshare-session-id` in multi-party-schnorr), mixed into the eval SID.
    keygen_session_id: Option<SessionId>,

    h_con: [u8; 32],
    final_session_id: SessionId,
    pid_list: Vec<u8>,
    m_point: RistrettoPoint,

    msg0_generated: bool,
    round0_complete: bool,
}

impl Context {
    #[allow(clippy::too_many_arguments)]
    pub fn new<R: RngCore + CryptoRng>(
        party_id: u8,
        threshold: u8,
        total_parties: u8,
        message: Vec<u8>,
        shamir_share: Scalar,
        public_key: RistrettoPoint,
        party_public_shares: Vec<RistrettoPoint>,
        rng: &mut R,
    ) -> Result<Self, VrfError> {
        Self::new_with_output_bits(
            party_id,
            threshold,
            total_parties,
            message,
            ED25519_VRF_OUTPUT_BITS,
            shamir_share,
            public_key,
            party_public_shares,
            None,
            rng,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_output_bits<R: RngCore + CryptoRng>(
        party_id: u8,
        threshold: u8,
        total_parties: u8,
        message: Vec<u8>,
        output_bits: usize,
        shamir_share: Scalar,
        public_key: RistrettoPoint,
        party_public_shares: Vec<RistrettoPoint>,
        keygen_session_id: Option<SessionId>,
        rng: &mut R,
    ) -> Result<Self, VrfError> {
        if party_id >= total_parties {
            return Err(VrfError::InvalidKeyshare);
        }
        if party_public_shares.len() != total_parties as usize {
            return Err(VrfError::InvalidKeyshare);
        }

        Ok(Self {
            party_id,
            threshold,
            total_parties,
            message,
            output_bits,
            shamir_share,
            public_key,
            party_public_shares,
            session_id: rng.gen(),
            seed: rng.gen(),
            keygen_session_id,
            h_con: [0u8; 32],
            final_session_id: [0u8; 32],
            pid_list: Vec::new(),
            m_point: RistrettoPoint::identity(),
            msg0_generated: false,
            round0_complete: false,
        })
    }

    pub fn party_id(&self) -> u8 {
        self.party_id
    }

    pub fn h_con(&self) -> &[u8; 32] {
        &self.h_con
    }

    pub fn final_session_id(&self) -> &SessionId {
        &self.final_session_id
    }

    pub fn pid_list(&self) -> &[u8] {
        &self.pid_list
    }

    /// Round 0 outbound: consistency hash and session id contribution.
    pub fn round0_out(&mut self) -> Result<VrfMsg0, VrfError> {
        let vrf_ki = get_lagrange_coeff::<RistrettoPoint>(&self.party_id, 0..self.total_parties)
            * self.shamir_share;
        let ki = self.party_public_shares[self.party_id as usize];
        let expected_ki = RistrettoPoint::generator() * vrf_ki;
        if !bool::from(expected_ki.ct_eq(&ki)) {
            return Err(VrfError::InvalidLocalKey);
        }

        let mut sum_k = RistrettoPoint::identity();
        for share in &self.party_public_shares {
            sum_k += *share;
        }
        if !bool::from(sum_k.ct_eq(&self.public_key)) {
            return Err(VrfError::InvalidPublicShares);
        }

        self.h_con = hash_consistency(
            &self.public_key,
            &self.party_public_shares,
            &self.message,
            self.output_bits,
        );
        self.msg0_generated = true;

        Ok(VrfMsg0 {
            from_party: self.party_id,
            session_id: self.session_id,
            h_con: self.h_con,
        })
    }

    /// Round 0 inbound: `messages` must include this party's round-0 message.
    ///
    /// When `quorum` is `None`, exactly `threshold` messages are required.
    /// When `quorum` is `Some`, senders must match that party-id set exactly.
    pub fn round0_in(
        &mut self,
        messages: Vec<VrfMsg0>,
        quorum: Option<&[u8]>,
    ) -> Result<VrfMsg1, VrfError> {
        if !self.msg0_generated {
            return Err(VrfError::InvalidState);
        }

        let mut messages = messages;
        messages.sort_by_key(|m| m.from_party);

        if let Some(quorum) = quorum {
            if messages.len() != quorum.len() {
                return Err(VrfError::InvalidMsgCount);
            }
            let mut expected = quorum.to_vec();
            expected.sort_unstable();
            let mut actual: Vec<u8> = messages.iter().map(|m| m.from_party).collect();
            actual.sort_unstable();
            if actual != expected {
                return Err(VrfError::InvalidParticipantSet);
            }
        } else if messages.len() != self.threshold as usize {
            return Err(VrfError::InvalidMsgCount);
        }

        let local_msg = messages
            .iter()
            .find(|msg| msg.from_party == self.party_id)
            .ok_or(VrfError::InvalidParticipantSet)?;

        if local_msg.session_id != self.session_id {
            return Err(VrfError::InvalidParticipantSet);
        }

        let mut party_ids: Vec<u8> = messages.iter().map(|m| m.from_party).collect();
        party_ids.sort_unstable();
        party_ids.dedup();
        if party_ids.len() != messages.len() {
            return Err(VrfError::InvalidParticipantSet);
        }

        for msg in &messages {
            if msg.from_party >= self.total_parties {
                return Err(VrfError::InvalidMsgPartyId);
            }
            if msg.h_con != self.h_con {
                return Err(VrfError::ConsistencyHashMismatch(msg.from_party));
            }
        }

        let pairs: Vec<_> = messages
            .iter()
            .map(|m| (m.from_party, m.session_id))
            .collect();
        let extra = self.session_id_extra();
        self.final_session_id = calculate_final_session_id_pairs(pairs, &extra);
        self.pid_list = party_ids;

        self.m_point = RistrettoPoint::hash_vrf_message(&[self.message.as_slice()])
            .map_err(|_| VrfError::HashToCurve)?;

        let coeff =
            get_lagrange_coeff::<RistrettoPoint>(&self.party_id, self.pid_list.iter().copied());
        let vrf_ki = coeff * self.shamir_share;
        let party_ki = RistrettoPoint::generator() * vrf_ki;

        let aux = (self.party_id as u32).to_be_bytes();
        let mut proof_rng = ChaCha20Rng::from_seed(self.seed);
        let z_i = self.m_point * vrf_ki;
        let mut transcript = dh_tuple_transcript(&self.final_session_id, &aux);
        let pi = DhTupleProof::prove(
            DhTuplePoints {
                g: &RistrettoPoint::generator(),
                q: &self.m_point,
                a: &party_ki,
                b: &z_i,
            },
            &vrf_ki,
            &mut transcript,
            &mut proof_rng,
        );

        self.round0_complete = true;

        Ok(VrfMsg1 {
            from_party: self.party_id,
            session_id: self.final_session_id,
            z_i: z_i.compress().to_bytes().to_vec(),
            pi,
        })
    }

    /// Round 1 inbound: verify partial points and derive the VRF output.
    pub fn round1_in(&self, messages: Vec<VrfMsg1>) -> Result<VrfOutput, VrfError> {
        if !self.round0_complete {
            return Err(VrfError::InvalidState);
        }
        let messages = validate_input_messages(messages, &self.pid_list)?;

        let g = RistrettoPoint::generator();
        let mut z = RistrettoPoint::identity();

        for msg in &messages {
            if msg.from_party >= self.total_parties {
                return Err(VrfError::InvalidMsgPartyId);
            }
            if msg.session_id != self.final_session_id {
                return Err(VrfError::InvalidDhProof(msg.from_party));
            }
            let z_j = decode_point(&msg.z_i).ok_or(VrfError::InvalidZ(msg.from_party))?;
            if !RistrettoPoint::is_valid_partial_vrf_point(&z_j) {
                return Err(VrfError::InvalidZ(msg.from_party));
            }

            let aux = (msg.from_party as u32).to_be_bytes();
            let k_j = participant_public_share(
                &self.party_public_shares[msg.from_party as usize],
                msg.from_party,
                self.total_parties,
                self.pid_list.iter().copied(),
            );
            let mut transcript = dh_tuple_transcript(&self.final_session_id, &aux);
            if !msg.pi.verify(
                DhTuplePoints {
                    g: &g,
                    q: &self.m_point,
                    a: &k_j,
                    b: &z_j,
                },
                &mut transcript,
            ) {
                return Err(VrfError::InvalidDhProof(msg.from_party));
            }

            z += z_j;
        }

        let output = ro_hash_string(&[z.compress().as_bytes()], self.output_bits);

        Ok(VrfOutput {
            output,
            session_id: self.final_session_id,
            pid_list: self.pid_list.clone(),
        })
    }

    fn session_id_extra(&self) -> Vec<&[u8]> {
        match self.keygen_session_id {
            Some(ref sid) => vec![self.message.as_slice(), sid.as_slice()],
            None => vec![self.message.as_slice()],
        }
    }
}

fn decode_point(bytes: &[u8]) -> Option<RistrettoPoint> {
    let mut encoding = <RistrettoPoint as GroupEncoding>::Repr::default();
    if encoding.as_ref().len() != bytes.len() {
        return None;
    }
    encoding.as_mut().copy_from_slice(bytes);
    Option::from(RistrettoPoint::from_bytes(&encoding))
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::dkg::VrfKeyshare;

    pub fn init_eval_states(shares: &[VrfKeyshare], message: &[u8]) -> Vec<Context> {
        let mut rng = rand::thread_rng();
        shares
            .iter()
            .map(|ks| {
                Context::new(
                    ks.party_id,
                    ks.threshold,
                    ks.total_parties,
                    message.to_vec(),
                    *ks.shamir_share(),
                    *ks.public_key(),
                    ks.party_public_shares().to_vec(),
                    &mut rng,
                )
                .unwrap()
            })
            .collect()
    }

    pub fn vrf_eval_inner(mut parties: Vec<Context>, threshold: usize) -> Vec<VrfOutput> {
        let msg0: Vec<VrfMsg0> = parties
            .iter_mut()
            .map(|party| party.round0_out().unwrap())
            .collect();
        let msg0_subset: Vec<_> = msg0.into_iter().take(threshold).collect();

        let mut active: Vec<Context> = parties.into_iter().take(threshold).collect();
        let msg1: Vec<VrfMsg1> = active
            .iter_mut()
            .map(|party| party.round0_in(msg0_subset.clone(), None).unwrap())
            .collect();

        active
            .into_iter()
            .map(|party| party.round1_in(msg1.clone()).unwrap())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{init_eval_states, vrf_eval_inner};
    use super::{Context, VrfError};
    use crate::dkg::test_support::{init_states, vrf_dkg_inner};

    fn assert_matching_outputs(outputs: &[super::VrfOutput]) {
        let reference = &outputs[0].output;
        for output in &outputs[1..] {
            assert_eq!(&output.output, reference);
            assert_eq!(output.session_id, outputs[0].session_id);
            assert_eq!(output.pid_list, outputs[0].pid_list);
        }
    }

    #[test]
    fn vrf_eval_3_out_of_3() {
        let shares = vrf_dkg_inner(init_states(3, 3));
        let parties = init_eval_states(&shares, b"vrf-eval-3x3");
        let outputs = vrf_eval_inner(parties, 3);
        assert_eq!(outputs.len(), 3);
        assert_matching_outputs(&outputs);
    }

    #[test]
    fn vrf_eval_2_out_of_3() {
        let shares = vrf_dkg_inner(init_states(3, 2));
        let parties = init_eval_states(&shares, b"vrf-eval-2x3");
        let outputs = vrf_eval_inner(parties, 2);
        assert_eq!(outputs.len(), 2);
        assert_matching_outputs(&outputs);
    }

    #[test]
    fn vrf_eval_same_message_same_output() {
        let shares = vrf_dkg_inner(init_states(3, 2));
        let message = b"deterministic-input";

        let outputs_a = vrf_eval_inner(init_eval_states(&shares, message), 2);
        let outputs_b = vrf_eval_inner(init_eval_states(&shares, message), 2);

        assert_eq!(outputs_a[0].output, outputs_b[0].output);
    }

    #[test]
    fn new_rejects_malformed_keyshare_public_shares_len() {
        let shares = vrf_dkg_inner(init_states(3, 2));
        let ks = &shares[0];
        let mut party_public_shares = ks.party_public_shares().to_vec();
        party_public_shares.pop();

        assert!(matches!(
            Context::new(
                ks.party_id,
                ks.threshold,
                ks.total_parties,
                b"msg".to_vec(),
                *ks.shamir_share(),
                *ks.public_key(),
                party_public_shares,
                &mut rand::thread_rng(),
            ),
            Err(VrfError::InvalidKeyshare)
        ));
    }

    #[test]
    fn new_rejects_malformed_keyshare_party_id() {
        let shares = vrf_dkg_inner(init_states(3, 2));
        let ks = &shares[0];

        assert!(matches!(
            Context::new(
                ks.total_parties,
                ks.threshold,
                ks.total_parties,
                b"msg".to_vec(),
                *ks.shamir_share(),
                *ks.public_key(),
                ks.party_public_shares().to_vec(),
                &mut rand::thread_rng(),
            ),
            Err(VrfError::InvalidKeyshare)
        ));
    }
}
