// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Quorum change protocol
//! Based on dkls23-rs/docs/quorum_change_protocol.txt and
//! Protocol 7.1. Relaxed DLog Keygen https://eprint.iacr.org/2023/765.pdf

use crypto_bigint::subtle::ConstantTimeEq;

use elliptic_curve::{group::GroupEncoding, Group};

use ff::PrimeField;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use sha2::{Digest, Sha256};
use sl_mpc_mate::math::GroupPolynomial;

use crate::common::{
    traits::{GroupElem, Round},
    utils::{HashBytes, SessionId},
};
use crate::keygen::Keyshare;
use crate::quorum_change::messages::{QCBroadcastMsg1, QCBroadcastMsg2, QCP2PMsg1, QCP2PMsg2};
use crate::quorum_change::pairs::Pairs;
use crate::quorum_change::types::{QCEntropyNew, QCEntropyOld, QCError, QCParams};

/// LABEL for the QuorumChange protocol
pub const QC_LABEL: &[u8] = b"Schnorr-QC";

/// LABEL for the QuorumChange protocol COMMITMENT_1
pub const QC_COMMITMENT_1_LABEL: &[u8] = b"Schnorr-QC-commit1";

/// LABEL for the QuorumChange protocol COMMITMENT_2
pub const QC_COMMITMENT_2_LABEL: &[u8] = b"Schnorr-QC-commit2";

/// The QCPartyOld is a state machine that implements the QuorumChange protocol for old participant.
pub struct QCPartyOld<T, G>
where
    G: Group + GroupEncoding,
{
    params: QCParams<G>,
    rand_params: QCEntropyOld<G>,
    state: T,
}

/// The QCPartyOldToNew is a state machine that implements the QuorumChange protocol for old to new participant.
pub struct QCPartyOldToNew<T, G>
where
    G: Group + GroupEncoding,
{
    params: QCParams<G>,
    party_id: u8,
    rand_params: QCEntropyOld<G>,
    state: T,
}

/// The QCPartyNew is a state machine that implements the QuorumChange protocol for new participant.
pub struct QCPartyNew<T, G>
where
    G: Group,
{
    params: QCParams<G>,
    rand_params: QCEntropyNew,
    state: T,
}

pub struct R0;

pub struct R1Old<G>
where
    G: Group + GroupEncoding,
{
    big_p_i_poly: GroupPolynomial<G>,
    commitment_1: HashBytes,
}

pub struct R1New;

/// State of a QCPartyOld after processing the first message.
pub struct R2Old<G>
where
    G: Group + GroupEncoding,
{
    sid_i_list: Vec<SessionId>,
    commitment_list: Vec<HashBytes>,
    big_p_i_poly: GroupPolynomial<G>,
}

/// State of a QCPartyOldToNew after processing the first message.
pub struct R2OldToNew<G>
where
    G: Group + GroupEncoding,
{
    final_session_id: SessionId,
    sid_i_list: Vec<SessionId>,
    commitment_list: Vec<HashBytes>,
    big_p_i_poly: GroupPolynomial<G>,
    new_x_i_list: Vec<G::Scalar>,
    p_i_list: Pairs<G::Scalar, u8>,
    p_i_j_list: Pairs<G::Scalar, u8>,
}

/// State of a QCPartyNew after processing the first message.
pub struct R2New {
    final_session_id: SessionId,
    sid_i_list: Vec<SessionId>,
    commitment_list: Vec<HashBytes>,
}

/// State of a QCPartyOldToNew after processing p2p messages 1.
pub struct R3OldToNew<G>
where
    G: Group + GroupEncoding,
{
    final_session_id: SessionId,
    sid_i_list: Vec<SessionId>,
    commitment_list: Vec<HashBytes>,
    commitment2_list: Pairs<HashBytes, u8>,
    big_p_i_poly: GroupPolynomial<G>,
    new_x_i_list: Vec<G::Scalar>,
    p_i_list: Pairs<G::Scalar, u8>,
}

/// State of a QCPartyNew after processing p2p messages 1.
pub struct R3New {
    final_session_id: SessionId,
    sid_i_list: Vec<SessionId>,
    commitment_list: Vec<HashBytes>,
    commitment2_list: Pairs<HashBytes, u8>,
}

impl<G> QCPartyOld<R0, G>
where
    G: Group + GroupEncoding,
{
    /// Create a new QC party for old participant.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        total_parties: u8,
        new_t: u8,
        party_index: usize,
        old_parties: Vec<usize>,
        new_parties: Vec<usize>,
        old_party_ids: Vec<(usize, u8)>,
        old_keyshare: &Keyshare<G>,
        key_id: Option<[u8; 32]>,
        seed: [u8; 32],
        extra_data: Option<Vec<u8>>,
    ) -> Result<Self, QCError> {
        let mut old_party_id_pairs = Pairs::new();
        for (party_index, party_id) in old_party_ids {
            old_party_id_pairs.push(party_index, party_id);
        }

        let mut rng = ChaCha20Rng::from_seed(seed);

        assert!(old_parties.contains(&party_index));
        assert!(!new_parties.contains(&party_index));

        // calculate additive share s_i_0 of participant_i,
        // \sum_{i=0}^{n-1} s_i_0 = private_key
        let s_i_0 = {
            assert!(old_parties.len() >= old_keyshare.threshold as usize);
            let old_party_id_list = old_party_id_pairs.remove_ids();
            old_keyshare.scalar_share_interpolate(old_party_id_list)
        };

        let rand_params = QCEntropyOld::generate(new_t, s_i_0, &new_parties, &mut rng);

        if new_t < 2 {
            return Err(QCError::InvalidT);
        }

        Ok(Self {
            params: QCParams {
                total_parties,
                new_t,
                party_index,
                new_parties,
                old_parties,
                old_party_ids: old_party_id_pairs,
                public_key: old_keyshare.public_key,
                key_id,
                extra_data,
            },
            rand_params,
            state: R0,
        })
    }
}

impl<G: GroupElem> Round for QCPartyOld<R0, G> {
    type Input = ();

    type Output = Result<(QCPartyOld<R1Old<G>, G>, QCBroadcastMsg1), QCError>;

    /// Creates first broadcast message
    fn process(self, _: ()) -> Self::Output {
        let sid_i = self.rand_params.sid_i;
        let big_p_i_poly = self.rand_params.polynomial.commit();
        let r1_i = self.rand_params.r1_i;

        let commitment_1 = hash_commitment_1(&sid_i, self.params.party_index, &big_p_i_poly, &r1_i);

        let broadcast_msg1 = QCBroadcastMsg1 {
            from_party: self.params.party_index as u8,
            sid_i,
            commitment_1,
        };

        let next_state = QCPartyOld {
            params: self.params,
            rand_params: self.rand_params,
            state: R1Old {
                big_p_i_poly,
                commitment_1,
            },
        };

        Ok((next_state, broadcast_msg1))
    }
}

impl<G: GroupElem> Round for QCPartyOld<R1Old<G>, G>
where
    G: GroupElem,
{
    type Input = Vec<QCBroadcastMsg1>;

    type Output = Result<
        (
            QCPartyOld<R2Old<G>, G>,
            Vec<QCP2PMsg1>,
            Vec<QCP2PMsg2<G>>,
            QCBroadcastMsg2<G>,
        ),
        QCError,
    >;

    /// Processes BroadcastMsg1 and creates p2p commitment2, p2p decommit2, BroadcastMsg2
    fn process(self, messages: Self::Input) -> Self::Output {
        let total_parties = self.params.total_parties as usize;
        if messages.len() != total_parties {
            return Err(QCError::InvalidMsgCount);
        }
        let mut messages = messages;
        messages.sort_by_key(|msg| msg.from_party);

        let messages = messages
            .iter()
            .enumerate()
            .all(|(pid, msg)| msg.from_party as usize == pid)
            .then_some(messages)
            .ok_or(QCError::InvalidParticipantSet)?;

        let mut sid_i_list = Vec::with_capacity(total_parties);
        let mut commitment_list = Vec::with_capacity(total_parties);

        for message in &messages {
            if message.from_party as usize == self.params.party_index {
                let cond1 = self.rand_params.sid_i == message.sid_i;
                let cond2 = self.state.commitment_1 == message.commitment_1;
                if !(cond1 && cond2) {
                    return Err(QCError::InvalidMessage);
                }
            }
            sid_i_list.push(message.sid_i);
            commitment_list.push(message.commitment_1);
        }

        let final_session_id: [u8; 32] = sid_i_list
            .iter()
            .fold(Sha256::new(), |hash, sid| hash.chain_update(sid))
            .finalize()
            .into();

        let new_n = self.params.new_parties.len();
        let new_x_i_list: Vec<G::Scalar> = (1..=new_n as u64).map(G::Scalar::from).collect();

        // blind commitment2 values for receiver_ids
        let mut r2_j_list: Pairs<[u8; 32], u8> = Pairs::new();
        let mut p_i_j_list: Pairs<G::Scalar, u8> = Pairs::new();

        let mut p2p_messages_1 = Vec::with_capacity(self.params.new_parties.len());
        let mut p2p_messages_2 = Vec::with_capacity(self.params.new_parties.len());

        for &receiver_index in self.params.new_parties.iter() {
            if receiver_index == self.params.party_index {
                return Err(QCError::InvalidMessage);
            }

            let receiver_id = new_party_id(&self.params.new_parties, receiver_index).unwrap();

            let r2_j = self.rand_params.r2_j_list.find_pair(receiver_id);
            r2_j_list.push(receiver_id, *r2_j);

            let x_j = new_x_i_list[receiver_id as usize];
            let p_i_j = self.rand_params.polynomial.evaluate_at(&x_j);
            p_i_j_list.push(receiver_id, p_i_j);

            let commitment_2 = hash_commitment_2::<G>(
                &final_session_id,
                self.params.party_index,
                receiver_index,
                &p_i_j,
                r2_j,
            );

            let p2p_msg_1 = QCP2PMsg1 {
                from_party: self.params.party_index as u8,
                to_party: receiver_index as u8,
                commitment_2,
            };
            p2p_messages_1.push(p2p_msg_1);

            let p2p_msg_2 = QCP2PMsg2 {
                from_party: self.params.party_index as u8,
                to_party: receiver_index as u8,
                p_i: p_i_j,
                r_2_i: *r2_j,
                root_chain_code: [0u8; 32],
            };
            p2p_messages_2.push(p2p_msg_2);
        }

        let broadcast_mgs2 = QCBroadcastMsg2 {
            from_party: self.params.party_index as u8,
            r_1_i: self.rand_params.r1_i,
            big_p_i_poly: self.state.big_p_i_poly.coeffs.clone(),
        };

        let next_state = QCPartyOld {
            params: self.params,
            rand_params: self.rand_params,
            state: R2Old {
                sid_i_list,
                commitment_list,
                big_p_i_poly: self.state.big_p_i_poly,
            },
        };

        Ok((next_state, p2p_messages_1, p2p_messages_2, broadcast_mgs2))
    }
}

impl<G> Round for QCPartyOld<R2Old<G>, G>
where
    G: GroupElem,
{
    type Input = Vec<QCBroadcastMsg2<G>>;

    type Output = Result<(), QCError>;

    fn process(self, messages: Self::Input) -> Self::Output {
        if messages.len() != self.params.old_parties.len() {
            return Err(QCError::InvalidMsgCount);
        }
        let mut messages = messages;
        messages.sort_by_key(|msg| msg.from_party);

        let messages = messages
            .iter()
            .all(|msg| self.params.old_parties.contains(&(msg.from_party as usize)))
            .then_some(messages)
            .ok_or(QCError::InvalidParticipantSet)?;

        let mut r1_j_list = Pairs::new();
        let mut big_p_j_poly_list = Pairs::new();

        for message in &messages {
            if message.from_party as usize == self.params.party_index {
                let cond1 = self.rand_params.r1_i == message.r_1_i;
                let cond2 = self.state.big_p_i_poly.coeffs == message.big_p_i_poly;
                if !(cond1 && cond2) {
                    return Err(QCError::InvalidMessage);
                }
            }
            r1_j_list.push(message.from_party as usize, message.r_1_i);
            big_p_j_poly_list.push(message.from_party as usize, message.big_p_i_poly.clone());
        }

        // checks for old party
        for &old_party_index in self.params.old_parties.iter() {
            let r1_j = r1_j_list.find_pair_or_err(old_party_index, QCError::InvalidMessage)?;
            let sid_j = &self.state.sid_i_list[old_party_index];
            let commitment1 = &self.state.commitment_list[old_party_index];
            let big_p_i_poly =
                big_p_j_poly_list.find_pair_or_err(old_party_index, QCError::InvalidMessage)?;

            if big_p_i_poly.len() != self.params.new_t as usize {
                return Err(QCError::InvalidMessage);
            }

            if big_p_i_poly.iter().any(|p| p.is_identity().into()) {
                return Err(QCError::InvalidMessage);
            }

            let commit_hash1 = hash_commitment_1(sid_j, old_party_index, big_p_i_poly, r1_j);
            if commit_hash1.ct_ne(commitment1).into() {
                return Err(QCError::InvalidCommitmentHash);
            }
        }

        let mut big_p_vec = GroupPolynomial::identity(self.params.new_t as usize);
        for (_, v) in &big_p_j_poly_list {
            big_p_vec.add_mut(v); // big_f_vec += v;
        }

        if big_p_vec.get_constant() != self.params.public_key {
            return Err(QCError::PublicKeyMismatch);
        }

        Ok(())
    }
}

impl<G> QCPartyOldToNew<R0, G>
where
    G: Group + GroupEncoding,
{
    /// Create a new QC party for old to new participant.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        total_parties: u8,
        new_t: u8,
        party_index: usize,
        old_parties: Vec<usize>,
        new_parties: Vec<usize>,
        old_party_ids: Vec<(usize, u8)>,
        old_keyshare: &Keyshare<G>,
        key_id: Option<[u8; 32]>,
        seed: [u8; 32],
        extra_data: Option<Vec<u8>>,
    ) -> Result<Self, QCError> {
        let mut old_party_id_pairs = Pairs::new();
        for (party_index, party_id) in old_party_ids {
            old_party_id_pairs.push(party_index, party_id);
        }

        let mut rng = ChaCha20Rng::from_seed(seed);

        // calculate additive share s_i_0 of participant_i,
        // \sum_{i=0}^{n-1} s_i_0 = private_key
        let s_i_0 = {
            assert!(old_parties.len() >= old_keyshare.threshold as usize);
            let old_party_id_list = old_party_id_pairs.remove_ids();
            old_keyshare.scalar_share_interpolate(old_party_id_list)
        };

        let rand_params = QCEntropyOld::generate(new_t, s_i_0, &new_parties, &mut rng);

        if new_t < 2 {
            return Err(QCError::InvalidT);
        }

        Ok(Self {
            params: QCParams {
                total_parties,
                new_t,
                party_index,
                new_parties,
                old_parties,
                old_party_ids: old_party_id_pairs,
                public_key: old_keyshare.public_key,
                key_id,
                extra_data,
            },
            party_id: old_keyshare.party_id,
            rand_params,
            state: R0,
        })
    }
}

impl<G: GroupElem> Round for QCPartyOldToNew<R0, G> {
    type Input = ();

    type Output = Result<(QCPartyOldToNew<R1Old<G>, G>, QCBroadcastMsg1), QCError>;

    /// Creates first broadcast message
    fn process(self, _: ()) -> Self::Output {
        let sid_i = self.rand_params.sid_i;
        let big_p_i_poly = self.rand_params.polynomial.commit();
        let r1_i = self.rand_params.r1_i;

        let commitment_1 = hash_commitment_1(&sid_i, self.params.party_index, &big_p_i_poly, &r1_i);

        let broadcast_msg1 = QCBroadcastMsg1 {
            from_party: self.params.party_index as u8,
            sid_i,
            commitment_1,
        };

        let next_state = QCPartyOldToNew {
            params: self.params,
            party_id: self.party_id,
            rand_params: self.rand_params,
            state: R1Old {
                big_p_i_poly,
                commitment_1,
            },
        };

        Ok((next_state, broadcast_msg1))
    }
}

impl<G: GroupElem> Round for QCPartyOldToNew<R1Old<G>, G>
where
    G: GroupElem,
{
    type Input = Vec<QCBroadcastMsg1>;

    type Output = Result<(QCPartyOldToNew<R2OldToNew<G>, G>, Vec<QCP2PMsg1>), QCError>;

    /// Processes BroadcastMsg1 and creates p2p commitment2
    fn process(self, messages: Self::Input) -> Self::Output {
        let total_parties = self.params.total_parties as usize;
        if messages.len() != total_parties {
            return Err(QCError::InvalidMsgCount);
        }
        let mut messages = messages;
        messages.sort_by_key(|msg| msg.from_party);

        let messages = messages
            .iter()
            .enumerate()
            .all(|(pid, msg)| msg.from_party as usize == pid)
            .then_some(messages)
            .ok_or(QCError::InvalidParticipantSet)?;

        let mut sid_i_list = Vec::with_capacity(total_parties);
        let mut commitment_list = Vec::with_capacity(total_parties);

        for message in &messages {
            if message.from_party as usize == self.params.party_index {
                let cond1 = self.rand_params.sid_i == message.sid_i;
                let cond2 = self.state.commitment_1 == message.commitment_1;
                if !(cond1 && cond2) {
                    return Err(QCError::InvalidMessage);
                }
            }
            sid_i_list.push(message.sid_i);
            commitment_list.push(message.commitment_1);
        }

        let final_session_id: [u8; 32] = sid_i_list
            .iter()
            .fold(Sha256::new(), |hash, sid| hash.chain_update(sid))
            .finalize()
            .into();

        let new_n = self.params.new_parties.len();
        let new_x_i_list: Vec<G::Scalar> = (1..=new_n as u64).map(G::Scalar::from).collect();

        // For old to new party
        let mut p_i_list: Pairs<G::Scalar, u8> = Pairs::new();
        let my_old_party_id = self.party_id;
        let my_new_party_id =
            new_party_id(&self.params.new_parties, self.params.party_index).unwrap();
        let x_i = new_x_i_list[my_new_party_id as usize];
        let p_i_i = self.rand_params.polynomial.evaluate_at(&x_i);
        p_i_list.push(my_old_party_id, p_i_i);

        // blind commitment2 values for receiver_ids
        let mut p_i_j_list: Pairs<G::Scalar, u8> = Pairs::new();

        let mut p2p_messages_1 = Vec::with_capacity(self.params.new_parties.len());
        for &receiver_index in self.params.new_parties.iter() {
            if receiver_index == self.params.party_index {
                continue;
            }

            let receiver_id = new_party_id(&self.params.new_parties, receiver_index).unwrap();

            let r2_j = self.rand_params.r2_j_list.find_pair(receiver_id);

            let x_j = new_x_i_list[receiver_id as usize];
            let p_i_j = self.rand_params.polynomial.evaluate_at(&x_j);
            p_i_j_list.push(receiver_id, p_i_j);

            let commitment_2 = hash_commitment_2::<G>(
                &final_session_id,
                self.params.party_index,
                receiver_index,
                &p_i_j,
                r2_j,
            );

            let p2p_msg_1 = QCP2PMsg1 {
                from_party: self.params.party_index as u8,
                to_party: receiver_index as u8,
                commitment_2,
            };
            p2p_messages_1.push(p2p_msg_1);
        }

        let next_state = QCPartyOldToNew {
            params: self.params,
            party_id: self.party_id,
            rand_params: self.rand_params,
            state: R2OldToNew {
                final_session_id,
                sid_i_list,
                commitment_list,
                big_p_i_poly: self.state.big_p_i_poly,
                new_x_i_list,
                p_i_list,
                p_i_j_list,
            },
        };

        Ok((next_state, p2p_messages_1))
    }
}

impl<G: GroupElem> Round for QCPartyOldToNew<R2OldToNew<G>, G>
where
    G: GroupElem,
{
    type Input = Vec<QCP2PMsg1>;

    type Output = Result<
        (
            QCPartyOldToNew<R3OldToNew<G>, G>,
            Vec<QCP2PMsg2<G>>,
            QCBroadcastMsg2<G>,
        ),
        QCError,
    >;

    /// Collects commitment_2 from (all old parties - 1)
    /// and creates p2p decommit2 and BroadcastMsg2
    fn process(self, messages: Self::Input) -> Self::Output {
        if messages.len() != (self.params.old_parties.len() - 1) {
            return Err(QCError::InvalidMsgCount);
        }
        let mut p2p_messages = messages;
        p2p_messages.sort_by_key(|msg| msg.from_party);

        // new_party collects (all - 1) commitments2 from old parties
        let mut commitment2_list: Pairs<HashBytes, u8> = Pairs::new();
        for message in &p2p_messages {
            if message.to_party as usize != self.params.party_index {
                return Err(QCError::InvalidMessage);
            }
            let from_party_index = message.from_party as usize;
            let from_party_id = *self
                .params
                .old_party_ids
                .find_pair_or_err(from_party_index, QCError::InvalidMessage)?;
            commitment2_list.push(from_party_id, message.commitment_2);
        }
        if commitment2_list.remove_ids().len() != (self.params.old_parties.len() - 1) {
            return Err(QCError::InvalidMessage);
        }

        let mut p2p_messages_2 = Vec::with_capacity(self.params.new_parties.len());
        for &receiver_index in self.params.new_parties.iter() {
            if receiver_index == self.params.party_index {
                continue;
            }

            let receiver_id = new_party_id(&self.params.new_parties, receiver_index).unwrap();

            let r2_j = self.rand_params.r2_j_list.find_pair(receiver_id);
            let p_i_j = self.state.p_i_j_list.find_pair(receiver_id);

            let p2p_msg_2 = QCP2PMsg2 {
                from_party: self.params.party_index as u8,
                to_party: receiver_index as u8,
                p_i: *p_i_j,
                r_2_i: *r2_j,
                root_chain_code: [0u8; 32],
            };
            p2p_messages_2.push(p2p_msg_2);
        }

        let broadcast_mgs2 = QCBroadcastMsg2 {
            from_party: self.params.party_index as u8,
            r_1_i: self.rand_params.r1_i,
            big_p_i_poly: self.state.big_p_i_poly.coeffs.clone(),
        };

        let next_state = QCPartyOldToNew {
            params: self.params,
            party_id: self.party_id,
            rand_params: self.rand_params,
            state: R3OldToNew {
                final_session_id: self.state.final_session_id,
                sid_i_list: self.state.sid_i_list,
                commitment_list: self.state.commitment_list,
                commitment2_list,
                big_p_i_poly: self.state.big_p_i_poly,
                new_x_i_list: self.state.new_x_i_list,
                p_i_list: self.state.p_i_list,
            },
        };

        Ok((next_state, p2p_messages_2, broadcast_mgs2))
    }
}

impl<G: GroupElem> Round for QCPartyOldToNew<R3OldToNew<G>, G>
where
    G: GroupElem,
{
    type Input = (Vec<QCP2PMsg2<G>>, Vec<QCBroadcastMsg2<G>>);

    type Output = Result<Keyshare<G>, QCError>;

    /// Processes decomit_2 and BroadcastMsg2 from old parties
    fn process(self, messages: Self::Input) -> Self::Output {
        let (mut p2p_messages, mut broadcast_msgs_2) = messages;

        if p2p_messages.len() != (self.params.old_parties.len() - 1) {
            return Err(QCError::InvalidMsgCount);
        }
        if broadcast_msgs_2.len() != self.params.old_parties.len() {
            return Err(QCError::InvalidMsgCount);
        }

        p2p_messages.sort_by_key(|msg| msg.from_party);
        broadcast_msgs_2.sort_by_key(|msg| msg.from_party);

        let mut p_i_list = self.state.p_i_list;
        let mut root_chain_code_list = Pairs::new_with_item(self.party_id, [0u8; 32]);

        for p2p_msg2 in &p2p_messages {
            if p2p_msg2.to_party as usize != self.params.party_index {
                return Err(QCError::InvalidMessage);
            }
            let from_party_index = p2p_msg2.from_party as usize;
            let from_party_id = *self
                .params
                .old_party_ids
                .find_pair_or_err(from_party_index, QCError::InvalidMessage)?;

            let p_j_i = p2p_msg2.p_i;
            let r_2_i = p2p_msg2.r_2_i;

            let commitment2 = self.state.commitment2_list.find_pair(from_party_id);
            let commit_hash_2 = hash_commitment_2::<G>(
                &self.state.final_session_id,
                from_party_index,
                self.params.party_index,
                &p_j_i,
                &r_2_i,
            );

            if commit_hash_2.ct_ne(commitment2).into() {
                return Err(QCError::InvalidCommitmentHash);
            }

            p_i_list.push(from_party_id, p_j_i);

            root_chain_code_list.push(from_party_id, p2p_msg2.root_chain_code);
        }
        if p_i_list.remove_ids().len() != self.params.old_parties.len() {
            return Err(QCError::InvalidMessage);
        }

        let mut r1_j_list = Pairs::new();
        let mut big_p_j_poly_list = Pairs::new();

        for message in &broadcast_msgs_2 {
            if message.from_party as usize == self.params.party_index {
                let cond1 = self.rand_params.r1_i == message.r_1_i;
                let cond2 = self.state.big_p_i_poly.coeffs == message.big_p_i_poly;
                if !(cond1 && cond2) {
                    return Err(QCError::InvalidMessage);
                }
            }
            r1_j_list.push(message.from_party as usize, message.r_1_i);
            big_p_j_poly_list.push(message.from_party as usize, message.big_p_i_poly.clone());
        }

        // checks for old party
        for &old_party_index in self.params.old_parties.iter() {
            let r1_j = r1_j_list.find_pair_or_err(old_party_index, QCError::InvalidMessage)?;
            let sid_j = &self.state.sid_i_list[old_party_index];
            let commitment1 = &self.state.commitment_list[old_party_index];
            let big_p_i_poly =
                big_p_j_poly_list.find_pair_or_err(old_party_index, QCError::InvalidMessage)?;

            if big_p_i_poly.len() != self.params.new_t as usize {
                return Err(QCError::InvalidMessage);
            }

            if big_p_i_poly.iter().any(|p| p.is_identity().into()) {
                return Err(QCError::InvalidMessage);
            }

            let commit_hash1 = hash_commitment_1(sid_j, old_party_index, big_p_i_poly, r1_j);
            if commit_hash1.ct_ne(commitment1).into() {
                return Err(QCError::InvalidCommitmentHash);
            }
        }

        let mut big_p_poly = GroupPolynomial::identity(self.params.new_t as usize);

        // sort by old_party_id
        let mut big_p_j_poly_list_sorted_by_old_id = Pairs::new();
        for &old_party_index in self.params.old_parties.iter() {
            let old_party_id = self.params.old_party_ids.find_pair(old_party_index);
            big_p_j_poly_list_sorted_by_old_id.push(
                *old_party_id,
                big_p_j_poly_list.find_pair(old_party_index).clone(),
            );
        }

        let big_p_j_poly_list = big_p_j_poly_list_sorted_by_old_id.remove_ids();
        let big_p_j_poly_list = big_p_j_poly_list
            .into_iter()
            .map(|v| GroupPolynomial::new(v))
            .collect::<Vec<_>>();

        let p_i_list = p_i_list.remove_ids();
        for v in &big_p_j_poly_list {
            big_p_poly.add_mut(v); // big_f_vec += v;
        }

        if big_p_j_poly_list.len() != p_i_list.len() {
            return Err(QCError::FailedFeldmanVerify);
        }

        let my_new_party_id =
            new_party_id(&self.params.new_parties, self.params.party_index).unwrap();

        let x_i = self.state.new_x_i_list[my_new_party_id as usize];

        // check that P_j(x_i) = p_j_i * G
        for (big_p_j, p_j_i) in big_p_j_poly_list.iter().zip(&p_i_list) {
            let big_p_j_i = G::generator() * p_j_i;
            let calc_point = big_p_j.evaluate_at(&x_i);
            if !bool::from(big_p_j_i.ct_eq(&calc_point)) {
                return Err(QCError::FailedFeldmanVerify);
            }
        }

        let p_i: G::Scalar = p_i_list.iter().sum();

        // check if p_i is correct, P(x_i) = p_i * G
        let big_p_i = G::generator() * p_i;
        let calc_point = big_p_poly.evaluate_at(&x_i);
        if !bool::from(big_p_i.ct_eq(&calc_point)) {
            return Err(QCError::FailedFeldmanVerify);
        }

        let public_key = big_p_poly.get_constant();
        if public_key != self.params.public_key {
            return Err(QCError::PublicKeyMismatch);
        }

        let key_id = if let Some(key_id) = self.params.key_id {
            key_id
        } else {
            sha2::Sha256::digest(public_key.to_bytes()).into()
        };

        let keyshare = Keyshare {
            threshold: self.params.new_t,
            total_parties: self.params.new_parties.len() as u8,
            party_id: my_new_party_id,
            key_id,
            d_i: p_i,
            public_key,
            extra_data: self.params.extra_data,
        };
        Ok(keyshare)
    }
}

impl<G> QCPartyNew<R0, G>
where
    G: Group,
{
    /// Create a new QC party for new participant.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        total_parties: u8,
        new_t: u8,
        party_index: usize,
        old_parties: Vec<usize>,
        new_parties: Vec<usize>,
        old_party_ids: Vec<(usize, u8)>,
        expected_public_key: G,
        key_id: Option<[u8; 32]>,
        seed: [u8; 32],
        extra_data: Option<Vec<u8>>,
    ) -> Result<Self, QCError> {
        let mut old_party_id_pairs = Pairs::new();
        for (party_index, party_id) in old_party_ids {
            old_party_id_pairs.push(party_index, party_id);
        }

        let mut rng = ChaCha20Rng::from_seed(seed);
        let rand_params = QCEntropyNew::generate(&mut rng);

        assert!(!old_parties.contains(&party_index));
        assert!(new_parties.contains(&party_index));

        if new_t < 2 {
            return Err(QCError::InvalidT);
        }

        Ok(Self {
            params: QCParams {
                total_parties,
                new_t,
                party_index,
                new_parties,
                old_parties,
                old_party_ids: old_party_id_pairs,
                public_key: expected_public_key,
                key_id,
                extra_data,
            },
            rand_params,
            state: R0,
        })
    }
}

impl<G: GroupElem> Round for QCPartyNew<R0, G> {
    type Input = ();

    type Output = Result<(QCPartyNew<R1New, G>, QCBroadcastMsg1), QCError>;

    /// Creates first broadcast message
    fn process(self, _: ()) -> Self::Output {
        let broadcast_msg1 = QCBroadcastMsg1 {
            from_party: self.params.party_index as u8,
            sid_i: self.rand_params.sid_i,
            commitment_1: [0u8; 32],
        };

        let next_state = QCPartyNew {
            params: self.params,
            rand_params: self.rand_params,
            state: R1New,
        };

        Ok((next_state, broadcast_msg1))
    }
}

impl<G: GroupElem> Round for QCPartyNew<R1New, G>
where
    G: GroupElem,
{
    type Input = Vec<QCBroadcastMsg1>;

    type Output = Result<QCPartyNew<R2New, G>, QCError>;

    /// Processes BroadcastMsg1
    fn process(self, messages: Self::Input) -> Self::Output {
        let total_parties = self.params.total_parties as usize;
        if messages.len() != total_parties {
            return Err(QCError::InvalidMsgCount);
        }
        let mut messages = messages;
        messages.sort_by_key(|msg| msg.from_party);

        let messages = messages
            .iter()
            .enumerate()
            .all(|(pid, msg)| msg.from_party as usize == pid)
            .then_some(messages)
            .ok_or(QCError::InvalidParticipantSet)?;

        let mut sid_i_list = Vec::with_capacity(total_parties);
        let mut commitment_list = Vec::with_capacity(total_parties);

        for message in &messages {
            if message.from_party as usize == self.params.party_index {
                let cond1 = self.rand_params.sid_i == message.sid_i;
                let cond2 = message.commitment_1 == [0u8; 32];
                if !(cond1 && cond2) {
                    return Err(QCError::InvalidMessage);
                }
            }
            sid_i_list.push(message.sid_i);
            commitment_list.push(message.commitment_1);
        }

        let final_session_id: [u8; 32] = sid_i_list
            .iter()
            .fold(Sha256::new(), |hash, sid| hash.chain_update(sid))
            .finalize()
            .into();

        let next_state = QCPartyNew {
            params: self.params,
            rand_params: self.rand_params,
            state: R2New {
                final_session_id,
                sid_i_list,
                commitment_list,
            },
        };

        Ok(next_state)
    }
}

impl<G: GroupElem> Round for QCPartyNew<R2New, G>
where
    G: GroupElem,
{
    type Input = Vec<QCP2PMsg1>;

    type Output = Result<QCPartyNew<R3New, G>, QCError>;

    /// Collects commitment_2 from all old parties
    fn process(self, messages: Self::Input) -> Self::Output {
        if messages.len() != self.params.old_parties.len() {
            return Err(QCError::InvalidMsgCount);
        }
        let mut p2p_messages = messages;
        p2p_messages.sort_by_key(|msg| msg.from_party);

        // new_party collects (all - 1) commitments2 from old parties
        let mut commitment2_list: Pairs<HashBytes, u8> = Pairs::new();
        for message in &p2p_messages {
            if message.to_party as usize != self.params.party_index {
                return Err(QCError::InvalidMessage);
            }
            let from_party_index = message.from_party as usize;
            let from_party_id = *self
                .params
                .old_party_ids
                .find_pair_or_err(from_party_index, QCError::InvalidMessage)?;
            commitment2_list.push(from_party_id, message.commitment_2);
        }
        if commitment2_list.remove_ids().len() != self.params.old_parties.len() {
            return Err(QCError::InvalidMessage);
        }

        let next_state = QCPartyNew {
            params: self.params,
            rand_params: self.rand_params,
            state: R3New {
                final_session_id: self.state.final_session_id,
                sid_i_list: self.state.sid_i_list,
                commitment_list: self.state.commitment_list,
                commitment2_list,
            },
        };

        Ok(next_state)
    }
}

impl<G: GroupElem> Round for QCPartyNew<R3New, G>
where
    G: GroupElem,
{
    type Input = (Vec<QCP2PMsg2<G>>, Vec<QCBroadcastMsg2<G>>);

    type Output = Result<Keyshare<G>, QCError>;

    /// Processes decomit_2 and BroadcastMsg2 from old parties
    fn process(self, messages: Self::Input) -> Self::Output {
        let (mut p2p_messages, mut broadcast_msgs_2) = messages;

        if p2p_messages.len() != self.params.old_parties.len() {
            return Err(QCError::InvalidMsgCount);
        }
        if broadcast_msgs_2.len() != self.params.old_parties.len() {
            return Err(QCError::InvalidMsgCount);
        }

        p2p_messages.sort_by_key(|msg| msg.from_party);
        broadcast_msgs_2.sort_by_key(|msg| msg.from_party);

        let mut p_i_list: Pairs<G::Scalar, u8> = Pairs::new();
        let mut root_chain_code_list = Pairs::new();

        for p2p_msg2 in &p2p_messages {
            if p2p_msg2.to_party as usize != self.params.party_index {
                return Err(QCError::InvalidMessage);
            }
            let from_party_index = p2p_msg2.from_party as usize;
            let from_party_id = *self
                .params
                .old_party_ids
                .find_pair_or_err(from_party_index, QCError::InvalidMessage)?;

            let p_j_i = p2p_msg2.p_i;
            let r_2_i = p2p_msg2.r_2_i;

            let commitment2 = self.state.commitment2_list.find_pair(from_party_id);
            let commit_hash_2 = hash_commitment_2::<G>(
                &self.state.final_session_id,
                from_party_index,
                self.params.party_index,
                &p_j_i,
                &r_2_i,
            );

            if commit_hash_2.ct_ne(commitment2).into() {
                return Err(QCError::InvalidCommitmentHash);
            }

            p_i_list.push(from_party_id, p_j_i);

            root_chain_code_list.push(from_party_id, p2p_msg2.root_chain_code);
        }
        if p_i_list.remove_ids().len() != self.params.old_parties.len() {
            return Err(QCError::InvalidMessage);
        }

        let mut r1_j_list = Pairs::new();
        let mut big_p_j_poly_list = Pairs::new();

        for message in &broadcast_msgs_2 {
            r1_j_list.push(message.from_party as usize, message.r_1_i);
            big_p_j_poly_list.push(message.from_party as usize, message.big_p_i_poly.clone());
        }

        // checks
        for &old_party_index in self.params.old_parties.iter() {
            let r1_j = r1_j_list.find_pair_or_err(old_party_index, QCError::InvalidMessage)?;
            let sid_j = &self.state.sid_i_list[old_party_index];
            let commitment1 = &self.state.commitment_list[old_party_index];
            let big_p_i_poly =
                big_p_j_poly_list.find_pair_or_err(old_party_index, QCError::InvalidMessage)?;

            if big_p_i_poly.len() != self.params.new_t as usize {
                return Err(QCError::InvalidMessage);
            }

            if big_p_i_poly.iter().any(|p| p.is_identity().into()) {
                return Err(QCError::InvalidMessage);
            }

            let commit_hash1 = hash_commitment_1(sid_j, old_party_index, big_p_i_poly, r1_j);
            if commit_hash1.ct_ne(commitment1).into() {
                return Err(QCError::InvalidCommitmentHash);
            }
        }

        let mut big_p_poly = GroupPolynomial::identity(self.params.new_t as usize);

        // sort by old_party_id
        let mut big_p_j_poly_list_sorted_by_old_id = Pairs::new();
        for &old_party_index in self.params.old_parties.iter() {
            let old_party_id = self.params.old_party_ids.find_pair(old_party_index);
            big_p_j_poly_list_sorted_by_old_id.push(
                *old_party_id,
                big_p_j_poly_list.find_pair(old_party_index).clone(),
            );
        }

        let big_p_j_poly_list = big_p_j_poly_list_sorted_by_old_id.remove_ids();
        let big_p_j_poly_list = big_p_j_poly_list
            .into_iter()
            .map(|v| GroupPolynomial::new(v))
            .collect::<Vec<_>>();

        let p_i_list = p_i_list.remove_ids();
        for v in &big_p_j_poly_list {
            big_p_poly.add_mut(v); // big_f_vec += v;
        }

        if big_p_j_poly_list.len() != p_i_list.len() {
            return Err(QCError::FailedFeldmanVerify);
        }

        let my_new_party_id =
            new_party_id(&self.params.new_parties, self.params.party_index).unwrap();

        let x_i = G::Scalar::from((my_new_party_id + 1) as u64);

        // check that P_j(x_i) = p_j_i * G
        for (big_p_j, p_j_i) in big_p_j_poly_list.iter().zip(&p_i_list) {
            let big_p_j_i = G::generator() * p_j_i;
            let calc_point = big_p_j.evaluate_at(&x_i);
            if !bool::from(big_p_j_i.ct_eq(&calc_point)) {
                return Err(QCError::FailedFeldmanVerify);
            }
        }

        let p_i: G::Scalar = p_i_list.iter().sum();

        // check if p_i is correct, P(x_i) = p_i * G
        let big_p_i = G::generator() * p_i;
        let calc_point = big_p_poly.evaluate_at(&x_i);
        if !bool::from(big_p_i.ct_eq(&calc_point)) {
            return Err(QCError::FailedFeldmanVerify);
        }

        let public_key = big_p_poly.get_constant();
        if public_key != self.params.public_key {
            return Err(QCError::PublicKeyMismatch);
        }

        let key_id = if let Some(key_id) = self.params.key_id {
            key_id
        } else {
            sha2::Sha256::digest(public_key.to_bytes()).into()
        };

        let keyshare = Keyshare {
            threshold: self.params.new_t,
            total_parties: self.params.new_parties.len() as u8,
            party_id: my_new_party_id,
            key_id,
            d_i: p_i,
            public_key,
            extra_data: self.params.extra_data,
        };
        Ok(keyshare)
    }
}

fn hash_commitment_1<G>(
    session_id: &[u8],
    party_index: usize,
    big_f_i_vec: &[G],
    r1_i: &[u8; 32],
) -> [u8; 32]
where
    G: GroupElem,
{
    let mut hasher = Sha256::new()
        .chain_update(QC_LABEL)
        .chain_update(QC_COMMITMENT_1_LABEL)
        .chain_update(session_id)
        .chain_update((party_index as u64).to_be_bytes());
    for point in big_f_i_vec.iter() {
        sha2::Digest::update(&mut hasher, point.to_bytes());
    }
    sha2::Digest::update(&mut hasher, r1_i);
    sha2::Digest::update(&mut hasher, r1_i);
    hasher.finalize().into()
}

fn hash_commitment_2<G>(
    session_id: &[u8],
    from_party_i_index: usize,
    to_party_j_index: usize,
    p_i_j: &G::Scalar,
    r2_i: &[u8; 32],
) -> [u8; 32]
where
    G: GroupElem,
{
    let mut hasher = Sha256::new()
        .chain_update(QC_LABEL)
        .chain_update(QC_COMMITMENT_2_LABEL)
        .chain_update(session_id)
        .chain_update((from_party_i_index as u64).to_be_bytes())
        .chain_update((to_party_j_index as u64).to_be_bytes());
    sha2::Digest::update(&mut hasher, p_i_j.to_repr().as_ref());
    sha2::Digest::update(&mut hasher, r2_i);
    hasher.finalize().into()
}

/// return new_party_id by party_index
pub fn new_party_id(new_party_indices: &[usize], index: usize) -> Option<u8> {
    new_party_indices
        .iter()
        .position(|p| p == &index)
        .map(|p| p as u8)
}

#[cfg(test)]
mod test {
    use crate::common::traits::Round;
    use crate::common::utils::run_keygen;
    use crate::group::Group;
    use crate::quorum_change::qc::{QCPartyNew, QCPartyOld, QCPartyOldToNew};
    use curve25519_dalek::EdwardsPoint;
    use k256::ProjectivePoint;
    use rand::Rng;

    #[test]
    fn quorum_change_all_new() {
        let mut rng = rand::thread_rng();

        let [old_keyshare_p0, old_keyshare_p1] = run_keygen::<2, 2, EdwardsPoint>();
        let expected_public_key = old_keyshare_p0.public_key;

        // test for unordered case
        let total_parties = 5;
        let new_t = 3;
        let new_n = 3;
        let old_parties = vec![0, 2];
        let new_parties = vec![1, 3, 4];
        let old_party_ids = vec![(0, 0), (2, 1)];

        let old_party_p0 = QCPartyOld::new(
            total_parties,
            new_t,
            0,
            old_parties.clone(),
            new_parties.clone(),
            old_party_ids.clone(),
            &old_keyshare_p0,
            None,
            rng.gen(),
            None,
        )
        .unwrap();

        let old_party_p1 = QCPartyOld::new(
            total_parties,
            new_t,
            2,
            old_parties.clone(),
            new_parties.clone(),
            old_party_ids.clone(),
            &old_keyshare_p1,
            None,
            rng.gen(),
            None,
        )
        .unwrap();

        let new_party_p2 = QCPartyNew::new(
            total_parties,
            new_t,
            1,
            old_parties.clone(),
            new_parties.clone(),
            old_party_ids.clone(),
            expected_public_key,
            None,
            rng.gen(),
            None,
        )
        .unwrap();

        let new_party_p3 = QCPartyNew::new(
            total_parties,
            new_t,
            3,
            old_parties.clone(),
            new_parties.clone(),
            old_party_ids.clone(),
            expected_public_key,
            None,
            rng.gen(),
            None,
        )
        .unwrap();

        let new_party_p4 = QCPartyNew::new(
            total_parties,
            new_t,
            4,
            old_parties.clone(),
            new_parties.clone(),
            old_party_ids.clone(),
            expected_public_key,
            None,
            rng.gen(),
            None,
        )
        .unwrap();

        // run protocol
        let (old_party_p0, msg1_p0) = old_party_p0.process(()).unwrap();
        let (old_party_p1, msg1_p1) = old_party_p1.process(()).unwrap();
        let (new_party_p2, msg1_p2) = new_party_p2.process(()).unwrap();
        let (new_party_p3, msg1_p3) = new_party_p3.process(()).unwrap();
        let (new_party_p4, msg1_p4) = new_party_p4.process(()).unwrap();

        let broadcast_messages_1 = vec![msg1_p0, msg1_p1, msg1_p2, msg1_p3, msg1_p4];

        let (old_party_p0, p2p_msg1_from_p0, p2p_msg2_from_p0, broadcast_msg2_p0) =
            old_party_p0.process(broadcast_messages_1.clone()).unwrap();
        let (old_party_p1, p2p_msg1_from_p1, p2p_msg2_from_p1, broadcast_msg2_p1) =
            old_party_p1.process(broadcast_messages_1.clone()).unwrap();
        let new_party_p2 = new_party_p2.process(broadcast_messages_1.clone()).unwrap();
        let new_party_p3 = new_party_p3.process(broadcast_messages_1.clone()).unwrap();
        let new_party_p4 = new_party_p4.process(broadcast_messages_1.clone()).unwrap();

        let broadcast_messages_2 = vec![broadcast_msg2_p0, broadcast_msg2_p1];
        old_party_p0.process(broadcast_messages_2.clone()).unwrap();
        old_party_p1.process(broadcast_messages_2.clone()).unwrap();

        let mut p2p_messages_1_to_p2 = vec![];
        let mut p2p_messages_1_to_p3 = vec![];
        let mut p2p_messages_1_to_p4 = vec![];
        // collect
        for msg in p2p_msg1_from_p0 {
            let to_party_index = msg.to_party as usize;
            if to_party_index == 1 {
                p2p_messages_1_to_p2.push(msg.clone())
            }
            if to_party_index == 3 {
                p2p_messages_1_to_p3.push(msg.clone())
            }
            if to_party_index == 4 {
                p2p_messages_1_to_p4.push(msg.clone())
            }
        }
        for msg in p2p_msg1_from_p1 {
            let to_party_index = msg.to_party as usize;
            if to_party_index == 1 {
                p2p_messages_1_to_p2.push(msg.clone())
            }
            if to_party_index == 3 {
                p2p_messages_1_to_p3.push(msg.clone())
            }
            if to_party_index == 4 {
                p2p_messages_1_to_p4.push(msg.clone())
            }
        }

        let new_party_p2 = new_party_p2.process(p2p_messages_1_to_p2).unwrap();
        let new_party_p3 = new_party_p3.process(p2p_messages_1_to_p3).unwrap();
        let new_party_p4 = new_party_p4.process(p2p_messages_1_to_p4).unwrap();

        let mut p2p_messages_2_to_p2 = vec![];
        let mut p2p_messages_2_to_p3 = vec![];
        let mut p2p_messages_2_to_p4 = vec![];
        // collect
        for msg in p2p_msg2_from_p0 {
            let to_party_index = msg.to_party as usize;
            if to_party_index == 1 {
                p2p_messages_2_to_p2.push(msg.clone())
            }
            if to_party_index == 3 {
                p2p_messages_2_to_p3.push(msg.clone())
            }
            if to_party_index == 4 {
                p2p_messages_2_to_p4.push(msg.clone())
            }
        }
        for msg in p2p_msg2_from_p1 {
            let to_party_index = msg.to_party as usize;
            if to_party_index == 1 {
                p2p_messages_2_to_p2.push(msg.clone())
            }
            if to_party_index == 3 {
                p2p_messages_2_to_p3.push(msg.clone())
            }
            if to_party_index == 4 {
                p2p_messages_2_to_p4.push(msg.clone())
            }
        }

        let new_keyshare_p2 = new_party_p2
            .process((p2p_messages_2_to_p2, broadcast_messages_2.clone()))
            .unwrap();
        let new_keyshare_p3 = new_party_p3
            .process((p2p_messages_2_to_p3, broadcast_messages_2.clone()))
            .unwrap();
        let new_keyshare_p4 = new_party_p4
            .process((p2p_messages_2_to_p4, broadcast_messages_2.clone()))
            .unwrap();

        assert_eq!(new_keyshare_p2.threshold, new_t);
        assert_eq!(new_keyshare_p3.threshold, new_t);
        assert_eq!(new_keyshare_p4.threshold, new_t);

        assert_eq!(new_keyshare_p2.total_parties, new_n);
        assert_eq!(new_keyshare_p3.total_parties, new_n);
        assert_eq!(new_keyshare_p4.total_parties, new_n);

        assert_eq!(new_keyshare_p2.party_id, 0);
        assert_eq!(new_keyshare_p3.party_id, 1);
        assert_eq!(new_keyshare_p4.party_id, 2);

        assert_eq!(new_keyshare_p2.public_key, expected_public_key);
        assert_eq!(new_keyshare_p3.public_key, expected_public_key);
        assert_eq!(new_keyshare_p4.public_key, expected_public_key);

        assert_eq!(new_keyshare_p2.key_id, new_keyshare_p3.key_id);
        assert_eq!(new_keyshare_p2.key_id, new_keyshare_p4.key_id);

        assert_eq!(new_keyshare_p2.extra_data, new_keyshare_p3.extra_data);
        assert_eq!(new_keyshare_p2.extra_data, new_keyshare_p4.extra_data);

        let d_2 = new_keyshare_p2.scalar_share();
        let d_3 = new_keyshare_p3.scalar_share();
        let d_4 = new_keyshare_p4.scalar_share();
        let public_key = EdwardsPoint::generator() * (d_2 + d_3 + d_4);
        assert_eq!(public_key, expected_public_key);
    }

    #[test]
    fn quorum_change_extend_parties() {
        let mut rng = rand::thread_rng();

        let [old_keyshare_p0, old_keyshare_p1] = run_keygen::<2, 2, EdwardsPoint>();
        let expected_public_key = old_keyshare_p0.public_key;

        // test for unordered case
        let total_parties = 3;
        let new_t = 2;
        let new_n = 3;
        let old_parties = vec![0, 1];
        let new_parties = vec![0, 1, 2];
        let old_party_ids = vec![(0, 1), (1, 0)];

        let old_party_p0 = QCPartyOldToNew::new(
            total_parties,
            new_t,
            0,
            old_parties.clone(),
            new_parties.clone(),
            old_party_ids.clone(),
            &old_keyshare_p1,
            None,
            rng.gen(),
            None,
        )
        .unwrap();

        let old_party_p1 = QCPartyOldToNew::new(
            total_parties,
            new_t,
            1,
            old_parties.clone(),
            new_parties.clone(),
            old_party_ids.clone(),
            &old_keyshare_p0,
            None,
            rng.gen(),
            None,
        )
        .unwrap();

        let new_party_p2 = QCPartyNew::new(
            total_parties,
            new_t,
            2,
            old_parties.clone(),
            new_parties.clone(),
            old_party_ids.clone(),
            expected_public_key,
            None,
            rng.gen(),
            None,
        )
        .unwrap();

        // run protocol
        let (old_party_p0, msg1_p0) = old_party_p0.process(()).unwrap();
        let (old_party_p1, msg1_p1) = old_party_p1.process(()).unwrap();
        let (new_party_p2, msg1_p2) = new_party_p2.process(()).unwrap();

        let broadcast_messages_1 = vec![msg1_p0, msg1_p1, msg1_p2];

        let (old_party_p0, p2p_msg1_from_p0) =
            old_party_p0.process(broadcast_messages_1.clone()).unwrap();
        let (old_party_p1, p2p_msg1_from_p1) =
            old_party_p1.process(broadcast_messages_1.clone()).unwrap();
        let new_party_p2 = new_party_p2.process(broadcast_messages_1.clone()).unwrap();

        let mut p2p_messages_1_to_p0 = vec![];
        let mut p2p_messages_1_to_p1 = vec![];
        let mut p2p_messages_1_to_p2 = vec![];
        // collect
        for msg in p2p_msg1_from_p0 {
            let to_party_index = msg.to_party as usize;
            if to_party_index == 1 {
                p2p_messages_1_to_p1.push(msg.clone())
            }
            if to_party_index == 2 {
                p2p_messages_1_to_p2.push(msg.clone())
            }
        }
        for msg in p2p_msg1_from_p1 {
            let to_party_index = msg.to_party as usize;
            if to_party_index == 0 {
                p2p_messages_1_to_p0.push(msg.clone())
            }
            if to_party_index == 2 {
                p2p_messages_1_to_p2.push(msg.clone())
            }
        }

        let (old_party_p0, p2p_msg2_from_p0, broadcast_msg2_p0) =
            old_party_p0.process(p2p_messages_1_to_p0).unwrap();
        let (old_party_p1, p2p_msg2_from_p1, broadcast_msg2_p1) =
            old_party_p1.process(p2p_messages_1_to_p1).unwrap();
        let new_party_p2 = new_party_p2.process(p2p_messages_1_to_p2).unwrap();

        let mut p2p_messages_2_to_p0 = vec![];
        let mut p2p_messages_2_to_p1 = vec![];
        let mut p2p_messages_2_to_p2 = vec![];
        // collect
        for msg in p2p_msg2_from_p0 {
            let to_party_index = msg.to_party as usize;
            if to_party_index == 1 {
                p2p_messages_2_to_p1.push(msg.clone())
            }
            if to_party_index == 2 {
                p2p_messages_2_to_p2.push(msg.clone())
            }
        }
        for msg in p2p_msg2_from_p1 {
            let to_party_index = msg.to_party as usize;
            if to_party_index == 0 {
                p2p_messages_2_to_p0.push(msg.clone())
            }
            if to_party_index == 2 {
                p2p_messages_2_to_p2.push(msg.clone())
            }
        }

        let broadcast_messages_2 = vec![broadcast_msg2_p0, broadcast_msg2_p1];

        let new_keyshare_p0 = old_party_p0
            .process((p2p_messages_2_to_p0, broadcast_messages_2.clone()))
            .unwrap();
        let new_keyshare_p1 = old_party_p1
            .process((p2p_messages_2_to_p1, broadcast_messages_2.clone()))
            .unwrap();
        let new_keyshare_p2 = new_party_p2
            .process((p2p_messages_2_to_p2, broadcast_messages_2.clone()))
            .unwrap();

        assert_eq!(new_keyshare_p0.threshold, new_t);
        assert_eq!(new_keyshare_p1.threshold, new_t);
        assert_eq!(new_keyshare_p2.threshold, new_t);

        assert_eq!(new_keyshare_p0.total_parties, new_n);
        assert_eq!(new_keyshare_p1.total_parties, new_n);
        assert_eq!(new_keyshare_p2.total_parties, new_n);

        assert_eq!(new_keyshare_p0.party_id, 0);
        assert_eq!(new_keyshare_p1.party_id, 1);
        assert_eq!(new_keyshare_p2.party_id, 2);

        assert_eq!(new_keyshare_p0.public_key, expected_public_key);
        assert_eq!(new_keyshare_p1.public_key, expected_public_key);
        assert_eq!(new_keyshare_p2.public_key, expected_public_key);

        assert_eq!(new_keyshare_p0.key_id, new_keyshare_p1.key_id);
        assert_eq!(new_keyshare_p0.key_id, new_keyshare_p2.key_id);

        assert_eq!(new_keyshare_p0.extra_data, new_keyshare_p1.extra_data);
        assert_eq!(new_keyshare_p0.extra_data, new_keyshare_p2.extra_data);

        let d_2 = new_keyshare_p0.scalar_share();
        let d_3 = new_keyshare_p1.scalar_share();
        let d_4 = new_keyshare_p2.scalar_share();
        let public_key = EdwardsPoint::generator() * (d_2 + d_3 + d_4);
        assert_eq!(public_key, expected_public_key);
    }

    #[test]
    fn quorum_change_only_change_threshold() {
        let mut rng = rand::thread_rng();

        let [old_keyshare_p0, old_keyshare_p1, old_keyshare_p2, old_keyshare_p3] =
            run_keygen::<2, 4, ProjectivePoint>();
        let expected_public_key = old_keyshare_p0.public_key;

        // test for unordered case
        let total_parties = 4;
        let new_t = 3;
        let new_n = 4;
        let old_parties = vec![0, 1, 2, 3];
        let new_parties = vec![0, 1, 2, 3];
        let old_party_ids = vec![(0, 0), (1, 1), (2, 2), (3, 3)];

        let old_party_p0 = QCPartyOldToNew::new(
            total_parties,
            new_t,
            0,
            old_parties.clone(),
            new_parties.clone(),
            old_party_ids.clone(),
            &old_keyshare_p0,
            None,
            rng.gen(),
            None,
        )
        .unwrap();

        let old_party_p1 = QCPartyOldToNew::new(
            total_parties,
            new_t,
            1,
            old_parties.clone(),
            new_parties.clone(),
            old_party_ids.clone(),
            &old_keyshare_p1,
            None,
            rng.gen(),
            None,
        )
        .unwrap();

        let old_party_p2 = QCPartyOldToNew::new(
            total_parties,
            new_t,
            2,
            old_parties.clone(),
            new_parties.clone(),
            old_party_ids.clone(),
            &old_keyshare_p2,
            None,
            rng.gen(),
            None,
        )
        .unwrap();

        let old_party_p3 = QCPartyOldToNew::new(
            total_parties,
            new_t,
            3,
            old_parties.clone(),
            new_parties.clone(),
            old_party_ids.clone(),
            &old_keyshare_p3,
            None,
            rng.gen(),
            None,
        )
        .unwrap();

        // run protocol
        let (old_party_p0, msg1_p0) = old_party_p0.process(()).unwrap();
        let (old_party_p1, msg1_p1) = old_party_p1.process(()).unwrap();
        let (old_party_p2, msg1_p2) = old_party_p2.process(()).unwrap();
        let (old_party_p3, msg1_p3) = old_party_p3.process(()).unwrap();

        let broadcast_messages_1 = vec![msg1_p0, msg1_p1, msg1_p2, msg1_p3];

        let (old_party_p0, p2p_msg1_from_p0) =
            old_party_p0.process(broadcast_messages_1.clone()).unwrap();
        let (old_party_p1, p2p_msg1_from_p1) =
            old_party_p1.process(broadcast_messages_1.clone()).unwrap();
        let (old_party_p2, p2p_msg1_from_p2) =
            old_party_p2.process(broadcast_messages_1.clone()).unwrap();
        let (old_party_p3, p2p_msg1_from_p3) =
            old_party_p3.process(broadcast_messages_1.clone()).unwrap();

        let mut p2p_messages_1_to_p0 = vec![];
        let mut p2p_messages_1_to_p1 = vec![];
        let mut p2p_messages_1_to_p2 = vec![];
        let mut p2p_messages_1_to_p3 = vec![];
        // collect
        for msg in p2p_msg1_from_p0 {
            let to_party_index = msg.to_party as usize;
            if to_party_index == 1 {
                p2p_messages_1_to_p1.push(msg.clone())
            }
            if to_party_index == 2 {
                p2p_messages_1_to_p2.push(msg.clone())
            }
            if to_party_index == 3 {
                p2p_messages_1_to_p3.push(msg.clone())
            }
        }
        for msg in p2p_msg1_from_p1 {
            let to_party_index = msg.to_party as usize;
            if to_party_index == 0 {
                p2p_messages_1_to_p0.push(msg.clone())
            }
            if to_party_index == 2 {
                p2p_messages_1_to_p2.push(msg.clone())
            }
            if to_party_index == 3 {
                p2p_messages_1_to_p3.push(msg.clone())
            }
        }
        for msg in p2p_msg1_from_p2 {
            let to_party_index = msg.to_party as usize;
            if to_party_index == 0 {
                p2p_messages_1_to_p0.push(msg.clone())
            }
            if to_party_index == 1 {
                p2p_messages_1_to_p1.push(msg.clone())
            }
            if to_party_index == 3 {
                p2p_messages_1_to_p3.push(msg.clone())
            }
        }
        for msg in p2p_msg1_from_p3 {
            let to_party_index = msg.to_party as usize;
            if to_party_index == 0 {
                p2p_messages_1_to_p0.push(msg.clone())
            }
            if to_party_index == 1 {
                p2p_messages_1_to_p1.push(msg.clone())
            }
            if to_party_index == 2 {
                p2p_messages_1_to_p2.push(msg.clone())
            }
        }

        let (old_party_p0, p2p_msg2_from_p0, broadcast_msg2_p0) =
            old_party_p0.process(p2p_messages_1_to_p0).unwrap();
        let (old_party_p1, p2p_msg2_from_p1, broadcast_msg2_p1) =
            old_party_p1.process(p2p_messages_1_to_p1).unwrap();
        let (old_party_p2, p2p_msg2_from_p2, broadcast_msg2_p2) =
            old_party_p2.process(p2p_messages_1_to_p2).unwrap();
        let (old_party_p3, p2p_msg2_from_p3, broadcast_msg2_p3) =
            old_party_p3.process(p2p_messages_1_to_p3).unwrap();

        let mut p2p_messages_2_to_p0 = vec![];
        let mut p2p_messages_2_to_p1 = vec![];
        let mut p2p_messages_2_to_p2 = vec![];
        let mut p2p_messages_2_to_p3 = vec![];
        // collect
        for msg in p2p_msg2_from_p0 {
            let to_party_index = msg.to_party as usize;
            if to_party_index == 1 {
                p2p_messages_2_to_p1.push(msg.clone())
            }
            if to_party_index == 2 {
                p2p_messages_2_to_p2.push(msg.clone())
            }
            if to_party_index == 3 {
                p2p_messages_2_to_p3.push(msg.clone())
            }
        }
        for msg in p2p_msg2_from_p1 {
            let to_party_index = msg.to_party as usize;
            if to_party_index == 0 {
                p2p_messages_2_to_p0.push(msg.clone())
            }
            if to_party_index == 2 {
                p2p_messages_2_to_p2.push(msg.clone())
            }
            if to_party_index == 3 {
                p2p_messages_2_to_p3.push(msg.clone())
            }
        }
        for msg in p2p_msg2_from_p2 {
            let to_party_index = msg.to_party as usize;
            if to_party_index == 0 {
                p2p_messages_2_to_p0.push(msg.clone())
            }
            if to_party_index == 1 {
                p2p_messages_2_to_p1.push(msg.clone())
            }
            if to_party_index == 3 {
                p2p_messages_2_to_p3.push(msg.clone())
            }
        }
        for msg in p2p_msg2_from_p3 {
            let to_party_index = msg.to_party as usize;
            if to_party_index == 0 {
                p2p_messages_2_to_p0.push(msg.clone())
            }
            if to_party_index == 1 {
                p2p_messages_2_to_p1.push(msg.clone())
            }
            if to_party_index == 2 {
                p2p_messages_2_to_p2.push(msg.clone())
            }
        }

        let broadcast_messages_2 = vec![
            broadcast_msg2_p0,
            broadcast_msg2_p1,
            broadcast_msg2_p2,
            broadcast_msg2_p3,
        ];

        let new_keyshare_p0 = old_party_p0
            .process((p2p_messages_2_to_p0, broadcast_messages_2.clone()))
            .unwrap();
        let new_keyshare_p1 = old_party_p1
            .process((p2p_messages_2_to_p1, broadcast_messages_2.clone()))
            .unwrap();
        let new_keyshare_p2 = old_party_p2
            .process((p2p_messages_2_to_p2, broadcast_messages_2.clone()))
            .unwrap();
        let new_keyshare_p3 = old_party_p3
            .process((p2p_messages_2_to_p3, broadcast_messages_2.clone()))
            .unwrap();

        assert_eq!(new_keyshare_p0.threshold, new_t);
        assert_eq!(new_keyshare_p1.threshold, new_t);
        assert_eq!(new_keyshare_p2.threshold, new_t);
        assert_eq!(new_keyshare_p3.threshold, new_t);

        assert_eq!(new_keyshare_p0.total_parties, new_n);
        assert_eq!(new_keyshare_p1.total_parties, new_n);
        assert_eq!(new_keyshare_p2.total_parties, new_n);
        assert_eq!(new_keyshare_p3.total_parties, new_n);

        assert_eq!(new_keyshare_p0.party_id, 0);
        assert_eq!(new_keyshare_p1.party_id, 1);
        assert_eq!(new_keyshare_p2.party_id, 2);
        assert_eq!(new_keyshare_p3.party_id, 3);

        assert_eq!(new_keyshare_p0.public_key, expected_public_key);
        assert_eq!(new_keyshare_p1.public_key, expected_public_key);
        assert_eq!(new_keyshare_p2.public_key, expected_public_key);
        assert_eq!(new_keyshare_p3.public_key, expected_public_key);

        assert_eq!(new_keyshare_p0.key_id, new_keyshare_p1.key_id);
        assert_eq!(new_keyshare_p0.key_id, new_keyshare_p2.key_id);
        assert_eq!(new_keyshare_p0.key_id, new_keyshare_p3.key_id);

        assert_eq!(new_keyshare_p0.extra_data, new_keyshare_p1.extra_data);
        assert_eq!(new_keyshare_p0.extra_data, new_keyshare_p2.extra_data);
        assert_eq!(new_keyshare_p0.extra_data, new_keyshare_p3.extra_data);

        let d_0 = new_keyshare_p0.scalar_share();
        let d_1 = new_keyshare_p1.scalar_share();
        let d_2 = new_keyshare_p2.scalar_share();
        let d_3 = new_keyshare_p3.scalar_share();
        let public_key = ProjectivePoint::GENERATOR * (d_0 + d_1 + d_2 + d_3);
        assert_eq!(public_key, expected_public_key);
    }
}
