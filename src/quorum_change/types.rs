// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use crypto_bigint::rand_core::{CryptoRng, RngCore};
use rand::Rng;
use thiserror::Error;

use crate::{
    common::ser::Serializable,
    group::Group,
    quorum_change::{pairs::Pairs, qc::new_party_id},
};

use sl_mpc_mate::math::Polynomial;
use sl_mpc_mate::random_bytes;

/// Parameters for the QuorumChange protocol. Constant across all rounds.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct QCParams<G>
where
    G: Group,
{
    /// Total parties
    pub total_parties: u8,
    /// New threshold
    pub new_t: u8,
    /// This party index
    pub party_index: usize,
    /// Indices of old parties
    pub old_parties: Vec<usize>,
    /// Indices of new parties
    pub new_parties: Vec<usize>,
    /// old parties index to id mapping
    pub old_party_ids: Pairs<u8, usize>,
    /// Expected public_key
    pub public_key: G,

    /// Optional key id that will be used for the keygen protocol.
    /// If None then hash of the public key will be used.
    pub key_id: Option<[u8; 32]>,
    /// Extra data
    pub extra_data: Option<Vec<u8>>,
}

/// All random params needed for QuorumChange protocol.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct QCEntropyOld<G>
where
    G: Group,
    G::Scalar: Serializable,
{
    /// New threshold
    pub new_t: u8,
    /// sid_i for the QuorumChange protocol
    pub sid_i: [u8; 32],
    pub(crate) polynomial: Polynomial<G>,
    /// Random bytes for the commitment1
    pub(crate) r1_i: [u8; 32],
    /// Random bytes for the commitment2 from old parties to new parties
    pub(crate) r2_j_list: Pairs<[u8; 32], u8>,
}

impl<G> QCEntropyOld<G>
where
    G: Group,
    G::Scalar: Serializable,
{
    /// Generate a new set of random params
    pub fn generate<R: CryptoRng + RngCore>(
        new_t: u8,
        s_i_0: G::Scalar,
        new_parties: &[usize],
        rng: &mut R,
    ) -> Self {
        let sid_i = rng.gen();
        let mut polynomial = Polynomial::random(rng, (new_t - 1) as usize);
        polynomial.set_constant(s_i_0);
        let r1_i = random_bytes(rng);
        let mut r2_j_list: Pairs<[u8; 32], u8> = Pairs::new();
        for receiver_index in new_parties {
            let receiver_id = new_party_id(new_parties, *receiver_index).unwrap();
            let r2_j: [u8; 32] = rng.gen();
            r2_j_list.push(receiver_id, r2_j);
        }

        QCEntropyOld {
            new_t,
            sid_i,
            polynomial,
            r1_i,
            r2_j_list,
        }
    }
}

/// All random params needed for QuorumChange protocol.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct QCEntropyNew {
    /// sid_i for the QuorumChange protocol
    pub sid_i: [u8; 32],
}

impl QCEntropyNew {
    /// Generate a new set of random params
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let sid_i = rng.gen();
        QCEntropyNew { sid_i }
    }
}

#[derive(Debug, Error)]
/// Distributed key generation errors
pub enum QCError {
    /// Invalid Pid value
    #[error("Invalid pid, it must be in the range [1,n]")]
    InvalidPid,

    /// Invalid data given in message, serialization/deserialization error
    #[error("Invalid message")]
    InvalidMessage,

    /// Invalid threshold t value
    #[error("Invalid t, must be less than n")]
    InvalidT,

    /// Invalid length of messages list
    #[error("Provided messages list has invalid length")]
    InvalidMsgCount,

    /// Given message list pid's do not match with the expected pid's.
    #[error("Incorrect participant pid's in the message list")]
    InvalidParticipantSet,

    /// Invalid commitment hash
    #[error("Invalid commitment hash")]
    InvalidCommitmentHash,

    /// Failed Feldman verify
    #[error("Failed Feldman verify")]
    FailedFeldmanVerify,

    /// Public key mismatch
    #[error("Public key mismatch")]
    PublicKeyMismatch,

    #[error("Invalid root chain code")]
    InvalidRootChainCode,
}
