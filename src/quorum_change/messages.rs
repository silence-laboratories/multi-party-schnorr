// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use crate::common::utils::{BaseP2PMessage, HashBytes, SessionId};
use elliptic_curve::{group::GroupEncoding, Group};
use std::hash::Hash;
use std::mem;

#[cfg(feature = "serde")]
use crate::common::utils::serde_vec_point;

/// Type for the QC protocol's broadcast message 1
#[derive(Hash, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct QCBroadcastMsg1 {
    /// Participant index of the sender
    pub from_party: u8,

    /// sid_i
    pub sid_i: SessionId,

    /// Participants commitment_1
    pub commitment_1: HashBytes,
}

impl QCBroadcastMsg1 {
    pub fn external_size() -> usize {
        mem::size_of::<u8>() + mem::size_of::<SessionId>() + mem::size_of::<HashBytes>()
    }
}

/// Type for the QC protocol's p2p message 1
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone)]
pub struct QCP2PMsg1 {
    /// Participant index of the sender
    pub from_party: u8,
    /// Participant index of the receiver
    pub to_party: u8,
    /// Participants commitment_2
    pub commitment_2: HashBytes,
}

impl QCP2PMsg1 {
    pub fn external_size() -> usize {
        mem::size_of::<HashBytes>() + 2
    }
}

/// Type for the QC protocol's p2p message 2
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone)]
pub struct QCP2PMsg2<G>
where
    G: Group + GroupEncoding,
{
    /// Participant index of the sender
    pub from_party: u8,
    /// Participant index of the receiver
    pub to_party: u8,
    /// p_i
    pub p_i: G::Scalar,
    /// r_2_i
    pub r_2_i: [u8; 32],
    /// root_chain_code
    pub root_chain_code: [u8; 32],
}

impl<G> QCP2PMsg2<G>
where
    G: Group + GroupEncoding,
{
    pub fn external_size() -> usize {
        mem::size_of::<G::Scalar>() + 32 + 32 + 2
    }
}

/// Type for the QC protocol's broadcast message 2
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct QCBroadcastMsg2<G>
where
    G: Group + GroupEncoding,
{
    /// Participant index of the sender
    pub from_party: u8,

    /// Random 32 bytes
    pub r_1_i: [u8; 32],

    /// Participants Fik values
    #[cfg_attr(feature = "serde", serde(with = "serde_vec_point"))]
    pub big_p_i_poly: Vec<G>,
}

impl<G> QCBroadcastMsg2<G>
where
    G: Group + GroupEncoding,
{
    /// Returns size in bytes of QCBroadcastMsg2
    /// from_party: 1 byte
    /// r_1_i: 32 bytes
    /// big_p_i_poly: l * point_size + 8,
    /// where l is the vector length,
    /// 8 - size in bytes for length
    pub fn external_size(l: usize) -> usize {
        let point_size = G::generator().to_bytes().as_ref().len();
        1 + 32 + 8 + l * point_size
    }
}

impl BaseP2PMessage for QCP2PMsg1 {
    fn from_party(&self) -> usize {
        self.from_party as usize
    }

    fn to_party(&self) -> usize {
        self.to_party as usize
    }
}

impl<G> BaseP2PMessage for QCP2PMsg2<G>
where
    G: Group + GroupEncoding,
{
    fn from_party(&self) -> usize {
        self.from_party as usize
    }

    fn to_party(&self) -> usize {
        self.to_party as usize
    }
}
