// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::hash::Hash;

use elliptic_curve::{group::GroupEncoding, Group};

use crate::common::utils::{HashBytes, SessionId};

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
