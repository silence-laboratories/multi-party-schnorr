// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{dh_tuple::DhTupleProof, types::SessionId};

/// Round 0 broadcast: session id contribution and consistency hash.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VrfMsg0 {
    pub from_party: u8,
    pub session_id: SessionId,
    pub h_con: [u8; 32],
}

/// Round 1 broadcast: partial VRF point and DH-tuple proof.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone)]
pub struct VrfMsg1 {
    pub from_party: u8,
    pub session_id: SessionId,
    pub z_i: Vec<u8>,
    pub pi: DhTupleProof,
}

impl VrfMsg1 {
    pub fn party_id(&self) -> u8 {
        self.from_party
    }
}
