// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::common::{
    traits::GroupElem,
    utils::{BaseMessage, SessionId},
    DhTupleProof,
};

#[cfg(feature = "serde")]
use crate::common::ser::Serializable;

/// Round 0 broadcast: session id contribution and consistency hash.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VrfMsg0 {
    pub from_party: u8,
    pub session_id: SessionId,
    pub h_con: [u8; 32],
}

/// Round 1 broadcast: partial VRF point and DH-tuple proof.
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "G: GroupElem + serde::Serialize, G::Scalar: Serializable",
        deserialize = "G: GroupElem + serde::Deserialize<'de>, G::Scalar: Serializable"
    ))
)]
#[derive(Clone)]
pub struct VrfMsg1<G: GroupElem> {
    pub from_party: u8,
    pub session_id: SessionId,
    pub z_i: Vec<u8>,
    pub pi: DhTupleProof<G>,
}

impl<G: GroupElem> BaseMessage for VrfMsg1<G> {
    fn party_id(&self) -> u8 {
        self.from_party
    }
}
