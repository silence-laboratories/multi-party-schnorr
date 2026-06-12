// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use curve25519_dalek::RistrettoPoint;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::crypto::{DLogProof, HashBytes, P2pShare, SessionId};

/// Broadcast: round-1 commitment.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VrfKeygenMsg1 {
    pub from_party: u8,
    pub session_id: SessionId,
    pub commitment: HashBytes,
}

/// Broadcast: round-2 opening.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfKeygenMsg2 {
    pub from_party: u8,
    pub session_id: SessionId,
    pub r_i: [u8; 32],
    pub big_a_i_poly: Vec<RistrettoPoint>,
    pub c_i_list: Vec<P2pShare>,
    pub dlog_proofs_i: Vec<DLogProof>,
}

/// Ristretto VRF key share after DKG (includes additive public shares for VRF eval).
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfKeyshare {
    pub threshold: u8,
    pub total_parties: u8,
    pub party_id: u8,
    pub(crate) d_i: curve25519_dalek::Scalar,
    pub public_key: RistrettoPoint,
    pub(crate) party_public_shares: Vec<RistrettoPoint>,
    pub key_id: [u8; 32],
    pub root_chain_code: [u8; 32],
    pub final_session_id: SessionId,
}

impl VrfKeyshare {
    pub fn public_key(&self) -> &RistrettoPoint {
        &self.public_key
    }

    pub fn shamir_share(&self) -> &curve25519_dalek::Scalar {
        &self.d_i
    }

    pub fn party_public_share(&self) -> &RistrettoPoint {
        &self.party_public_shares[self.party_id as usize]
    }

    pub fn party_public_shares(&self) -> &[RistrettoPoint] {
        &self.party_public_shares
    }
}
