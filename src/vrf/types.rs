// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use rand::{CryptoRng, Rng, RngCore};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::common::utils::SessionId;

/// Randomness for the MPC VRF evaluation protocol (session id generation).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VrfEntropy {
    pub(crate) session_id: SessionId,
    pub(crate) seed: [u8; 32],
}

impl VrfEntropy {
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Self {
            session_id: rng.gen(),
            seed: rng.gen(),
        }
    }
}

/// MPC VRF evaluation errors.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum VrfError {
    #[error("Invalid party ids on messages list")]
    InvalidParticipantSet,
    #[error("Invalid input message count")]
    InvalidMsgCount,
    #[error("Received duplicate party id")]
    DuplicatePartyId,
    #[error("Invalid party id, message from party not in id list")]
    InvalidMsgPartyId,
    #[error("Malformed VRF keyshare (party id or public shares length)")]
    InvalidKeyshare,
    #[error("Local VRF key validation failed")]
    InvalidLocalKey,
    #[error("Party public shares do not sum to K")]
    InvalidPublicShares,
    #[error("Consistency hash mismatch from party {0}")]
    ConsistencyHashMismatch(u8),
    #[error("Invalid Z point from party {0}")]
    InvalidZ(u8),
    #[error("Invalid DH-tuple proof from party {0}")]
    InvalidDhProof(u8),
    #[error("Hash-to-curve failed")]
    HashToCurve,
}
