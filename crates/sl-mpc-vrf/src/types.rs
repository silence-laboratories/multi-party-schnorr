// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use thiserror::Error;

pub type SessionId = [u8; 32];

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
    #[error("protocol called out of phase")]
    InvalidState,
}
