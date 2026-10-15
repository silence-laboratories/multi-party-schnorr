// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use thiserror::Error;

use sl_mpc_vrf::VrfKeygenError;

/// Errors for MLSAG DKG (Shamir keygen + key-image assembly).
#[derive(Error, Debug, PartialEq, Eq)]
pub enum MlsagError {
    #[error("VRF DKG: {0}")]
    Dkg(#[from] VrfKeygenError),
    #[error("Invalid party ids on messages list")]
    InvalidParticipantSet,
    #[error("Invalid input message count")]
    InvalidMsgCount,
    #[error("Received duplicate party id")]
    DuplicatePartyId,
    #[error("Invalid party id")]
    InvalidMsgPartyId,
    #[error("Malformed keyshare")]
    InvalidKeyshare,
    #[error("Participating set smaller than threshold")]
    InvalidThreshold,
    #[error("Invalid key-image point from party {0}")]
    InvalidKeyImagePoint(u8),
    #[error("Invalid nonce commitment from party {0}")]
    InvalidNonceCommitment(u8),
    #[error("Invalid DH-tuple proof from party {0}")]
    InvalidDhProof(u8),
    #[error("Invalid spend response from party {0}")]
    InvalidResponse(u8),
    #[error("protocol called out of phase")]
    InvalidState,
    #[error("real index out of ring bounds")]
    IndexOutOfBounds,
    #[error("invalid ring point at index {0}")]
    InvalidRingPoint(usize),
    #[error("invalid output commitment")]
    InvalidCommitment,
    #[error("invalid key image")]
    InvalidKeyImage,
    #[error("input and output amounts are not equal")]
    ValueNotConserved,
    #[error("ring onetime key does not match keyshare")]
    PublicKeyMismatch,
    #[error("expected {expected} responses, found {found}")]
    LengthMismatch { expected: usize, found: usize },
    #[error("invalid MLSAG signature")]
    InvalidSignature,
    #[error("challenge does not match the signing transcript")]
    InvalidChallenge,
}
