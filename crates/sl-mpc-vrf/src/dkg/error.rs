// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VrfKeygenError {
    #[error("invalid party id")]
    InvalidPid,

    #[error("invalid threshold")]
    InvalidT,

    #[error("invalid participant set")]
    InvalidParticipantSet,

    #[error("invalid message count")]
    InvalidMsgCount,

    #[error("proof verification failed")]
    ProofError,

    #[error("invalid share plaintext")]
    InvalidDiPlaintext,

    #[error("protocol abort: {0}")]
    Abort(&'static str),

    #[error("protocol called out of phase")]
    InvalidState,
}
