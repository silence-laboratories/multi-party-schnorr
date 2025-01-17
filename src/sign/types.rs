use elliptic_curve::Group;
use ff::Field;
use rand::{CryptoRng, Rng, RngCore};
use thiserror::Error;

use crate::common::utils::SessionId;

/// All random params needed for sign protocol
pub struct SignEntropy<G: Group> {
    pub(crate) session_id: SessionId,
    pub(crate) k_i: G::Scalar,
    pub(crate) blind_factor: [u8; 32],
}
impl<G: Group> SignEntropy<G> {
    /// Generate all the random values used in the sign protocol
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Self {
            session_id: rng.gen(),
            blind_factor: rng.gen(),
            k_i: <G::Scalar as Field>::random(rng),
        }
    }
}

// impl PersistentObj for PartyPublicKeys {}
/// Distributed key generation errors
#[derive(Error, Debug)]
pub enum SignError {
    #[error("Invalid party ids on messages list")]
    /// Invalid party ids on messages list
    InvalidParticipantSet,
    /// Party key not found
    #[error("Party key not found")]
    PartyKeyNotFound,
    #[error("Invalid input message count")]
    /// Invalid input message count
    InvalidMsgCount,
    #[error("Invalid party id, message from party not in id list")]
    /// Invalid party id
    UnexpectedPartyId,
    /// Received duplicate party id
    #[error("Received duplicate party id")]
    DuplicatePartyId,
    /// Received duplicate session id
    #[error("Received duplicate session id")]
    DuplicateSessionId,
    /// Invalid party ids
    #[error("Invalid party ids")]
    InvalidMsgPartyId,
    #[error("Wrong receipient, received message for party {0}, expected {1}")]
    /// Wrong receipient
    WrongReceipient(usize, usize),
    /// Already processed message from party
    #[error("Already processed message from party {0}")]
    AlreadyProcessed(usize),

    #[error("Invalid message")]
    /// Invalid message
    InvalidPlaintext,

    /// Decryption error
    #[error("Decryption error: {0}")]
    DecryptionError(String),

    /// Invalid commitment
    #[error("Invalid commitment from party {0}")]
    InvalidCommitment(u8),

    /// Invalid digest
    #[error("Invalid digest")]
    InvalidDigest,

    #[error("Invalid Big R_i, cannot be identity")]
    /// Invalid Big R_i, cannot be identity
    InvalidBigRi,

    /// Invalid DLog proof
    #[error("Invalid DLog proof from party {0}")]
    InvalidDLogProof(u8),

    /// Math error
    #[error("Math error: {0}")]
    MathError(String),

    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid threshold")]
    InvalidThreshold,
}
