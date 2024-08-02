use curve25519_dalek::Scalar;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::{CryptoRng, Rng, RngCore};
use thiserror::Error;

use crate::{common::utils::SessionId, keygen::Keyshare};

/// Parameters for the sign protocol. Constant across all rounds.
pub struct SignParams {
    /// The party's id
    pub party_id: u8,
    /// Party's index in pubkey list
    pub party_index: u8,
    pub(crate) keyshare: Keyshare,
    pub(crate) signing_key: SigningKey,
    /// List of all parties' public keys
    pub party_pubkeys: Vec<VerifyingKey>,
}

/// All random params needed for sign protocol
pub struct SignEntropy {
    pub(crate) session_id: SessionId,
    pub(crate) k_i: Scalar,
    pub(crate) blind_factor: [u8; 32],
}
impl SignEntropy {
    /// Generate all the random values used in the sign protocol
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Self {
            session_id: rng.gen(),
            k_i: Scalar::random(rng),
            blind_factor: rng.gen(),
        }
    }
}

// impl PersistentObj for PartyPublicKeys {}
/// Distributed key generation errors
#[derive(Error, Debug)]
pub enum SignError {
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

    #[error("Already processed message from all parties, please use check_proceed to proceed to next state ")]
    /// Already processed message from all parties
    AlreadyProcessedAll,

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
    InvalidSignature(#[from] ed25519_dalek::SignatureError),
}
