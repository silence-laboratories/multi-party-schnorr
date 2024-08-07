use curve25519_dalek::{scalar::Scalar, EdwardsPoint};
use rand::{CryptoRng, Rng, RngCore};
use sl_mpc_mate::{math::Polynomial, random_bytes};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Parameters for the keygen protocol. Constant across all rounds.
#[derive(Clone)]
pub struct KeygenParams {
    /// Number of parties in the keygen protocol.
    pub n: u8,
    /// Threshold for the keygen protocol.
    pub t: u8,
    /// Party id of the party.
    pub party_id: u8,

    /// Party's scalar.
    pub x_i: Scalar,

    /// Encryption secret key
    pub(crate) dec_key: crypto_box::SecretKey,
    pub party_enc_keys: Vec<crypto_box::PublicKey>,
}

/// All random params needed for keygen
pub struct KeyEntropy {
    /// Threshold for the keygen protocol.
    pub t: u8,
    /// Number of parties in the keygen protocol.
    pub n: u8,
    /// Session id for the keygen protocol,
    pub session_id: [u8; 32],
    pub(crate) polynomial: Polynomial<EdwardsPoint>,
    /// Random bytes for the keygen protocol.
    pub(crate) r_i: [u8; 32],
}

impl KeyEntropy {
    /// Generate a new set of random params
    pub fn generate<R: CryptoRng + RngCore>(t: u8, n: u8, rng: &mut R) -> Self {
        // 11.2(a)
        let session_id = rng.gen();

        // 11.2(b)
        let polynomial = Polynomial::random(rng, (t - 1) as usize);

        KeyEntropy {
            t,
            n,
            session_id,
            polynomial,
            r_i: random_bytes(rng),
        }
    }

    pub fn generate_refresh<R: CryptoRng + RngCore>(t: u8, n: u8, rng: &mut R) -> Self {
        let session_id = rng.gen();
        let mut polynomial = Polynomial::random(rng, (t - 1) as usize);
        polynomial.reset_contant();

        KeyEntropy {
            t,
            n,
            session_id,
            polynomial,
            r_i: random_bytes(rng),
        }
    }
}

#[derive(Debug, Error)]
/// Distributed key generation errors
pub enum KeygenError {
    /// Invalid Pid value
    #[error("Invalid pid, it must be in the range [1,n]")]
    InvalidPid,

    /// Invalid threshold t value
    #[error("Invalid t, must be less than n")]
    InvalidT,

    /// Invalid length of messages list
    #[error("Provided messages list has invalid length")]
    InvalidMessageLength,

    /// Given message list pid's do not match with the expected pid's.
    #[error("Incorrect participant pid's in the message list")]
    InvalidParticipantSet,

    /// Error while verifiying proofs or checks.
    #[error("Proof error")]
    ProofError,

    /// Decrypted d_i scalar cannot be deserialized
    #[error("Decrypted d_i scalar cannot be deserialized")]
    InvalidDiPlaintext,

    /// Encryption error
    #[error("Encryption Error")]
    EncryptionError,

    /// Decryption error
    #[error("Decryption Error")]
    DecryptionError,

    #[error("Invalid signature")]
    InvalidSignature(#[from] ed25519_dalek::SignatureError),

    #[error("Abort")]
    Abort(&'static str),

    #[error("Error during key refresh or recovery protocol")]
    InvalidRefresh,
}
