use elliptic_curve::Group;
use rand::{CryptoRng, Rng, RngCore};
use std::sync::Arc;
use thiserror::Error;

use sl_mpc_mate::{math::Polynomial, random_bytes};

/// Parameters for the keygen protocol. Constant across all rounds.
pub(crate) struct KeygenParams {
    /// Number of parties in the keygen protocol.
    pub n: u8,
    /// Threshold for the keygen protocol.
    pub t: u8,
    /// Party id of the party.
    pub party_id: u8,

    /// Optional key id that will be used for the keygen protocol.
    /// If None then hash of the public key will be used.
    pub key_id: Option<[u8; 32]>,

    /// Encryption secret key
    pub dec_key: Arc<crypto_box::SecretKey>,
    pub party_enc_keys: Vec<(u8, crypto_box::PublicKey)>,

    /// Extra data
    pub extra_data: Option<Vec<u8>>,
}

/// All random params needed for keygen
pub struct KeyEntropy<G>
where
    G: Group,
{
    /// Threshold for the keygen protocol.
    pub t: u8,
    /// Number of parties in the keygen protocol.
    pub n: u8,
    /// Session id for the keygen protocol,
    pub session_id: [u8; 32],
    pub(crate) polynomial: Polynomial<G>,
    /// Random bytes for the keygen protocol.
    pub(crate) r_i: [u8; 32],
    ///chain_code_sid: the chain code for each player in order to compute the final root_chain_code
    pub(crate) chain_code_id: [u8; 32],
}

impl<G> KeyEntropy<G>
where
    G: Group,
{
    /// Generate a new set of random params
    pub fn generate<R: CryptoRng + RngCore>(t: u8, n: u8, rng: &mut R) -> Self {
        // 11.2(a)
        let session_id = rng.gen();

        // 11.2(b)
        let polynomial = Polynomial::random(rng, (t - 1) as usize);
        let chain_code_id = rng.gen();

        KeyEntropy {
            t,
            n,
            session_id,
            polynomial,
            r_i: random_bytes(rng),
            chain_code_id,
        }
    }

    pub fn generate_refresh<R: CryptoRng + RngCore>(t: u8, n: u8, rng: &mut R) -> Self {
        let mut ent = Self::generate(t, n, rng);
        ent.polynomial.reset_constant();
        ent
    }
}

#[derive(Debug, Error)]
/// Distributed key generation errors
pub enum KeygenError {
    /// Invalid Pid value
    #[error("Invalid pid, it must be in the range [1,n]")]
    InvalidPid,

    /// Invalid data given in message, serialization/deserialization error
    #[error("Invalid message data")]
    InvalidMsgData,

    /// Invalid threshold t value
    #[error("Invalid t, must be less than n")]
    InvalidT,

    /// Invalid length of messages list
    #[error("Provided messages list has invalid length")]
    InvalidMsgCount,

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
    InvalidSignature,

    #[error("Abort")]
    Abort(&'static str),

    #[error("Error during key refresh or recovery protocol")]
    InvalidRefresh,
}
