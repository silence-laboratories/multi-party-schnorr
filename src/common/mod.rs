mod dlog_proof;
mod math;
mod poly;
/// Utility functions
pub mod utils;

use bincode::{
    de::Decoder,
    enc::Encoder,
    error::{DecodeError, EncodeError},
    Decode, Encode,
};
pub use dlog_proof::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
pub use math::*;
pub use poly::*;
use rand::{CryptoRng, RngCore};
use sl_mpc_mate::message::Opaque;

/// Set of a party's keys that can be reused
/// for independent execution of DKG
#[derive(Clone, PartialEq)]
pub struct PartyKeys {
    /// Signing keys for the party
    pub(crate) signing_key: SigningKey,

    pub(crate) encryption_secret_key: crypto_box::SecretKey,
}

/// Datatype for all of the participants public keys (verification, encryption)
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PartyPublicKeys {
    /// The public key for signature verification.
    pub verify_key: VerifyingKey,

    /// Public key for encryption
    pub encryption_key: crypto_box::PublicKey,
}

impl Encode for PartyPublicKeys {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        Opaque::from(self.verify_key.to_bytes()).encode(encoder)?;
        Opaque::from(self.encryption_key.to_bytes()).encode(encoder)?;
        Ok(())
    }
}

impl Decode for PartyPublicKeys {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let verify_key = VerifyingKey::from_bytes(&Opaque::decode(decoder)?.0)
            .map_err(|_| DecodeError::Other("Bad verify_key"))?;
        let encryption_key = crypto_box::PublicKey::from_bytes(Opaque::decode(decoder)?.0);
        Ok(Self {
            verify_key,
            encryption_key,
        })
    }
}

impl PartyKeys {
    /// Create a new set of party keys
    #[allow(clippy::new_without_default)]
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let signing_key = SigningKey::generate(rng);
        let encryption_secret_key = crypto_box::SecretKey::generate(rng);
        Self {
            signing_key,
            encryption_secret_key,
        }
    }

    pub fn from_keys(
        signing_key: SigningKey,
        encryption_secret_key: crypto_box::SecretKey,
    ) -> Self {
        Self {
            signing_key,
            encryption_secret_key,
        }
    }

    /// Extract public keys
    pub fn public_keys(&self) -> PartyPublicKeys {
        PartyPublicKeys {
            verify_key: self.signing_key.verifying_key(),
            encryption_key: self.encryption_secret_key.public_key(),
        }
    }
}

pub mod traits {

    /// Trait that defines a state transition for any round based protocol.
    pub trait Round {
        /// Output of the state transition.
        type Output;
        /// Input of the state transition.
        type Input;
        /// Transition to the next state.
        fn process(self, messages: Self::Input) -> Self::Output;
    }

    // TODO: Do we need this?
    pub trait PersistentObj: bincode::Encode + bincode::Decode {
        fn to_bytes(&self) -> Option<Vec<u8>> {
            bincode::encode_to_vec(self, bincode::config::standard()).ok()
        }
        fn from_bytes(data: &[u8]) -> Option<Self> {
            bincode::decode_from_slice(data, bincode::config::standard())
                .ok()
                .and_then(
                    |(obj, read)| {
                        if read != data.len() {
                            None
                        } else {
                            Some(obj)
                        }
                    },
                )
        }
    }
}
