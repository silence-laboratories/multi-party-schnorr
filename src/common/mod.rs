mod dlog_proof;
mod math;
// mod poly;
/// Utility functions
pub mod utils;

pub use dlog_proof::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
pub use math::*;
// pub use poly::*;
use rand::{CryptoRng, RngCore};

pub mod traits {
    use serde::{de::DeserializeOwned, Serialize};

    /// Trait that defines a state transition for any round based protocol.
    pub trait Round {
        /// Output of the state transition.
        type Output;
        /// Input of the state transition.
        type Input;
        /// Transition to the next state.
        fn process(self, messages: Self::Input) -> Self::Output;
    }

    pub trait PersistentObj {
        type Repr: AsRef<[u8]>;
        fn to_bytes(&self) -> Option<Self::Repr>;
        fn from_bytes(bytes: &[u8]) -> Option<Self>
        where
            Self: Sized;
    }

    impl<T> PersistentObj for T
    where
        T: Serialize + DeserializeOwned,
    {
        type Repr = Vec<u8>;
        fn to_bytes(&self) -> Option<Self::Repr> {
            bincode::serialize(&self).ok()
        }

        fn from_bytes(bytes: &[u8]) -> Option<Self> {
            bincode::deserialize(bytes).ok()
        }
    }
}
