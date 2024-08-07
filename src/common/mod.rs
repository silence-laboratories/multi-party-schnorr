mod dlog_proof;
mod math;
// mod poly;
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
// pub use poly::*;
use rand::{CryptoRng, RngCore};

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
}
