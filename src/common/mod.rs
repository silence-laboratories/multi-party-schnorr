// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

mod dlog_proof;
mod math;

/// Utility functions
pub mod utils;

pub use dlog_proof::*;

pub use math::*;

pub mod traits {
    #[cfg(feature = "taproot")]
    use crypto_bigint::U512;

    #[cfg(any(feature = "eddsa", feature = "taproot"))]
    use crypto_bigint::U256;

    use crypto_bigint::subtle::{ConstantTimeEq, CtOption};

    #[cfg(feature = "eddsa")]
    use crypto_bigint::Encoding;

    use elliptic_curve::{group::GroupEncoding, Group};

    #[cfg(feature = "taproot")]
    use elliptic_curve::ops::Reduce;

    pub trait InitRound {
        type OutputMessage;
        type Next: Round;
        type Error;

        fn init(self) -> Result<(Self::Next, Self::OutputMessage), Self::Error>;
    }

    /// Trait that defines a state transition for any round based protocol.
    pub trait Round {
        /// Output of the state transition.
        type Output;

        /// Type of input messages
        type InputMessage;

        /// Input of the state transition, such as `Vec<InputMessage>`.
        type Input;

        type Error;

        /// Transition to the next state.
        fn process(self, messages: Self::Input) -> Result<Self::Output, Self::Error>;
    }

    pub trait RoundSize {
        fn message_count(&self) -> usize;
    }

    pub trait GroupElem: Group + GroupEncoding + ConstantTimeEq {}

    impl<G> GroupElem for G
    where
        G: Group + GroupEncoding + ConstantTimeEq,
        G::Scalar: ScalarReduce<[u8; 32]>,
    {
    }

    /// Reduce (little endian) bytes to a scalar.
    pub trait ScalarReduce<T> {
        fn reduce_from_bytes(bytes: &T) -> Self;
    }

    /// Trait that signifies that the Group supports BIP32 derivation and can parse the I_L bytes
    /// into a valid scalar offset, while performing the less than group order check.
    /// I_L bytes are the left most 32 bytes of the HMAC-SHA512 output.
    pub trait BIP32Derive {
        /// Given the I_L bytes perform the less than group order check and returns a valid scalar.
        /// Arguments:
        /// - `bytes`: I_L bytes (32 bytes)
        ///
        /// Returns a valid scalar after parsing the I_L bytes.
        fn parse_offset(bytes: [u8; 32]) -> CtOption<Self>
        where
            Self: Sized;
    }

    #[cfg(feature = "eddsa")]
    impl BIP32Derive for curve25519_dalek::Scalar {
        fn parse_offset(bytes: [u8; 32]) -> CtOption<Self> {
            let mut z_l = [0u8; 32];
            // NOTE: Follwing BIP32-Ed25519 spec for parsing I_L bytes.
            z_l[0..28].copy_from_slice(&bytes[..28]);
            let mut z_l = U256::from_le_slice(&z_l);
            z_l = z_l.shl(3);
            Self::from_canonical_bytes(z_l.to_le_bytes())
        }
    }

    #[cfg(feature = "taproot")]
    impl BIP32Derive for k256::Scalar {
        fn parse_offset(bytes: [u8; 32]) -> CtOption<k256::Scalar> {
            use ff::PrimeField;
            Self::from_repr(bytes.into())
        }
    }

    #[cfg(feature = "eddsa")]
    impl ScalarReduce<[u8; 32]> for curve25519_dalek::Scalar {
        fn reduce_from_bytes(bytes: &[u8; 32]) -> Self {
            Self::from_bytes_mod_order(*bytes)
        }
    }

    #[cfg(feature = "eddsa")]
    impl ScalarReduce<[u8; 64]> for curve25519_dalek::Scalar {
        fn reduce_from_bytes(bytes: &[u8; 64]) -> Self {
            Self::from_bytes_mod_order_wide(bytes)
        }
    }

    #[cfg(feature = "taproot")]
    impl ScalarReduce<[u8; 32]> for k256::Scalar {
        fn reduce_from_bytes(bytes: &[u8; 32]) -> Self {
            Reduce::<U256>::reduce(U256::from_be_slice(bytes))
        }
    }

    #[cfg(feature = "taproot")]
    impl ScalarReduce<[u8; 64]> for k256::Scalar {
        fn reduce_from_bytes(bytes: &[u8; 64]) -> Self {
            Reduce::<U512>::reduce(U512::from_be_slice(bytes))
        }
    }
}

#[cfg(not(feature = "serde"))]
pub mod ser {
    pub trait Serializable {}
    impl<T> Serializable for T {}
}

#[cfg(feature = "serde")]
pub mod ser {
    pub trait Serializable: serde::Serialize + serde::de::DeserializeOwned {}
    impl<T: serde::Serialize + serde::de::DeserializeOwned> Serializable for T {}
}
