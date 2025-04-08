mod dlog_proof;
mod math;
// mod poly;
/// Utility functions
pub mod utils;

pub use dlog_proof::*;

pub use math::*;

pub mod traits {
    use crypto_bigint::subtle::CtOption;
    use crypto_bigint::U256;
    use crypto_bigint::{subtle::ConstantTimeEq, Encoding};
    use curve25519_dalek::Scalar;
    use elliptic_curve::{group::GroupEncoding, Group};

    /// Trait that defines a state transition for any round based protocol.
    pub trait Round {
        /// Output of the state transition.
        type Output;
        /// Input of the state transition.
        type Input;
        /// Transition to the next state.
        fn process(self, messages: Self::Input) -> Self::Output;
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

    #[cfg(any(feature = "eddsa", test))]
    impl BIP32Derive for curve25519_dalek::Scalar {
        fn parse_offset(bytes: [u8; 32]) -> CtOption<Scalar> {
            let mut z_l = [0u8; 32];
            // NOTE: Follwing BIP32-Ed25519 spec for parsing I_L bytes.
            z_l[0..28].copy_from_slice(&bytes[..28]);
            let mut z_l = U256::from_le_slice(&z_l);
            z_l = z_l.shl(3);
            Scalar::from_canonical_bytes(z_l.to_le_bytes())
        }
    }

    #[cfg(any(feature = "taproot", test))]
    impl BIP32Derive for k256::Scalar {
        fn parse_offset(bytes: [u8; 32]) -> CtOption<k256::Scalar> {
            use ff::PrimeField;
            k256::Scalar::from_repr(bytes.into())
        }
    }

    #[cfg(any(feature = "eddsa", test))]
    impl ScalarReduce<[u8; 32]> for curve25519_dalek::Scalar {
        fn reduce_from_bytes(bytes: &[u8; 32]) -> Self {
            Self::from_bytes_mod_order(*bytes)
        }
    }

    #[cfg(any(feature = "eddsa", test))]
    impl ScalarReduce<[u8; 64]> for curve25519_dalek::Scalar {
        fn reduce_from_bytes(bytes: &[u8; 64]) -> Self {
            Self::from_bytes_mod_order_wide(bytes)
        }
    }

    #[cfg(any(feature = "taproot", test))]
    impl ScalarReduce<[u8; 32]> for k256::Scalar {
        fn reduce_from_bytes(bytes: &[u8; 32]) -> Self {
            use elliptic_curve::ops::Reduce;
            <Self as Reduce<crypto_bigint::U256>>::reduce(crypto_bigint::U256::from_be_slice(bytes))
        }
    }

    #[cfg(any(feature = "taproot", test))]
    impl ScalarReduce<[u8; 64]> for k256::Scalar {
        fn reduce_from_bytes(bytes: &[u8; 64]) -> Self {
            use elliptic_curve::ops::Reduce;
            <Self as Reduce<crypto_bigint::U512>>::reduce(crypto_bigint::U512::from_be_slice(bytes))
        }
    }
}
