mod dlog_proof;
mod math;
// mod poly;
/// Utility functions
pub mod utils;

pub use dlog_proof::*;

pub use math::*;
pub const BASEPOINT_ORDER_CURVE_25519: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
    0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x10,
];

pub mod traits {
    use crypto_bigint::subtle::ConstantTimeEq;
    use crypto_bigint::U256;
    use elliptic_curve::{group::GroupEncoding, Curve, Group};
    use sl_mpc_mate::bip32::BIP32Error;

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
        fn check_bip32_left_rnd(bytes: &T) -> Result<(), BIP32Error>;
    }

    #[cfg(any(feature = "eddsa", test))]
    impl ScalarReduce<[u8; 32]> for curve25519_dalek::Scalar {
        fn reduce_from_bytes(bytes: &[u8; 32]) -> Self {
            Self::from_bytes_mod_order(*bytes)
        }
        fn check_bip32_left_rnd(bytes: &[u8; 32]) -> Result<(), BIP32Error> {
            if U256::from_be_slice(bytes)
                > U256::from_be_slice(&crate::common::BASEPOINT_ORDER_CURVE_25519)
            {
                return Err(BIP32Error::InvalidChildScalar);
            }
            Ok(())
        }
    }

    #[cfg(any(feature = "eddsa", test))]
    impl ScalarReduce<[u8; 64]> for curve25519_dalek::Scalar {
        fn reduce_from_bytes(bytes: &[u8; 64]) -> Self {
            Self::from_bytes_mod_order_wide(bytes)
        }
        fn check_bip32_left_rnd(bytes: &[u8; 64]) -> Result<(), BIP32Error> {
            if U256::from_be_slice(bytes)
                > U256::from_be_slice(&crate::common::BASEPOINT_ORDER_CURVE_25519)
            {
                return Err(BIP32Error::InvalidChildScalar);
            }
            Ok(())
        }
    }

    #[cfg(any(feature = "taproot", test))]
    impl ScalarReduce<[u8; 32]> for k256::Scalar {
        fn reduce_from_bytes(bytes: &[u8; 32]) -> Self {
            use elliptic_curve::ops::Reduce;
            <Self as Reduce<crypto_bigint::U256>>::reduce(crypto_bigint::U256::from_be_slice(bytes))
        }
        fn check_bip32_left_rnd(bytes: &[u8; 32]) -> Result<(), BIP32Error> {
            if U256::from_be_slice(bytes) > k256::Secp256k1::ORDER {
                return Err(BIP32Error::InvalidChildScalar);
            }
            Ok(())
        }
    }

    #[cfg(any(feature = "taproot", test))]
    impl ScalarReduce<[u8; 64]> for k256::Scalar {
        fn reduce_from_bytes(bytes: &[u8; 64]) -> Self {
            use elliptic_curve::ops::Reduce;
            <Self as Reduce<crypto_bigint::U512>>::reduce(crypto_bigint::U512::from_be_slice(bytes))
        }
        fn check_bip32_left_rnd(bytes: &[u8; 64]) -> Result<(), BIP32Error> {
            if U256::from_be_slice(bytes) > k256::Secp256k1::ORDER {
                return Err(BIP32Error::InvalidChildScalar);
            }
            Ok(())
        }
    }
}
