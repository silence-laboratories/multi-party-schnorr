mod dlog_proof;
mod math;
// mod poly;
/// Utility functions
pub mod utils;

pub use dlog_proof::*;

pub use math::*;

pub mod traits {
    use crypto_bigint::subtle::ConstantTimeEq;
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
