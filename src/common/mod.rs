pub mod dlog_proof;
pub mod math;
// mod poly;
/// Utility functions
pub mod utils;

pub use dlog_proof::*;

pub use math::*;

pub mod traits {
    // * MY CODE: ADDED
    use std::println;
    // * MY CODE: ADDED
    use std::sync::Arc;
    use crypto_bigint::subtle::ConstantTimeEq;
    // * MY CODE: ADDED
    use crypto_box::{PublicKey, SecretKey};
    // * MY CODE: ADDED
    use curve25519_dalek::{EdwardsPoint, Scalar};
    use elliptic_curve::{group::GroupEncoding, Group};
    // * MY CODE: ADDED
    use sl_mpc_mate::math::Polynomial;
    // * MY CODE: ADDED
    use crate::common::utils::{EncryptedScalar, HashBytes, Seed, SessionId}; // * MY CODE: ADDED
    // * MY CODE: ADDED
    use crate::keygen::{KeyEntropy, KeygenError, KeygenParams, R1, R2}; // * MY CODE: ADDED

    /// Trait that defines a state transition for any round based protocol.
    pub trait Round {
        /// Output of the state transition.
        type Output;
        /// Input of the state transition.
        type Input;
        /// Transition to the next state.
        // * MY CODE: ADDED
        type Scalar; // Associated scalar type
        // * MY CODE: ADDED
        type GroupElem; // Associated group element type

        fn process(self, messages: Self::Input) -> Self::Output;

        // * MY CODE: ADDED
        fn from_saved_state(
            serialized_state: Vec<u8>,
            private_key: Arc<SecretKey>,
            party_pubkey_list: Vec<(u8, PublicKey)>,
            seed: [u8; 32],
            // * MY CODE: ADDED, scalar coefficients
            coefficients_scalars: Vec<Self::Scalar>,
            coefficients_points: Vec<Self::GroupElem>, // Use Self::GroupElem for group elements
            session_id: SessionId,
            // * MY CODE: ADDED
            c_i_j: Vec<EncryptedScalar>,
            r_i: [u8; 32],
        ) -> Result<Self, KeygenError>
        where
            Self: Sized;

        // * MY CODE: ADDED, from_saved_state_r1
        /// Reinitialize a KeygenParty instance from a saved state.
        fn from_saved_state_r1(
            commitment: [u8; 32],
            coefficients_scalars: Vec<Self::Scalar>,
            shared_session_id: SessionId,
            c_i_j: Vec<EncryptedScalar>,
            r_i: [u8; 32],
            seed: Seed,
        ) -> Result<Self, KeygenError>
        where
            Self: Sized;


        // * MY CODE: ADDED, from_saved_state_r2
        fn from_saved_state_r2(
            private_key: Arc<SecretKey>,
            party_pubkey_list: Vec<(u8, PublicKey)>,
            seed: Seed,
            coefficients_scalars: Vec<Self::Scalar>,
            session_id: SessionId,
            shared_session_id: SessionId,
            sid_i_list: Vec<SessionId>,
            commitment_list: Vec<HashBytes>,
            r_i: [u8; 32]
        ) -> Result<Self, KeygenError>
        where
            Self: Sized;

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
        fn reduce_from_bytes(bytes: &[u8; 32]) -> Self; // * MY CODE: ADDED, changed from 64 to 32
    }

    #[cfg(any(feature = "eddsa", test))]
    impl ScalarReduce<[u8; 32]> for curve25519_dalek::Scalar {
        fn reduce_from_bytes(bytes: &[u8; 32]) -> Self {
            Self::from_bytes_mod_order(*bytes)
        }
    }

    // * MY CODE: ADDED, COMMENTED OUT, existing implementation
    // #[cfg(any(feature = "eddsa", test))]
    // impl ScalarReduce<[u8; 64]> for curve25519_dalek::Scalar {
    //     fn reduce_from_bytes(bytes: &[u8; 32]) -> Self {
    //         Self::from_bytes_mod_order_wide(bytes)
    //     }
    // }

    #[cfg(any(feature = "eddsa", test))]
    impl ScalarReduce<[u8; 64]> for curve25519_dalek::Scalar {
        fn reduce_from_bytes(bytes: &[u8; 32]) -> Self {
            let mut wide_bytes = [0u8; 64];  // * MY CODE: ADDED, Create a zero-initialized 64-byte array
            wide_bytes[..32].copy_from_slice(bytes); // * MY CODE: ADDED, Copy the input 32 bytes into the first half
            Self::from_bytes_mod_order_wide(&wide_bytes)
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
        fn reduce_from_bytes(bytes: &[u8; 32]) -> Self { // * MY CODE: CHANGED from 64 to 32
            use elliptic_curve::ops::Reduce;
            <Self as Reduce<crypto_bigint::U512>>::reduce(crypto_bigint::U512::from_be_slice(bytes))
        }
    }
}
