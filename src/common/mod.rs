mod dlog_proof;
mod math;
// mod poly;
/// Utility functions
pub mod utils;


pub use dlog_proof::*;

pub use math::*;
// pub use poly::*;


pub mod traits {
    use crypto_bigint::U512;
    use crypto_bigint::{subtle::ConstantTimeEq};
    use curve25519_dalek::EdwardsPoint;
    use ed25519_dalek::Verifier;
    use ed25519_dalek::{SignatureError, VerifyingKey};
    use elliptic_curve::sec1::FromEncodedPoint;
    use elliptic_curve::{group::GroupEncoding, ops::Reduce, Group};
    
    use k256::{ProjectivePoint, PublicKey, U256};
    

    /// Trait that defines a state transition for any round based protocol.
    pub trait Round {
        /// Output of the state transition.
        type Output;
        /// Input of the state transition.
        type Input;
        /// Transition to the next state.
        fn process(self, messages: Self::Input) -> Self::Output;
    }

    // pub trait PersistentObj {
    //     type Repr: AsRef<[u8]>;
    //     fn to_bytes(&self) -> Option<Self::Repr>;
    //     fn from_bytes(bytes: &[u8]) -> Option<Self>
    //     where
    //         Self: Sized;
    // }
    //
    // impl<T> PersistentObj for T
    // where
    //     T: Serialize + DeserializeOwned,
    // {
    //     type Repr = Vec<u8>;
    //     fn to_bytes(&self) -> Option<Self::Repr> {
    //         bincode::serialize(&self).ok()
    //     }
    //
    //     fn from_bytes(bytes: &[u8]) -> Option<Self> {
    //         bincode::deserialize(bytes).ok()
    //     }
    // }

    pub trait GroupElem: Group + GroupEncoding + ConstantTimeEq {}

    impl<G> GroupElem for G
    where
        G: Group + GroupEncoding + ConstantTimeEq,
        G::Scalar: ScalarReduce<[u8; 32]>,
    {
    }
    pub trait GroupVerifier {
        fn verify(&self, signature: &[u8; 64], msg: &[u8]) -> Result<(), SignatureError>;
    }

    /// Reduce (little endian) bytes to a scalar.
    pub trait ScalarReduce<T> {
        fn reduce_from_bytes(bytes: &T) -> Self;
    }

    impl ScalarReduce<[u8; 32]> for curve25519_dalek::Scalar {
        fn reduce_from_bytes(bytes: &[u8; 32]) -> Self {
            Self::from_bytes_mod_order(*bytes)
        }
    }

    impl ScalarReduce<[u8; 64]> for curve25519_dalek::Scalar {
        fn reduce_from_bytes(bytes: &[u8; 64]) -> Self {
            Self::from_bytes_mod_order_wide(bytes)
        }
    }

    impl ScalarReduce<[u8; 32]> for k256::Scalar {
        fn reduce_from_bytes(bytes: &[u8; 32]) -> Self {
            <Self as Reduce<U256>>::reduce(U256::from_le_slice(bytes))
        }
    }

    impl ScalarReduce<[u8; 64]> for k256::Scalar {
        fn reduce_from_bytes(bytes: &[u8; 64]) -> Self {
            <Self as Reduce<U512>>::reduce(U512::from_le_slice(bytes))
        }
    }

    impl GroupVerifier for EdwardsPoint {
        fn verify(&self, signature: &[u8; 64], msg: &[u8]) -> Result<(), SignatureError> {
            let sig = ed25519_dalek::Signature::from_bytes(signature);
            let vk = VerifyingKey::from_bytes(&self.to_bytes())?;
            vk.verify(msg, &sig)
        }
    }

    impl GroupVerifier for ProjectivePoint {
        fn verify(&self, signature: &[u8; 64], msg: &[u8]) -> Result<(), SignatureError> {
            use elliptic_curve::sec1::ToEncodedPoint;
            
            let sig = k256::schnorr::Signature::try_from(signature.as_ref())?;
            let pk = PublicKey::from_encoded_point(&self.to_encoded_point(true)).unwrap();
            let vk = k256::schnorr::VerifyingKey::try_from(pk).unwrap();
            vk.verify(msg, &sig)
        }
    }
}
