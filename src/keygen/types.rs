use std::sync::Arc;
// * MY CODE: ADDED
use std::fmt;
// * MY CODE: ADDED
use curve25519_dalek::EdwardsPoint;

// * MY CODE: ADDED
use elliptic_curve::{group::GroupEncoding, Group};
// * MY CODE: ADDED
use ff::Field;
use rand::{CryptoRng, Rng, RngCore};
// * MY CODE: ADDED
// use serde::Serialize;
use thiserror::Error;

// * MY CODE: ADDED
use crate::common::traits::ScalarReduce;
use sl_mpc_mate::{math::Polynomial, random_bytes};
// * MY CODE: ADDED
use sl_mpc_mate::math::GroupPolynomial;

// Parameters for the keygen protocol. Constant across all rounds.
#[derive(Debug)]
// * MY CODE: COMMENTED OUT
// pub(crate) struct KeygenParams {
//     /// Number of parties in the keygen protocol.
//     pub n: u8,
//     /// Threshold for the keygen protocol.
//     pub t: u8,
//     /// Party id of the party.
//     pub party_id: u8,
//
//     /// Optional key id that will be used for the keygen protocol.
//     /// If None then hash of the public key will be used.
//     pub key_id: Option<[u8; 32]>,
//
//     /// Encryption secret key
//     pub dec_key: Arc<crypto_box::SecretKey>,
//     pub party_enc_keys: Vec<(u8, crypto_box::PublicKey)>,
//
//     /// Extra data
//     pub extra_data: Option<Vec<u8>>,
// }

// * MY CODE: ADDED
pub struct KeygenParams {
    pub n: u8,
    pub t: u8,
    pub party_id: u8,
    pub key_id: Option<[u8; 32]>,
    pub dec_key: Option<Arc<crypto_box::SecretKey>>, // * MY CODE: ADDED, Wrap in Option
    pub party_enc_keys: Option<Vec<(u8, crypto_box::PublicKey)>>, // * MY CODE: ADDED, Wrap in Option
    pub extra_data: Option<Vec<u8>>,
}


// * MY CODE: ADDED
impl Clone for KeygenParams {
    fn clone(&self) -> Self {
        Self {
            n: self.n,
            t: self.t,
            party_id: self.party_id,
            key_id: self.key_id.clone(),
            dec_key: self.dec_key.clone(),
            party_enc_keys: self.party_enc_keys.clone(),
            extra_data: self.extra_data.clone(),
        }
    }
}


// * MY CODE: ADDED, not used
// pub fn create_keygen_params(
//     t: u8,
//     n: u8,
//     party_id: u8,
//     key_id: Option<[u8; 32]>,
//     dec_key: Arc<crypto_box::SecretKey>,
//     party_enc_keys: Vec<(u8, crypto_box::PublicKey)>,
//     extra_data: Option<Vec<u8>>,
// ) -> KeygenParams {
//     KeygenParams {
//         t,
//         n,
//         party_id,
//         key_id,
//         dec_key: Some(dec_key),  // Wrap in Some
//         party_enc_keys: Some(party_enc_keys),  // Wrap in Some
//         extra_data,
//     }
// }


/// All random params needed for keygen
// #[derive(Debug, Clone)] // TODO: ADDED this line of Debug and Clone
// TODO: COMMENTED THIS OUT SINCE polynomial private
// pub struct KeyEntropy<G>
// where
//     G: Group,
// {
//     /// Threshold for the keygen protocol.
//     pub t: u8,
//     /// Number of parties in the keygen protocol.
//     pub n: u8,
//     /// Session id for the keygen protocol,
//     pub session_id: [u8; 32],
//     pub(crate) polynomial: Polynomial<G>,  // TODO: REMOVE THIS CUSTOM WRAPPER PolynomialWrapper<G>
//     /// Random bytes for the keygen protocol.
//     pub(crate) r_i: [u8; 32],
// }

// TODO: MY CODE changed polynomial to pub
// * MY CODE: ADDED and COMMENTED OUT
// #[derive(Debug)]
pub struct KeyEntropy<G>
where
    G: Group + GroupEncoding + for<'a> std::ops::Mul<<G as Group>::Scalar, Output = G>, // * MY CODE: ADDED
{
    /// Threshold for the keygen protocol.
    pub t: u8,
    /// Number of parties in the keygen protocol.
    pub n: u8,
    /// Session id for the keygen protocol,
    pub session_id: [u8; 32],
    // pub polynomial: Polynomial<G>, // * MY CODE: ADDED
    pub polynomial: GroupPolynomial<G>, // * MY CODE: ADDED
    /// Scalar-based polynomial coefficients.
    pub scalar_polynomial: Polynomial<G>, // New field for scalar-based polynomial // * MY CODE: ADDED
    /// Scalars corresponding to the group-based polynomial coefficients.
    pub scalars: Vec<G::Scalar>, // New field for storing scalars // * MY CODE: ADDED
    /// Random bytes for the keygen protocol.
    pub r_i: [u8; 32], // * MY CODE: ADDED
}

// * MY CODE: ADDED
impl<G> fmt::Debug for KeyEntropy<G>
where
    G: Group + GroupEncoding + for<'a> std::ops::Mul<<G as Group>::Scalar, Output = G>,
    G::Scalar: fmt::Debug, // Ensure that scalar coefficients are Debug-printable
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyEntropy")
            .field("t", &self.t)
            .field("n", &self.n)
            .field("session_id", &self.session_id)
            .field("polynomial", &self.polynomial) // GroupPolynomial should implement Debug
            .field("scalars", &self.scalars) // Scalars should be Debug-printable
            .field("r_i", &self.r_i)
            .field("scalar_polynomial", &"<non-debuggable>") // Placeholder or omit entirely
            .finish()
    }
}



// TODO: ADDED MY CLONE impl for KeyEntropy
// Updated Clone implementation for KeyEntropy
// TODO: consider this:
// if you replace the original polynomial in Clone with a placeholder or random value, you risk invalidating any dependent computations,
// especially if the cloned KeyEntropy is used in subsequent rounds.
// * MY CODE: ADDED
// impl<G> Clone for KeyEntropy<G>
// where
//     G: Group,
// {
//     fn clone(&self) -> Self {
//         Self {
//             t: self.t,
//             n: self.n,
//             session_id: self.session_id,
//             //polynomial: Polynomial::random(&mut rand::thread_rng(), (self.t - 1) as usize), // Replace with valid constructor
//             polynomial: self.polynomial.clone(), // Clone the polynomial
//             scalar_polynomial: self.scalar_polynomial.clone(), // Clone the scalar-based polynomial
//             scalars: self.scalars.clone(), // Clone the scalars
//             r_i: self.r_i,
//         }
//     }
// }

impl<G> KeyEntropy<G>
where
    G: Group + GroupEncoding + for<'a> std::ops::Mul<<G as Group>::Scalar, Output = G>, // * MY CODE: ADDED
{
    /// Generate a new set of random params
    // * MY CODE: ADDED, session_id is now an input parameter
    pub fn generate<R: CryptoRng + RngCore>(t: u8, n: u8, rng: &mut R, session_id: [u8; 32]) -> Self {
        // 11.2(a)
        // * MY CODE: COMMENTED OUT
        // let session_id = rng.gen();

        // * MY CODE: ADDED
        // Generate random scalars and their corresponding group elements
        let mut scalars = Vec::with_capacity(t as usize);
        let mut points = Vec::with_capacity(t as usize);

        // * MY CODE: ADDED, generate random scalars and corresponding group elements
        for _ in 0..t {
            let random_scalar = <G as Group>::Scalar::random(&mut *rng); // Reborrow rng
            let point = G::generator() * random_scalar;                 // Compute corresponding group element
            scalars.push(random_scalar);
            points.push(point);
        }

        // * MY CODE: ADDED, store the scalar-based and group-based polynomials
        // Create scalar-based and group-based polynomials
        let scalars_clone = scalars.clone(); // Clone the scalars before moving them
        let scalar_polynomial = Polynomial::new(scalars);
        // let points = points.into_iter().map(|p| p.to_bytes()).collect();
        let points_clone = points.clone();
        // let point_polynomial = GroupPolynomial::new(points);
        let point_polynomial = scalar_polynomial.commit(); // Commit the group-based polynomial


        println!("Generated scalars: {:?}", scalars_clone);
        println!("Generated points: {:?}", points_clone);
        // println!("Generated scalar polynomial: {:?}", scalar_polynomial);
        println!("Generated point polynomial: {:?}", point_polynomial);
        println!("Generated session id: {:?}", session_id);
        KeyEntropy {
            t,
            n,
            session_id,
            polynomial: point_polynomial, // * MY CODE: ADDED, Store the group-based polynomial
            scalar_polynomial, // * MY CODE: ADDED, Store the scalar-based polynomial
            scalars: scalars_clone,  // * MY CODE: ADDED, Store the scalars, coefficients of the scalar-based polynomial
            r_i: random_bytes(rng),
        }
    }

    /// Getter for `session_id`.
    // * MY CODE: ADDED
    pub fn get_session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// Getter for `r_i`.
    // * MY CODE: ADDED
    pub fn get_r_i(&self) -> &[u8; 32] {
        &self.r_i
    }

    /// Getter for `polynomial`.
    // * MY CODE: ADDED
    pub fn get_point_based_polynomial(&self) -> &GroupPolynomial<G> {
        &self.polynomial
    }

    // * MY CODE: ADDED
    pub fn get_scalar_based_polynomial(&self) -> &Polynomial<G> {
        &self.scalar_polynomial
    }

    // * MY CODE: ADDED
    pub fn get_scalar_coeffs(&self) -> &Vec<G::Scalar> {
        &self.scalars
    }

    // * MY CODE: ADDED, Clone the scalar-based polynomial
    pub fn clone_scalar_polynomial(&self) -> Polynomial<G> {
        let cloned_polynomial = Polynomial::new(self.scalar_polynomial.iter().cloned().collect());

        // commented out, requires Debug implementation for Polynomial
        // Verification step: Ensure the cloned polynomial matches the original
        // assert_eq!(
        //     &cloned_polynomial,
        //     &self.scalar_polynomial,
        //     "Cloning failed: scalar_polynomial does not match the original"
        // );
        if cloned_polynomial != self.scalar_polynomial {
            panic!("Cloning failed: scalar_polynomial does not match the original");
        }

        println!("Clone verification successful. Cloned polynomial matches the original.");

        cloned_polynomial
    }
}


// TODO: REOPEN - ORIGINAL
// impl<G> KeyEntropy<G>
// where
//     G: Group,
// {
//     /// Generate a new set of random params
//     pub fn generate<R: CryptoRng + RngCore>(t: u8, n: u8, rng: &mut R) -> Self {
//         // 11.2(a)
//         let session_id = rng.gen();
//
//         // 11.2(b)
//         let polynomial = Polynomial::random(rng, (t - 1) as usize);   // TODO: REMOVE THIS CUSTOM WRAPPER PolynomialWrapper::random(rng, (t - 1) as usize);
//
//         KeyEntropy {
//             t,
//             n,
//             session_id,
//             polynomial,
//             r_i: random_bytes(rng),
//         }
//     }
//
//     pub fn generate_refresh<R: CryptoRng + RngCore>(t: u8, n: u8, rng: &mut R) -> Self {
//         let mut ent = Self::generate(t, n, rng);
//         ent.polynomial.reset_contant();
//         ent
//     }
// }

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

    // * MY CODE: ADDED
    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    /// Decryption error
    #[error("Decryption Error")]
    DecryptionError,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Abort")]
    Abort(&'static str),

    #[error("Error during key refresh or recovery protocol")]
    InvalidRefresh,

    // * MY CODE: ADDED
    #[error("Invalid polynomial: {0}")]
    InvalidPolynomial(String), 

    // * MY CODE: ADDED
    #[error("Invalid polynomial length: {0}")]
    InvalidPolynomialLength(String), 

    // * MY CODE: ADDED
    #[error("Not Implemented: {0}")]
    NotImplemented(String),

    // * MY CODE: ADDED
    #[error("Invalid message counter: {0}")]
    InvalidMsgCountMismatch(String),

    // * MY CODE: ADDED
    #[error("Invalid session id: {0}")]
    InvalidSessionId(String),

    // * MY CODE: ADDED
    #[error("Invalid party id: {0}")]
    InvalidPartyId(String),

    // * MY CODE: ADDED
    #[error("Duplicate Messages: {0}")]
    DuplicateMessage(String),

    // * MY CODE: ADDED
    #[error("Missing Encryption Key")]
    MissingEncryptionKey,

    // * MY CODE: ADDED
    #[error("Missing Decryption Key")]
    MissingDecryptionKey,

    // * MY CODE: ADDED
    #[error("Invalid Decryption Key")]
    InvalidDecryptionKey
}
