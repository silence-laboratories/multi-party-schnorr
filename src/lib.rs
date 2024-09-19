//! Threshold Signing Scheme for EdDSA in Rust.
#![deny(unsafe_code)]
#![doc = include_str!("../README.md")]

/// The `keygen` module contains the key generation protocol
pub mod keygen;

/// The `sign` module contains the signing protocol
pub mod sign;

/// Common utility functions and types
pub mod common;

pub const VERSION: u16 = 1;

#[cfg(feature = "eddsa")]
pub use curve25519_dalek::{edwards::CompressedEdwardsY, EdwardsPoint};

#[cfg(feature = "taproot")]
pub use k256::{schnorr::VerifyingKey, AffinePoint, ProjectivePoint, PublicKey};

pub use elliptic_curve::group;
