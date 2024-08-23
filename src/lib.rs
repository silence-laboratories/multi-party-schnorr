//! Threshold Signing Scheme for EdDSA in Rust.
#![deny(unsafe_code)]

/// The `keygen` module contains the key generation protocol
pub mod keygen;

/// The `sign` module contains the signing protocol
pub mod sign;

/// Common utility functions and types
pub mod common;

pub const VERSION: u16 = 1;

pub use curve25519_dalek::{edwards::CompressedEdwardsY, EdwardsPoint};
pub use elliptic_curve::group;
