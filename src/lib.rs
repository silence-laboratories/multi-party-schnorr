// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Threshold Signing Scheme for EdDSA in Rust.
#![deny(unsafe_code)]
#![doc = include_str!("../README.md")]

/// The `keygen` module contains the key generation protocol
pub mod keygen;

/// The `sign` module contains the signing protocol
pub mod sign;

/// Threshold MPC VRF (DKG keygen + multi-round evaluation)
#[cfg(feature = "vrf")]
pub mod vrf;

/// Common utility functions and types
pub mod common;
pub mod derive;
#[cfg(all(feature = "eddsa", feature = "vrf"))]
mod ed25519_vrf_derive;
pub mod quorum_change;
#[cfg(feature = "eddsa")]
mod soft_derive;

pub const VERSION: u16 = 1;

#[cfg(feature = "eddsa")]
pub use curve25519_dalek;

#[cfg(feature = "taproot")]
pub use k256::{schnorr::VerifyingKey, AffinePoint, ProjectivePoint, PublicKey};

pub use elliptic_curve::group;
