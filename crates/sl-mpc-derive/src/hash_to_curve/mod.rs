// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! RoHMAC hash-to-curve: [`HashToCurve`], protocol constants, and curve backends.
//!
//! The trait definition and error type live in [`crate::traits::hash_to_curve`].
//! Concrete maps: [`EdwardsRo`] (Ed25519), [`RistrettoRo`] (MPC VRF).

pub use crate::oracle::ro_hash_string;
pub use crate::protocol::*;
pub use crate::traits::hash_to_curve::{HashToCurve, HashToCurveError};

pub use crate::impls::ed25519::{try_hash_bytes_to_point, EdwardsRo};

pub use crate::impls::ristretto::RistrettoRo;
