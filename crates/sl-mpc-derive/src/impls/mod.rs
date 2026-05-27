// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Curve-specific implementations of [`crate::traits`].

#[cfg(feature = "eddsa")]
pub mod ed25519;

#[cfg(feature = "eddsa")]
pub mod ristretto;

/// secp256k1 (`k256`) hard-derive signing hooks (VRF stays on Ristretto; no k256 hash-to-curve).
#[cfg(feature = "k256")]
pub mod k256;
