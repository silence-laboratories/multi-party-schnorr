// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Signing-curve hooks for MPC hard derivation (VRF bytes → Δ, tweak root keyshare).
//! Implement on the signing group in `derive::impls` (here: Ed25519) or in DKLS (e.g. k256).

use crate::traits::GroupElem;

/// Signing group used to apply a Ristretto VRF output to a root DKG keyshare.
/// VRF evaluation stays on [`crate::impls::ristretto::VrfPoint`]. Only
/// [`Self::delta_from_vrf`] is curve-specific; `Δ / t` uses [`ff::Field`] on
/// [`GroupElem::Scalar`] (`From<u64>`, [`Field::invert`](ff::Field::invert)).
pub trait HardDeriveSigning: GroupElem {
    /// Map `delta_prime` (|q| + κ bytes from VRF output) to Δ mod the signing scalar field.
    fn delta_from_vrf(delta_prime: &[u8]) -> Self::Scalar;
}
