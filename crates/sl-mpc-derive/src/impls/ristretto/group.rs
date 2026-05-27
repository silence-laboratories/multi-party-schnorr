// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! VRF group hooks for Ristretto (hash-to-curve + partial-point checks).

use curve25519_dalek::{traits::IsIdentity, RistrettoPoint};

use crate::{
    impls::ristretto::hash_to_curve::RistrettoRo,
    traits::{
        hash_to_curve::{HashToCurve, HashToCurveError},
        GroupElem, ScalarReduce,
    },
};

/// Group type for MPC VRF together with its RoHMAC hash-to-curve backend and point checks.
pub trait VrfGroup: GroupElem {
    /// [`HashToCurve`] marker whose [`HashToCurve::Point`] is `Self`.
    type HashBackend: HashToCurve<Point = Self>;

    /// Map protocol message chunks to `M = hash_curve(m)` for this VRF curve.
    fn hash_vrf_message(parts: &[&[u8]]) -> Result<Self, HashToCurveError> {
        Self::HashBackend::hash_curve(parts)
    }

    /// Whether a partial VRF contribution `Z_j` is admissible (non-identity; curve-specific).
    fn is_valid_partial_vrf_point(point: &Self) -> bool;
}

impl VrfGroup for RistrettoPoint {
    type HashBackend = RistrettoRo;

    fn is_valid_partial_vrf_point(point: &Self) -> bool {
        !IsIdentity::is_identity(point)
    }
}

/// Scalar field for Ristretto / Curve25519 VRF (`G::Scalar` in eval).
pub trait VrfScalar: ScalarReduce<[u8; 32]> {}

impl VrfScalar for curve25519_dalek::Scalar {}
