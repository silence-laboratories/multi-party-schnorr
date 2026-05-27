// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! [`HashToCurve`] trait. Protocol sizes: [`crate::protocol`]. Curve backends: [`crate::impls`].

use thiserror::Error;

use crate::traits::GroupElem;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HashToCurveError {
    #[error("hash_to_curve: no valid point after 256 attempts")]
    ExhaustedAttempts,
}

/// Transforms protocol byte chunks to a group element.
///
/// `Self` is **not** the curve point. It is a zero-sized **algorithm marker**
/// (e.g. [`crate::impls::ed25519::EdwardsRo`], [`crate::impls::ristretto::RistrettoRo`])
/// that fixes *how* inputs are encoded (RoHMAC over `parts` in order) and how the
/// digest is turned into [`Self::Point`]. Callers use `Backend::hash_curve(parts)`.
///
/// [`Self::Point`] is the elliptic-curve type that comes out of
/// that map, e.g. `EdwardsPoint` or `RistrettoPoint`.
///
/// ## Several `HashToCurve` impls with the same [`Self::Point`]
///
/// Distinct markers can share one [`Self::Point`] if they use
/// different encodings. That is only useful when two protocols genuinely need
/// different maps onto the same curve; otherwise pick a single canonical marker
/// per curve (here: `RistrettoRo` → VRF, `EdwardsRo` → Ed25519-side tooling).
///
/// In production VRF code, [`crate::impls::ristretto::group::VrfGroup`] ties one
/// group type to exactly one backend via
/// `type HashBackend: HashToCurve<Point = Self>`, so `hash_vrf_message` is unambiguous.
pub trait HashToCurve {
    /// Curve point type produced by **this** encoding (`Self`), not by `Self` itself.
    type Point: GroupElem;

    /// `parts` are fed in order through this backend's RoHMAC oracle, then mapped to a point.
    fn hash_curve(parts: &[&[u8]]) -> Result<Self::Point, HashToCurveError>;
}
