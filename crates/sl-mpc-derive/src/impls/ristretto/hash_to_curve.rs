// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Ristretto RoHMAC hash-to-curve ([`super::point::VrfPoint`]).

use curve25519_dalek::RistrettoPoint;
use sha2::Sha512;

use crate::{
    oracle::ro_hmac_digest,
    traits::hash_to_curve::{HashToCurve, HashToCurveError},
};

/// Ristretto backend for VRF `M = hash_curve(m)`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RistrettoRo;

impl HashToCurve for RistrettoRo {
    type Point = RistrettoPoint;

    fn hash_curve(parts: &[&[u8]]) -> Result<Self::Point, HashToCurveError> {
        let digest = ro_hmac_digest(parts);
        Ok(RistrettoPoint::hash_from_bytes::<Sha512>(&digest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::traits::IsIdentity;

    #[test]
    fn encoding_is_prefix_sensitive_ristretto() {
        let p1 = RistrettoRo::hash_curve(&[b"AABBCCDD", b"EEFF"]).unwrap();
        let p2 = RistrettoRo::hash_curve(&[b"AABB", b"CCDDEEFF"]).unwrap();
        assert_ne!(p1, p2);
    }

    #[test]
    fn hash_curve_ristretto_non_identity() {
        let p = RistrettoRo::hash_curve(&[b"vrf-input"]).unwrap();
        assert!(!IsIdentity::is_identity(&p));
    }
}
