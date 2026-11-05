// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! MobileCoin-compatible hash-to-point for key images.
//!
//! Matches `mc_crypto_ring_signature::hash_to_point` without depending on MC crates:
//! `Blake2b-512("mc_onetime_key_hash_to_point" || compress(P))` → `RistrettoPoint::from_hash`.

use blake2::{Blake2b512, Digest};
use curve25519_dalek::ristretto::RistrettoPoint;

/// Domain separator for onetime-key hash-to-point (MobileCoin).
pub const HASH_TO_POINT_DOMAIN_TAG: &str = "mc_onetime_key_hash_to_point";

/// `H_p(P)` used in `I = x · H_p(P)`.
pub fn hash_to_point(public_key: &RistrettoPoint) -> RistrettoPoint {
    let mut hasher = Blake2b512::new();
    hasher.update(HASH_TO_POINT_DOMAIN_TAG.as_bytes());
    hasher.update(public_key.compress().as_bytes());
    RistrettoPoint::from_hash(hasher)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, Scalar};
    use elliptic_curve::Group;

    #[test]
    fn hash_to_point_deterministic() {
        let p = RistrettoPoint::generator() * Scalar::from(7u64);
        assert_eq!(hash_to_point(&p), hash_to_point(&p));
    }

    #[test]
    fn hash_to_point_differs_for_distinct_keys() {
        let p1 = RistrettoPoint::generator() * Scalar::from(1u64);
        let p2 = RistrettoPoint::generator() * Scalar::from(2u64);
        assert_ne!(hash_to_point(&p1), hash_to_point(&p2));
    }

    #[test]
    fn hash_to_point_basepoint_non_identity() {
        let hp = hash_to_point(&RISTRETTO_BASEPOINT_POINT);
        assert!(!bool::from(hp.is_identity()));
    }
}
