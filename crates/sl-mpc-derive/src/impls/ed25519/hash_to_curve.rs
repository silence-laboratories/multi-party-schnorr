// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use curve25519_dalek::{traits::IsIdentity, EdwardsPoint};
use elliptic_curve::group::GroupEncoding;

use crate::{
    oracle::RoHmac,
    traits::hash_to_curve::{HashToCurve, HashToCurveError},
};

/// Maximum cofactor-clearing attempts for Edwards hash-to-curve.
const MAX_HASH_CURVE_ATTEMPTS: u32 = 256;

/// Edwards25519: cofactor clearing + rejection sampling on 32-byte RO trials.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EdwardsRo;

impl HashToCurve for EdwardsRo {
    type Point = EdwardsPoint;

    fn hash_curve(parts: &[&[u8]]) -> Result<Self::Point, HashToCurveError> {
        let mut ro = RoHmac::new();
        for part in parts {
            ro.encode_and_update(part);
        }

        for i in 0..MAX_HASH_CURVE_ATTEMPTS {
            let mut trial = ro.clone();
            trial.encode_and_update_i32(i as i32);
            if let Some(point) = try_hash_bytes_to_point(&trial.bitlen256()) {
                return Ok(point);
            }
        }

        Err(HashToCurveError::ExhaustedAttempts)
    }
}

/// Map 32 bytes to an Edwards point in the prime-order subgroup.
pub fn try_hash_bytes_to_point(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    let p: EdwardsPoint = Option::from(EdwardsPoint::from_bytes(bytes))?;
    let p = p.mul_by_cofactor();
    if IsIdentity::is_identity(&p) || p.is_small_order() {
        return None;
    }
    Some(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::traits::{Identity, IsIdentity};
    use elliptic_curve::group::GroupEncoding;

    #[test]
    fn encoding_is_prefix_sensitive_edwards() {
        let p1 = EdwardsRo::hash_curve(&[b"AABBCCDD", b"EEFF"]).unwrap();
        let p2 = EdwardsRo::hash_curve(&[b"AABB", b"CCDDEEFF"]).unwrap();
        assert_ne!(p1, p2);
    }

    #[test]
    fn hash_curve_edwards_is_deterministic() {
        let p1 = EdwardsRo::hash_curve(&[b"alpha", b"beta"]).unwrap();
        let p2 = EdwardsRo::hash_curve(&[b"alpha", b"beta"]).unwrap();
        assert_eq!(p1, p2);
    }

    #[test]
    fn try_hash_bytes_rejects_identity_after_cofactor() {
        let identity = <EdwardsPoint as Identity>::identity();
        assert_eq!(try_hash_bytes_to_point(&identity.to_bytes()), None);
    }

    #[test]
    fn hash_curve_edwards_yields_prime_order_point() {
        let p = EdwardsRo::hash_curve(&[b"vrf-input"]).unwrap();
        assert!(!IsIdentity::is_identity(&p));
        assert!(!p.is_small_order());
    }
}
