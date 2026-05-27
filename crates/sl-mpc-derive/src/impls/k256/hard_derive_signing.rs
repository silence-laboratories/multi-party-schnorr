// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use crypto_bigint::U512;
use elliptic_curve::ops::Reduce;
use k256::{ProjectivePoint, Scalar};

use crate::traits::HardDeriveSigning;

impl HardDeriveSigning for ProjectivePoint {
    /// Map delta_prime (|q|+κ bytes from VRF output) to Δ mod n (secp256k1 scalar field).
    /// VRF bytes come from Ristretto eval; this is scalar reduction on the signing curve.
    fn delta_from_vrf(delta_prime: &[u8]) -> Scalar {
        let mut wide = [0u8; 64];
        let n = delta_prime.len().min(64);
        wide[..n].copy_from_slice(&delta_prime[..n]);
        Reduce::<U512>::reduce(U512::from_be_slice(&wide))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::HARD_DERIVE_DELTA_BYTES;

    #[test]
    fn delta_from_vrf_is_deterministic() {
        let delta_prime = vec![0x42u8; HARD_DERIVE_DELTA_BYTES];
        let a = ProjectivePoint::delta_from_vrf(&delta_prime);
        let b = ProjectivePoint::delta_from_vrf(&delta_prime);
        assert_eq!(a, b);
    }
}
