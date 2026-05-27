// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use curve25519_dalek::{EdwardsPoint, Scalar};

use crate::traits::HardDeriveSigning;

impl HardDeriveSigning for EdwardsPoint {
    fn delta_from_vrf(delta_prime: &[u8]) -> Scalar {
        let mut wide = [0u8; 64];
        let n = delta_prime.len().min(64);
        wide[..n].copy_from_slice(&delta_prime[..n]);
        Scalar::from_bytes_mod_order_wide(&wide)
    }
}
