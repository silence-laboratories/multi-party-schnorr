// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Default MPC VRF curve: prime-order Ristretto (not EdDSA `EdwardsPoint`).

use crate::{impls::ristretto::hash_to_curve::RistrettoRo, traits::hash_to_curve::HashToCurve};

/// Prime-order curve25519 group used for MPC VRF keys and evaluation.
pub type VrfPoint = <RistrettoRo as HashToCurve>::Point;

/// RoHMAC hash-to-curve backend for [`VrfPoint`].
pub type VrfHashToCurve = RistrettoRo;

#[cfg(test)]
mod tests {
    use curve25519_dalek::Scalar;
    use elliptic_curve::Group;

    use crate::{math::get_lagrange_coeff, traits::GroupElem};

    use super::VrfPoint;

    fn assert_vrf_point_is_group_elem() {
        fn check<G: GroupElem>() {}
        check::<VrfPoint>();
    }

    #[test]
    fn vrf_point_satisfies_group_elem() {
        assert_vrf_point_is_group_elem();
    }

    #[test]
    fn vrf_point_lagrange_and_generator() {
        let g = VrfPoint::generator();
        let s = Scalar::from(3u64);
        let p = g * s;
        let coeff = get_lagrange_coeff::<VrfPoint>(&1, [0u8, 1, 2].into_iter());
        let _ = p * coeff;
    }
}
