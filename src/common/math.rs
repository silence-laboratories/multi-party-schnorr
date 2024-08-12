use crypto_bigint::subtle::ConstantTimeEq;
use curve25519_dalek::{traits::Identity, EdwardsPoint, Scalar};
use ff::Field;
use sl_mpc_mate::math::factorial_range;

use super::{traits::GroupElem, utils::ToCurveScalar};

/// Feldman verification
pub fn feldman_verify(
    u_i_k: &[EdwardsPoint],
    x_i: &Scalar,
    f_i_value: &Scalar,
    g: &EdwardsPoint,
) -> Option<bool> {
    if u_i_k.is_empty() {
        return None;
    }

    let mut point = EdwardsPoint::identity();

    for (i, coeff) in u_i_k.iter().enumerate() {
        // x_i^i mod p
        let val = x_i.pow([i as u64]);

        // x_i^i * coeff mod p
        point += *coeff * val;
    }

    let expected_point = *g * f_i_value;

    Some(point == expected_point)
}

/// Get the multipliers for the coefficients of the polynomial,
/// given the x_i (point of evaluation),
/// `n_i` (order of derivative)
/// `n` (degree of polynomial - 1)
/// `p` prime order of field
pub fn polynomial_coeff_multipliers(x_i: &Scalar, n_i: usize, n: usize) -> Vec<Scalar> {
    let mut v = vec![Scalar::ZERO; n];
    v.iter_mut()
        .enumerate()
        .take(n)
        .skip(n_i)
        .for_each(|(idx, vi)| {
            let num: Scalar = factorial_range(idx - n_i, idx).to_25519_scalar();
            let exponent = [(idx - n_i) as u64];
            let result = x_i.pow_vartime(exponent);
            *vi = num * result;
        });

    v
}

pub fn get_lagrange_coeff<G: GroupElem>(
    my_party_id: &u8,
    party_ids: impl Iterator<Item = u8>,
) -> G::Scalar {
    let mut coeff = G::Scalar::ONE;
    let x_i = G::Scalar::from((my_party_id + 1) as u64);
    for party_id in party_ids {
        let x_j = G::Scalar::from((party_id + 1) as u64);
        if x_i.ct_ne(&x_j).into() {
            let sub = x_j - x_i;

            // SAFETY: Invert is safe because we check x_j != x_i, so sub is not zero.
            coeff *= x_j * sub.invert().unwrap();
        }
    }
    coeff
}

pub(crate) fn _get_lagrange_coeff_list(party_points: &[Scalar]) -> Vec<Scalar> {
    let mut coeff_list = Vec::with_capacity(party_points.len());
    for x_i in party_points {
        let mut coeff = Scalar::ONE;
        for x_j in party_points {
            if x_i.ct_ne(x_j).into() {
                let sub = x_j - x_i;
                // SAFETY: Invert is safe because we check x_j != x_i, so sub is not zero.
                coeff *= x_j * sub.invert();
            }
        }
        coeff_list.push(coeff);
    }
    coeff_list
}
