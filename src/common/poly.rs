use std::ops::Deref;

use crypto_bigint::{Encoding, U256};
use curve25519_dalek::{traits::Identity, EdwardsPoint, Scalar};
use ff::Field;
use rand::{CryptoRng, RngCore};

use sl_mpc_mate::{
    math::factorial_range,
    message::{Opaque, GR},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A polynomial with coefficients of type `Scalar`.
#[derive(Zeroize, ZeroizeOnDrop, Clone, Debug)]
pub struct Polynomial {
    /// The coefficients of the polynomial.
    pub coeffs: Vec<Scalar>,
}

#[allow(unused)]
impl Polynomial {
    /// Create a new polynomial with the given coefficients.
    pub fn new(coeffs: Vec<Scalar>) -> Self {
        Self { coeffs }
    }

    /// Create a new polynomial with random coefficients.
    pub fn random<R: CryptoRng + RngCore>(rng: &mut R, degree: usize) -> Self {
        let mut coeffs = Vec::with_capacity(degree + 1);
        for _ in 0..=degree {
            coeffs.push(Scalar::random(&mut *rng));
        }
        Self { coeffs }
    }

    /// Sample a random polynomial with zero constant term.
    /// This is needed for key refresh
    pub(crate) fn random_with_zero<R: CryptoRng + RngCore>(rng: &mut R, degree: usize) -> Self {
        let mut coeffs = Vec::with_capacity(degree + 1);

        // Need this for key-refresh
        coeffs.push(Scalar::ZERO);

        for _ in 1..=degree {
            coeffs.push(Scalar::random(&mut *rng));
        }
        Self { coeffs }
    }

    /// Evaluate the polynomial at 0 (the constant term).
    pub fn get_constant(&self) -> Scalar {
        self.coeffs[0]
    }

    /// Commit to this polynomial by multiplying each coefficient by the generator.
    pub fn commit(&self) -> GroupPolynomial {
        let mut points = Vec::with_capacity(self.coeffs.len());
        for coeff in &self.coeffs {
            points.push(Opaque::from(EdwardsPoint::mul_base(coeff)));
        }
        GroupPolynomial::new(points)
    }
    /// Computes the n_i derivative of a polynomial with coefficients u_i_k at the point x
    ///
    /// `n`: order of the derivative
    ///
    /// `x`: point at which to compute the derivative.
    /// Arithmetic is done modulo the curve order
    pub fn derivative_at(&self, n: u8, x: Scalar) -> Scalar {
        (n as usize..self.coeffs.len())
            .map(|i| {
                let num: U256 = factorial_range(i - n as usize, i);
                let scalar_num = Scalar::from_bytes_mod_order(num.to_le_bytes());
                let coeff = self.coeffs[i];
                // Take exponent of x
                // TODO: Review this, does not use any optimisations
                let result = x.pow_vartime([(i - n as usize) as u64]);
                scalar_num * coeff * result
            })
            .fold(Scalar::ZERO, |acc, x| acc + x)
    }

    /// Evaluates the polynomial at the point x
    /// Arithmetic is done modulo the curve order
    pub fn evaluate_at(&self, x: Scalar) -> Scalar {
        (0..self.coeffs.len())
            .map(|i| self.coeffs[i] * x.pow_vartime([i as u64]))
            .fold(Scalar::ZERO, |acc, x| acc + x)
    }
}

/// A polynomial with coefficients of type `ProjectivePoint`.
#[derive(bincode::Encode, bincode::Decode, Clone, Debug, PartialEq, Eq)]
pub struct GroupPolynomial {
    /// The coefficients of the polynomial.
    pub coeffs: Vec<Opaque<EdwardsPoint, GR>>,
}

// FIXME: Add the fixes from the ToB audit for DKLs
impl GroupPolynomial {
    /// Create a new polynomial with the given coefficients.
    pub fn new(coeffs: Vec<Opaque<EdwardsPoint, GR>>) -> Self {
        Self { coeffs }
    }

    /// Evaluate the polynomial at 0 (the constant term).
    pub fn get_constant(&self) -> EdwardsPoint {
        self.coeffs[0].0
    }

    /// Add another polynomial's coefficients element wise to this one inplace.
    /// If the other polynomial has more coefficients than this one, the extra
    /// coefficients are ignored.
    pub fn add_mut(&mut self, other: &Self) {
        self.coeffs
            .iter_mut()
            .zip(&other.coeffs)
            .for_each(|(a, b)| {
                a.0 += b.0;
            });
    }
    /// Get the coeffs of the polynomial derivative
    pub fn derivative_coeffs(&self, n: usize) -> Vec<EdwardsPoint> {
        let (_, sub_v) = self.coeffs.split_at(n);

        sub_v
            .iter()
            .enumerate()
            .map(|(position, u_i)| {
                let num: U256 = factorial_range(position, position + n);
                let scalar_num = Scalar::from_bytes_mod_order(num.to_le_bytes());
                *u_i * scalar_num
            })
            .collect()
    }
    /// Evaluates the polynomial at the point x
    /// Arithmetic is done modulo the curve order
    pub fn evaluate_at(&self, x: &Scalar) -> EdwardsPoint {
        (0..self.coeffs.len())
            .map(|i| self.coeffs[i] * x.pow_vartime([i as u64]))
            .fold(EdwardsPoint::identity(), |acc, x| acc + x)
    }
}

impl Deref for Polynomial {
    type Target = [Scalar];

    fn deref(&self) -> &Self::Target {
        &self.coeffs
    }
}

impl Deref for GroupPolynomial {
    type Target = [Opaque<EdwardsPoint, GR>];

    fn deref(&self) -> &Self::Target {
        &self.coeffs
    }
}

#[cfg(test)]
mod tests {
    #[allow(deprecated)]
    use curve25519_dalek::{constants::BASEPOINT_ORDER, EdwardsPoint, Scalar};
    use sl_mpc_mate::message::Opaque;

    use crate::common::{GroupPolynomial, Polynomial};

    #[test]
    fn test_derivative_large() {
        // f(x) = 1 + 2x + (p-1)x^2

        #[allow(deprecated)]
        let order = BASEPOINT_ORDER;
        // p is the curve order
        let u_i_k = vec![
            Scalar::from(1_u64),
            Scalar::from(2_u64),
            order - Scalar::from(1_u64),
        ];

        // f'(x) = 2 + 2(p-1)x
        // f'(2) = (4p-2) mod p => p - 2
        let poly = Polynomial::new(u_i_k);
        let n = 1;

        let result = poly.derivative_at(n, Scalar::from(2_u64));

        println!("result: {:?}", result);
        println!("order: {:?}", order - Scalar::from(2_u64));
        assert_eq!(result, order - Scalar::from(2_u64),);
    }

    #[test]
    fn test_derivative_normal() {
        // f(x) = 1 + 2x + 3x^2 + 4x^3
        let u_i_k = vec![
            Scalar::from(1_u64),
            Scalar::from(2_u64),
            Scalar::from(3_u64),
            Scalar::from(4_u64),
        ];

        let poly = Polynomial::new(u_i_k);

        // f''(x) = 6 + 24x
        let n = 2;
        // f''(2) = 6 + 24(2) = 54
        let result = poly.derivative_at(n, Scalar::from(2_u64));

        assert_eq!(result, Scalar::from(54_u64));
    }
    #[test]
    fn test_derivative_coeffs() {
        // f(x) = 1 + 2x + 3x^2 + 4x^3
        let u_i_k = vec![
            Opaque::from(EdwardsPoint::mul_base(&Scalar::from(1_u64))),
            Opaque::from(EdwardsPoint::mul_base(&Scalar::from(2_u64))),
            Opaque::from(EdwardsPoint::mul_base(&Scalar::from(3_u64))),
            Opaque::from(EdwardsPoint::mul_base(&Scalar::from(4_u64))),
        ];

        let poly = GroupPolynomial::new(u_i_k);

        // f''(x) = 6 + 24x
        let n = 2;
        let coeffs = poly.derivative_coeffs(n);

        assert_eq!(coeffs.len(), 2);
        assert_eq!(coeffs[0], EdwardsPoint::mul_base(&Scalar::from(6_u64)));
        assert_eq!(coeffs[1], EdwardsPoint::mul_base(&Scalar::from(24_u64)));

        // f'(x) = 2 + 6x + 12x^2
        let coeffs = poly.derivative_coeffs(1);

        assert_eq!(coeffs.len(), 3);
        assert_eq!(coeffs[0], EdwardsPoint::mul_base(&Scalar::from(2_u64)));
        assert_eq!(coeffs[1], EdwardsPoint::mul_base(&Scalar::from(6_u64)));
        assert_eq!(coeffs[2], EdwardsPoint::mul_base(&Scalar::from(12_u64)));
    }
}
