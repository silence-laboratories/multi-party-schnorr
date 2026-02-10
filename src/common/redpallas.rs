// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::iter::Sum;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use blake2b_simd::Params as Blake2bParams;
use crypto_bigint::subtle::ConstantTimeEq;
use elliptic_curve::subtle;
use ff::FromUniformBytes;
use group::{Group, GroupEncoding};
use pasta_curves::{pallas, Fq};
use rand_core::RngCore;

use crate::common::traits::ScalarReduce;

/// Orchard SpendAuth basepoint for RedDSA (Pallas).
/// Same as reddsa orchard::SpendAuth: pallas::Point::hash_to_curve("z.cash:Orchard")(b"G").
const ORCHARD_SPENDAUTHSIG_BASEPOINT_BYTES: [u8; 32] = [
    99, 201, 117, 184, 132, 114, 26, 141, 12, 161, 112, 123, 227, 12, 127, 12, 95, 68, 95, 62, 124,
    24, 141, 59, 6, 214, 241, 40, 179, 35, 85, 183,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RedPallasPoint(pub pallas::Point);

impl RedPallasPoint {
    /// Hash bytes to a scalar using BLAKE2b-512.
    pub fn hash_randomizer(m: &[u8]) -> Fq {
        const LABEL: &[u8] = b"SchnorrRedPallas";
        let hash = Blake2bParams::new()
            .hash_length(64)
            .personal(LABEL)
            .to_state()
            .update(m)
            .finalize();
        <Fq as FromUniformBytes<64>>::from_uniform_bytes(hash.as_array())
    }
}

impl Mul<&Fq> for RedPallasPoint {
    type Output = RedPallasPoint;

    fn mul(self, scalar: &Fq) -> Self::Output {
        RedPallasPoint(self.0 * *scalar)
    }
}

impl Mul<Fq> for RedPallasPoint {
    type Output = RedPallasPoint;

    fn mul(self, scalar: Fq) -> Self::Output {
        RedPallasPoint(self.0 * scalar)
    }
}

impl MulAssign<&Fq> for RedPallasPoint {
    fn mul_assign(&mut self, scalar: &Fq) {
        *self = *self * scalar;
    }
}

impl MulAssign<Fq> for RedPallasPoint {
    fn mul_assign(&mut self, scalar: Fq) {
        *self = *self * scalar;
    }
}

impl Add for RedPallasPoint {
    type Output = RedPallasPoint;

    fn add(self, rhs: RedPallasPoint) -> Self::Output {
        RedPallasPoint(self.0 + rhs.0)
    }
}

impl Add<&RedPallasPoint> for RedPallasPoint {
    type Output = RedPallasPoint;

    fn add(self, rhs: &RedPallasPoint) -> Self::Output {
        RedPallasPoint(self.0 + rhs.0)
    }
}

impl AddAssign for RedPallasPoint {
    fn add_assign(&mut self, rhs: RedPallasPoint) {
        self.0 += rhs.0;
    }
}

impl AddAssign<&RedPallasPoint> for RedPallasPoint {
    fn add_assign(&mut self, rhs: &RedPallasPoint) {
        self.0 += rhs.0;
    }
}

impl Sub for RedPallasPoint {
    type Output = RedPallasPoint;

    fn sub(self, rhs: RedPallasPoint) -> Self::Output {
        RedPallasPoint(self.0 - rhs.0)
    }
}

impl Sub<&RedPallasPoint> for RedPallasPoint {
    type Output = RedPallasPoint;

    fn sub(self, rhs: &RedPallasPoint) -> Self::Output {
        RedPallasPoint(self.0 - rhs.0)
    }
}

impl SubAssign for RedPallasPoint {
    fn sub_assign(&mut self, rhs: RedPallasPoint) {
        self.0 -= rhs.0;
    }
}

impl SubAssign<&RedPallasPoint> for RedPallasPoint {
    fn sub_assign(&mut self, rhs: &RedPallasPoint) {
        self.0 -= rhs.0;
    }
}

impl Neg for RedPallasPoint {
    type Output = RedPallasPoint;

    fn neg(self) -> Self::Output {
        RedPallasPoint(-self.0)
    }
}

impl Sum for RedPallasPoint {
    fn sum<I: Iterator<Item = RedPallasPoint>>(iter: I) -> Self {
        RedPallasPoint(iter.map(|p| p.0).sum())
    }
}

impl<'a> Sum<&'a RedPallasPoint> for RedPallasPoint {
    fn sum<I: Iterator<Item = &'a RedPallasPoint>>(iter: I) -> Self {
        RedPallasPoint(iter.map(|p| p.0).sum())
    }
}

impl Group for RedPallasPoint {
    type Scalar = Fq;
    fn generator() -> Self {
        let mut repr = <pallas::Point as GroupEncoding>::Repr::default();
        repr.as_mut()
            .copy_from_slice(&ORCHARD_SPENDAUTHSIG_BASEPOINT_BYTES);
        Self(pallas::Point::from_bytes(&repr).unwrap())
    }
    fn identity() -> Self {
        Self(pallas::Point::identity())
    }
    fn is_identity(&self) -> crypto_bigint::subtle::Choice {
        self.0.is_identity()
    }
    fn double(&self) -> Self {
        Self(self.0.double())
    }

    fn random(mut rng: impl RngCore) -> Self {
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        let scalar = <Fq as FromUniformBytes<64>>::from_uniform_bytes(&bytes);
        Self(Self::generator().0 * scalar)
    }
}

impl GroupEncoding for RedPallasPoint {
    type Repr = <pallas::Point as GroupEncoding>::Repr;
    fn from_bytes(bytes: &Self::Repr) -> subtle::CtOption<Self> {
        pallas::Point::from_bytes(bytes).map(Self)
    }
    fn from_bytes_unchecked(bytes: &Self::Repr) -> subtle::CtOption<Self> {
        pallas::Point::from_bytes_unchecked(bytes).map(Self)
    }
    fn to_bytes(&self) -> Self::Repr {
        self.0.to_bytes()
    }
}

impl ConstantTimeEq for RedPallasPoint {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ScalarReduce<[u8; 32]> for Fq {
    fn reduce_from_bytes(bytes: &[u8; 32]) -> Self {
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(bytes);
        <Fq as FromUniformBytes<64>>::from_uniform_bytes(&wide)
    }
}
