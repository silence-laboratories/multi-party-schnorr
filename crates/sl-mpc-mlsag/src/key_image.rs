// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    Scalar,
};

use crate::hash_to_point::hash_to_point;

/// MobileCoin-style key image: `I = x · H_p(x·G)`, compressed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyImage {
    pub point: CompressedRistretto,
}

impl KeyImage {
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.point.as_bytes()
    }

    /// `I = x · H_p(P)` with `P = x·G`.
    pub fn from_scalar(x: &Scalar) -> Self {
        let p = RistrettoPoint::mul_base(x);
        let hp = hash_to_point(&p);
        Self {
            point: (hp * x).compress(),
        }
    }

    pub fn decompress(&self) -> Option<RistrettoPoint> {
        self.point.decompress()
    }
}

impl From<&Scalar> for KeyImage {
    fn from(x: &Scalar) -> Self {
        Self::from_scalar(x)
    }
}

impl TryFrom<[u8; 32]> for KeyImage {
    type Error = ();

    fn try_from(src: [u8; 32]) -> Result<Self, Self::Error> {
        let point = CompressedRistretto(src);
        point.decompress().map(|_| Self { point }).ok_or(())
    }
}
