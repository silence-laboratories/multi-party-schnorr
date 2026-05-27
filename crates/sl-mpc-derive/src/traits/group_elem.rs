// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use crypto_bigint::subtle::ConstantTimeEq;
use elliptic_curve::{group::GroupEncoding, Group};

/// Prime-order group used by derivation / VRF curve code in this crate.
pub trait GroupElem: Group + GroupEncoding + ConstantTimeEq {}

impl<G> GroupElem for G where G: Group + GroupEncoding + ConstantTimeEq {}

/// Reduce (little endian) bytes to a scalar.
pub trait ScalarReduce<T> {
    fn reduce_from_bytes(bytes: &T) -> Self;
}

#[cfg(feature = "eddsa")]
impl ScalarReduce<[u8; 32]> for curve25519_dalek::Scalar {
    fn reduce_from_bytes(bytes: &[u8; 32]) -> Self {
        Self::from_bytes_mod_order(*bytes)
    }
}
