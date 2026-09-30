// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! MobileCoin `RingMLSAG` challenge hash.
//!
//! `c = Scalar::from_hash(Blake2b-512("mc_ring_mlsag_challenge" || m || I || L0 || R0 || L1))`.

use blake2::{Blake2b512, Digest};
use curve25519_dalek::{RistrettoPoint, Scalar};

use crate::key_image::KeyImage;

/// Domain separator for RingMLSAG challenges (MobileCoin).
pub const RING_MLSAG_CHALLENGE_DOMAIN_TAG: &str = "mc_ring_mlsag_challenge";

/// `Hn(m | key_image | L0 | R0 | L1)`.
pub fn challenge(
    message: &[u8],
    key_image: &KeyImage,
    l0: &RistrettoPoint,
    r0: &RistrettoPoint,
    l1: &RistrettoPoint,
) -> Scalar {
    let mut hasher = Blake2b512::new();
    hasher.update(RING_MLSAG_CHALLENGE_DOMAIN_TAG.as_bytes());
    hasher.update(message);
    hasher.update(key_image.as_bytes());
    hasher.update(l0.compress().as_bytes());
    hasher.update(r0.compress().as_bytes());
    hasher.update(l1.compress().as_bytes());
    Scalar::from_hash(hasher)
}
