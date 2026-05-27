// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Ed25519 aliases for VRF-backed hard derivation (main crate only: needs [`crate::vrf`]).

use curve25519_dalek::{EdwardsPoint, Scalar};

use crate::{
    derive::{hard_derive::HardDeriveOutput, traits::HardDeriveSigning},
    keygen::Keyshare,
    vrf::{
        hard_derivation::{HardDeriveParty, MpcDeriveInit},
        VrfPoint,
    },
};

pub type MpcDeriveInitEd25519 = MpcDeriveInit<EdwardsPoint>;
pub type HardDeriveOutputEd25519 = HardDeriveOutput<EdwardsPoint>;
pub type HardDerivePartyEd25519<T> = HardDeriveParty<T, EdwardsPoint>;

pub fn with_ristretto_vrf(
    root_keyshare: Keyshare<EdwardsPoint>,
    vrf_keyshare: Keyshare<VrfPoint>,
) -> MpcDeriveInitEd25519 {
    MpcDeriveInit::with_ristretto_vrf(root_keyshare, vrf_keyshare)
}

pub fn delta_from_vrf(delta_prime: &[u8]) -> Scalar {
    EdwardsPoint::delta_from_vrf(delta_prime)
}

pub use crate::derive::impls::ed25519::hash_to_curve::try_hash_bytes_to_point;
