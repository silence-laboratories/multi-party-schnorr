// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Signing-side derivation: re-exports [`sl_mpc_derive`] for stable `crate::derive` paths.

#[cfg(feature = "eddsa")]
pub use sl_mpc_derive::*;

#[cfg(feature = "eddsa")]
pub use crate::soft_derive::DeriveParty;

#[cfg(all(feature = "eddsa", feature = "vrf"))]
pub use crate::ed25519_vrf_derive::{
    delta_from_vrf, try_hash_bytes_to_point, with_ristretto_vrf as with_ristretto_vrf_ed25519,
    HardDeriveOutputEd25519, HardDerivePartyEd25519, MpcDeriveInitEd25519,
};

#[cfg(feature = "vrf")]
pub use sl_mpc_derive::shamir_share_from_additive_share;
