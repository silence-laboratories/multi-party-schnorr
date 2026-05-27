// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Signing-side derivation: traits, hash-to-curve, hard-derive tweak, Ristretto VRF curve types.

pub mod math;
pub mod protocol;
pub mod traits;

#[cfg(feature = "eddsa")]
pub mod oracle;

#[cfg(feature = "eddsa")]
pub mod hash_to_curve;

#[cfg(feature = "eddsa")]
pub mod impls;

#[cfg(feature = "vrf")]
pub mod hard_derive;

pub use protocol::{
    ED25519_SCALAR_FIELD_BITS, ED25519_VRF_OUTPUT_BITS, ED25519_VRF_OUTPUT_LEN,
    HARD_DERIVE_CHAINCODE_BITS, HARD_DERIVE_CHAINCODE_BYTES, HARD_DERIVE_DELTA_BITS,
    HARD_DERIVE_DELTA_BYTES, HARD_DERIVE_VRF_OUTPUT_BITS, SCALAR_FIELD_BITS, STAT_SEC_PARAM_BITS,
    VRF_CHAINCODE_BITS, VRF_OUTPUT_BITS, VRF_OUTPUT_LEN,
};

#[cfg(feature = "eddsa")]
pub use hash_to_curve::{
    ro_hash_string, EdwardsRo, HashToCurve, HashToCurveError, try_hash_bytes_to_point,
};

#[cfg(feature = "eddsa")]
pub use traits::{HardDeriveRoot, HardDeriveSigning};

#[cfg(all(feature = "eddsa", feature = "vrf"))]
pub use impls::ristretto::{RistrettoRo, VrfGroup, VrfHashToCurve, VrfPoint, VrfScalar};

#[cfg(feature = "k256")]
pub use impls::k256::hard_derive_signing;

#[cfg(feature = "vrf")]
pub use hard_derive::{HardDeriveError as HardDeriveTweakError, HardDeriveOutput};

#[cfg(feature = "vrf")]
pub use math::shamir_share_from_additive_share;
