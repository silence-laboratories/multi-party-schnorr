// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Threshold MPC VRF protocol and VRF-backed hard derivation.

pub mod eval;
pub mod hard_derivation;
pub mod messages;
pub mod types;

pub use crate::derive::hard_derive::HardDeriveOutput;
pub use crate::derive::impls::ristretto::{
    RistrettoRo, VrfGroup, VrfHashToCurve, VrfPoint, VrfScalar,
};
pub use eval::{VrfOutput, VrfParty, VrfPartyRistretto, VrfR0, VrfR1, VrfR2};
pub use hard_derivation::{
    keyshare_after_hard_derive, HardDeriveError, HardDeriveMsg0, HardDeriveMsg1, HardDeriveParty,
    HardDeriveR0, HardDeriveR1, HardDeriveR2, MpcDeriveInit,
};
pub use messages::{VrfMsg0, VrfMsg1};
pub use types::{VrfEntropy, VrfError};
