// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Feldman–Shamir DKG on Ristretto and DH-tuple proofs.
//!
//! The implementation is shared with `sl-mpc-vrf`, which needs the same
//! keygen. MLSAG uses only the keygen and the proofs, under the names below.

pub use sl_mpc_vrf::{dh_tuple_transcript, DhTuplePoints, DhTupleProof, SessionId};

/// Party metadata `(n, t, party id)` for MLSAG DKG.
pub type MlsagDkgParty = sl_mpc_vrf::VrfDkgParty;

/// State of the Feldman–Shamir phase of MLSAG DKG (rounds 1 and 2).
pub type MlsagDkgShareContext = sl_mpc_vrf::VrfDkgContext;

/// Output of the Feldman–Shamir phase: Shamir share of the root spend key `b`,
/// `B = b·G`, and every party's public share.
pub type MlsagDkgKeyshare = sl_mpc_vrf::VrfKeyshare;

/// Error of the Feldman–Shamir phase.
pub type MlsagDkgError = sl_mpc_vrf::VrfKeygenError;

/// MLSAG DKG round 1: commitment.
pub type MlsagDkgMsg1 = sl_mpc_vrf::VrfKeygenMsg1;

/// MLSAG DKG round 2: opening and the recipient's Shamir share.
pub type MlsagDkgMsg2 = sl_mpc_vrf::VrfKeygenMsg2;
