// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Threshold MPC VRF protocols on Ristretto.
//!
//! Host crates (`multi-party-schnorr`, `dkls23-ll`) wrap [`eval::Context`] round methods in their
//! preferred API (`Round::process` vs `generate_msg*` / `handle_msg*`).

pub mod crypto;
pub mod dh_tuple;
pub mod dkg;
pub mod eval;
pub mod messages;
pub mod transcript;
pub mod types;

pub use dh_tuple::{
    dh_tuple_transcript, DhTuplePoints, DhTupleProof, DH_TUPLE_CHALLENGE_LABEL,
    DH_TUPLE_TRANSCRIPT_LABEL,
};
pub use dkg::{
    Context as VrfDkgContext, Party as VrfDkgParty, P2pShare, VrfKeygenError, VrfKeygenMsg1,
    VrfKeygenMsg2, VrfKeyshare,
};
pub use eval::{Context as VrfEvalContext, VrfOutput};
pub use messages::{VrfMsg0, VrfMsg1};
pub use transcript::Sha256Transcript;
pub use types::{SessionId, VrfError};
