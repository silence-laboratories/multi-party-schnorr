// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Threshold MLSAG keygen and signing on Ristretto (MobileCoin-compatible key image).

#![deny(unsafe_code)]

pub mod challenge;
pub mod dkg;
pub mod error;
pub mod hash_to_point;
pub mod key_image;
pub mod messages;
pub mod ring_mlsag;
pub mod sign;

pub use challenge::{challenge, RING_MLSAG_CHALLENGE_DOMAIN_TAG};
pub use dkg::{keyshare_session_id, KeyshareContext, MlsagDkgContext, MlsagDkgParty};
pub use error::MlsagError;
pub use hash_to_point::{hash_to_point, HASH_TO_POINT_DOMAIN_TAG};
pub use key_image::KeyImage;
pub use messages::{KeyshareMsg, MlsagKeyshare};
pub use ring_mlsag::{
    assemble_ring_mlsag, fill_ring, sign_with_scalar, RingMLSAG, RingMember, RingTour,
    SignPublicInput,
};
pub use sign::{sign_session_id, MlsagSignContext, NonceCommit, SignMsg1, SignMsg2, SignMsg3};

// Re-export message types used by [`MlsagDkgContext`] rounds.
pub use sl_mpc_vrf::{SessionId, VrfKeygenMsg1, VrfKeygenMsg2};
