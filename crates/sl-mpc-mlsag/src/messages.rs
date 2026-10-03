// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use curve25519_dalek::{RistrettoPoint, Scalar};
use sl_mpc_vrf::{DhTupleProof, SessionId, VrfKeyshare};

use crate::key_image::KeyImage;

/// Partial key-image contribution with DH-tuple proof.
///
/// Delivery: broadcast, signed only.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyshareMsg {
    pub from_party: u8,
    pub session_id: SessionId,
    /// Compressed `I_j = k_j · H_p(P)`.
    pub i_j: [u8; 32],
    pub pi: DhTupleProof,
}

/// MLSAG signing-key share after end-to-end DKG (Shamir share + key image `I`).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsagKeyshare {
    pub threshold: u8,
    pub total_parties: u8,
    pub party_id: u8,
    pub(crate) d_i: Scalar,
    pub public_key: RistrettoPoint,
    pub(crate) party_public_shares: Vec<RistrettoPoint>,
    pub key_id: [u8; 32],
    pub root_chain_code: [u8; 32],
    pub dkg_session_id: SessionId,
    pub keyshare_session_id: SessionId,
    pub key_image: KeyImage,
    /// Quorum that produced `key_image`.
    pub keyshare_pid_list: Vec<u8>,
}

impl MlsagKeyshare {
    pub fn from_vrf_keyshare(
        share: &VrfKeyshare,
        key_image: KeyImage,
        keyshare_session_id: SessionId,
        keyshare_pid_list: Vec<u8>,
    ) -> Self {
        Self {
            threshold: share.threshold,
            total_parties: share.total_parties,
            party_id: share.party_id,
            d_i: *share.shamir_share(),
            public_key: *share.public_key(),
            party_public_shares: share.party_public_shares().to_vec(),
            key_id: share.key_id,
            root_chain_code: share.root_chain_code,
            dkg_session_id: share.final_session_id,
            keyshare_session_id,
            key_image,
            keyshare_pid_list,
        }
    }

    pub fn public_key(&self) -> &RistrettoPoint {
        &self.public_key
    }

    pub fn shamir_share(&self) -> &Scalar {
        &self.d_i
    }

    pub fn key_image(&self) -> &KeyImage {
        &self.key_image
    }

    pub fn party_public_shares(&self) -> &[RistrettoPoint] {
        &self.party_public_shares
    }
}
