// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use rand::{CryptoRng, Rng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::common::utils::SessionId;

pub use sl_mpc_vrf::VrfError;

/// Randomness for the MPC VRF evaluation protocol (session id generation).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VrfEntropy {
    pub(crate) session_id: SessionId,
    pub(crate) seed: [u8; 32],
}

impl VrfEntropy {
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Self {
            session_id: rng.gen(),
            seed: rng.gen(),
        }
    }
}
