// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! MPC hard derivation tweak (VRF bytes → Δ, update signing root). No VRF protocol rounds.

use ff::Field;
use thiserror::Error;

use crate::{
    math::participant_public_share,
    protocol::{HARD_DERIVE_CHAINCODE_BYTES, HARD_DERIVE_DELTA_BYTES, HARD_DERIVE_VRF_OUTPUT_BITS},
    traits::{GroupElem, HardDeriveRoot, HardDeriveSigning},
};

/// Result of hard derivation for one party (signing curve only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HardDeriveOutput<G: GroupElem> {
    pub xi_prime: G::Scalar,
    pub public_key_prime: G,
    pub party_public_shares_prime: Vec<G>,
    pub chain_code: [u8; 32],
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum HardDeriveError {
    #[error("VRF output length mismatch")]
    InvalidVrfOutputLength,
    #[error("threshold must be positive")]
    InvalidThreshold,
    #[error(
        "participating party id {pid} out of range (total_parties={total_parties}, public_shares_len={public_shares_len})"
    )]
    InvalidParticipatingPartyId {
        pid: u8,
        total_parties: u8,
        public_shares_len: usize,
    },
    #[error("duplicate participating party id {pid}")]
    DuplicateParticipatingPartyId { pid: u8 },
}

impl<G> HardDeriveOutput<G>
where
    G: GroupElem + HardDeriveSigning,
    G::Scalar: Field + From<u64>,
{
    /// Split VRF output y into delta_prime and chain code c_tilde.
    pub fn split_vrf_output(y: &[u8]) -> Result<(Vec<u8>, [u8; 32]), HardDeriveError> {
        if y.len() != HARD_DERIVE_VRF_OUTPUT_BITS.div_ceil(8) {
            return Err(HardDeriveError::InvalidVrfOutputLength);
        }
        let delta_prime = y[..HARD_DERIVE_DELTA_BYTES].to_vec();
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(
            &y[HARD_DERIVE_DELTA_BYTES..HARD_DERIVE_DELTA_BYTES + HARD_DERIVE_CHAINCODE_BYTES],
        );
        Ok((delta_prime, chain_code))
    }

    /// Hard derivation: symmetric tweak of the reconstructed signing key in additive form.
    pub fn apply_hard_derive<R: HardDeriveRoot<Point = G>>(
        root: &R,
        vrf_output_y: &[u8],
        threshold: u8,
        participating_party_ids: &[u8],
    ) -> Result<Self, HardDeriveError> {
        if threshold == 0 {
            return Err(HardDeriveError::InvalidThreshold);
        }
        if participating_party_ids.len() < threshold as usize {
            return Err(HardDeriveError::InvalidThreshold);
        }

        let (delta_prime, chain_code) = Self::split_vrf_output(vrf_output_y)?;
        let delta = G::delta_from_vrf(&delta_prime);

        let participant_count = G::Scalar::from(participating_party_ids.len() as u64);
        let delta_over_t = delta * participant_count.invert().unwrap();

        let g = G::generator();
        let delta_g = g * delta;
        let delta_over_t_g = g * delta_over_t;

        let public_key_prime = *root.public_key() + delta_g;

        let total_parties = root.total_parties();
        let mut party_public_shares_prime = root.party_public_shares().to_vec();
        let public_shares_len = party_public_shares_prime.len();
        let mut seen_participants = vec![false; public_shares_len];
        for &pid in participating_party_ids {
            let pid_index = pid as usize;
            if pid >= total_parties || pid_index >= public_shares_len {
                return Err(HardDeriveError::InvalidParticipatingPartyId {
                    pid,
                    total_parties,
                    public_shares_len,
                });
            }
            if seen_participants[pid_index] {
                return Err(HardDeriveError::DuplicateParticipatingPartyId { pid });
            }
            seen_participants[pid_index] = true;
        }
        for &pid in participating_party_ids {
            let pid_index = pid as usize;
            let k_j = participant_public_share(
                &party_public_shares_prime[pid_index],
                pid,
                total_parties,
                participating_party_ids.iter().copied(),
            );
            party_public_shares_prime[pid_index] = k_j + delta_over_t_g;
        }

        let mut xi_prime = root.scalar_share_for_participants(participating_party_ids);
        if participating_party_ids.contains(&root.party_id()) {
            xi_prime += delta_over_t;
        }

        Ok(Self {
            xi_prime,
            public_key_prime,
            party_public_shares_prime,
            chain_code,
        })
    }
}
