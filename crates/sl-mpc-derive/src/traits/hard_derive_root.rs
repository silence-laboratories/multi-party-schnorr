// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Signing-root key material for MPC hard derivation (VRF output → tweaked key).

use crate::traits::HardDeriveSigning;

/// One party's signing root state generic for dkls and mps .
pub trait HardDeriveRoot {
    /// Signing curve point type (e.g. EdwardsPoint, `k256::ProjectivePoint`).
    type Point: HardDeriveSigning;

    fn party_id(&self) -> u8;
    fn threshold(&self) -> u8;
    fn total_parties(&self) -> u8;
    fn public_key(&self) -> &Self::Point;
    fn party_public_shares(&self) -> &[Self::Point];
    /// Additive share  for the given participating party ids (Lagrange on Shamir share).
    fn scalar_share_for_participants(
        &self,
        participating_party_ids: &[u8],
    ) -> <Self::Point as elliptic_curve::Group>::Scalar;
}
