// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use crate::derive::traits::{HardDeriveRoot, HardDeriveSigning};
use crate::{common::traits::GroupElem, keygen::Keyshare};

#[cfg(feature = "vrf")]
impl<G> HardDeriveRoot for Keyshare<G>
where
    G: GroupElem + HardDeriveSigning,
{
    type Point = G;

    fn party_id(&self) -> u8 {
        self.party_id()
    }

    fn threshold(&self) -> u8 {
        self.threshold
    }

    fn total_parties(&self) -> u8 {
        self.total_parties
    }

    fn public_key(&self) -> &G {
        self.public_key()
    }

    fn party_public_shares(&self) -> &[G] {
        self.party_public_shares()
    }

    fn scalar_share_for_participants(
        &self,
        participating_party_ids: &[u8],
    ) -> <G as elliptic_curve::Group>::Scalar {
        self.scalar_share_interpolate(participating_party_ids.to_vec())
    }
}
