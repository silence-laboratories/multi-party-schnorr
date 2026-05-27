// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Lagrange helpers for hard derivation (same formulas as the main crate's `common::math`).

use crypto_bigint::subtle::ConstantTimeEq;
use elliptic_curve::Group;
use ff::Field;

/// Recover Shamir share d_i from additive share w_i.
pub fn shamir_share_from_additive_share<G: Group>(
    additive_share: G::Scalar,
    party_id: u8,
    participating_party_ids: impl IntoIterator<Item = u8>,
) -> G::Scalar
where
    G::Scalar: Field,
{
    let coeff = get_lagrange_coeff::<G>(&party_id, participating_party_ids);
    additive_share * coeff.invert().unwrap()
}

/// Additive public share for `party_id` over the active set, from a full-quorum share.
pub fn participant_public_share<G: Group>(
    full_quorum_share: &G,
    party_id: u8,
    total_parties: u8,
    pid_list: impl IntoIterator<Item = u8>,
) -> G
where
    G::Scalar: Field,
{
    let full_coeff = get_lagrange_coeff::<G>(&party_id, 0..total_parties);
    let part_coeff = get_lagrange_coeff::<G>(&party_id, pid_list);
    *full_quorum_share * (part_coeff * full_coeff.invert().unwrap())
}

pub fn get_lagrange_coeff<G: Group>(
    my_party_id: &u8,
    party_ids: impl IntoIterator<Item = u8>,
) -> G::Scalar {
    let mut coeff = G::Scalar::ONE;
    let x_i = G::Scalar::from((my_party_id + 1) as u64);
    for party_id in party_ids {
        let x_j = G::Scalar::from((party_id + 1) as u64);
        if x_i.ct_ne(&x_j).into() {
            let sub = x_j - x_i;
            coeff *= x_j * sub.invert().unwrap();
        }
    }
    coeff
}
