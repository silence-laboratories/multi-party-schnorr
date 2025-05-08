// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::time::Instant;

use curve25519_dalek::EdwardsPoint;

use k256::elliptic_curve::group::GroupEncoding;

use multi_party_schnorr::{
    common::utils::{run_keygen, run_round},
    keygen::utils::setup_refresh,
};

fn main() {
    const T: usize = 2;
    const N: usize = 3;

    let mut rng = rand::thread_rng();
    // Perform keygen to generate keyshares
    let shares = run_keygen::<T, N, EdwardsPoint>();

    let start = Instant::now();
    // Setup the refresh protocol, initialize parties.

    // Get the refresh data from the keyshares
    let refresh_data = shares
        .into_iter()
        .map(|data| data.get_refresh_data(None))
        .collect();

    let parties0 = setup_refresh(refresh_data, &mut rng).unwrap();

    // Locally running keygen refresh protocol
    // Run Round 1
    let (actors, msgs): (Vec<_>, Vec<_>) = run_round(parties0, ()).into_iter().unzip();

    // Run Round 2
    let (actors, msgs): (Vec<_>, Vec<_>) = run_round(actors, msgs).into_iter().unzip();

    // Run Round 3
    let new_shares = run_round(actors, msgs);

    println!("Time elapsed: {:?}", start.elapsed());

    for (i, keyshare) in new_shares.iter().enumerate() {
        println!(
            "Party-{}'s old keyshare: {}",
            i,
            bs58::encode(keyshare.public_key().to_bytes()).into_string()
        );
    }

    for (i, new_share) in new_shares.iter().enumerate() {
        println!(
            "Party-{}'s refreshed keyshare: {}",
            i,
            bs58::encode(new_share.public_key().to_bytes()).into_string()
        );
    }
}
