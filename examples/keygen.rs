use std::time::Instant;

use curve25519_dalek::EdwardsPoint;
use multi_party_schnorr::{
    common::utils::run_round,
    group::GroupEncoding,
    keygen::{utils::setup_keygen, Keyshare},
};

fn main() {
    const T: usize = 2;
    const N: usize = 3;
    let start = Instant::now();

    // Setup keygen, create the encryption keys for each party
    let parties = setup_keygen(T as u8, N as u8).unwrap();

    // Locally run the keygen protocol
    // Run Round 1
    let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, ()).into_iter().unzip();

    // Run Round 2
    let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, msgs).into_iter().unzip();

    // Run Round 3
    let keyshares: Vec<Keyshare<EdwardsPoint>> = run_round(parties, msgs);

    println!("Time elapsed: {:?}", start.elapsed());

    for (i, keyshare) in keyshares.iter().enumerate() {
        println!(
            "Party-{}'s keyshare: {}",
            i,
            bs58::encode(keyshare.public_key().to_bytes()).into_string(),
        );
    }
}
