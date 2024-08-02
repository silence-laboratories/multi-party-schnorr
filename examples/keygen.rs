use std::time::Instant;

use multi_party_schnorr::{
    common::{
        traits::Round,
        utils::{cooridinator::recv_broadcast, run_round},
    },
    keygen::{utils::setup_keygen, Keyshare},
};

use rayon::prelude::{IntoParallelIterator, ParallelIterator};

fn main() {
    const T: usize = 2;
    const N: usize = 3;
    let start = Instant::now();
    let (parties, mut coord) = setup_keygen::<T, N>().unwrap();
    let parties1 = run_round(&mut coord, parties, 0);
    let msgs = recv_broadcast(&mut coord, 1);

    let keyshares: Vec<Keyshare> = parties1
        .into_par_iter()
        .map(|actor| actor.process(msgs.clone()).unwrap())
        .collect();

    let keyshares: [Keyshare; N] = keyshares
        .try_into()
        .map_err(|_| "Failed to convert keyshares to array")
        .unwrap();

    println!("Time elapsed: {:?}", start.elapsed());

    for (i, keyshare) in keyshares.iter().enumerate() {
        println!(
            "Party-{}'s keyshare: {}",
            i,
            bs58::encode(keyshare.public_key.compress().as_bytes()).into_string()
        );
    }
}
