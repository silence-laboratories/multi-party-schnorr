use std::time::Instant;

use multi_party_schnorr::{
    common::{
        traits::{PersistentObj, Round},
        utils::{
            cooridinator::{recv_broadcast, Coordinator},
            generate_pki, run_round,
        },
    },
    keygen::{utils::process_keygen, KeygenParty, Keyshare},
};
use rayon::iter::{IntoParallelIterator, ParallelIterator};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    const N: usize = 5;
    const T: usize = 3;

    // Generate some keyshares
    let keyshares = process_keygen::<T, N>();
    let mut rng = rand::thread_rng();

    let start = Instant::now();
    let (party_pubkey_list, party_key_list) = generate_pki(N, &mut rng);

    // Start refresh protocol
    let parties0 = keyshares
        .iter()
        .zip(party_key_list)
        .map(|(keyshare, party_key)| {
            let data = keyshare.get_refresh_data();
            KeygenParty::new(
                T as u8,
                N as u8,
                keyshare.party_id,
                &party_key,
                party_pubkey_list.clone(),
                Some(data),
                &mut rng,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut coord = Coordinator::new(N as u8, 2);
    let parties1 = parties0
        .into_iter()
        .map(|party| {
            let (p, msg) = party.process(()).unwrap();
            coord.send(0, msg.to_bytes().unwrap()).unwrap();
            p
        })
        .collect();

    let parties2 = run_round(&mut coord, parties1, 0);

    let msgs = recv_broadcast(&mut coord, 1);
    let new_keyshares: Vec<Keyshare> = parties2
        .into_par_iter()
        .map(|actor| actor.process(msgs.clone()).unwrap())
        .collect();

    println!("Time taken: {:?}", start.elapsed());

    println!("Previous keyshare public keys------------------");
    for (i, keyshare) in keyshares.iter().enumerate() {
        println!(
            "Party-{}'s keyshare: {}",
            i,
            bs58::encode(keyshare.public_key.compress().as_bytes()).into_string()
        );
    }
    println!("Refreshed keyshare public keys (must be the same)------------------");

    for (i, keyshares) in new_keyshares.iter().enumerate() {
        println!(
            "Party-{}'s keyshare: {}",
            i,
            bs58::encode(keyshares.public_key.compress().as_bytes()).into_string()
        );
    }
    Ok(())
}
