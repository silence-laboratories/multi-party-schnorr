use std::time::Instant;

use multi_party_schnorr::{
    common::{
        traits::{PersistentObj, Round},
        utils::{
            cooridinator::{recv_broadcast, Coordinator},
            generate_pki, run_round,
        },
    },
    keygen::{utils::process_keygen, KeyRefreshData, KeygenParty, Keyshare},
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
    let lost_party_ids: Vec<u8> = vec![3];

    let mut parties0 = vec![];
    for pid in 0..N {
        let data = if lost_party_ids.contains(&(pid as u8)) {
            KeyRefreshData::recovery_data_for_lost(lost_party_ids.clone(), *keyshares[0].public_key)
        } else {
            keyshares[pid].get_recovery_data(lost_party_ids.clone())
        };

        parties0.push(KeygenParty::new(
            T as u8,
            N as u8,
            pid as u8,
            &party_key_list[pid],
            party_pubkey_list.clone(),
            Some(data),
            &mut rng,
        )?);
    }

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
