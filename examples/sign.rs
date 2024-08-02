use ed25519_dalek::SigningKey;
use multi_party_schnorr::common::traits::{PersistentObj, Round};
use multi_party_schnorr::common::utils::cooridinator::{recv_broadcast, Coordinator};
use multi_party_schnorr::common::utils::run_round;
use multi_party_schnorr::{
    keygen::utils::process_keygen,
    sign::{messages::SignMsg2, SignerParty},
};
use rand::seq::IteratorRandom;

fn main() {
    const N: usize = 5;
    const T: usize = 3;
    let keyshares = process_keygen::<T, N>();
    let mut rng = rand::thread_rng();

    let subset = keyshares.into_iter().choose_multiple(&mut rng, T);
    let mut coord = Coordinator::new(subset.len() as u8, 6);

    let mut party_pubkey_list = vec![];
    let party_key_list = (0..subset.len())
        .map(|_| {
            // Generate or load from persistent storage
            // set of party's keys
            let party_keys = SigningKey::generate(&mut rng);

            // extract public keys
            let actor_pubkeys = party_keys.verifying_key();
            party_pubkey_list.push(actor_pubkeys);

            party_keys
        })
        .collect::<Vec<_>>();

    let start = std::time::Instant::now();
    let parties = subset
        .into_iter()
        .enumerate()
        .map(|(idx, keyshare)| {
            let s0 = SignerParty::new(
                keyshare,
                party_key_list[idx].clone(),
                party_pubkey_list.clone(),
                &mut rng,
            )
            .unwrap();
            let (s1, msg1) = s0.process(()).unwrap();
            coord.send(0, msg1.to_bytes().unwrap()).unwrap();
            s1
        })
        .collect::<Vec<_>>();

    let parties1 = run_round(&mut coord, parties, 0);

    let messages: Vec<SignMsg2> = recv_broadcast(&mut coord, 1);

    let ready_parties = parties1
        .into_iter()
        .map(|party| party.process(messages.clone()).unwrap())
        .collect::<Vec<_>>();

    let message = b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks.";

    let partial_sign_parties = ready_parties
        .into_iter()
        .map(|party| {
            let (p, m) = party.process(message.to_vec()).unwrap();
            coord.send(2, m.to_bytes().unwrap()).unwrap();
            p
        })
        .collect::<Vec<_>>();

    let signatures = run_round(&mut coord, partial_sign_parties, 2);
    println!("Time: {:?}ms", start.elapsed());
    for sig in signatures {
        println!("Signature: {}", bs58::encode(sig.to_bytes()).into_string())
    }
}
