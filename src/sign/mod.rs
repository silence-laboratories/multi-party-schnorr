// mod dsg;
mod types;

/// Messages used in the signing protocol
pub mod messages;

mod dsg;

pub use dsg::*;

use ed25519_dalek::{Signature, SigningKey};

use rand::{CryptoRng, RngCore};
pub use types::*;

use crate::{
    common::{
        traits::{PersistentObj, Round},
        utils::{
            cooridinator::{recv_broadcast, Coordinator},
            run_round,
        },
    },
    keygen::Keyshare,
    sign::messages::SignMsg2,
};

#[allow(unused)]
fn generate_sign<R: CryptoRng + RngCore>(
    subset: Vec<Keyshare>,
    message: &[u8],
    rng: &mut R,
) -> Vec<Signature> {
    let mut coord = Coordinator::new(subset.len() as u8, 6);

    let mut party_pubkey_list = vec![];
    let party_key_list = (0..subset.len())
        .map(|idx| {
            // Generate or load from persistent storage
            // set of party's keys
            let party_keys = SigningKey::generate(rng);

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
                rng,
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

    let partial_sign_parties = ready_parties
        .into_iter()
        .map(|party| {
            let (p, m) = party.process(message.to_vec()).unwrap();
            coord.send(2, m.to_bytes().unwrap()).unwrap();
            p
        })
        .collect::<Vec<_>>();

    let signatures = run_round(&mut coord, partial_sign_parties, 2);
    println!("Time: {:?}", start.elapsed());
    signatures
}

#[cfg(test)]
mod test {
    use rand::seq::SliceRandom;

    use crate::keygen::utils::process_keygen;

    use super::generate_sign;

    #[test]
    fn sign() {
        let mut rng = rand::thread_rng();
        let keyshares = process_keygen::<3, 5>();

        let subset = keyshares.choose_multiple(&mut rng, 3).cloned().collect();
        let message =
            "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks".as_bytes();

        let signatures = generate_sign(subset, message, &mut rng);

        for sig in &signatures {
            assert_eq!(sig, &signatures[0])
        }
    }

    #[test]
    // We check that the party-id set is of length T
    #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: InvalidMsgCount")]
    fn sign_fail_threshold() {
        let mut rng = rand::thread_rng();
        let keyshares = process_keygen::<3, 5>();

        let subset = keyshares.choose_multiple(&mut rng, 2).cloned().collect();
        let message =
            "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks".as_bytes();
        let signatures = generate_sign(subset, message, &mut rng);

        for sig in &signatures {
            assert_eq!(sig, &signatures[0])
        }
    }

    #[test]
    fn keygen_with_ranks() {
        let _ = process_keygen::<3, 5>();
        let _ = process_keygen::<3, 5>();
        let _ = process_keygen::<3, 5>();
        let _ = process_keygen::<3, 5>();
        let _ = process_keygen::<3, 5>();
    }
}
