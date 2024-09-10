use curve25519_dalek::EdwardsPoint;
use multi_party_schnorr::common::utils::{run_keygen, run_round};
use multi_party_schnorr::sign::SignerParty;
use rand::seq::SliceRandom;

fn main() {
    const N: usize = 5;
    const T: usize = 3;

    let keyshares = run_keygen::<T, N, EdwardsPoint>();
    let mut rng = rand::thread_rng();
    let start = std::time::Instant::now();

    let subset: Vec<_> = keyshares
        .choose_multiple(&mut rand::thread_rng(), T)
        .cloned()
        .collect();

    let parties = subset
        .iter()
        .map(|keyshare| SignerParty::new(keyshare.clone().into(), &mut rng))
        .collect::<Vec<_>>();

    // Pre-Signature phase
    let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, ()).into_iter().unzip();
    let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, msgs).into_iter().unzip();
    let ready_parties = run_round(parties, msgs);

    // Signature phase
    let msg = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    let (parties, partial_sigs): (Vec<_>, Vec<_>) =
        run_round(ready_parties, msg.into()).into_iter().unzip();

    let (signatures, _complete_msg): (Vec<_>, Vec<_>) =
        run_round(parties, partial_sigs).into_iter().unzip();

    println!("Time: {:?}ms", start.elapsed());
    for sig in signatures {
        println!("Signature: {}", bs58::encode(sig.to_bytes()).into_string())
    }
}
