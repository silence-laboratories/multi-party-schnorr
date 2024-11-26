# Multiparty Schnorr

This is a pure Rust implementation of a threshold signing scheme for Schnorr signatures based on the paper [Simple Three-Round Multiparty Schnorr Signing with Full Simulatability](https://eprint.iacr.org/2022/374.pdf).


## Generic over Elliptic Curve Group

- This library provides Distributed Key Generation generic over any elliptic curve group that implements the `Group` trait from the `elliptic-curve` crate.
- We currently support Distributed signing for random nonce EdDSA - thus Schnorr - over curve25519 and Bitcoin Taproot Schnorr over the secp256k1 curve.

## Examples

### Distributed Keygen (ed25519)
```rust
use std::time::Instant;

use curve25519_dalek::EdwardsPoint;
use k256::elliptic_curve::group::GroupEncoding;
use multi_party_schnorr::{
    common::utils::run_round,
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
    // If you want to perform DKG for secp256k1 curve, you can use the following line instead! (enable the `taproot` feature)
    // let keyshares: Vec<Keyshare<ProjectivePoint>> = run_round(parties, msgs);


    println!("Time elapsed: {:?}", start.elapsed());

    for (i, keyshare) in keyshares.iter().enumerate() {
        println!(
            "Party-{}'s keyshare: {}",
            i,
            bs58::encode(keyshare.public_key().to_bytes()).into_string()
        );
    }
}
```

### Distributed Signing (ed25519)
```rust
use curve25519_dalek::EdwardsPoint;
use multi_party_schnorr::common::utils::{run_keygen, run_round};
use multi_party_schnorr::sign::SignerParty;
use rand::seq::SliceRandom;

fn main() {
    const N: usize = 5;
    const T: usize = 3;

    let keyshares = run_keygen::<T, N, EdwardsPoint>();
    // If you want to perform DSG for Bitcoin Taproot Schnorr, you can use the following line instead! (enable the `taproot` feature)
    // Based on keyshare type, signing will be performed accordingly.
    // let keyshares = run_keygen::<T, N, ProjectivePoint>();
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
```

## Feature Flags

| Feature            | Default? | Description |
| :---               |  :---:   | :---        |
| `eddsa`            |    ✓     | Enables signing over curve25519 with edd25519-dalek signing objects compatibility|
| `taproot`          |        | Enables Bitcoin Taproot Schnorr signing over secp256k1 |

## Note on Networking
- This library contains only the cryptographic protocol and does not provide any networking functionality. Networking can be built on top of this library easily.
- The parties in the protocol don't sign the messages, this is expected to be done on the networking layer.

### Examples
Please find the examples in the [examples](./examples/) folder.





