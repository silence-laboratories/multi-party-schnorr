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
    common::{traits::Round, utils::run_round},
    keygen::Keyshare,
    sign::messages::SignMsg2,
};

#[cfg(test)]
mod test {
    // use rand::seq::SliceRandom;
    //
    // use crate::keygen::utils::process_keygen;
    //
    // use super::generate_sign;
    //
    // #[test]
    // fn sign() {
    //     let mut rng = rand::thread_rng();
    //     let keyshares = process_keygen::<3, 5>();
    //
    //     let subset = keyshares.choose_multiple(&mut rng, 3).cloned().collect();
    //     let message =
    //         "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks".as_bytes();
    //
    //     let signatures = generate_sign(subset, message, &mut rng);
    //
    //     for sig in &signatures {
    //         assert_eq!(sig, &signatures[0])
    //     }
    // }
    //
    // #[test]
    // // We check that the party-id set is of length T
    // #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: InvalidMsgCount")]
    // fn sign_fail_threshold() {
    //     let mut rng = rand::thread_rng();
    //     let keyshares = process_keygen::<3, 5>();
    //
    //     let subset = keyshares.choose_multiple(&mut rng, 2).cloned().collect();
    //     let message =
    //         "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks".as_bytes();
    //     let signatures = generate_sign(subset, message, &mut rng);
    //
    //     for sig in &signatures {
    //         assert_eq!(sig, &signatures[0])
    //     }
    // }
    //
    // #[test]
    // fn keygen_with_ranks() {
    //     let _ = process_keygen::<3, 5>();
    //     let _ = process_keygen::<3, 5>();
    //     let _ = process_keygen::<3, 5>();
    //     let _ = process_keygen::<3, 5>();
    //     let _ = process_keygen::<3, 5>();
    // }
}
