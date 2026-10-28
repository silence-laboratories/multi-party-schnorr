// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use wasm_bindgen::{prelude::*, UnwrapThrowExt};

pub mod keygen;
pub mod keyshare;
pub mod message;
pub mod sign;

pub use keygen::KeygenSession;
pub use keyshare::Keyshare;
pub use message::Message;
pub use sign::{fill_ring, verify_signature, SignInput, SignSession};

pub(crate) fn maybe_seeded_rng<T: AsRef<[u8]>>(seed: Option<T>) -> ChaCha20Rng {
    let seed = match seed.as_ref() {
        None => rand::thread_rng().gen(),
        Some(seed) => seed.as_ref().try_into().expect_throw("invalid seed size"),
    };

    ChaCha20Rng::from_seed(seed)
}

/// Installs a panic hook so Rust panics surface in the JavaScript console
/// instead of silently aborting execution.
#[wasm_bindgen]
pub fn enable_panic_hook() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}
