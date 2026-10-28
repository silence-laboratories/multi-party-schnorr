// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use wasm_bindgen::prelude::*;

pub mod keygen;
pub mod keyshare;
pub mod message;
pub mod sign;

pub use keygen::KeygenSession;
pub use keyshare::Keyshare;
pub use message::Message;
pub use sign::{fill_ring, verify_signature, SignInput, SignSession};

/// Installs a panic hook so Rust panics surface in the JavaScript console
/// instead of silently aborting execution.
#[wasm_bindgen]
pub fn enable_panic_hook() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}
