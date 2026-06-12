// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! RoHMAC-SHA256 random oracle + encoding
use hmac::{Hmac, Mac};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;

/// RoHMAC-SHA256 key (16 bytes).
const RO_HMAC_KEY: [u8; 16] = [
    0x49, 0xe5, 0x64, 0x72, 0x00, 0xe8, 0xd0, 0xbc, 0x8a, 0x8f, 0x44, 0x76, 0x2b, 0x14, 0x05, 0xb9,
];

#[derive(Clone)]
pub(crate) struct RoHmac {
    mac: Hmac<Sha256>,
}

impl RoHmac {
    pub fn new() -> Self {
        Self {
            mac: Hmac::<Sha256>::new_from_slice(&RO_HMAC_KEY).expect("HMAC accepts 16-byte key"),
        }
    }

    /// encode_and_update for a byte string: I2OSP(len,4) || bytes.
    pub fn encode_and_update(&mut self, bytes: &[u8]) {
        self.encode_bin_size(i32::try_from(bytes.len()).expect("message chunk exceeds i32::MAX"));
        self.mac.update(bytes);
    }

    /// encode_and_update for int32 (e.g. retry counter): I2OSP(4,4) || I2OSP(i,4).
    pub fn encode_and_update_i32(&mut self, value: i32) {
        self.encode_bin_size(4);
        self.mac.update(&value.to_be_bytes());
    }

    fn encode_bin_size(&mut self, size: i32) {
        self.mac.update(&size.to_be_bytes());
    }

    /// hash_string_t::bitlen(256) — first 32 bytes of the HMAC output.
    pub fn bitlen256(&self) -> [u8; 32] {
        let digest = self.mac.clone().finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest[..32]);
        out
    }
}

impl Default for RoHmac {
    fn default() -> Self {
        Self::new()
    }
}

/// First 32 bytes of RoHMAC-SHA256 over encoded `parts`.
pub fn ro_hmac_digest(parts: &[&[u8]]) -> [u8; 32] {
    let mut ro = RoHmac::new();
    for part in parts {
        ro.encode_and_update(part);
    }
    ro.bitlen256()
}

/// If t_bits ≤ 256, returns Truncate_t(HMAC(...)). Otherwise derives a ChaCha20 DRBG from the
/// HMAC digest and samples t_bits.
pub fn ro_hash_string(parts: &[&[u8]], t_bits: usize) -> Vec<u8> {
    let digest = ro_hmac_digest(parts);
    if t_bits <= 256 {
        truncate_to_bits(&digest, t_bits)
    } else {
        drbg_sample_string(digest, t_bits)
    }
}

fn truncate_to_bits(digest: &[u8], t_bits: usize) -> Vec<u8> {
    let byte_len = t_bits.div_ceil(8);
    let mut out = digest[..byte_len.min(digest.len())].to_vec();
    if let Some(last) = out.last_mut() {
        if let Some(extra_bits) = t_bits.checked_rem(8) {
            if extra_bits != 0 {
                *last &= 0xFFu8 << (8 - extra_bits);
            }
        }
    }
    out
}

fn drbg_sample_string(seed: [u8; 32], t_bits: usize) -> Vec<u8> {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let byte_len = t_bits.div_ceil(8);
    let mut out = vec![0u8; byte_len];
    rng.fill_bytes(&mut out);
    if let Some(extra_bits) = t_bits.checked_rem(8) {
        if extra_bits != 0 {
            if let Some(last) = out.last_mut() {
                *last &= 0xFFu8 << (8 - extra_bits);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::SCALAR_FIELD_BITS;

    #[test]
    fn bitlen256_matches_scalar_field_size() {
        assert_eq!(SCALAR_FIELD_BITS / 8, 32);
    }

    #[test]
    fn ro_hash_string_short_output() {
        let s = ro_hash_string(&[b"abc"], 128);
        assert_eq!(s.len(), 16);
    }

    #[test]
    fn ro_hash_string_drbg_path_is_deterministic() {
        let a = ro_hash_string(&[b"x", b"y"], 512);
        let b = ro_hash_string(&[b"x", b"y"], 512);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }
}
