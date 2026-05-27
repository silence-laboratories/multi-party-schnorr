// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! SHA-256 transcript
use sha2::{Digest, Sha256};
use sl_transcript::TranscriptProtocol;

pub struct Sha256Transcript(Sha256);

impl TranscriptProtocol for Sha256Transcript {
    fn new(label: &'static [u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update((label.len() as u64).to_le_bytes());
        hasher.update(label);
        Self(hasher)
    }

    fn append_message(&mut self, label: &'static [u8], message: &[u8]) {
        self.0.update((label.len() as u64).to_le_bytes());
        self.0.update(label);
        self.0.update((message.len() as u64).to_le_bytes());
        self.0.update(message);
    }

    fn append_u64(&mut self, label: &'static [u8], value: u64) {
        self.append_message(label, &value.to_le_bytes());
    }

    fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8]) {
        self.0.update((label.len() as u32).to_le_bytes());
        self.0.update(label);
        self.0.update((dest.len() as u32).to_le_bytes());
        let digest = self.0.clone().finalize();
        let n = dest.len().min(digest.len());
        dest[..n].copy_from_slice(&digest[..n]);
    }
}
