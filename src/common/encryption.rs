// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Encryption trait and implementations for server state encryption

/// Trait for encrypting and decrypting server state
pub trait StateEncryption: Send + Sync {
    /// Encrypt data with authenticated data (AAD)
    /// Returns: nonce || ciphertext || tag
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, EncryptionError>;

    /// Decrypt data with authenticated data (AAD)
    /// Input format: nonce || ciphertext || tag
    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, EncryptionError>;
}

#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("Encryption error: {0}")]
    Encryption(&'static str),
    #[error("Decryption error: {0}")]
    Decryption(&'static str),
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Invalid ciphertext length")]
    InvalidCiphertextLength,
}

#[cfg(feature = "encryption-chacha20poly1305")]
mod chacha20poly1305_impl {
    use super::{EncryptionError, StateEncryption};
    use chacha20poly1305::{
        aead::{AeadCore, AeadInPlace, KeyInit, OsRng},
        ChaCha20Poly1305, Nonce,
    };

    /// ChaCha20Poly1305 implementation of StateEncryption
    pub struct ChaCha20Poly1305Encryption {
        key: [u8; 32],
    }

    impl ChaCha20Poly1305Encryption {
        pub fn new(key: [u8; 32]) -> Self {
            Self { key }
        }
    }

    impl StateEncryption for ChaCha20Poly1305Encryption {
        fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, EncryptionError> {
            let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
                .map_err(|_| EncryptionError::InvalidKeyLength)?;

            // Generate a random nonce (12 bytes for ChaCha20Poly1305)
            let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

            // Encrypt with AAD
            let mut buffer = plaintext.to_vec();
            let tag = cipher
                .encrypt_in_place_detached(&nonce, aad, &mut buffer)
                .map_err(|_| EncryptionError::Encryption("Encryption failed"))?;

            // Combine: nonce || ciphertext || tag
            let mut result = nonce.to_vec();
            result.extend_from_slice(&buffer);
            result.extend_from_slice(tag.as_slice());

            Ok(result)
        }

        fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, EncryptionError> {
            // Extract nonce (first 12 bytes)
            if ciphertext.len() < 12 {
                return Err(EncryptionError::InvalidCiphertextLength);
            }

            let nonce = Nonce::from_slice(&ciphertext[..12]);
            let rest = &ciphertext[12..];

            // Extract tag (last 16 bytes for Poly1305)
            if rest.len() < 16 {
                return Err(EncryptionError::InvalidCiphertextLength);
            }

            let tag_len = rest.len() - 16;
            let mut buffer = rest[..tag_len].to_vec();
            let tag = chacha20poly1305::Tag::from_slice(&rest[tag_len..]);

            // Decrypt with AAD
            let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
                .map_err(|_| EncryptionError::InvalidKeyLength)?;

            cipher
                .decrypt_in_place_detached(nonce, aad, &mut buffer, tag)
                .map_err(|_| {
                    EncryptionError::Decryption(
                        "Decryption failed - wrong session or corrupted data",
                    )
                })?;

            Ok(buffer)
        }
    }
}

#[cfg(feature = "encryption-aes256gcm")]
mod aes256gcm_impl {
    use super::{EncryptionError, StateEncryption};
    use aes_gcm::{
        aead::{AeadCore, AeadInPlace, KeyInit, OsRng},
        Aes256Gcm, Nonce,
    };

    /// AES-256-GCM implementation of StateEncryption
    pub struct Aes256GcmEncryption {
        key: [u8; 32],
    }

    impl Aes256GcmEncryption {
        pub fn new(key: [u8; 32]) -> Self {
            Self { key }
        }
    }

    impl StateEncryption for Aes256GcmEncryption {
        fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, EncryptionError> {
            let cipher = Aes256Gcm::new_from_slice(&self.key)
                .map_err(|_| EncryptionError::InvalidKeyLength)?;

            // Generate a random nonce (12 bytes for AES-GCM)
            let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

            // Encrypt with AAD
            let mut buffer = plaintext.to_vec();
            let tag = cipher
                .encrypt_in_place_detached(&nonce, aad, &mut buffer)
                .map_err(|_| EncryptionError::Encryption("Encryption failed"))?;

            // Combine: nonce || ciphertext || tag
            let mut result = nonce.to_vec();
            result.extend_from_slice(&buffer);
            result.extend_from_slice(tag.as_slice());

            Ok(result)
        }

        fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, EncryptionError> {
            // Extract nonce (first 12 bytes)
            if ciphertext.len() < 12 {
                return Err(EncryptionError::InvalidCiphertextLength);
            }

            let nonce = Nonce::from_slice(&ciphertext[..12]);
            let rest = &ciphertext[12..];

            // Extract tag (last 16 bytes for GCM)
            if rest.len() < 16 {
                return Err(EncryptionError::InvalidCiphertextLength);
            }

            let tag_len = rest.len() - 16;
            let mut buffer = rest[..tag_len].to_vec();
            let tag = aes_gcm::Tag::from_slice(&rest[tag_len..]);

            // Decrypt with AAD
            let cipher = Aes256Gcm::new_from_slice(&self.key)
                .map_err(|_| EncryptionError::InvalidKeyLength)?;

            cipher
                .decrypt_in_place_detached(nonce, aad, &mut buffer, tag)
                .map_err(|_| {
                    EncryptionError::Decryption(
                        "Decryption failed - wrong session or corrupted data",
                    )
                })?;

            Ok(buffer)
        }
    }
}

// Re-export implementations
#[cfg(feature = "encryption-chacha20poly1305")]
pub use chacha20poly1305_impl::ChaCha20Poly1305Encryption;

#[cfg(feature = "encryption-aes256gcm")]
pub use aes256gcm_impl::Aes256GcmEncryption;

/// Create a StateEncryption instance based on enabled features
/// Defaults to ChaCha20Poly1305 if both are enabled
pub fn create_encryption(key: [u8; 32]) -> Box<dyn StateEncryption> {
    #[cfg(feature = "encryption-chacha20poly1305")]
    {
        Box::new(ChaCha20Poly1305Encryption::new(key))
    }

    #[cfg(all(
        not(feature = "encryption-chacha20poly1305"),
        feature = "encryption-aes256gcm"
    ))]
    {
        Box::new(Aes256GcmEncryption::new(key))
    }

    #[cfg(all(
        not(feature = "encryption-chacha20poly1305"),
        not(feature = "encryption-aes256gcm")
    ))]
    {
        compile_error!("At least one encryption feature must be enabled: encryption-chacha20poly1305 or encryption-aes256gcm");
        
    }
}
