// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

#[cfg(feature = "serde")]
use std::marker::PhantomData;
#[cfg(feature = "serde")]
use std::sync::Arc;

#[cfg(feature = "serde")]
use crate::common::{
    encryption::{create_encryption, EncryptionError, StateEncryption},
    ser::Serializable,
    storage::{DBKey, StorageError, UntrustedDB},
    traits::{GroupElem, Round, ScalarReduce},
    utils::SessionId,
};

#[cfg(feature = "serde")]
use super::{
    dkg::{KeygenParty, R0, R1, R2},
    messages::{KeygenMsg1, KeygenMsg2},
    types::KeygenError,
    Keyshare,
};

/// Server-side DKG handler that stores encrypted state in untrusted database
/// Requires the `serde` feature to be enabled for serialization
#[cfg(feature = "serde")]
pub struct DkgServer<G, DB>
where
    G: GroupElem,
    G::Scalar: ScalarReduce<[u8; 32]> + Serializable,
    DB: UntrustedDB,
{
    /// Encryption implementation (ChaCha20Poly1305 or AES-256-GCM)
    encryption: Box<dyn StateEncryption>,
    /// Untrusted database for storing encrypted state
    db: Arc<DB>,
    /// Phantom data to mark the group type
    _phantom: PhantomData<G>,
}

#[cfg(feature = "serde")]
impl<G, DB> DkgServer<G, DB>
where
    G: GroupElem,
    G::Scalar: ScalarReduce<[u8; 32]> + Serializable,
    DB: UntrustedDB,
{
    /// Create a new DKG server
    pub fn new(encryption_key: [u8; 32], db: Arc<DB>) -> Self {
        Self {
            encryption: create_encryption(encryption_key),
            db,
            _phantom: PhantomData,
        }
    }

    /// Start round 0: Initialize the DKG protocol
    pub fn start_round_0(
        &self,
        session_id: SessionId,
        party: KeygenParty<R0, G>,
    ) -> Result<KeygenMsg1, ServerError> {
        // Process round 0 using Round trait (same as run_round does)
        // KeygenParty<R0, G> with input () outputs (KeygenParty<R1<G>, G>, KeygenMsg1)
        let (party_r1, msg1) = party
            .process(())
            .map_err(|_e| ServerError::ProtocolError("Round 0 processing failed"))?;

        // Encrypt party_r1 state and store in DB with key (0, session_id)
        let encrypted_state = self.encrypt_state(&party_r1, &session_id)?;
        self.db
            .store(DBKey(0, session_id), encrypted_state)
            .map_err(ServerError::Storage)?;

        Ok(msg1)
    }

    /// Process round 1: Handle KeygenMsg1 messages and produce KeygenMsg2
    pub fn process_round_1(
        &self,
        session_id: SessionId,
        messages: Vec<KeygenMsg1>,
    ) -> Result<KeygenMsg2<G>, ServerError> {
        // Retrieve and decrypt state from DB
        let encrypted_state = self
            .db
            .retrieve(DBKey(0, session_id))
            .map_err(ServerError::Storage)?;
        let party_r1: KeygenParty<R1<G>, G> = self.decrypt_state(&encrypted_state, &session_id)?;

        // Process round 1 using Round trait (same as run_round does)
        // KeygenParty<R1<G>, G> with input Vec<KeygenMsg1> outputs (KeygenParty<R2, G>, KeygenMsg2<G>)
        let (party_r2, msg2) = party_r1
            .process(messages)
            .map_err(|_e| ServerError::ProtocolError("Round 1 processing failed"))?;

        // Encrypt party_r2 state and store in DB with key (1, session_id)
        let encrypted_state = self.encrypt_state(&party_r2, &session_id)?;
        self.db
            .store(DBKey(1, session_id), encrypted_state)
            .map_err(ServerError::Storage)?;

        // Clean up round 0 state
        let _ = self.db.delete(DBKey(0, session_id));

        Ok(msg2)
    }

    /// Process round 2: Handle KeygenMsg2 messages and produce final Keyshare
    pub fn process_round_2(
        &self,
        session_id: SessionId,
        messages: Vec<KeygenMsg2<G>>,
    ) -> Result<Keyshare<G>, ServerError> {
        // Retrieve and decrypt state from DB
        let encrypted_state = self
            .db
            .retrieve(DBKey(1, session_id))
            .map_err(ServerError::Storage)?;
        let party_r2: KeygenParty<R2, G> = self.decrypt_state(&encrypted_state, &session_id)?;

        // Process round 2 using Round trait (same as run_round does)
        // KeygenParty<R2, G> with input Vec<KeygenMsg2<G>> outputs Keyshare<G>
        let keyshare = party_r2
            .process(messages)
            .map_err(|_e| ServerError::ProtocolError("Round 2 processing failed"))?;

        // Clean up: delete state from DB
        self.db
            .delete(DBKey(1, session_id))
            .map_err(ServerError::Storage)?;

        Ok(keyshare)
    }

    /// Encrypt state using the configured encryption algorithm with session_id as authenticated data
    #[cfg(feature = "serde")]
    fn encrypt_state<T>(&self, state: &T, session_id: &SessionId) -> Result<Vec<u8>, ServerError>
    where
        T: Serializable + serde::Serialize,
    {
        // Serialize the state
        let serialized = bincode::serialize(state)
            .map_err(|e| ServerError::SerializationError(e.to_string()))?;

        // Encrypt with session_id as authenticated data (AAD)
        self.encryption
            .encrypt(&serialized, session_id.as_ref())
            .map_err(|e| match e {
                EncryptionError::Encryption(msg) => ServerError::EncryptionError(msg),
                EncryptionError::InvalidKeyLength => {
                    ServerError::EncryptionError("Invalid key length")
                }
                EncryptionError::InvalidCiphertextLength => {
                    ServerError::EncryptionError("Invalid ciphertext length")
                }
                EncryptionError::Decryption(_) => {
                    ServerError::EncryptionError("Unexpected decryption error")
                }
            })
    }

    /// Decrypt state using the configured encryption algorithm with session_id as authenticated data
    #[cfg(feature = "serde")]
    fn decrypt_state<T>(&self, encrypted: &[u8], session_id: &SessionId) -> Result<T, ServerError>
    where
        T: Serializable + serde::de::DeserializeOwned,
    {
        // Decrypt with session_id as authenticated data (AAD)
        let plaintext = self
            .encryption
            .decrypt(encrypted, session_id.as_ref())
            .map_err(|e| match e {
                EncryptionError::Decryption(msg) => ServerError::DecryptionError(msg),
                EncryptionError::InvalidKeyLength => {
                    ServerError::DecryptionError("Invalid key length")
                }
                EncryptionError::InvalidCiphertextLength => {
                    ServerError::DecryptionError("Invalid ciphertext length")
                }
                EncryptionError::Encryption(_) => {
                    ServerError::DecryptionError("Unexpected encryption error")
                }
            })?;

        // Deserialize the state
        let state: T = bincode::deserialize(&plaintext)
            .map_err(|e| ServerError::DeserializationError(e.to_string()))?;

        Ok(state)
    }
}

#[cfg(feature = "serde")]
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("Encryption error: {0}")]
    EncryptionError(&'static str),
    #[error("Decryption error: {0}")]
    DecryptionError(&'static str),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    #[error("Protocol error: {0}")]
    ProtocolError(&'static str),
}

#[cfg(feature = "serde")]
impl From<KeygenError> for ServerError {
    fn from(err: KeygenError) -> Self {
        match err {
            KeygenError::DecryptionError => ServerError::DecryptionError("Keygen decryption error"),
            KeygenError::EncryptionError => ServerError::EncryptionError("Keygen encryption error"),
            _ => ServerError::ProtocolError("Keygen protocol error"),
        }
    }
}
