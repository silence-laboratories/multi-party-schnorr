// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::marker::PhantomData;
use std::sync::Arc;

use crate::common::{
    encryption::{create_encryption, EncryptionError, StateEncryption},
    ser::Serializable,
    storage::{DBKey, StorageError, UntrustedDB},
    traits::{GroupElem, Round, ScalarReduce},
    utils::SessionId,
};
use crypto_bigint::subtle::ConstantTimeEq;
use elliptic_curve::group::GroupEncoding;
use sha2::{Digest, Sha256};

use super::{
    dkg::{KeygenParty, R0, R1, R2},
    messages::{KeygenMsg1, KeygenMsg2},
    types::KeygenError,
    Keyshare,
};

/// Server-side DKG handler that stores encrypted state in untrusted database
/// Requires the `serde` feature to be enabled for serialization
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

    /// Compute H(session_id || final_session_id) for round 2 key
    fn compute_round2_key(session_id: &SessionId, final_session_id: &SessionId) -> SessionId {
        Sha256::new()
            .chain_update(session_id)
            .chain_update(final_session_id)
            .finalize()
            .into()
    }

    /// Start round 0: Initialize the DKG protocol
    pub fn start_round_0(
        &self,
        session_id: SessionId,
        party: KeygenParty<R0, G>,
    ) -> Result<KeygenMsg1, ServerError> {
        // Process round 0 using Round trait (same as run_round does)
        // KeygenParty<R0, G> with input () outputs (KeygenParty<R1<G>, G>, KeygenMsg1)
        let (party_r1, msg1) = party.process(()).map_err(ServerError::from)?;

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
        let (party_r2, msg2) = party_r1.process(messages).map_err(ServerError::from)?;

        // Extract final_session_id from msg2.session_id (KeygenMsg2.session_id is the final_session_id)
        let final_session_id = msg2.session_id;

        // Compute H(session_id || final_session_id) for round 2 storage key
        let round2_key = Self::compute_round2_key(&session_id, &final_session_id);

        // Encrypt party_r2 state with round2_key as AAD and store in DB with key (1, H(session_id || final_session_id))
        let encrypted_state = self.encrypt_state(&party_r2, &round2_key)?;
        self.db
            .store(DBKey(1, round2_key), encrypted_state)
            .map_err(ServerError::Storage)?;

        // Clean up round 0 state
        let _ = self.db.delete(DBKey(0, session_id));

        Ok(msg2)
    }

    /// Process round 2: Handle KeygenMsg2 messages and produce final Keyshare
    pub fn process_round_2(
        &self,
        session_id: SessionId,
        final_session_id: SessionId,
        messages: Vec<KeygenMsg2<G>>,
    ) -> Result<Keyshare<G>, ServerError> {
        // Compute H(session_id || final_session_id) for round 2 retrieval key
        let round2_key = Self::compute_round2_key(&session_id, &final_session_id);

        // Retrieve and decrypt state from DB using the computed key
        // Decrypt with round2_key as AAD (must match the AAD used during encryption)
        let encrypted_state = self
            .db
            .retrieve(DBKey(1, round2_key))
            .map_err(ServerError::Storage)?;
        let party_r2: KeygenParty<R2, G> = self.decrypt_state(&encrypted_state, &round2_key)?;

        // Process round 2 using Round trait (same as run_round does)
        // KeygenParty<R2, G> with input Vec<KeygenMsg2<G>> outputs Keyshare<G>
        let keyshare = party_r2.process(messages).map_err(ServerError::from)?;

        // Clean up: delete state from DB using the computed key
        self.db
            .delete(DBKey(1, round2_key))
            .map_err(ServerError::Storage)?;

        Ok(keyshare)
    }

    /// Encrypt state using the configured encryption algorithm with session_id as authenticated data
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
    #[error("Keygen protocol error: {0}")]
    KeygenProtocol(#[from] KeygenError),
}

pub struct ServerSessionRound0<G, DB>
where
    G: GroupElem + GroupEncoding,
    G::Scalar: ScalarReduce<[u8; 32]> + Serializable,
    DB: UntrustedDB,
{
    session_id: SessionId,
    server: Arc<DkgServer<G, DB>>,
    output_msg: KeygenMsg1,
    messages: Vec<KeygenMsg1>,
    n: usize,
}

impl<G, DB> ServerSessionRound0<G, DB>
where
    G: GroupElem + GroupEncoding,
    G::Scalar: ScalarReduce<[u8; 32]> + Serializable,
    DB: UntrustedDB,
{
    /// Initialize round 0 session with server-side state storage.
    pub fn init(
        session_id: SessionId,
        server: Arc<DkgServer<G, DB>>,
        party: KeygenParty<R0, G>,
        n: usize,
    ) -> Result<Self, ServerError> {
        let output_msg = server.start_round_0(session_id, party)?;
        let messages = vec![output_msg.clone()];
        Ok(Self {
            session_id,
            server,
            output_msg,
            messages,
            n,
        })
    }

    /// Get the output message for this round.
    pub fn output_message(&self) -> KeygenMsg1 {
        self.output_msg.clone()
    }

    /// Receive a broadcast message. Returns `true` if all messages have been received.
    pub fn recv_message(&mut self, msg: KeygenMsg1) -> bool {
        self.messages.push(msg);
        self.messages.len() == self.n
    }

    /// Process messages and return next round session and message.
    pub fn process_messages(
        self,
    ) -> Result<(ServerSessionRound1<G, DB>, KeygenMsg2<G>), ServerError> {
        let msg2 = self
            .server
            .process_round_1(self.session_id, self.messages)?;
        let messages = vec![msg2.clone()];
        let output_msg = messages[0].clone();
        Ok((
            ServerSessionRound1 {
                session_id: self.session_id,
                server: self.server,
                output_msg,
                messages,
                n: self.n,
            },
            msg2,
        ))
    }

    /// Get the session ID (for use in tests and transitions).
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Get a reference to the server (for use in tests and transitions).
    pub fn server(&self) -> &Arc<DkgServer<G, DB>> {
        &self.server
    }
}

pub struct ServerSessionRound1<G, DB>
where
    G: GroupElem + GroupEncoding + ConstantTimeEq,
    G::Scalar: ScalarReduce<[u8; 32]> + Serializable,
    DB: UntrustedDB,
{
    session_id: SessionId,
    server: Arc<DkgServer<G, DB>>,
    output_msg: KeygenMsg2<G>,
    messages: Vec<KeygenMsg2<G>>,
    n: usize,
}

impl<G, DB> ServerSessionRound1<G, DB>
where
    G: GroupElem + GroupEncoding + ConstantTimeEq,
    G::Scalar: ScalarReduce<[u8; 32]> + Serializable,
    DB: UntrustedDB,
{
    /// Create round 1 session from previous round output.
    pub fn next(
        session_id: SessionId,
        server: Arc<DkgServer<G, DB>>,
        prev: KeygenMsg2<G>,
        n: usize,
    ) -> Self {
        let messages = vec![prev.clone()];
        let output_msg = prev;
        Self {
            session_id,
            server,
            output_msg,
            messages,
            n,
        }
    }

    /// Get the output message for this round.
    pub fn output_message(&self) -> KeygenMsg2<G> {
        self.output_msg.clone()
    }

    /// Receive a broadcast message. Returns `true` if all messages
    /// received and session ready to call method `process_messages()`.
    pub fn recv_message(&mut self, msg: KeygenMsg2<G>) -> bool {
        self.messages.push(msg);
        self.messages.len() == self.n
    }

    /// Process messages and return final keyshare.
    pub fn process_messages(self) -> Result<Keyshare<G>, ServerError> {
        // Extract final_session_id from the first message
        // KeygenMsg2.session_id is the final_session_id computed in round 1
        let final_session_id = self.messages[0].session_id;
        self.server
            .process_round_2(self.session_id, final_session_id, self.messages)
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn server(&self) -> &Arc<DkgServer<G, DB>> {
        &self.server
    }
}
