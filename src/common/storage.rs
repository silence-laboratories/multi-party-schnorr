// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use crate::common::utils::SessionId;

/// Database key: (round_number, session_id)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DBKey(pub u8, pub SessionId);

/// Database value: encrypted ciphertext
pub type DBValue = Vec<u8>;

/// Trait for untrusted database storage
pub trait UntrustedDB: Send + Sync {
    /// Store a value in the database
    fn store(&self, key: DBKey, value: DBValue) -> Result<(), StorageError>;

    /// Retrieve a value from the database
    fn retrieve(&self, key: DBKey) -> Result<DBValue, StorageError>;

    /// Delete a value from the database
    fn delete(&self, key: DBKey) -> Result<(), StorageError>;
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Key not found in database")]
    KeyNotFound,
    #[error("Failed to acquire lock")]
    LockError,
}

mod in_memory_db {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// In-memory implementation of UntrustedDB using HashMap
    pub struct InMemoryDB {
        storage: Arc<Mutex<HashMap<DBKey, DBValue>>>,
    }

    impl InMemoryDB {
        /// Create a new in-memory database
        pub fn new() -> Self {
            Self {
                storage: Arc::new(Mutex::new(HashMap::new())),
            }
        }
    }

    impl Default for InMemoryDB {
        fn default() -> Self {
            Self::new()
        }
    }

    impl UntrustedDB for InMemoryDB {
        fn store(&self, key: DBKey, value: DBValue) -> Result<(), StorageError> {
            let mut storage = self.storage.lock().map_err(|_| StorageError::LockError)?;
            storage.insert(key, value);
            Ok(())
        }

        fn retrieve(&self, key: DBKey) -> Result<DBValue, StorageError> {
            let storage = self.storage.lock().map_err(|_| StorageError::LockError)?;
            storage.get(&key).cloned().ok_or(StorageError::KeyNotFound)
        }

        fn delete(&self, key: DBKey) -> Result<(), StorageError> {
            let mut storage = self.storage.lock().map_err(|_| StorageError::LockError)?;
            storage.remove(&key);
            Ok(())
        }
    }
}

pub use in_memory_db::InMemoryDB;
