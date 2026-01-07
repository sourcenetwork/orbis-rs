use crate::{
    error::{LocalStorageError, Result},
    r#trait::{LocalStorage, LocalStorageKeys},
};
use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
use argon2::{password_hash::SaltString, Argon2};
use rand_core::{OsRng, RngCore};
use redb::{Database, ReadableDatabase, TableDefinition};
use std::sync::Arc;
use zeroize::Zeroizing;

const TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("orbis_local");

fn serialize_key(key: &LocalStorageKeys) -> Result<Vec<u8>> {
    bincode::serialize(key)
        .map_err(|e| LocalStorageError::UniqueDBError(format!("Failed to serialize key: {}", e)))
}

#[derive(Clone)]
pub struct RedbStorage {
    pub store: Arc<Database>,
    pub cipher: Aes256Gcm,
    pub salt: Option<Vec<u8>>,
}

#[cfg(test)]
mod tests;

impl LocalStorage for RedbStorage {
    fn new(password: Option<String>, db_path: String) -> Result<Self> {
        // TODO: pass in path
        let db = Database::create(db_path).map_err(|e| {
            LocalStorageError::UniqueDBError(format!("Failed to create database: {}", e))
        })?;

        match password {
            Some(password) => {
                let mut rng = OsRng;
                let salt = SaltString::generate(&mut rng);
                let argon2 = Argon2::default();

                // Use Zeroizing wrapper to ensure key bytes are zeroed on drop
                let mut key_bytes = Zeroizing::new([0u8; 32]);
                let salt_bytes = salt.as_salt().as_str().as_bytes();
                argon2
                    .hash_password_into(password.as_bytes(), salt_bytes, key_bytes.as_mut())
                    .expect("argon2 key derivation failed");

                let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes.as_ref()));
                // key_bytes is automatically zeroed when it goes out of scope here

                Ok(Self {
                    store: db.into(),
                    cipher,
                    salt: Some(salt.as_salt().as_str().as_bytes().to_vec()),
                })
            }
            None => {
                let mut rng = OsRng;
                // Use Zeroizing wrapper to ensure key bytes are zeroed on drop
                let mut key_bytes = Zeroizing::new([0u8; 32]);
                rng.fill_bytes(key_bytes.as_mut());

                let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes.as_ref()));
                // key_bytes is automatically zeroed when it goes out of scope here

                Ok(Self {
                    store: db.into(),
                    cipher,
                    salt: None,
                })
            }
        }
    }
    fn get(&self, key: LocalStorageKeys) -> Result<Option<Vec<u8>>> {
        let key_bytes = serialize_key(&key)?;
        let read_txn = self.store.begin_read().map_err(|e| {
            LocalStorageError::UniqueDBError(format!("Failed to begin read transaction: {}", e))
        })?;
        let table = read_txn.open_table(TABLE).map_err(|e| {
            LocalStorageError::UniqueDBError(format!("Failed to open table: {}", e))
        })?;
        let value = table
            .get(key_bytes.as_slice())
            .map_err(|e| LocalStorageError::UniqueDBError(format!("Failed to get value: {}", e)))?;
        Ok(value.map(|v| v.value().to_vec()))
    }
    fn set(&self, key: LocalStorageKeys, value: Vec<u8>) -> Result<()> {
        let key_bytes = serialize_key(&key)?;
        let write_txn = self.store.begin_write().map_err(|e| {
            LocalStorageError::UniqueDBError(format!("Failed to begin read transaction: {}", e))
        })?;
        {
            let mut table = write_txn.open_table(TABLE).map_err(|e| {
                LocalStorageError::UniqueDBError(format!("Failed to open table: {}", e))
            })?;
            table
                .insert(key_bytes.as_slice(), value.as_slice())
                .map_err(|e| {
                    LocalStorageError::UniqueDBError(format!("Failed to open table: {}", e))
                })?;
        }
        write_txn.commit().map_err(|e| {
            LocalStorageError::UniqueDBError(format!("Failed to open table: {}", e))
        })?;
        Ok(())
    }
    fn delete(&self, key: LocalStorageKeys) -> Result<()> {
        let key_bytes = serialize_key(&key)?;
        let write_txn = self.store.begin_write().map_err(|e| {
            LocalStorageError::UniqueDBError(format!("Failed to begin read transaction: {}", e))
        })?;
        {
            let mut table = write_txn.open_table(TABLE).map_err(|e| {
                LocalStorageError::UniqueDBError(format!("Failed to open table: {}", e))
            })?;
            table.remove(key_bytes.as_slice()).map_err(|e| {
                LocalStorageError::UniqueDBError(format!("Failed to open table: {}", e))
            })?;
        }
        write_txn.commit().map_err(|e| {
            LocalStorageError::UniqueDBError(format!("Failed to open table: {}", e))
        })?;
        Ok(())
    }
    fn contains(&self, key: LocalStorageKeys) -> Result<bool> {
        Ok(self.get(key)?.is_some())
    }
    fn get_encrypted(&self, key: LocalStorageKeys) -> Result<Option<Vec<u8>>> {
        let stored = self
            .get(key)?
            .ok_or_else(|| LocalStorageError::UniqueDBError("Issue getting value".to_string()))?;

        if stored.len() < 12 {
            return Err(LocalStorageError::CorruptData);
        }

        let (nonce_bytes, ciphertext) = stored.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| LocalStorageError::DecryptionError)?;

        Ok(Some(plaintext))
    }
    fn set_encrypted(&self, key: LocalStorageKeys, value: Vec<u8>) -> Result<()> {
        // generate random nonce
        let mut rng = OsRng;
        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // encrypt
        let ciphertext = self
            .cipher
            .encrypt(nonce, value.as_ref())
            .map_err(|_| LocalStorageError::EncryptionError)?;

        // store nonce and ciphertext
        let mut store_value = Vec::with_capacity(12 + ciphertext.len());
        store_value.extend_from_slice(&nonce_bytes);
        store_value.extend_from_slice(&ciphertext);

        self.set(key, store_value).map_err(|e| {
            LocalStorageError::UniqueDBError(format!("Failed to store value: {}", e))
        })?;
        Ok(())
    }
}
