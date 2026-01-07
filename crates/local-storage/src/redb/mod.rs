use crate::{
    common::{decrypt_value, derive_cipher, encrypt_value},
    error::{LocalStorageError, Result},
    r#trait::{LocalStorage, LocalStorageKeys},
};
use aes_gcm::{Aes256Gcm, Key, KeyInit};
use argon2::password_hash::SaltString;
use rand_core::{OsRng, RngCore};
use redb::{Database, ReadableDatabase, TableDefinition};
use std::path::Path;
use std::sync::Arc;
use zeroize::Zeroizing;

const TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("orbis_local");

// Internal keys for password verification (prefixed with __internal__ to avoid collisions)
const INTERNAL_SALT_KEY: &[u8] = b"__internal__salt";
const INTERNAL_PASSWORD_CHECK_KEY: &[u8] = b"__internal__password_check";
const PASSWORD_CHECK_VALUE: &[u8] = b"password_check_ok";

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
        // Create parent directories if they don't exist
        if let Some(parent) = Path::new(&db_path).parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    LocalStorageError::UniqueDBError(format!(
                        "Failed to create database directory: {}",
                        e
                    ))
                })?;
            }
        }

        let db = Database::create(&db_path).map_err(|e| {
            LocalStorageError::UniqueDBError(format!("Failed to create database: {}", e))
        })?;

        let existing_salt = raw_get(&db, INTERNAL_SALT_KEY)?;

        match password {
            Some(password) => {
                let (cipher, salt_bytes) = if let Some(stored_salt) = existing_salt {
                    // Existing database - verify password
                    let cipher = derive_cipher(&password, &stored_salt);
                    let encrypted_check = raw_get(&db, INTERNAL_PASSWORD_CHECK_KEY)?
                        .ok_or(LocalStorageError::CorruptData)?;
                    let decrypted = decrypt_value(&cipher, &encrypted_check)
                        .map_err(|_| LocalStorageError::InvalidPassword)?;

                    if decrypted != PASSWORD_CHECK_VALUE {
                        return Err(LocalStorageError::InvalidPassword);
                    }
                    (cipher, stored_salt)
                } else {
                    // New database - generate salt and store password check
                    let salt = SaltString::generate(&mut OsRng);
                    let salt_bytes = salt.as_salt().as_str().as_bytes().to_vec();
                    let cipher = derive_cipher(&password, &salt_bytes);
                    let encrypted_check = encrypt_value(&cipher, PASSWORD_CHECK_VALUE)?;

                    raw_set(&db, INTERNAL_SALT_KEY, &salt_bytes)?;
                    raw_set(&db, INTERNAL_PASSWORD_CHECK_KEY, &encrypted_check)?;
                    (cipher, salt_bytes)
                };

                Ok(Self {
                    store: db.into(),
                    cipher,
                    salt: Some(salt_bytes),
                })
            }
            None => {
                // No password - use random key (encryption still works but key isn't persisted)
                let mut key_bytes = Zeroizing::new([0u8; 32]);
                OsRng.fill_bytes(key_bytes.as_mut());
                let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes.as_ref()));

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
        raw_get(&self.store, &key_bytes)
    }

    fn set(&self, key: LocalStorageKeys, value: Vec<u8>) -> Result<()> {
        let key_bytes = serialize_key(&key)?;
        raw_set(&self.store, &key_bytes, &value)
    }

    fn delete(&self, key: LocalStorageKeys) -> Result<()> {
        let key_bytes = serialize_key(&key)?;
        raw_delete(&self.store, &key_bytes)
    }

    fn contains(&self, key: LocalStorageKeys) -> Result<bool> {
        Ok(self.get(key)?.is_some())
    }

    fn get_encrypted(&self, key: LocalStorageKeys) -> Result<Option<Vec<u8>>> {
        let stored = self.get(key)?.ok_or(LocalStorageError::NotFound)?;
        decrypt_value(&self.cipher, &stored).map(Some)
    }

    fn set_encrypted(&self, key: LocalStorageKeys, value: Vec<u8>) -> Result<()> {
        let encrypted = encrypt_value(&self.cipher, &value)?;
        self.set(key, encrypted)
    }
}

fn serialize_key(key: &LocalStorageKeys) -> Result<Vec<u8>> {
    bincode::serialize(key)
        .map_err(|e| LocalStorageError::UniqueDBError(format!("Failed to serialize key: {}", e)))
}

/// Raw get operation on database (used during initialization before self exists)
fn raw_get(db: &Database, key: &[u8]) -> Result<Option<Vec<u8>>> {
    let read_txn = db.begin_read().map_err(|e| {
        LocalStorageError::UniqueDBError(format!("Failed to begin read transaction: {}", e))
    })?;
    match read_txn.open_table(TABLE) {
        Ok(table) => {
            let value = table.get(key).map_err(|e| {
                LocalStorageError::UniqueDBError(format!("Failed to get value: {}", e))
            })?;
            Ok(value.map(|v| v.value().to_vec()))
        }
        Err(_) => Ok(None), // Table doesn't exist yet
    }
}

/// Raw set operation on database
fn raw_set(db: &Database, key: &[u8], value: &[u8]) -> Result<()> {
    let write_txn = db.begin_write().map_err(|e| {
        LocalStorageError::UniqueDBError(format!("Failed to begin write transaction: {}", e))
    })?;
    {
        let mut table = write_txn.open_table(TABLE).map_err(|e| {
            LocalStorageError::UniqueDBError(format!("Failed to open table: {}", e))
        })?;
        table.insert(key, value).map_err(|e| {
            LocalStorageError::UniqueDBError(format!("Failed to insert value: {}", e))
        })?;
    }
    write_txn.commit().map_err(|e| {
        LocalStorageError::UniqueDBError(format!("Failed to commit transaction: {}", e))
    })?;
    Ok(())
}

/// Raw delete operation on database
fn raw_delete(db: &Database, key: &[u8]) -> Result<()> {
    let write_txn = db.begin_write().map_err(|e| {
        LocalStorageError::UniqueDBError(format!("Failed to begin write transaction: {}", e))
    })?;
    {
        let mut table = write_txn.open_table(TABLE).map_err(|e| {
            LocalStorageError::UniqueDBError(format!("Failed to open table: {}", e))
        })?;
        table.remove(key).map_err(|e| {
            LocalStorageError::UniqueDBError(format!("Failed to delete value: {}", e))
        })?;
    }
    write_txn.commit().map_err(|e| {
        LocalStorageError::UniqueDBError(format!("Failed to commit transaction: {}", e))
    })?;
    Ok(())
}

impl std::fmt::Debug for RedbStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedbStorage")
            .field("store", &"<Database>")
            .field("cipher", &"<Aes256Gcm>")
            .field("salt", &self.salt.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}
