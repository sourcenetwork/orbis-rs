use crate::{
    error::{LocalStorageError, Result},
    r#trait::{LocalStorage, LocalStorageKeys},
};
use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
use argon2::{password_hash::SaltString, Argon2};
use rand_core::{OsRng, RngCore};
use redb::{Database, Error, ReadableDatabase, TableDefinition};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct RedbStorage {
    pub store: Arc<Database>,
    pub cipher: Aes256Gcm,
    pub salt: Option<Vec<u8>>,
}

#[cfg(test)]
mod tests;

impl LocalStorage for RedbStorage {
    fn new(password: Option<String>) -> Result<Self> {
        // TODO: pass in path
        let db = Database::create("my_db.redb").map_err(|e| {
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
        todo!()
    }
    fn set(&self, key: LocalStorageKeys, value: Vec<u8>) -> Result<()> {
        todo!()
    }
    fn delete(&self, key: LocalStorageKeys) -> Result<()> {
        todo!()
    }
    fn contains(&self, key: LocalStorageKeys) -> Result<bool> {
        todo!()
    }
    fn get_encrypted(&self, key: LocalStorageKeys) -> Result<Option<Vec<u8>>> {
        todo!()
    }
    fn set_encrypted(&self, key: LocalStorageKeys, value: Vec<u8>) -> Result<()> {
        todo!()
    }
}
