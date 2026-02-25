use crate::{
    common::{decrypt_value, derive_cipher, encrypt_value},
    error::{LocalStorageError, Result},
    r#trait::{LocalStorage, LocalStorageKeys},
};
use aes_gcm::{Aes256Gcm, Key, KeyInit};
use argon2::password_hash::SaltString;
use rand_core::{OsRng, RngCore};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use zeroize::Zeroizing;

const NAME: &str = "local-storage/memory";

#[derive(Clone)]
pub struct MemoryStorage {
    pub store: Arc<RwLock<HashMap<LocalStorageKeys, Vec<u8>>>>,
    pub cipher: Aes256Gcm,
    pub salt: Option<Vec<u8>>,
}

#[cfg(test)]
mod tests;

impl LocalStorage for MemoryStorage {
    fn name() -> String {
        NAME.to_string()
    }

    fn new(password: Option<String>, _db_path: String) -> Result<Self> {
        let store = Arc::new(RwLock::new(HashMap::new()));

        match password {
            Some(password) => {
                let salt = SaltString::generate(&mut OsRng);
                let salt_bytes = salt.as_salt().as_str().as_bytes().to_vec();
                let cipher = derive_cipher(&password, &salt_bytes)?;

                Ok(Self {
                    store,
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
                    store,
                    cipher,
                    salt: None,
                })
            }
        }
    }

    fn get(&self, key: LocalStorageKeys) -> Result<Option<Vec<u8>>> {
        let store = self
            .store
            .read()
            .map_err(|e| LocalStorageError::PoisonError(e.to_string()))?;
        Ok(store.get(&key).cloned())
    }

    fn set(&self, key: LocalStorageKeys, value: Vec<u8>) -> Result<()> {
        let mut store = self
            .store
            .write()
            .map_err(|e| LocalStorageError::PoisonError(e.to_string()))?;
        store.insert(key, value);
        Ok(())
    }

    fn delete(&self, key: LocalStorageKeys) -> Result<()> {
        let mut store = self
            .store
            .write()
            .map_err(|e| LocalStorageError::PoisonError(e.to_string()))?;
        store.remove(&key);
        Ok(())
    }

    fn contains(&self, key: LocalStorageKeys) -> Result<bool> {
        let store = self
            .store
            .read()
            .map_err(|e| LocalStorageError::PoisonError(e.to_string()))?;
        Ok(store.contains_key(&key))
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
