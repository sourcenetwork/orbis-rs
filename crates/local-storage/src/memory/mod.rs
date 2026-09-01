use crate::{
    common::{decrypt_value, derive_cipher, encrypt_value},
    error::{LocalStorageError, Result},
    r#trait::{LocalStorage, LocalStorageKeys},
};
use aes_gcm::Aes256Gcm;
use argon2::password_hash::SaltString;
use rand_core::OsRng;
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

    fn new(password: String, _db_path: String) -> Result<Self> {
        let salt = SaltString::generate(&mut OsRng);
        let salt_bytes = salt.as_salt().as_str().as_bytes().to_vec();
        let (cipher, _key) = derive_cipher(&password, &salt_bytes)?;

        Ok(Self {
            store: Arc::new(RwLock::new(HashMap::new())),
            cipher,
            salt: Some(salt_bytes),
        })
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
    // The in-memory backend is testing-only and never persisted, so there is no
    // at-rest tamper / rollback surface: it encrypts with an empty AAD rather
    // than the redb backend's slot/epoch binding.
    fn get_encrypted(&self, key: LocalStorageKeys) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.get(key)?
            .map(|stored| decrypt_value(&self.cipher, &[], &stored).map(Zeroizing::new))
            .transpose()
    }

    fn set_encrypted(&self, key: LocalStorageKeys, value: Zeroizing<Vec<u8>>) -> Result<()> {
        let encrypted = encrypt_value(&self.cipher, &[], &value)?;
        self.set(key, encrypted)
    }
}
