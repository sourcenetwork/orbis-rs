use crate::{
    error::{LocalStorageError, Result},
    r#trait::{LocalStorage, LocalStorageKeys},
};
use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
use argon2::{password_hash::SaltString, Argon2};
use rand_core::{OsRng, RngCore};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct MemoryStorage {
    pub store: Arc<RwLock<HashMap<LocalStorageKeys, Vec<u8>>>>,
    pub cipher: Aes256Gcm,
    pub salt: Option<Vec<u8>>,
}

#[cfg(test)]
mod tests;

impl LocalStorage for MemoryStorage {
    // TODO: determine how to handle poisoned mutex

    fn new(password: Option<String>, _db_path: String) -> Result<Self> {
        let store = Arc::new(RwLock::new(HashMap::new()));

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
                    store,
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
            .map_err(|e| LocalStorageError::PosionError(e.to_string()))?;
        Ok(store.get(&key).cloned())
    }

    fn set(&self, key: LocalStorageKeys, value: Vec<u8>) -> Result<()> {
        let mut store = self
            .store
            .write()
            .map_err(|e| LocalStorageError::PosionError(e.to_string()))?;
        store.insert(key, value);
        Ok(())
    }

    fn delete(&self, key: LocalStorageKeys) -> Result<()> {
        let mut store = self
            .store
            .write()
            .map_err(|e| LocalStorageError::PosionError(e.to_string()))?;
        store.remove(&key);
        Ok(())
    }

    fn contains(&self, key: LocalStorageKeys) -> Result<bool> {
        let store = self
            .store
            .read()
            .map_err(|e| LocalStorageError::PosionError(e.to_string()))?;
        Ok(store.contains_key(&key))
    }
    fn get_encrypted(&self, key: LocalStorageKeys) -> Result<Option<Vec<u8>>> {
        let store = self
            .store
            .read()
            .map_err(|e| LocalStorageError::PosionError(e.to_string()))?;

        let stored = store.get(&key).ok_or(LocalStorageError::NotFound)?;

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

        let mut store = self
            .store
            .write()
            .map_err(|e| LocalStorageError::PosionError(e.to_string()))?;

        store.insert(key, store_value);
        Ok(())
    }
}
