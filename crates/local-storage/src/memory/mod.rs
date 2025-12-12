use crate::{
    error::{LocalStorageError, Result},
    r#trait::{LocalStorage, LocalStorageKeys},
};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
pub struct MemoryStorage {
    pub store: Arc<RwLock<HashMap<LocalStorageKeys, Vec<u8>>>>,
}

impl LocalStorage for MemoryStorage {
    // TODO: determine how to handle poisoned mutex

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

        // TODO: decrypt here NOT PROD READY!!!!!!!!
        Ok(store.get(&key).cloned())
    }

    fn set_encrypted(&self, key: LocalStorageKeys, value: Vec<u8>) -> Result<()> {
        let mut store = self
            .store
            .write()
            .map_err(|e| LocalStorageError::PosionError(e.to_string()))?;
        // TODO: encrypt value here NOT PROD READY!!!!!!!!
        store.insert(key, value);
        Ok(())
    }
}
