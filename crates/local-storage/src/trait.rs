use crate::error::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Eq, Hash, PartialEq)]
pub enum LocalStorageKeys {}

pub trait LocalStorage {
    /// Get an item from your local store
    fn get(&self, key: LocalStorageKeys) -> Result<Option<Vec<u8>>>;
    /// Set an item into your local store
    fn set(&self, key: LocalStorageKeys, value: Vec<u8>) -> Result<()>;
    /// Delete an item from your local store
    fn delete(&self, key: LocalStorageKeys) -> Result<()>;
    /// Checks if item is in local store
    fn contains(&self, key: LocalStorageKeys) -> Result<bool>;
    /// Gets an item stored encrypted at rest and decrypts it
    fn get_encrypted(&self, key: LocalStorageKeys) -> Result<Option<Vec<u8>>>;
    /// Sets an item and encrypts it
    fn set_encrypted(&self, key: LocalStorageKeys, value: Vec<u8>) -> Result<()>;
}
