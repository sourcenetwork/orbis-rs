use crate::error::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, Eq, Hash, PartialEq)]
pub enum LocalStorageKeys {
    RingKey(String),
    /// Maps ring public key (serialized G1Affine bytes as hex) to DKG session ID
    RingPkMapping(String),
    /// The node's iroh secret key for deterministic peer identity
    NodeSecretKey,
    /// The node's secp256k1 signing key for chain transactions
    NodeSigningKey,
}

pub trait LocalStorage {
    fn name(&self) -> &str;
    fn new(password: Option<String>, db_path: String) -> Result<Self>
    where
        Self: Sized;
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
