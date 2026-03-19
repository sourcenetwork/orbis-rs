use crate::error::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, Eq, Hash, PartialEq)]
pub enum LocalStorageKeys {
    /// Encrypted `RingShareBundle` for one ring, keyed by `aggregate_pk.to_string()`.
    /// Contains the node's threshold secret share, the current public polynomial,
    /// and the unix timestamp of the last PSS refresh. Written once at DKG Phase 4
    /// and updated atomically on every PSS refresh. Never holds ring configuration
    /// (peer_ids, threshold, pss_interval) — that lives on the bulletin.
    RingKey(String),
    /// JSON-encoded `Vec<RingIndexEntry>` of rings this node has joined.
    /// Each entry contains the local storage key (`ring_pk_str`) and the bulletin
    /// `post_id` needed to fetch the canonical `RingPayload`. This is the single
    /// index that ties local cryptographic material to the on-chain ring record.
    RingIndex,
    /// The node's iroh secret key for deterministic peer identity
    NodeSecretKey,
    /// The node's secp256k1 signing key for chain transactions
    NodeSigningKey,
}

pub trait LocalStorage {
    fn name() -> String;
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
