use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use local_storage::LocalStorageImpl;

/// Node-local state for a ring's public polynomial and this node's position.
/// Stored under `LocalStorageKeys::RingPolyState(ring_pk_hex)` and updated
/// atomically with the private share after every fresh DKG and PSS refresh.
/// Never posted to the bulletin.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RingPolyState {
    /// Hex-encoded current public polynomial (updated after each PSS refresh).
    pub public_polynomial: String,
    /// Unix timestamp (seconds) of the most recent PSS refresh, or 0 for the
    /// initial DKG. Updated atomically with `public_polynomial`.
    #[serde(default)]
    pub refreshed_at: u64,
}

impl RingPolyState {
    pub fn load(storage: &LocalStorageImpl, ring_pk_hex: &str) -> Result<Self, String> {
        let bytes = storage
            .get(LocalStorageKeys::RingPolyState(ring_pk_hex.to_string()))
            .map_err(|e| format!("Failed to read RingPolyState for {}: {}", ring_pk_hex, e))?
            .ok_or_else(|| format!("RingPolyState not found for ring_pk {}", ring_pk_hex))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| format!("Failed to deserialize RingPolyState: {}", e))
    }

    pub fn save(&self, storage: &LocalStorageImpl, ring_pk_hex: &str) -> Result<(), String> {
        let bytes = serde_json::to_vec(self)
            .map_err(|e| format!("Failed to serialize RingPolyState: {}", e))?;
        storage
            .set(
                LocalStorageKeys::RingPolyState(ring_pk_hex.to_string()),
                bytes,
            )
            .map_err(|e| format!("Failed to store RingPolyState for {}: {}", ring_pk_hex, e))
    }
}
