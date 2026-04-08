use crypto::r#trait::{CryptoDeserialize, PriShare};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use zeroize::Zeroizing;

/// One entry in the node's ring index.
///
/// Stored as a JSON `Vec<RingIndexEntry>` under `LocalStorageKeys::RingIndex`.
/// Gives the PSS scheduler and refresh validator everything they need to locate
/// a ring in local storage and on the bulletin without any extra round-trips.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RingIndexEntry {
    /// `aggregate_pk.to_string()` — the key used for `RingKey` / `RingShareBundle`.
    pub ring_pk_str: String,
    /// Content-hash post_id of this ring's `RingPayload` on the bulletin.
    pub bulletin_post_id: String,
}

/// Combined share + polynomial bundle stored as a single encrypted write under
/// `RingKey(ring_pk.to_string())`.  Writing both fields together in one
/// `set_encrypted` call makes them atomic: a crash can leave the entry absent
/// (ring not yet committed) but never partially updated.
///
/// Serialized with `bincode` so the plaintext buffer can be held in a
/// `Zeroizing` wrapper throughout the write path.
#[derive(Clone, Debug)]
pub struct RingShareBundle {
    /// Serialized `PriShare<Fr>` (output of `CryptoSerialize::to_bytes`).
    pub share_bytes: Zeroizing<Vec<u8>>,
    /// Hex-encoded current public polynomial (updated after each PSS refresh).
    pub public_polynomial: String,
    /// Unix timestamp (seconds) of the most recent PSS ceremony (fresh DKG, refresh,
    /// or reshare), or 0 before the first completion.
    pub last_pss: u64,
}

impl RingShareBundle {
    fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(
            bincode::serialize(&(&*self.share_bytes, &self.public_polynomial, self.last_pss))
                .expect("RingShareBundle serialization is infallible"),
        )
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let (share_bytes, public_polynomial, last_pss): (Vec<u8>, String, u64) =
            bincode::deserialize(bytes).map_err(|e| format!("RingShareBundle: {e}"))?;
        Ok(Self {
            share_bytes: Zeroizing::new(share_bytes),
            public_polynomial,
            last_pss,
        })
    }

    /// Load the bundle from encrypted storage keyed by `ring_pk.to_string()`.
    pub fn load(storage: &impl LocalStorage, ring_pk: &G1Affine) -> Result<Self, String> {
        let bytes = storage
            .get_encrypted(LocalStorageKeys::RingKey(ring_pk.to_string()))
            .map_err(|e| format!("Failed to read RingShareBundle: {}", e))?
            .ok_or_else(|| format!("RingShareBundle not found for ring_pk {}", ring_pk))?;
        Self::from_bytes(&bytes)
    }

    /// Save the bundle as a single encrypted write keyed by `ring_pk.to_string()`.
    pub fn save(&self, storage: &impl LocalStorage, ring_pk: &G1Affine) -> Result<(), String> {
        storage
            .set_encrypted(
                LocalStorageKeys::RingKey(ring_pk.to_string()),
                self.to_bytes(),
            )
            .map_err(|e| format!("Failed to store RingShareBundle: {}", e))
    }

    /// Load the bundle using the aggregate public key's display string (skips G1Affine deserialization).
    /// Used by callers that already hold the display string (e.g. PSS scheduler, refresh validator).
    pub fn load_by_ring_key(storage: &impl LocalStorage, ring_key: &str) -> Result<Self, String> {
        let bytes = storage
            .get_encrypted(LocalStorageKeys::RingKey(ring_key.to_string()))
            .map_err(|e| format!("Failed to read RingShareBundle: {}", e))?
            .ok_or_else(|| format!("RingShareBundle not found for ring_key {}", ring_key))?;
        Self::from_bytes(&bytes)
    }

    /// Save the bundle using the aggregate public key's display string.
    pub fn save_by_ring_key(
        &self,
        storage: &impl LocalStorage,
        ring_key: &str,
    ) -> Result<(), String> {
        storage
            .set_encrypted(
                LocalStorageKeys::RingKey(ring_key.to_string()),
                self.to_bytes(),
            )
            .map_err(|e| format!("Failed to store RingShareBundle: {}", e))
    }

    /// Deserialize the private share out of the bundle.
    pub fn pri_share(&self) -> Result<PriShare<Fr>, String> {
        PriShare::<Fr>::from_bytes(&self.share_bytes)
            .map_err(|e| format!("Failed to deserialize PriShare: {}", e))
    }

    /// Project out only the polynomial fields.
    pub fn to_poly_state(&self) -> RingPolyState {
        RingPolyState {
            public_polynomial: self.public_polynomial.clone(),
            last_pss: self.last_pss,
        }
    }
}

/// View of the public polynomial fields, projected from a `RingShareBundle`.
/// Callers that only need the polynomial (e.g. PRE/sign service entry points)
/// can use this lighter type.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RingPolyState {
    /// Hex-encoded current public polynomial.
    pub public_polynomial: String,
    /// Unix timestamp (seconds) of the most recent PSS ceremony (fresh DKG, refresh,
    /// or reshare), or 0 before the first completion.
    #[serde(default)]
    pub last_pss: u64,
}

impl RingPolyState {
    /// Load the polynomial state by reading the `RingShareBundle` for `ring_pk`.
    pub fn load(storage: &impl LocalStorage, ring_pk: &G1Affine) -> Result<Self, String> {
        RingShareBundle::load(storage, ring_pk).map(|b| b.to_poly_state())
    }

    /// Convenience wrapper for callers that have a hex-encoded ring public key
    /// (`hex::encode(to_bytes(aggregate_pk))`).  Deserializes the
    /// key internally and delegates to `load`.
    pub fn load_from_ring_pk_hex(
        storage: &impl LocalStorage,
        ring_pk_hex: &str,
    ) -> Result<Self, String> {
        let bytes = hex::decode(ring_pk_hex).map_err(|e| format!("Invalid ring_pk_hex: {}", e))?;
        let ring_pk = G1Affine::from_bytes(&bytes)
            .map_err(|e| format!("Failed to deserialize ring_pk: {}", e))?;
        Self::load(storage, &ring_pk)
    }
}
