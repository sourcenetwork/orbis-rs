use crate::constants::RING_POLY_HISTORY_RETENTION_SECS;
use crypto::r#trait::{CryptoDeserialize, PriShare};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use std::fmt;
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
    /// Unix timestamp when this local index entry was created or first observed.
    /// Pending fresh DKG cleanup uses this to age entries whose bulletin payload
    /// has not been finalized yet.
    pub indexed_at_secs: u64,
}

/// Combined share + polynomial bundle stored as a single encrypted write under
/// `RingKey(ring_pk.to_string())`.  Writing both fields together in one
/// `set_encrypted` call makes them atomic: a crash can leave the entry absent
/// (ring not yet committed) but never partially updated.
///
/// Serialized manually so the plaintext buffer can be held in a
/// `Zeroizing` wrapper throughout the write path.
#[derive(Clone)]
pub struct RingShareBundle {
    /// Serialized `PriShare<Fr>` (output of `CryptoSerialize::to_bytes`).
    pub share_bytes: Zeroizing<Vec<u8>>,
    /// Hex-encoded current public polynomial (updated after each PSS refresh).
    pub public_polynomial: String,
    /// Unix timestamp (seconds) of the most recent PSS ceremony (fresh DKG, refresh,
    /// or reshare), or 0 before the first completion.
    pub last_pss: u64,
}

// Hand-written rather than derived: `Zeroizing<Z>` derives `Debug` by forwarding to
// `Z`'s own impl, so a derived `Debug` here would print the raw secret share bytes
// on any accidental `{:?}` (log line, panic message, `expect`/`expect_err` on an
// unexpected branch, etc). Redacting `share_bytes` keeps `Debug` usable for tests
// and diagnostics without ever printing the secret.
impl fmt::Debug for RingShareBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RingShareBundle")
            .field("share_bytes", &"<redacted>")
            .field("public_polynomial", &self.public_polynomial)
            .field("last_pss", &self.last_pss)
            .finish()
    }
}

const BUNDLE_VERSION: u8 = 0x01;

impl RingShareBundle {
    /// Serialize to the binary wire format into a `Zeroizing` buffer so the
    /// plaintext containing `share_bytes` is wiped when the buffer is dropped.
    pub(crate) fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let poly_bytes = self.public_polynomial.as_bytes();
        // 1 (version) + 4 (share len prefix) + share + 4 (poly len prefix) + poly + 8 (last_pss)
        let capacity = 1 + 4 + self.share_bytes.len() + 4 + poly_bytes.len() + 8;
        let mut buf = Zeroizing::new(Vec::with_capacity(capacity));

        buf.push(BUNDLE_VERSION);
        buf.extend_from_slice(&(self.share_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.share_bytes);
        buf.extend_from_slice(&(poly_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(poly_bytes);
        buf.extend_from_slice(&self.last_pss.to_le_bytes());

        buf
    }

    /// Deserialize from the binary wire format.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() {
            return Err("RingShareBundle: empty buffer".to_string());
        }
        if bytes[0] != BUNDLE_VERSION {
            return Err(format!(
                "RingShareBundle: unsupported version 0x{:02X}",
                bytes[0]
            ));
        }

        let mut cursor = 1usize;

        let read_u32 = |buf: &[u8], pos: &mut usize| -> Result<u32, String> {
            if buf.len() < *pos + 4 {
                return Err("RingShareBundle: buffer too short (u32)".to_string());
            }
            let encoded = buf[*pos..*pos + 4]
                .try_into()
                .map_err(|_| "RingShareBundle: invalid u32 encoding".to_string())?;
            let v = u32::from_le_bytes(encoded);
            *pos += 4;
            Ok(v)
        };

        let share_len = read_u32(bytes, &mut cursor)? as usize;
        if bytes.len() < cursor + share_len {
            return Err("RingShareBundle: buffer too short (share_bytes)".to_string());
        }
        let share_bytes = Zeroizing::new(bytes[cursor..cursor + share_len].to_vec());
        cursor += share_len;

        let poly_len = read_u32(bytes, &mut cursor)? as usize;
        if bytes.len() < cursor + poly_len {
            return Err("RingShareBundle: buffer too short (public_polynomial)".to_string());
        }
        let public_polynomial = String::from_utf8(bytes[cursor..cursor + poly_len].to_vec())
            .map_err(|e| format!("RingShareBundle: invalid utf-8 in polynomial: {}", e))?;
        cursor += poly_len;

        if bytes.len() < cursor + 8 {
            return Err("RingShareBundle: buffer too short (last_pss)".to_string());
        }
        let encoded_last_pss = bytes[cursor..cursor + 8]
            .try_into()
            .map_err(|_| "RingShareBundle: invalid last_pss encoding".to_string())?;
        let last_pss = u64::from_le_bytes(encoded_last_pss);

        Ok(Self {
            share_bytes,
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
        self.stash_previous_polynomial(storage, &ring_pk.to_string());
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
        self.stash_previous_polynomial(storage, ring_key);
        storage
            .set_encrypted(
                LocalStorageKeys::RingKey(ring_key.to_string()),
                self.to_bytes(),
            )
            .map_err(|e| format!("Failed to store RingShareBundle: {}", e))
    }

    /// Best-effort: read whatever bundle currently occupies this ring's slot and,
    /// if its polynomial differs from the one about to be written, retain it in
    /// `RingPolyHistory` so invalid-crypto report verification can still check a
    /// PRE/Sign response against the generation it was actually produced under,
    /// even after this save moves the ring on to a new one. Must never fail the
    /// actual share/polynomial write over this side write — logs and moves on.
    fn stash_previous_polynomial(&self, storage: &impl LocalStorage, ring_key: &str) {
        let Ok(previous) = Self::load_by_ring_key(storage, ring_key) else {
            return; // First-ever write for this ring — nothing to retire.
        };
        if previous.public_polynomial == self.public_polynomial {
            return; // Retried/duplicate commit of the same generation.
        }
        if let Err(error) = RingPolyHistory::record_retired(
            storage,
            ring_key,
            previous.public_polynomial,
            self.last_pss,
        ) {
            tracing::warn!(
                ring_key = %ring_key,
                %error,
                "Failed to record retired ring polynomial for report verification"
            );
        }
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

#[cfg(test)]
mod tests {
    use super::{PendingReshareBundle, RingShareBundle, BUNDLE_VERSION};
    use zeroize::Zeroizing;

    #[test]
    fn pending_reshare_bundle_round_trips() {
        let pending = PendingReshareBundle {
            bundle: RingShareBundle {
                share_bytes: Zeroizing::new(vec![9, 9, 9]),
                public_polynomial: "poly".to_string(),
                last_pss: 42,
            },
            bulletin_post_id: "post-1".to_string(),
            expected_new_committee: vec!["old-a".to_string(), "new-b".to_string()],
            expected_new_threshold: 1,
        };

        let bytes = pending.to_bytes();
        let decoded = PendingReshareBundle::from_bytes(&bytes).expect("round-trip decode");

        assert_eq!(decoded.bundle.share_bytes.as_slice(), &[9, 9, 9]);
        assert_eq!(decoded.bundle.public_polynomial, "poly");
        assert_eq!(decoded.bundle.last_pss, 42);
        assert_eq!(decoded.bulletin_post_id, "post-1");
        assert_eq!(
            decoded.expected_new_committee,
            vec!["old-a".to_string(), "new-b".to_string()]
        );
        assert_eq!(decoded.expected_new_threshold, 1);
    }

    #[test]
    fn ring_share_bundle_rejects_truncated_length_prefix() {
        let result = RingShareBundle::from_bytes(&[BUNDLE_VERSION, 0, 0, 0]);

        assert_eq!(
            result.unwrap_err(),
            "RingShareBundle: buffer too short (u32)"
        );
    }

    #[test]
    fn ring_share_bundle_rejects_truncated_last_pss() {
        let bytes = [
            BUNDLE_VERSION,
            0,
            0,
            0,
            0, // empty share
            0,
            0,
            0,
            0, // empty polynomial
            0,
            0,
            0,
            0,
            0,
            0,
            0, // seven of eight last_pss bytes
        ];

        let result = RingShareBundle::from_bytes(&bytes);

        assert_eq!(
            result.unwrap_err(),
            "RingShareBundle: buffer too short (last_pss)"
        );
    }
}

const PENDING_RESHARE_BUNDLE_VERSION: u8 = 0x01;

/// Restart-insurance copy of a reshare's staged (not-yet-promoted) `RingShareBundle`,
/// stored encrypted under `LocalStorageKeys::PendingReshareBundle`. See that key's doc
/// comment for the lifecycle: written at staging time, cleared the moment the live
/// bulletin-confirmation wait (`wait_for_reshare_bulletin_finalized`) resolves, and
/// read by startup reconciliation to recover from a restart that happens in between.
///
/// `expected_new_committee`/`expected_new_threshold` are compared against the ring's
/// *current* bulletin state at reconciliation time using the exact same
/// `peer_node_keys_match(...) && threshold == ...` predicate the live path
/// (`wait_for_reshare_bulletin_finalized`'s `should_promote`) already uses — not a
/// hash of the full payload. A full-payload hash would also cover
/// `block_number_nonce`, which real finalization changes (confirmed via
/// `DummyBulletin::update`, which bumps it) in a way this node cannot predict ahead
/// of time, so a hash computed at staging time can never match the hash of the real
/// post-finalization payload.
#[derive(Clone)]
pub struct PendingReshareBundle {
    pub bundle: RingShareBundle,
    pub bulletin_post_id: String,
    pub expected_new_committee: Vec<String>,
    pub expected_new_threshold: u32,
}

// See `RingShareBundle`'s `Debug` impl — this embeds one, so the same redaction
// applies here for the same reason.
impl fmt::Debug for PendingReshareBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingReshareBundle")
            .field("bundle", &self.bundle)
            .field("bulletin_post_id", &self.bulletin_post_id)
            .field("expected_new_committee", &self.expected_new_committee)
            .field("expected_new_threshold", &self.expected_new_threshold)
            .finish()
    }
}

impl PendingReshareBundle {
    fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let bundle_bytes = self.bundle.to_bytes();
        let post_id_bytes = self.bulletin_post_id.as_bytes();
        // Not secret (ring committee membership, mirrors what's already public on
        // the bulletin) — JSON is fine for this sub-field.
        let committee_json = serde_json::to_vec(&self.expected_new_committee)
            .expect("Vec<String> serialization cannot fail");
        let capacity =
            1 + 4 + bundle_bytes.len() + 4 + post_id_bytes.len() + 4 + committee_json.len() + 4;
        let mut buf = Zeroizing::new(Vec::with_capacity(capacity));

        buf.push(PENDING_RESHARE_BUNDLE_VERSION);
        buf.extend_from_slice(&(bundle_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&bundle_bytes);
        buf.extend_from_slice(&(post_id_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(post_id_bytes);
        buf.extend_from_slice(&(committee_json.len() as u32).to_le_bytes());
        buf.extend_from_slice(&committee_json);
        buf.extend_from_slice(&self.expected_new_threshold.to_le_bytes());

        buf
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() {
            return Err("PendingReshareBundle: empty buffer".to_string());
        }
        if bytes[0] != PENDING_RESHARE_BUNDLE_VERSION {
            return Err(format!(
                "PendingReshareBundle: unsupported version 0x{:02X}",
                bytes[0]
            ));
        }

        let mut cursor = 1usize;

        let read_u32 = |buf: &[u8], pos: &mut usize| -> Result<u32, String> {
            if buf.len() < *pos + 4 {
                return Err("PendingReshareBundle: buffer too short (u32)".to_string());
            }
            let encoded = buf[*pos..*pos + 4]
                .try_into()
                .map_err(|_| "PendingReshareBundle: invalid u32 encoding".to_string())?;
            let v = u32::from_le_bytes(encoded);
            *pos += 4;
            Ok(v)
        };

        let bundle_len = read_u32(bytes, &mut cursor)? as usize;
        if bytes.len() < cursor + bundle_len {
            return Err("PendingReshareBundle: buffer too short (bundle)".to_string());
        }
        let bundle = RingShareBundle::from_bytes(&bytes[cursor..cursor + bundle_len])?;
        cursor += bundle_len;

        let post_id_len = read_u32(bytes, &mut cursor)? as usize;
        if bytes.len() < cursor + post_id_len {
            return Err("PendingReshareBundle: buffer too short (bulletin_post_id)".to_string());
        }
        let bulletin_post_id = String::from_utf8(bytes[cursor..cursor + post_id_len].to_vec())
            .map_err(|e| {
                format!(
                    "PendingReshareBundle: invalid utf-8 in bulletin_post_id: {}",
                    e
                )
            })?;
        cursor += post_id_len;

        let committee_len = read_u32(bytes, &mut cursor)? as usize;
        if bytes.len() < cursor + committee_len {
            return Err(
                "PendingReshareBundle: buffer too short (expected_new_committee)".to_string(),
            );
        }
        let expected_new_committee: Vec<String> =
            serde_json::from_slice(&bytes[cursor..cursor + committee_len]).map_err(|e| {
                format!(
                    "PendingReshareBundle: invalid expected_new_committee json: {}",
                    e
                )
            })?;
        cursor += committee_len;

        if bytes.len() < cursor + 4 {
            return Err(
                "PendingReshareBundle: buffer too short (expected_new_threshold)".to_string(),
            );
        }
        let threshold_bytes: [u8; 4] = bytes[cursor..cursor + 4]
            .try_into()
            .map_err(|_| "PendingReshareBundle: invalid u32 encoding".to_string())?;
        let expected_new_threshold = u32::from_le_bytes(threshold_bytes);

        Ok(Self {
            bundle,
            bulletin_post_id,
            expected_new_committee,
            expected_new_threshold,
        })
    }

    /// Best-effort write — callers must log and continue on `Err`, never fail the
    /// live reshare over this restart-insurance side write.
    pub fn save(&self, storage: &impl LocalStorage, ring_key: &str) -> Result<(), String> {
        storage
            .set_encrypted(
                LocalStorageKeys::PendingReshareBundle(ring_key.to_string()),
                self.to_bytes(),
            )
            .map_err(|e| format!("Failed to store PendingReshareBundle: {}", e))
    }

    /// Returns `Ok(None)` if no pending entry exists for `ring_key`.
    pub fn load(storage: &impl LocalStorage, ring_key: &str) -> Result<Option<Self>, String> {
        let Some(bytes) = storage
            .get_encrypted(LocalStorageKeys::PendingReshareBundle(ring_key.to_string()))
            .map_err(|e| format!("Failed to read PendingReshareBundle: {}", e))?
        else {
            return Ok(None);
        };
        Self::from_bytes(&bytes).map(Some)
    }

    /// Best-effort clear — callers must log and continue on `Err`.
    pub fn clear(storage: &impl LocalStorage, ring_key: &str) -> Result<(), String> {
        storage
            .delete(LocalStorageKeys::PendingReshareBundle(ring_key.to_string()))
            .map_err(|e| format!("Failed to clear PendingReshareBundle: {}", e))
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

/// Defense in depth on top of the retention-window filter in [`RingPolyHistory::recent`] —
/// the window is the real bound, this just caps storage if a ring somehow accumulates
/// entries faster than expected.
const RING_POLY_HISTORY_MAX_ENTRIES: usize = 4;

/// Short-lived history of a ring's recently-retired *public* polynomials, stored
/// separately from `RingShareBundle` under `LocalStorageKeys::RingPolyHistory` —
/// never alongside, or in place of, the current secret share, and never itself
/// secret (see that key's doc comment for why).
///
/// Exists so invalid-crypto report verification
/// (`reporting::v0::registry::invalid_crypto::pre_sign`) can still check a PRE/Sign
/// response against the share generation it was actually produced under, even
/// after a PSS ceremony has since moved the ring on to a new one — without
/// retaining the (unrecoverable, and rightly so) old private share.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct RingPolyHistory {
    /// Most-recently-retired first.
    entries: Vec<RetiredPolynomial>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct RetiredPolynomial {
    public_polynomial: String,
    /// Unix seconds this polynomial was retired — i.e. the completion time of the
    /// PSS ceremony that replaced it (the incoming bundle's own `last_pss`).
    retired_at: u64,
}

impl RingPolyHistory {
    fn load(storage: &impl LocalStorage, ring_key: &str) -> Self {
        storage
            .get(LocalStorageKeys::RingPolyHistory(ring_key.to_string()))
            .ok()
            .flatten()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    fn save(&self, storage: &impl LocalStorage, ring_key: &str) -> Result<(), String> {
        let bytes = serde_json::to_vec(self)
            .map_err(|e| format!("Failed to serialize RingPolyHistory: {}", e))?;
        storage
            .set(
                LocalStorageKeys::RingPolyHistory(ring_key.to_string()),
                bytes,
            )
            .map_err(|e| format!("Failed to store RingPolyHistory: {}", e))
    }

    /// Record a just-retired polynomial and prune anything past the retention
    /// window or the max entry count. Called right before a new `RingShareBundle`
    /// overwrites the current one (see `RingShareBundle::stash_previous_polynomial`).
    fn record_retired(
        storage: &impl LocalStorage,
        ring_key: &str,
        public_polynomial: String,
        retired_at: u64,
    ) -> Result<(), String> {
        let mut history = Self::load(storage, ring_key);
        history.entries.retain(|entry| {
            retired_at.saturating_sub(entry.retired_at) <= RING_POLY_HISTORY_RETENTION_SECS
        });
        history.entries.insert(
            0,
            RetiredPolynomial {
                public_polynomial,
                retired_at,
            },
        );
        history.entries.truncate(RING_POLY_HISTORY_MAX_ENTRIES);
        history.save(storage, ring_key)
    }

    /// Every still-in-window retired polynomial for `ring_key`, most-recent first,
    /// hex-encoded and ready for `PubPolyImpl::from_bytes(&hex::decode(..)?)`.
    pub fn recent(storage: &impl LocalStorage, ring_key: &str, now_secs: u64) -> Vec<String> {
        Self::load(storage, ring_key)
            .entries
            .into_iter()
            .filter(|entry| {
                now_secs.saturating_sub(entry.retired_at) <= RING_POLY_HISTORY_RETENTION_SECS
            })
            .map(|entry| entry.public_polynomial)
            .collect()
    }

    /// Convenience wrapper mirroring `RingPolyState::load_from_ring_pk_hex`, for
    /// callers (report verification) that only have the hex-encoded ring_pk, not
    /// the `.to_string()` display-format storage key `RingShareBundle` itself uses.
    pub fn recent_from_ring_pk_hex(
        storage: &impl LocalStorage,
        ring_pk_hex: &str,
        now_secs: u64,
    ) -> Vec<String> {
        let Ok(bytes) = hex::decode(ring_pk_hex) else {
            return Vec::new();
        };
        let Ok(ring_pk) = G1Affine::from_bytes(&bytes) else {
            return Vec::new();
        };
        Self::recent(storage, &ring_pk.to_string(), now_secs)
    }
}
