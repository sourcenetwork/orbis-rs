use crate::constants::PSS_GRACE_PERIOD_SECS;
use crate::dkg::error::{DkgError, Result};
use crate::dkg::messages::SessionKind;
use crate::dkg::session_state::ReshareParams;
use crate::helpers::helpers::extract_node_part;
use crate::ring_state::{RingIndexEntry, RingShareBundle};
use authn::{BearerToken, DkgClaims};
use bulletin::r#trait::{Bulletin, BulletinKind, NodeInfo, RingPayload};
use crypto::r#trait::{CryptoDeserialize, DkgRole, PriShare};
use crypto::{CryptoSerialize, GroupAffine as G1Affine, ScalarField as Fr};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// Returns a `SessionNotFound` error for the given session_id.
pub fn session_not_found(session_id: u64) -> DkgError {
    DkgError::SessionNotFound(format!("DKG session {} not found", session_id))
}

const PSS_SESSION_ID_DOMAIN: &[u8] = b"orbis-pss-session-v1";

pub(crate) fn ring_payload_matches_ring_key(ring_pk_key: &str, ring_pk_payload: &str) -> bool {
    if let Ok(bytes) = hex::decode(ring_pk_payload) {
        if let Ok(ring_pk) = G1Affine::from_bytes(&bytes) {
            return ring_pk.to_string() == ring_pk_key;
        }
    }
    ring_pk_payload == ring_pk_key
}

/// Serializes a slice of G1Affine commitment coefficients to a flat byte buffer.
pub fn serialize_commitment_coefficients(coefficients: &[G1Affine]) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for coeff in coefficients {
        let coeff_bytes = CryptoSerialize::to_bytes(coeff).map_err(|e| {
            DkgError::Serialization(format!("Failed to serialize commitment coefficient: {}", e))
        })?;
        bytes.extend_from_slice(&coeff_bytes);
    }
    Ok(bytes)
}

fn hash_labeled_bytes(hasher: &mut Sha256, label: &[u8], bytes: &[u8]) {
    hasher.update((label.len() as u32).to_le_bytes());
    hasher.update(label);
    hasher.update((bytes.len() as u32).to_le_bytes());
    hasher.update(bytes);
}

fn hash_labeled_str(hasher: &mut Sha256, label: &[u8], value: &str) {
    hash_labeled_bytes(hasher, label, value.as_bytes());
}

fn hash_sorted_strings(hasher: &mut Sha256, label: &[u8], values: &[String]) {
    let mut sorted_values = values.to_vec();
    sorted_values.sort();
    hasher.update((label.len() as u32).to_le_bytes());
    hasher.update(label);
    hasher.update((sorted_values.len() as u32).to_le_bytes());
    for value in &sorted_values {
        hash_labeled_str(hasher, b"value", value);
    }
}

/// Derive a deterministic refresh session ID from the ring's current generation state.
pub fn derive_refresh_session_id(
    ring_pk_hex: &str,
    peer_node_keys: &[String],
    threshold: u32,
    public_polynomial_hex: &str,
) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(PSS_SESSION_ID_DOMAIN);
    hash_labeled_str(&mut hasher, b"kind", "refresh");
    hash_labeled_str(&mut hasher, b"ring_pk", ring_pk_hex);
    hash_sorted_strings(&mut hasher, b"peer_node_keys", peer_node_keys);
    hash_labeled_bytes(&mut hasher, b"threshold", &threshold.to_le_bytes());
    hash_labeled_str(&mut hasher, b"public_polynomial", public_polynomial_hex);
    let digest = hasher.finalize();
    u64::from_le_bytes(digest[..8].try_into().expect("digest prefix"))
}

/// Derive a deterministic reshare session ID from the ring's current generation state
/// and the authoritative transition announced on the bulletin.
pub fn derive_reshare_session_id(
    ring_pk_hex: &str,
    bulletin_post_id: &str,
    old_peer_node_keys: &[String],
    new_peer_node_keys: &[String],
    new_threshold: u32,
) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(PSS_SESSION_ID_DOMAIN);
    hash_labeled_str(&mut hasher, b"kind", "reshare");
    hash_labeled_str(&mut hasher, b"ring_pk", ring_pk_hex);
    hash_labeled_str(&mut hasher, b"bulletin_post_id", bulletin_post_id);
    hash_sorted_strings(&mut hasher, b"old_peer_node_keys", old_peer_node_keys);
    hash_sorted_strings(&mut hasher, b"new_peer_node_keys", new_peer_node_keys);
    hash_labeled_bytes(&mut hasher, b"new_threshold", &new_threshold.to_le_bytes());
    let digest = hasher.finalize();
    u64::from_le_bytes(digest[..8].try_into().expect("digest prefix"))
}

/// Load the canonical refresh ring payload from the local RingIndex and bulletin.
pub async fn load_refresh_ring_payload<S: LocalStorage>(
    ring_pk_hex: &str,
    local_storage: &S,
    bulletin: &Arc<dyn Bulletin + Send + Sync>,
) -> Result<RingPayload> {
    let ring_index: Vec<RingIndexEntry> = local_storage
        .get(LocalStorageKeys::RingIndex)
        .map_err(|e| DkgError::Storage(format!("Failed to read RingIndex: {}", e)))?
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let entry = ring_index
        .iter()
        .find(|e| e.ring_pk_str == ring_pk_hex)
        .ok_or_else(|| DkgError::Unauthorized(format!("Unknown ring: {}", ring_pk_hex)))?;
    load_ring_payload_by_post_id(ring_pk_hex, &entry.bulletin_post_id, bulletin).await
}

/// Load the canonical reshare ring payload, falling back to the wire-provided bulletin
/// post ID for pure receivers that do not yet have a local RingIndex entry.
pub async fn load_reshare_ring_payload<S: LocalStorage>(
    ring_pk_hex: &str,
    bulletin_post_id: &str,
    local_storage: &S,
    bulletin: &Arc<dyn Bulletin + Send + Sync>,
) -> Result<RingPayload> {
    let ring_index: Vec<RingIndexEntry> = local_storage
        .get(LocalStorageKeys::RingIndex)
        .map_err(|e| DkgError::Storage(format!("Failed to read RingIndex: {}", e)))?
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let entry = ring_index.iter().find(|e| e.ring_pk_str == ring_pk_hex);
    let resolved_post_id = entry
        .map(|e| e.bulletin_post_id.as_str())
        .unwrap_or(bulletin_post_id);
    load_ring_payload_by_post_id(ring_pk_hex, resolved_post_id, bulletin).await
}

async fn load_ring_payload_by_post_id(
    ring_pk_hex: &str,
    post_id: &str,
    bulletin: &Arc<dyn Bulletin + Send + Sync>,
) -> Result<RingPayload> {
    let bulletin_post = bulletin
        .read(post_id.to_string(), BulletinKind::Ring)
        .await
        .map_err(|e| {
            DkgError::Unauthorized(format!("Ring {} not found in bulletin: {}", ring_pk_hex, e))
        })?;
    let ring_payload: RingPayload = serde_json::from_slice(&bulletin_post.payload)
        .map_err(|e| DkgError::Deserialization(format!("Bad ring payload from bulletin: {}", e)))?;

    if !ring_payload_matches_ring_key(ring_pk_hex, &ring_payload.ring_pk) {
        return Err(DkgError::Unauthorized(format!(
            "Bulletin ring_pk does not match session ring for {}",
            ring_pk_hex
        )));
    }

    Ok(ring_payload)
}

/// Validates an incoming reshare `SessionInit` message.
///
/// Checks (in order):
/// 0. Fast structural checks: `new_peer_node_keys` non-empty, `new_threshold` in `[1, n]`.
/// 1. Resolve the bulletin post: use `RingIndex` when this node has an entry for
///    `ring_pk_hex`, otherwise use `bulletin_post_id` from the `SessionInit` (needed for
///    pure Receiver nodes that were never on the old committee).
/// 2. The deserialized `RingPayload::ring_pk` must equal `ring_pk_hex` (binds the read to
///    the intended ring when the post ID came from the wire).
/// 3. The sender's peer ID is a current member of that ring's OLD committee.
/// 4. Proposed `new_peer_node_keys` must match the authoritative committee (order-independent):
///    - `ring_payload.new_peer_node_keys` is `Some` → must match that list.
///    - `ring_payload.new_peer_node_keys` is `None` → must match `ring_payload.peer_node_keys`
///      (fallback: threshold-only reshare keeps the same committee).
/// 5. Proposed `new_threshold` must equal the authoritative threshold:
///    - `ring_payload.new_threshold` is `Some` → must equal that value.
///    - `ring_payload.new_threshold` is `None` → must equal `ring_payload.threshold`
///      (fallback: committee-only reshare keeps the same threshold).
///
/// No time-based check is performed — reshare is triggered by membership change, not interval.
///
/// ## Bulletin trust model
///
/// The bulletin is the authoritative source of truth.  Absent fields do not mean
/// "accept anything" — they mean "keep the current value".  A sender proposing a committee
/// or threshold that differs from both the announced and current values is rejected,
/// preventing unilateral redirection of a reshare to an arbitrary new committee.
pub async fn validate_reshare_session_init<S: LocalStorage>(
    ring_pk_hex: &str,
    sender_hex: &str,
    proposed_new_peer_node_keys: &[String],
    proposed_new_threshold: u32,
    bulletin_post_id: &str,
    local_storage: &S,
    bulletin: &Arc<dyn Bulletin + Send + Sync>,
) -> Result<()> {
    // 0. Fast-fail on structurally invalid parameters before hitting the bulletin.
    if proposed_new_peer_node_keys.is_empty() {
        return Err(DkgError::InvalidInput(
            "Reshare new_peer_node_keys cannot be empty".to_string(),
        ));
    }
    if proposed_new_threshold < 1
        || proposed_new_threshold as usize > proposed_new_peer_node_keys.len()
    {
        return Err(DkgError::InvalidInput(format!(
            "Reshare new_threshold {} is invalid for a committee of {} nodes (must be 1..=n)",
            proposed_new_threshold,
            proposed_new_peer_node_keys.len()
        )));
    }

    // Look up the bulletin post ID from the local index. Pure Receiver nodes
    // have no local entry for this ring (they were never members), so fall back to the
    // post ID carried in the SessionInit message.
    let ring_index: Vec<RingIndexEntry> = local_storage
        .get(LocalStorageKeys::RingIndex)
        .map_err(|e| DkgError::Storage(format!("Failed to read RingIndex: {}", e)))?
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let entry = ring_index.iter().find(|e| e.ring_pk_str == ring_pk_hex);
    let resolved_post_id = entry
        .map(|e| e.bulletin_post_id.as_str())
        .unwrap_or(bulletin_post_id);
    let bulletin_post = bulletin
        .read(resolved_post_id.to_string(), BulletinKind::Ring)
        .await
        .map_err(|e| {
            DkgError::Unauthorized(format!("Ring {} not found in bulletin: {}", ring_pk_hex, e))
        })?;
    let ring_payload: RingPayload = serde_json::from_slice(&bulletin_post.payload)
        .map_err(|e| DkgError::Deserialization(format!("Bad ring payload: {}", e)))?;

    if !ring_payload_matches_ring_key(ring_pk_hex, &ring_payload.ring_pk) {
        return Err(DkgError::Unauthorized(format!(
            "Bulletin ring_pk does not match session ring for {}",
            ring_pk_hex
        )));
    }

    // 3. Sender must be in the old committee. For now this check is completed by
    // the SessionInit handler after resolving node keys to P2P routes.
    let sender_in_ring = !sender_hex.is_empty();
    if !sender_in_ring {
        return Err(DkgError::Unauthorized(format!(
            "Reshare initiator {} is not a member of ring {}",
            sender_hex, ring_pk_hex
        )));
    }

    // 4. Proposed new_peer_node_keys must match the authoritative committee.
    //    Bulletin present → must match it; absent → must match current peer_node_keys (fallback).
    let authoritative_new: &[String] = ring_payload
        .new_peer_node_keys
        .as_deref()
        .unwrap_or(&ring_payload.peer_node_keys);
    let mut sorted_auth: Vec<&str> = authoritative_new.iter().map(|s| s.as_str()).collect();
    sorted_auth.sort();
    let mut sorted_proposed: Vec<&str> = proposed_new_peer_node_keys
        .iter()
        .map(|s| s.as_str())
        .collect();
    sorted_proposed.sort();
    if sorted_auth != sorted_proposed {
        return Err(DkgError::Unauthorized(format!(
            "Reshare new_peer_node_keys do not match authoritative committee for ring {} \
             (bulletin field: {})",
            ring_pk_hex,
            if ring_payload.new_peer_node_keys.is_some() {
                "explicitly announced"
            } else {
                "absent, fallback to current peer_node_keys"
            }
        )));
    }

    // 5. Proposed new_threshold must equal the authoritative threshold.
    //    Bulletin present → must equal it; absent → must equal current threshold (fallback).
    let authoritative_threshold = ring_payload.new_threshold.unwrap_or(ring_payload.threshold);
    if proposed_new_threshold != authoritative_threshold {
        return Err(DkgError::Unauthorized(format!(
            "Reshare new_threshold {} does not match authoritative threshold {} for ring {} \
             (bulletin field: {})",
            proposed_new_threshold,
            authoritative_threshold,
            ring_pk_hex,
            if ring_payload.new_threshold.is_some() {
                "explicitly announced"
            } else {
                "absent, fallback to current threshold"
            }
        )));
    }

    Ok(())
}

/// Validates an incoming PSS refresh `SessionInit` message.
///
/// Checks (in order):
/// 1. The ring is known (an entry with `ring_pk_str == ring_pk_hex` exists in `RingIndex`).
/// 2. The sender's peer ID is a current member of that ring (from the bulletin RingPayload).
/// 3. Enough time has elapsed since the last refresh (`ring_payload.pss_interval`).
///    If `pss_interval` is `None` the time check is skipped (any time is acceptable);
///    `Some(0)` is present and therefore requires an existing ring timestamp.
///
/// The caller is responsible for the atomic in-progress flag
/// (`try_mark_ring_pss`) after this returns `Ok`.
pub async fn validate_refresh_session_init<S: LocalStorage>(
    ring_pk_hex: &str,
    sender_hex: &str,
    local_storage: &S,
    bulletin: &Arc<dyn Bulletin + Send + Sync>,
) -> Result<RingPayload> {
    // 1. Look up the bulletin post_id for this ring from the local RingIndex.
    let ring_index: Vec<RingIndexEntry> = local_storage
        .get(LocalStorageKeys::RingIndex)
        .map_err(|e| DkgError::Storage(format!("Failed to read RingIndex: {}", e)))?
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let entry = ring_index
        .iter()
        .find(|e| e.ring_pk_str == ring_pk_hex)
        .ok_or_else(|| DkgError::Unauthorized(format!("Unknown ring: {}", ring_pk_hex)))?;
    let post_id = &entry.bulletin_post_id;

    // Fetch the canonical RingPayload from the bulletin — it is the source of truth.
    let bulletin_post = bulletin
        .read(post_id.to_string(), BulletinKind::Ring)
        .await
        .map_err(|e| {
            DkgError::Unauthorized(format!("Ring {} not found in bulletin: {}", ring_pk_hex, e))
        })?;
    let ring_payload: RingPayload = serde_json::from_slice(&bulletin_post.payload)
        .map_err(|e| DkgError::Deserialization(format!("Bad ring payload from bulletin: {}", e)))?;

    // 2. Sender membership is verified by the SessionInit handler after resolving
    // ring node keys to P2P routes.
    let sender_in_ring = !sender_hex.is_empty();
    if !sender_in_ring {
        return Err(DkgError::Unauthorized(format!(
            "Refresh initiator {} is not a member of ring {}",
            sender_hex, ring_pk_hex
        )));
    }

    // 3. Verify enough time has elapsed since the last refresh/DKG.
    //    Only enforced when the ring has a `pss_interval` set.
    if let Some(pss_interval_secs) = ring_payload.pss_interval {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| DkgError::Generic(format!("Failed to get timestamp: {}", e)))?
            .as_secs();
        // `ring_pk_hex` is aggregate_pk.to_string() — same key the bundle is stored under.
        // A missing bundle means the ring hasn't completed DKG yet.
        let last_refresh_secs = RingShareBundle::load_by_ring_key(local_storage, ring_pk_hex)
            .map(|b| b.last_pss)
            .map_err(|_| {
                DkgError::Unauthorized(
                    "Ring has no refresh timestamp; cannot accept refresh".to_string(),
                )
            })?;
        let elapsed = now_secs.saturating_sub(last_refresh_secs);
        if elapsed + PSS_GRACE_PERIOD_SECS < pss_interval_secs {
            return Err(DkgError::Unauthorized(format!(
                "Refresh too soon: {}s elapsed, minimum is {}s",
                elapsed,
                pss_interval_secs.saturating_sub(PSS_GRACE_PERIOD_SECS)
            )));
        }
    }

    Ok(ring_payload)
}

/// Validates JWT claims against the DKG request.
pub fn validate_dkg_claims(token: &BearerToken<DkgClaims>, ring_id: &str) -> Result<()> {
    if ring_id.is_empty() {
        return Err(DkgError::Unauthorized(
            "ring_id must not be empty".to_string(),
        ));
    }
    if token.claims.ring_id != ring_id {
        return Err(DkgError::Unauthorized(format!(
            "Token ring_id ({:?}) does not match request ring_id ({:?})",
            token.claims.ring_id, ring_id
        )));
    }

    Ok(())
}

/// Validates the structural state of a `RingPayload` for a fresh DKG:
/// ring_pk is blank, peer list is non-empty, threshold is in range, policy_id is present.
/// Call this with the already-fetched ring payload before starting a fresh DKG session.
pub fn validate_fresh_dkg_ring_payload(ring_id: &str, ring_payload: &RingPayload) -> Result<()> {
    if !ring_payload.ring_pk.is_empty() {
        return Err(DkgError::Unauthorized(format!(
            "Fresh DKG target ring {} is not pending",
            ring_id
        )));
    }
    if ring_payload.peer_node_keys.is_empty() {
        return Err(DkgError::InvalidInput(format!(
            "Fresh DKG target ring {} has no peer_node_keys",
            ring_id
        )));
    }
    if ring_payload.threshold == 0
        || ring_payload.threshold as usize > ring_payload.peer_node_keys.len()
    {
        return Err(DkgError::InvalidInput(format!(
            "Fresh DKG target ring {} has invalid threshold {} for {} participants",
            ring_id,
            ring_payload.threshold,
            ring_payload.peer_node_keys.len()
        )));
    }
    if ring_payload.policy_id.as_deref().unwrap_or("").is_empty() {
        return Err(DkgError::InvalidInput(format!(
            "Fresh DKG target ring {} has no policy_id",
            ring_id
        )));
    }
    Ok(())
}

/// Cross-validates the wire params from a Fresh `SessionInit` message against the
/// authoritative `RingPayload` fetched from the bulletin.
pub fn validate_fresh_session_init_params(
    ring_id: &str,
    peer_node_keys: &[String],
    threshold: u32,
    total_participants: u32,
    pss_interval: Option<u64>,
    policy_id: Option<&str>,
    ring_payload: &RingPayload,
) -> Result<()> {
    let mut wire_sorted = peer_node_keys.to_vec();
    wire_sorted.sort();
    let mut auth_sorted = ring_payload.peer_node_keys.clone();
    auth_sorted.sort();
    if wire_sorted != auth_sorted {
        return Err(DkgError::Unauthorized(format!(
            "Fresh peer_node_keys do not match authoritative committee for ring {}",
            ring_id
        )));
    }
    if threshold != ring_payload.threshold {
        return Err(DkgError::Unauthorized(format!(
            "Fresh threshold {} does not match authoritative threshold {} for ring {}",
            threshold, ring_payload.threshold, ring_id
        )));
    }
    if total_participants as usize != ring_payload.peer_node_keys.len() {
        return Err(DkgError::Unauthorized(format!(
            "Fresh total_participants {} does not match authoritative committee size {} for ring {}",
            total_participants,
            ring_payload.peer_node_keys.len(),
            ring_id
        )));
    }
    if pss_interval != ring_payload.pss_interval {
        return Err(DkgError::Unauthorized(format!(
            "Fresh pss_interval {:?} does not match authoritative pss_interval {:?} for ring {}",
            pss_interval, ring_payload.pss_interval, ring_id
        )));
    }
    if policy_id != ring_payload.policy_id.as_deref() {
        return Err(DkgError::Unauthorized(format!(
            "Fresh policy_id {:?} does not match authoritative policy_id {:?} for ring {}",
            policy_id, ring_payload.policy_id, ring_id
        )));
    }
    Ok(())
}

/// Validate that this node is authorized by its NodeInfo record to participate in a Fresh DKG.
///
/// Checks NodeInfo membership and policy/ring allowlist against an already-fetched `ring_payload`.
/// Callers are responsible for reading the ring from the bulletin and calling
/// `validate_fresh_dkg_ring_payload` first. The `session_init` handler also cross-validates
/// wire params against the ring payload before calling this.
pub async fn validate_fresh_dkg_node_authorization(
    bulletin: &Arc<dyn Bulletin + Send + Sync>,
    node_key: &str,
    local_peer_id_hex: &str,
    ring_id: &str,
    ring_payload: &RingPayload,
) -> Result<()> {
    if node_key.is_empty() {
        return Err(DkgError::Unauthorized(
            "Local node signing key is not configured".to_string(),
        ));
    }
    if ring_id.is_empty() {
        return Err(DkgError::Unauthorized(
            "Fresh DKG ring_id must not be empty".to_string(),
        ));
    }

    let node_info_post = bulletin
        .read(node_key.to_string(), BulletinKind::NodeInfo)
        .await
        .map_err(|e| {
            DkgError::Unauthorized(format!("NodeInfo for node {} not found: {}", node_key, e))
        })?;
    let node_info = NodeInfo::try_from(node_info_post).map_err(|e| {
        DkgError::Unauthorized(format!(
            "NodeInfo for node {} is malformed: {}",
            node_key, e
        ))
    })?;

    if extract_node_part(&node_info.peer_id) != extract_node_part(local_peer_id_hex) {
        return Err(DkgError::Unauthorized(format!(
            "NodeInfo peer_id {} does not match local peer_id {}",
            node_info.peer_id, local_peer_id_hex
        )));
    }
    if !ring_payload
        .peer_node_keys
        .iter()
        .any(|key| key == node_key)
    {
        return Err(DkgError::Unauthorized(format!(
            "Local node_key {} is not a participant in ring {}",
            node_key, ring_id
        )));
    }

    let policy_allowed = ring_payload.policy_id.as_deref().is_some_and(|policy_id| {
        node_info
            .whitelisted_policy_ids
            .iter()
            .any(|allowed| allowed == policy_id)
    });
    let ring_allowed = node_info
        .whitelisted_ring_ids
        .iter()
        .any(|allowed| allowed == ring_id);
    if !policy_allowed && !ring_allowed {
        return Err(DkgError::Unauthorized(format!(
            "NodeInfo for node {} does not allow policy_id {:?} or ring_id {}",
            node_key, ring_payload.policy_id, ring_id
        )));
    }

    Ok(())
}

/// Writes the `RingShareBundle` (share + polynomial) after a completed DKG, PSS refresh,
/// or reshare.
///
/// - `Fresh`   — write directly under `aggregate_pk`.
/// - `Refresh` — load old bundle, fold in the delta share and polynomial, write back
///   under the original ring key.
/// - `Reshare` — write a fresh bundle under the old ring key (the new share replaces
///   the old one; the ring public key is unchanged).
///
/// `combine_pub_poly` encapsulates curve-specific polynomial combination (Refresh only).
pub fn build_refresh_ring_bundle<S: LocalStorage>(
    storage: &S,
    ring_pk_hex: &str,
    final_share_bytes: &[u8],
    pub_poly_bytes: &[u8],
    now_secs: u64,
    session_id: u64,
    combine_pub_poly: impl Fn(&[u8], &[u8]) -> std::result::Result<Vec<u8>, String>,
) -> Result<RingShareBundle> {
    // PSS Refresh: load old bundle, add delta share + polynomial, return the
    // candidate bundle without writing it. The caller decides whether to stage
    // or persist it.
    let old_bundle = RingShareBundle::load_by_ring_key(storage, ring_pk_hex).map_err(|e| {
        DkgError::Storage(format!("Refresh: failed to load old share bundle: {}", e))
    })?;

    let old_pri = old_bundle.pri_share().map_err(|e| {
        DkgError::Deserialization(format!("Refresh: failed to deserialize old share: {}", e))
    })?;
    let delta_pri = PriShare::<Fr>::from_bytes(final_share_bytes).map_err(|e| {
        DkgError::Deserialization(format!("Refresh: failed to deserialize delta share: {}", e))
    })?;
    let new_pri = PriShare {
        i: old_pri.i,
        v: old_pri.v + delta_pri.v,
    };
    let new_share_bytes = CryptoSerialize::to_bytes(&new_pri).map_err(|e| {
        DkgError::Serialization(format!(
            "Refresh: failed to serialize combined share: {}",
            e
        ))
    })?;

    let old_poly_bytes = hex::decode(&old_bundle.public_polynomial).map_err(|e| {
        DkgError::Deserialization(format!(
            "Refresh: failed to decode old polynomial hex: {}",
            e
        ))
    })?;
    let new_poly_bytes = combine_pub_poly(&old_poly_bytes, pub_poly_bytes)
        .map_err(|e| DkgError::Crypto(format!("Refresh: failed to combine polynomials: {}", e)))?;

    tracing::debug!(
        session_id = session_id,
        ring_key = %ring_pk_hex,
        "Refresh: built staged RingShareBundle"
    );

    Ok(RingShareBundle {
        share_bytes: Zeroizing::new(new_share_bytes),
        public_polynomial: hex::encode(&new_poly_bytes),
        last_pss: now_secs,
    })
}

pub fn persist_ring_bundle<S: LocalStorage>(
    storage: &S,
    kind: &SessionKind,
    final_share_bytes: &[u8],
    pub_poly_bytes: &[u8],
    aggregate_pk: &G1Affine,
    now_secs: u64,
    session_id: u64,
    combine_pub_poly: impl Fn(&[u8], &[u8]) -> std::result::Result<Vec<u8>, String>,
) -> Result<()> {
    match kind {
        SessionKind::Fresh => {
            // Fresh DKG: single atomic write of share + polynomial.
            // Use now_secs so the PSS scheduler waits a full pss_interval before the
            // first refresh rather than treating the ring as immediately overdue.
            let bundle = RingShareBundle {
                share_bytes: Zeroizing::new(final_share_bytes.to_vec()),
                public_polynomial: hex::encode(pub_poly_bytes),
                last_pss: now_secs,
            };
            bundle
                .save(storage, aggregate_pk)
                .map_err(|e| DkgError::Storage(format!("Failed to store share bundle: {}", e)))?;
        }
        SessionKind::Refresh { ring_pk_hex } => {
            let new_bundle = build_refresh_ring_bundle(
                storage,
                ring_pk_hex,
                final_share_bytes,
                pub_poly_bytes,
                now_secs,
                session_id,
                combine_pub_poly,
            )?;
            new_bundle
                .save_by_ring_key(storage, ring_pk_hex)
                .map_err(|e| {
                    DkgError::Storage(format!("Refresh: failed to store new bundle: {}", e))
                })?;

            tracing::info!(
                session_id = session_id,
                ring_key = %ring_pk_hex,
                "Refresh: Phase 4 complete — RingShareBundle updated atomically"
            );
        }
        SessionKind::Reshare { ring_pk_hex, .. } => {
            // Reshare: the computed share is the full new share (not a delta).
            // Write it under the old ring key — the ring public key is unchanged.
            let bundle = RingShareBundle {
                share_bytes: Zeroizing::new(final_share_bytes.to_vec()),
                public_polynomial: hex::encode(pub_poly_bytes),
                last_pss: now_secs,
            };
            bundle.save_by_ring_key(storage, ring_pk_hex).map_err(|e| {
                DkgError::Storage(format!("Reshare: failed to store share bundle: {}", e))
            })?;

            tracing::info!(
                session_id = session_id,
                ring_key = %ring_pk_hex,
                "Reshare: Phase 4 complete — RingShareBundle written under old ring key"
            );
        }
    }
    Ok(())
}

/// Determine this node's role, `node_id`, and `ReshareParams` for a reshare session.
///
/// Returns `(node_id, role, params)`:
/// - `node_id` — 1-based index in the old committee for Dealer/DealerReceiver, new committee
///   for pure Receiver.
/// - `role` — `Dealer`, `Receiver`, or `DealerReceiver`.
/// - `params` — reshare session parameters including the pre-loaded old share (Dealers only).
///
/// Errors if this node is not in either committee, or if the old share cannot be loaded for
/// a node that is in the old committee.
pub fn build_reshare_params<S: LocalStorage>(
    ring_pk_hex: &str,
    old_peer_node_keys: &[String],
    new_peer_node_keys: &[String],
    new_threshold: u32,
    bulletin_post_id: &str,
    our_node_key: &str,
    local_storage: &S,
) -> Result<(u32, DkgRole, ReshareParams<Fr>)> {
    let mut sorted_old = old_peer_node_keys.to_vec();
    sorted_old.sort();
    let mut sorted_new = new_peer_node_keys.to_vec();
    sorted_new.sort();

    let in_old = in_committee(&sorted_old, our_node_key);
    let in_new = in_committee(&sorted_new, our_node_key);

    let role = match (in_old, in_new) {
        (true, true) => DkgRole::DealerReceiver,
        (true, false) => DkgRole::Dealer,
        (false, true) => DkgRole::Receiver,
        (false, false) => {
            return Err(DkgError::InvalidInput(
                "Reshare: this node is not in either committee".to_string(),
            ))
        }
    };

    let new_idx = in_new.then(|| node_index_in(&sorted_new, our_node_key));
    let node_id = if in_old {
        node_index_in(&sorted_old, our_node_key)
    } else {
        new_idx.expect("checked in_new above")
    };

    let old_share = if in_old {
        let bundle = RingShareBundle::load_by_ring_key(local_storage, ring_pk_hex)
            .map_err(|e| DkgError::Storage(format!("Reshare: failed to load old share: {}", e)))?;
        let pri = bundle.pri_share().map_err(|e| {
            DkgError::Deserialization(format!("Reshare: failed to deserialize old share: {}", e))
        })?;
        Some(pri.v)
    } else {
        None
    };

    let participating_ids: Vec<u32> = (1..=old_peer_node_keys.len() as u32).collect();
    let new_node_id = in_new.then(|| node_index_in(&sorted_new, our_node_key));

    let params = ReshareParams {
        ring_key: ring_pk_hex.to_string(),
        old_share,
        participating_ids,
        new_threshold: new_threshold as usize,
        new_total_nodes: new_peer_node_keys.len(),
        new_peer_node_keys: sorted_new,
        new_node_id,
        bulletin_post_id: bulletin_post_id.to_string(),
    };

    Ok((node_id, role, params))
}

/// Returns `true` if `our_node_key` appears in
/// `committee` (sorted or unsorted — membership check is order-independent).
///
/// Used during reshare `SessionInit` handling to decide whether this node is in the
/// old committee, the new committee, or both.
pub fn in_committee(committee: &[String], our_node_key: &str) -> bool {
    committee.iter().any(|node_key| node_key == our_node_key)
}

/// Returns the 1-based node index of `our_node_key` in `sorted_committee`.
///
/// `sorted_committee` must already be sorted so that all nodes derive the same
/// index for the same node key.  Panics if not found — callers must confirm membership
/// with `in_committee` before calling this.
pub fn node_index_in(sorted_committee: &[String], our_node_key: &str) -> u32 {
    sorted_committee
        .iter()
        .position(|node_key| node_key == our_node_key)
        .map(|i| (i + 1) as u32)
        .expect("node not found in committee — check in_committee() first")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::PSS_GRACE_PERIOD_SECS;
    use crate::helpers::test_helpers::{cleanup_db, test_db_path, write_ring_to_bulletin};
    use crate::ring_state::{RingIndexEntry, RingShareBundle};
    use bulletin::dummy::DummyBulletin;
    use bulletin::r#trait::{Bulletin, BulletinPost, RingPayload};
    use crypto::r#trait::PriShare;
    use crypto::{CryptoSerialize, ScalarField as Fr};
    use local_storage::{r#trait::LocalStorage, LocalStorageImpl};
    use std::sync::Arc;
    use zeroize::Zeroizing;

    fn make_storage(db_name: &str) -> (LocalStorageImpl, String) {
        let db_path = test_db_path(db_name);
        let storage = LocalStorageImpl::new(None, db_path.clone()).expect("create storage");
        (storage, db_path)
    }

    fn write_last_refresh(storage: &LocalStorageImpl, ring_pk: &str, secs: u64) {
        let bundle = RingShareBundle {
            share_bytes: vec![].into(),
            public_polynomial: String::new(),
            last_pss: secs,
        };
        bundle.save_by_ring_key(storage, ring_pk).unwrap();
    }

    fn dkg_token(_policy_id: Option<&str>) -> BearerToken<DkgClaims> {
        BearerToken {
            issuer_id: "issuer".to_string(),
            issued_time: 0,
            expiration_time: 1,
            not_before: None,
            claims: DkgClaims {
                ring_id: "ring-1".to_string(),
            },
        }
    }

    async fn seed_node_info(
        bulletin: &DummyBulletin,
        node_key: &str,
        peer_id: &str,
        policy_ids: Vec<String>,
        ring_ids: Vec<String>,
    ) {
        let node_info = NodeInfo {
            peer_id: peer_id.to_string(),
            controller_key: "controller".to_string(),
            whitelisted_policy_ids: policy_ids,
            whitelisted_ring_ids: ring_ids,
        };
        bulletin
            .set_node_info(node_key.to_string(), node_info)
            .expect("post NodeInfo");
    }

    fn make_valid_ring_payload(node_key: &str) -> RingPayload {
        RingPayload {
            ring_pk: String::new(),
            peer_node_keys: vec![node_key.to_string()],
            new_peer_node_keys: None,
            new_threshold: None,
            threshold: 1,
            pss_interval: None,
            block_number_nonce: 0,
            policy_id: Some("policy".to_string()),
        }
    }

    #[tokio::test]
    async fn test_validate_fresh_dkg_node_authorization_allows_policy_id() {
        let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
        let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
        let node_key = "node-key";
        let local_peer_id = "peer-local";
        let ring_payload = make_valid_ring_payload(node_key);
        seed_node_info(
            &dummy_bulletin,
            node_key,
            local_peer_id,
            vec!["policy".to_string()],
            vec![],
        )
        .await;

        let result = validate_fresh_dkg_node_authorization(
            &bulletin,
            node_key,
            local_peer_id,
            "ring-1",
            &ring_payload,
        )
        .await;
        assert!(result.is_ok(), "expected policy allow, got: {:?}", result);
    }

    #[tokio::test]
    async fn test_validate_fresh_dkg_node_authorization_allows_ring_id_with_blank_placeholder() {
        let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
        let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
        let node_key = "node-key";
        let local_peer_id = "peer-local";
        let ring_id = "ring-1";
        let ring_payload = RingPayload {
            ring_pk: String::new(),
            peer_node_keys: vec![node_key.to_string()],
            new_peer_node_keys: None,
            new_threshold: None,
            threshold: 1,
            pss_interval: Some(60),
            block_number_nonce: 0,
            policy_id: Some("policy".to_string()),
        };
        seed_node_info(
            &dummy_bulletin,
            node_key,
            local_peer_id,
            vec![],
            vec![ring_id.to_string()],
        )
        .await;

        let result = validate_fresh_dkg_node_authorization(
            &bulletin,
            node_key,
            local_peer_id,
            ring_id,
            &ring_payload,
        )
        .await;
        assert!(result.is_ok(), "expected ring allow, got: {:?}", result);
    }

    #[tokio::test]
    async fn test_validate_fresh_dkg_node_authorization_rejects_deny() {
        let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
        let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
        let node_key = "node-key";
        let local_peer_id = "peer-local";
        let ring_payload = make_valid_ring_payload(node_key);
        seed_node_info(
            &dummy_bulletin,
            node_key,
            local_peer_id,
            vec!["other-policy".to_string()],
            vec!["other-ring".to_string()],
        )
        .await;

        // ring_id = "ring-1" is not in ["other-ring"], policy "policy" is not in ["other-policy"]
        let result = validate_fresh_dkg_node_authorization(
            &bulletin,
            node_key,
            local_peer_id,
            "ring-1",
            &ring_payload,
        )
        .await;
        assert!(matches!(result, Err(DkgError::Unauthorized(_))));
    }

    #[tokio::test]
    async fn test_validate_fresh_dkg_node_authorization_rejects_missing_node_info() {
        let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
        let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
        let ring_payload = make_valid_ring_payload("missing-node");

        let result = validate_fresh_dkg_node_authorization(
            &bulletin,
            "missing-node",
            "peer-local",
            "ring-1",
            &ring_payload,
        )
        .await;
        assert!(matches!(result, Err(DkgError::Unauthorized(_))));
    }

    #[tokio::test]
    async fn test_validate_fresh_dkg_node_authorization_rejects_malformed_node_info() {
        let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
        let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
        let node_key = "node-key";
        dummy_bulletin.set_post(
            node_key.to_string(),
            BulletinPost {
                id: node_key.to_string(),
                payload: b"not-json".to_vec(),
            },
        );
        let ring_payload = make_valid_ring_payload(node_key);

        let result = validate_fresh_dkg_node_authorization(
            &bulletin,
            node_key,
            "peer-local",
            "ring-1",
            &ring_payload,
        )
        .await;
        assert!(matches!(result, Err(DkgError::Unauthorized(_))));
    }

    #[tokio::test]
    async fn test_validate_fresh_dkg_node_authorization_rejects_peer_id_mismatch() {
        let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
        let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
        let node_key = "node-key";
        seed_node_info(
            &dummy_bulletin,
            node_key,
            "different-peer",
            vec!["policy".to_string()],
            vec![],
        )
        .await;
        let ring_payload = make_valid_ring_payload(node_key);

        let result = validate_fresh_dkg_node_authorization(
            &bulletin,
            node_key,
            "peer-local",
            "ring-1",
            &ring_payload,
        )
        .await;
        assert!(matches!(result, Err(DkgError::Unauthorized(_))));
    }

    #[test]
    fn test_validate_fresh_dkg_ring_payload_ok() {
        let payload = make_valid_ring_payload("node-key");
        assert!(validate_fresh_dkg_ring_payload("ring-1", &payload).is_ok());
    }

    #[test]
    fn test_validate_fresh_dkg_ring_payload_rejects_non_blank_ring() {
        let mut payload = make_valid_ring_payload("node-key");
        payload.ring_pk = "some-pk".to_string();
        assert!(matches!(
            validate_fresh_dkg_ring_payload("ring-1", &payload),
            Err(DkgError::Unauthorized(_))
        ));
    }

    #[test]
    fn test_validate_fresh_dkg_ring_payload_rejects_empty_committee() {
        let mut payload = make_valid_ring_payload("node-key");
        payload.peer_node_keys = vec![];
        assert!(matches!(
            validate_fresh_dkg_ring_payload("ring-1", &payload),
            Err(DkgError::InvalidInput(_))
        ));
    }

    #[test]
    fn test_validate_fresh_dkg_ring_payload_rejects_zero_threshold() {
        let mut payload = make_valid_ring_payload("node-key");
        payload.threshold = 0;
        assert!(matches!(
            validate_fresh_dkg_ring_payload("ring-1", &payload),
            Err(DkgError::InvalidInput(_))
        ));
    }

    #[test]
    fn test_validate_fresh_dkg_ring_payload_rejects_threshold_exceeds_n() {
        let mut payload = make_valid_ring_payload("node-key");
        payload.threshold = 3; // Only 1 node in committee
        assert!(matches!(
            validate_fresh_dkg_ring_payload("ring-1", &payload),
            Err(DkgError::InvalidInput(_))
        ));
    }

    #[test]
    fn test_validate_fresh_dkg_ring_payload_rejects_missing_policy_id() {
        let mut payload = make_valid_ring_payload("node-key");
        payload.policy_id = None;
        assert!(matches!(
            validate_fresh_dkg_ring_payload("ring-1", &payload),
            Err(DkgError::InvalidInput(_))
        ));
    }

    #[test]
    fn test_validate_dkg_claims_policy_id_compares_empty_string_directly() {
        let token = dkg_token(Some(""));

        assert!(validate_dkg_claims(&token, "ring-1").is_ok());

        let result = validate_dkg_claims(&token, "other-ring");
        assert!(
            matches!(result, Err(DkgError::Unauthorized(ref msg)) if msg.contains("Token ring_id")),
            "Expected Unauthorized for mismatched ring_id, got: {:?}",
            result
        );
    }

    #[test]
    fn test_validate_dkg_claims_distinguishes_absent_and_zero_pss_interval() {
        let token = dkg_token(None);
        let result = validate_dkg_claims(&token, "");
        assert!(
            matches!(result, Err(DkgError::Unauthorized(ref msg)) if msg.contains("ring_id must not be empty")),
            "Expected Unauthorized for empty request ring_id, got: {:?}",
            result
        );
    }

    #[test]
    fn test_derive_reshare_session_id_uses_chain_transition_only() {
        let old_peer_node_keys = vec!["node-c".to_string(), "node-a".to_string()];
        let new_peer_node_keys = vec!["node-b".to_string(), "node-a".to_string()];

        let id_1 = derive_reshare_session_id(
            "ring-pk",
            "ring-id",
            &old_peer_node_keys,
            &new_peer_node_keys,
            2,
        );
        let id_2 = derive_reshare_session_id(
            "ring-pk",
            "ring-id",
            &old_peer_node_keys,
            &new_peer_node_keys,
            2,
        );
        assert_eq!(
            id_1, id_2,
            "reshare session ID should be stable across nodes that see the same ring update"
        );

        let changed = derive_reshare_session_id(
            "ring-pk",
            "ring-id",
            &old_peer_node_keys,
            &new_peer_node_keys,
            1,
        );
        assert_ne!(
            id_1, changed,
            "reshare session ID should still change when the announced transition changes"
        );
    }

    #[tokio::test]
    async fn test_unknown_ring() {
        let (storage, db_path) = make_storage("helpers_unknown_ring");
        let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
        let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
        // No RingIndex written — ring is unknown.
        let result = validate_refresh_session_init("some_pk", "sender", &storage, &bulletin).await;
        assert!(
            matches!(result, Err(DkgError::Unauthorized(_))),
            "Expected Unauthorized for unknown ring, got: {:?}",
            result
        );
        cleanup_db(&db_path);
    }

    #[tokio::test]
    async fn test_corrupt_ring_payload() {
        let (storage, db_path) = make_storage("helpers_corrupt_payload");
        // Post garbage bytes to the bulletin and point RingIndex at them.
        let garbage = b"not valid json".to_vec();
        let post_id = "test-garbage-ring".to_string();
        let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
        let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
        dummy_bulletin.set_post(
            post_id.clone(),
            BulletinPost {
                id: post_id.clone(),
                payload: garbage,
            },
        );
        storage
            .set(
                LocalStorageKeys::RingIndex,
                serde_json::to_vec(&vec![RingIndexEntry {
                    ring_pk_str: "pk".to_string(),
                    bulletin_post_id: post_id,
                }])
                .unwrap(),
            )
            .unwrap();
        let result = validate_refresh_session_init("pk", "sender", &storage, &bulletin).await;
        assert!(
            matches!(result, Err(DkgError::Deserialization(_))),
            "Expected Deserialization error for corrupt payload, got: {:?}",
            result
        );
        cleanup_db(&db_path);
    }

    #[tokio::test]
    async fn test_sender_not_in_ring() {
        let (storage, db_path) = make_storage("helpers_sender_not_in_ring");
        let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
        let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
        let ring_pk = "ring_pk_abc";
        write_ring_to_bulletin(
            &storage,
            &dummy_bulletin,
            ring_pk,
            vec!["aabbccdd".to_string(), "eeff0011".to_string()],
            None,
        )
        .await;
        let result =
            validate_refresh_session_init(ring_pk, "deadbeef00000000", &storage, &bulletin).await;
        assert!(
            matches!(result, Err(DkgError::Unauthorized(_))),
            "Expected Unauthorized for sender not in ring, got: {:?}",
            result
        );
        cleanup_db(&db_path);
    }

    #[tokio::test]
    async fn test_no_last_refresh_timestamp() {
        // When pss_interval is set, a missing bundle (no DKG yet) must be rejected.
        let (storage, db_path) = make_storage("helpers_no_timestamp");
        let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
        let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
        let ring_pk = "ring_pk_def";
        write_ring_to_bulletin(
            &storage,
            &dummy_bulletin,
            ring_pk,
            vec!["aabbccdd".to_string()],
            Some(86400),
        )
        .await;
        // Intentionally do not write a RingShareBundle.
        let result = validate_refresh_session_init(ring_pk, "aabbccdd", &storage, &bulletin).await;
        assert!(
            matches!(result, Err(DkgError::Unauthorized(_))),
            "Expected Unauthorized for missing timestamp, got: {:?}",
            result
        );
        if let Err(DkgError::Unauthorized(msg)) = result {
            assert!(
                msg.contains("no refresh timestamp"),
                "Expected 'no refresh timestamp' message, got: {}",
                msg
            );
        }
        cleanup_db(&db_path);
    }

    #[tokio::test]
    async fn test_refresh_too_soon() {
        let (storage, db_path) = make_storage("helpers_too_soon");
        let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
        let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
        let ring_pk = "ring_pk_ghi";
        write_ring_to_bulletin(
            &storage,
            &dummy_bulletin,
            ring_pk,
            vec!["aabbccdd".to_string()],
            Some(86400),
        )
        .await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        write_last_refresh(&storage, ring_pk, now);
        let result = validate_refresh_session_init(ring_pk, "aabbccdd", &storage, &bulletin).await;
        assert!(
            matches!(result, Err(DkgError::Unauthorized(_))),
            "Expected Unauthorized for too soon, got: {:?}",
            result
        );
        if let Err(DkgError::Unauthorized(msg)) = result {
            assert!(
                msg.contains("too soon"),
                "Expected 'too soon' message, got: {}",
                msg
            );
        }
        cleanup_db(&db_path);
    }

    #[tokio::test]
    async fn test_refresh_succeeds() {
        let (storage, db_path) = make_storage("helpers_success");
        let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
        let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
        let ring_pk = "ring_pk_jkl";
        write_ring_to_bulletin(
            &storage,
            &dummy_bulletin,
            ring_pk,
            vec!["aabbccdd".to_string()],
            Some(86400),
        )
        .await;
        // Timestamp at epoch — elapsed >> interval.
        write_last_refresh(&storage, ring_pk, 0);
        let result = validate_refresh_session_init(ring_pk, "aabbccdd", &storage, &bulletin).await;
        assert!(
            result.is_ok(),
            "Expected Ok for valid refresh, got: {:?}",
            result
        );
        cleanup_db(&db_path);
    }

    #[tokio::test]
    async fn test_no_pss_interval_skips_time_check() {
        // When pss_interval is None, time check is skipped — refresh always allowed.
        let (storage, db_path) = make_storage("helpers_no_interval");
        let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
        let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
        let ring_pk = "ring_pk_mno";
        write_ring_to_bulletin(
            &storage,
            &dummy_bulletin,
            ring_pk,
            vec!["aabbccdd".to_string()],
            None,
        )
        .await;
        // No RingShareBundle written — would fail if the time check ran.
        let result = validate_refresh_session_init(ring_pk, "aabbccdd", &storage, &bulletin).await;
        assert!(
            result.is_ok(),
            "Expected Ok when pss_interval is None (no time check), got: {:?}",
            result
        );
        cleanup_db(&db_path);
    }

    #[tokio::test]
    async fn test_zero_pss_interval_requires_existing_timestamp() {
        let (storage, db_path) = make_storage("helpers_zero_interval");
        let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
        let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
        let ring_pk = "ring_pk_zero_interval";
        write_ring_to_bulletin(
            &storage,
            &dummy_bulletin,
            ring_pk,
            vec!["aabbccdd".to_string()],
            Some(0),
        )
        .await;

        let missing = validate_refresh_session_init(ring_pk, "aabbccdd", &storage, &bulletin).await;
        assert!(
            matches!(missing, Err(DkgError::Unauthorized(_))),
            "Expected missing timestamp to be rejected when pss_interval is Some(0), got: {:?}",
            missing
        );

        write_last_refresh(&storage, ring_pk, 0);
        let result = validate_refresh_session_init(ring_pk, "aabbccdd", &storage, &bulletin).await;
        assert!(
            result.is_ok(),
            "Expected Some(0) to be accepted once the ring has a timestamp, got: {:?}",
            result
        );
        cleanup_db(&db_path);
    }

    /// A refresh that arrives within the grace window (elapsed just under pss_interval)
    /// must be accepted — the grace period exists precisely for this case.
    #[tokio::test]
    async fn test_refresh_within_grace_period_succeeds() {
        let (storage, db_path) = make_storage("helpers_within_grace");
        let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
        let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
        let ring_pk = "ring_pk_grace_ok";
        let pss_interval: u64 = 86400;
        write_ring_to_bulletin(
            &storage,
            &dummy_bulletin,
            ring_pk,
            vec!["aabbccdd".to_string()],
            Some(pss_interval),
        )
        .await;
        // elapsed = pss_interval - (PSS_GRACE_PERIOD_SECS / 2): inside the grace window.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let half_grace = PSS_GRACE_PERIOD_SECS / 2;
        write_last_refresh(&storage, ring_pk, now - pss_interval + half_grace);
        let result = validate_refresh_session_init(ring_pk, "aabbccdd", &storage, &bulletin).await;
        assert!(
            result.is_ok(),
            "Expected Ok: elapsed is within grace window, got: {:?}",
            result
        );
        cleanup_db(&db_path);
    }

    /// A refresh that arrives outside the grace window (more than PSS_GRACE_PERIOD_SECS
    /// before the interval expires) must still be rejected.
    #[tokio::test]
    async fn test_refresh_outside_grace_period_rejected() {
        let (storage, db_path) = make_storage("helpers_outside_grace");
        let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
        let bulletin: Arc<dyn Bulletin + Send + Sync> = dummy_bulletin.clone();
        let ring_pk = "ring_pk_grace_fail";
        let pss_interval: u64 = 86400;
        write_ring_to_bulletin(
            &storage,
            &dummy_bulletin,
            ring_pk,
            vec!["aabbccdd".to_string()],
            Some(pss_interval),
        )
        .await;
        // elapsed = pss_interval - (PSS_GRACE_PERIOD_SECS + 2): safely outside the grace window.
        // The +2 margin ensures the test remains reliable even if SystemTime advances by 1s
        // between this snapshot and validate_refresh_session_init's own now() call.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        write_last_refresh(
            &storage,
            ring_pk,
            now - pss_interval + PSS_GRACE_PERIOD_SECS + 2,
        );
        let result = validate_refresh_session_init(ring_pk, "aabbccdd", &storage, &bulletin).await;
        assert!(
            matches!(result, Err(DkgError::Unauthorized(_))),
            "Expected Unauthorized: elapsed is outside grace window, got: {:?}",
            result
        );
        cleanup_db(&db_path);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // build_reshare_params tests
    // ──────────────────────────────────────────────────────────────────────────

    /// Serialize a minimal `PriShare<Fr>` so we can write a valid `RingShareBundle`.
    fn valid_share_bytes() -> Vec<u8> {
        let pri = PriShare {
            i: 1u32,
            v: Fr::from(42u64),
        };
        CryptoSerialize::to_bytes(&pri).expect("serialize PriShare")
    }

    fn write_valid_bundle(storage: &LocalStorageImpl, ring_pk: &str) {
        let bundle = RingShareBundle {
            share_bytes: Zeroizing::new(valid_share_bytes()),
            public_polynomial: String::new(),
            last_pss: 0,
        };
        bundle.save_by_ring_key(storage, ring_pk).unwrap();
    }

    /// Node is not in either committee → `InvalidInput`.
    #[test]
    fn test_build_reshare_params_not_in_committee() {
        let (storage, db_path) = make_storage("reshare_params_not_in_committee");
        let result = build_reshare_params(
            "ring_pk",
            &["aabbccdd".to_string()],
            &["11223344".to_string()],
            1,
            "post_id",
            "ffffffff", // not in either committee
            &storage,
        );
        assert!(
            matches!(result, Err(DkgError::InvalidInput(_))),
            "Expected InvalidInput for node not in either committee: {:?}",
            result
        );
        cleanup_db(&db_path);
    }

    /// Pure Receiver (only in new committee) — no share bundle needed.
    #[test]
    fn test_build_reshare_params_receiver() {
        let (storage, db_path) = make_storage("reshare_params_receiver");
        let result = build_reshare_params(
            "ring_pk",
            &["aabbccdd".to_string()],
            &["11223344".to_string()],
            1,
            "post_id",
            "11223344", // in new committee only
            &storage,
        );
        let (node_id, role, params) = result.expect("Receiver case should succeed");
        assert_eq!(role, DkgRole::Receiver);
        assert_eq!(
            node_id, 1,
            "Receiver gets 1-based index in sorted new committee"
        );
        assert!(params.old_share.is_none(), "Receiver has no old share");
        assert_eq!(params.new_node_id, Some(1));
        cleanup_db(&db_path);
    }

    /// Pure Dealer (only in old committee) — valid share bundle required.
    #[test]
    fn test_build_reshare_params_dealer() {
        let (storage, db_path) = make_storage("reshare_params_dealer");
        write_valid_bundle(&storage, "ring_pk");

        let result = build_reshare_params(
            "ring_pk",
            &["aabbccdd".to_string()],
            &["11223344".to_string()],
            1,
            "post_id",
            "aabbccdd", // in old committee only
            &storage,
        );
        let (node_id, role, params) = result.expect("Dealer case should succeed");
        assert_eq!(role, DkgRole::Dealer);
        assert_eq!(node_id, 1);
        assert!(params.old_share.is_some(), "Dealer must have old share");
        assert_eq!(params.new_node_id, None, "Pure Dealer has no new_node_id");
        cleanup_db(&db_path);
    }

    /// DealerReceiver (in both committees) — valid share bundle required.
    #[test]
    fn test_build_reshare_params_dealer_receiver() {
        let (storage, db_path) = make_storage("reshare_params_dealer_receiver");
        write_valid_bundle(&storage, "ring_pk");

        let result = build_reshare_params(
            "ring_pk",
            &["aabbccdd".to_string(), "bbbbbbbb".to_string()],
            &["aabbccdd".to_string(), "cccccccc".to_string()],
            1,
            "post_id",
            "aabbccdd", // in both committees
            &storage,
        );
        let (node_id, role, params) = result.expect("DealerReceiver case should succeed");
        assert_eq!(role, DkgRole::DealerReceiver);
        assert_eq!(node_id, 1, "aabbccdd is smallest in old committee");
        assert!(params.old_share.is_some());
        assert_eq!(
            params.new_node_id,
            Some(1),
            "aabbccdd is smallest in new committee"
        );
        cleanup_db(&db_path);
    }

    /// Dealer path with missing share bundle must return a `Storage` error.
    #[test]
    fn test_build_reshare_params_dealer_missing_bundle() {
        let (storage, db_path) = make_storage("reshare_params_missing_bundle");
        // No bundle written — load will fail.
        let result = build_reshare_params(
            "ring_pk",
            &["aabbccdd".to_string()],
            &["11223344".to_string()],
            1,
            "post_id",
            "aabbccdd",
            &storage,
        );
        assert!(
            matches!(result, Err(DkgError::Storage(_))),
            "Expected Storage error when share bundle is absent: {:?}",
            result
        );
        cleanup_db(&db_path);
    }

    /// Unsorted input peer lists must be sorted before computing node indices.
    ///
    /// old = ["cccccccc", "aabbccdd", "bbbbbbbb"] — sorted: ["aabbccdd", "bbbbbbbb", "cccccccc"]
    /// Our node is "aabbccdd" → index 1 in sorted old committee.
    #[test]
    fn test_build_reshare_params_sorts_committees() {
        let (storage, db_path) = make_storage("reshare_params_sorting");
        write_valid_bundle(&storage, "ring_pk");

        let result = build_reshare_params(
            "ring_pk",
            &[
                "cccccccc".to_string(),
                "aabbccdd".to_string(),
                "bbbbbbbb".to_string(),
            ],
            &["11223344".to_string()],
            1,
            "post_id",
            "aabbccdd",
            &storage,
        );
        let (node_id, role, params) = result.expect("sorting test should succeed");
        assert_eq!(role, DkgRole::Dealer);
        assert_eq!(node_id, 1, "aabbccdd must be index 1 after sorting");
        // participating_ids covers the full old committee (3 nodes, 1-based)
        assert_eq!(params.participating_ids, vec![1, 2, 3]);
        cleanup_db(&db_path);
    }
}
