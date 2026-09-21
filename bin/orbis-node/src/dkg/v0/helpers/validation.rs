//! Session-init and node-authorization validation.

use super::committee::{
    effective_new_peer_node_keys, peer_node_keys_match, ring_payload_matches_ring_key,
};
use crate::constants::{MAX_DKG_COMMITTEE_SIZE, PSS_GRACE_PERIOD_SECS};
use crate::dkg::v0::error::{DkgError, Result};
use crate::helpers::identity::extract_node_part;
use crate::helpers::protocol_version::read_ring_for_route;
use crate::ring_state::{RingIndexEntry, RingShareBundle};
use bulletin::r#trait::{Bulletin, BulletinKind, NodeInfo, RingPayload};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

async fn load_ring_payload_by_post_id(
    ring_pk_hex: &str,
    post_id: &str,
    bulletin: &Arc<dyn Bulletin + Send + Sync>,
    protocol_version: u64,
) -> Result<RingPayload> {
    let ring_payload = read_ring_for_route(&**bulletin, post_id, protocol_version)
        .await
        .map_err(DkgError::ProtocolError)?;

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
pub async fn validate_reshare_session_init_for_version<S: LocalStorage>(
    ring_pk_hex: &str,
    proposed_new_peer_node_keys: &[String],
    proposed_new_threshold: u32,
    bulletin_post_id: &str,
    local_storage: &S,
    bulletin: &Arc<dyn Bulletin + Send + Sync>,
    protocol_version: u64,
) -> Result<RingPayload> {
    // 0. Fast-fail on structurally invalid parameters before hitting the bulletin.
    if proposed_new_peer_node_keys.is_empty() {
        return Err(DkgError::InvalidInput(
            "Reshare new_peer_node_keys cannot be empty".to_string(),
        ));
    }
    if proposed_new_peer_node_keys.len() > MAX_DKG_COMMITTEE_SIZE {
        return Err(DkgError::InvalidInput(format!(
            "Reshare new committee has {} nodes, maximum is {}",
            proposed_new_peer_node_keys.len(),
            MAX_DKG_COMMITTEE_SIZE
        )));
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
    let ring_payload =
        load_ring_payload_by_post_id(ring_pk_hex, resolved_post_id, bulletin, protocol_version)
            .await?;
    if ring_payload.peer_node_keys.len() > MAX_DKG_COMMITTEE_SIZE {
        return Err(DkgError::InvalidInput(format!(
            "Reshare current committee has {} nodes, maximum is {}",
            ring_payload.peer_node_keys.len(),
            MAX_DKG_COMMITTEE_SIZE
        )));
    }

    // 3. Sender membership in the old committee is verified by the caller (session_init
    // handler) after resolving NodeInfo routes: it needs the resolved peer→node-key map
    // that this function cannot produce. No check is done here.

    // 4. Proposed new_peer_node_keys must match the authoritative committee.
    //    Bulletin present → must match it; absent → must match current peer_node_keys (fallback).
    let authoritative_new = effective_new_peer_node_keys(&ring_payload);
    if !peer_node_keys_match(authoritative_new, proposed_new_peer_node_keys) {
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

    Ok(ring_payload)
}

/// Validates an incoming PSS refresh `SessionInit` message.
///
/// Checks (in order):
/// 1. The ring is known (an entry with `ring_pk_str == ring_pk_hex` exists in `RingIndex`).
/// 2. Enough time has elapsed since the last refresh (`ring_payload.pss_interval`).
///    A bundle with a prior timestamp must always exist; `pss_interval = 0` means immediately due.
///
/// Local node membership is **not** checked here — it requires resolving node keys to
/// P2P peer IDs via NodeInfo bulletin lookups, which is done by the SessionInit
/// handler after this function returns.
///
/// The caller is responsible for the atomic in-progress flag
/// (`try_mark_ring_pss`) after this returns `Ok`.
pub async fn validate_refresh_session_init_for_version<S: LocalStorage>(
    ring_pk_hex: &str,
    local_storage: &S,
    bulletin: &Arc<dyn Bulletin + Send + Sync>,
    protocol_version: u64,
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
    let ring_payload =
        load_ring_payload_by_post_id(ring_pk_hex, post_id, bulletin, protocol_version).await?;
    if ring_payload.peer_node_keys.len() > MAX_DKG_COMMITTEE_SIZE {
        return Err(DkgError::InvalidInput(format!(
            "Refresh target ring {} has {} participants, maximum is {}",
            ring_pk_hex,
            ring_payload.peer_node_keys.len(),
            MAX_DKG_COMMITTEE_SIZE
        )));
    }

    // 2. Verify enough time has elapsed since the last refresh/DKG.
    let pss_interval_secs = ring_payload.pss_interval;
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

    Ok(ring_payload)
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
    if ring_payload.peer_node_keys.len() > MAX_DKG_COMMITTEE_SIZE {
        return Err(DkgError::InvalidInput(format!(
            "Fresh DKG target ring {} has {} participants, maximum is {}",
            ring_id,
            ring_payload.peer_node_keys.len(),
            MAX_DKG_COMMITTEE_SIZE
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
    if ring_payload
        .policy_id
        .as_deref()
        .is_none_or(|id| id.is_empty())
    {
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
    pss_interval: u64,
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

/// Validate that this node is authorized by its NodeInfo record to participate in a DKG session.
///
/// `authorized_committee` is the set of node keys that must include `node_key`:
/// - Fresh DKG: pass `&ring_payload.peer_node_keys`
/// - Reshare receiver: pass `effective_new_peer_node_keys(ring_payload)`
///
/// `session_label` is used only in error messages (e.g. `"Fresh DKG"`, `"Reshare"`).
/// Callers are responsible for fetching the ring payload and validating its structure before
/// calling this.
pub async fn validate_dkg_node_authorization_for_committee(
    bulletin: &Arc<dyn Bulletin + Send + Sync>,
    node_key: &str,
    local_peer_id_hex: &str,
    ring_id: &str,
    ring_payload: &RingPayload,
    authorized_committee: &[String],
    session_label: &str,
) -> Result<()> {
    if node_key.is_empty() {
        return Err(DkgError::Unauthorized(
            "Local node signing key is not configured".to_string(),
        ));
    }
    if ring_id.is_empty() {
        return Err(DkgError::Unauthorized(format!(
            "{} ring_id must not be empty",
            session_label
        )));
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
    if !authorized_committee.iter().any(|key| key == node_key) {
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
