//! PSS (Proactive Secret Sharing) — automatic refresh scheduler
//!
//! Periodically checks every known ring and initiates a refresh ceremony when the
//! ring's own `pss_interval` (stored in `RingPkMapping`) has elapsed since the last
//! refresh.  The check cadence (`check_interval`) is set at node startup; each ring
//! controls its own refresh frequency via the `pss_interval` field in `RingPayload`.
//!
//! ## Protocol
//! On each tick the node with the lexicographically smallest peer ID in the ring acts
//! as the initiator. It sends a `SessionInit { is_refresh: true }` to all ring members
//! and runs the standard DKG commitment/share protocol using `DkgMode::Refresh`
//! (zero constant term — same secret, new shares).
//!
//! Rings with `pss_interval = None` are skipped (automatic refresh disabled).

#[cfg(test)]
mod tests;

use crate::app_state::AppState;
use crate::dkg::coordinator::DkgCoordinator;
use crate::dkg::error::DkgError;
use crate::dkg::messages::DkgMessage;
use crate::helpers::helpers::{extract_node_part, validate_all_peer_ids};
use crate::ring_state::RingShareBundle;
use bulletin::r#trait::RingPayload;
use crypto::r#trait::{Dkg, DkgRole};
use crypto::{CryptoDeserialize, GroupAffine, PolynomialCommitmentImpl, ScalarField as Fr};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Spawn a background task that periodically checks rings for due PSS refreshes.
///
/// `check_interval` controls how often the scheduler wakes up to inspect all known
/// rings.  Each ring's own `pss_interval` (stored in `RingPkMapping`) determines
/// whether a refresh is actually triggered on that tick.
///
/// Setting `check_interval` to zero disables the scheduler entirely.
pub fn spawn_reshare_scheduler<D>(app_state: Arc<AppState<D>>, check_interval: Duration)
where
    D: Dkg<
            ShareValue = Fr,
            PublicKey = GroupAffine,
            PolynomialCommitment = PolynomialCommitmentImpl,
        > + Clone
        + Send
        + Sync
        + 'static,
{
    if check_interval.is_zero() {
        tracing::info!("PSS refresh scheduler disabled (check_interval = 0)");
        return;
    }

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(check_interval);
        ticker.tick().await; // skip the initial immediate tick at t=0
        loop {
            ticker.tick().await;
            tracing::debug!("PSS refresh scheduler: tick");
            if let Err(e) = refresh_all_rings(&app_state).await {
                tracing::error!(error = %e, "PSS refresh scheduler: error");
            }
        }
    });
}

/// Iterate over every known ring and trigger a refresh when its `pss_interval` is due.
async fn refresh_all_rings<D>(app_state: &Arc<AppState<D>>) -> Result<(), DkgError>
where
    D: Dkg<
            ShareValue = Fr,
            PublicKey = GroupAffine,
            PolynomialCommitment = PolynomialCommitmentImpl,
        > + Clone
        + Send
        + Sync
        + 'static,
{
    let ring_ids: Vec<String> = match app_state.local_storage.get(LocalStorageKeys::RingIndex) {
        Ok(Some(bytes)) => serde_json::from_slice(&bytes).unwrap_or_default(),
        _ => {
            tracing::debug!("PSS: ring index empty, nothing to refresh");
            return Ok(());
        }
    };

    for ring_id in &ring_ids {
        if let Err(e) = refresh_ring(app_state, ring_id).await {
            tracing::error!(ring_id = %ring_id, error = %e, "PSS: refresh failed for ring");
        }
    }
    Ok(())
}

/// Run one refresh ceremony for `ring_id` if this node is the initiator and the
/// ring's `pss_interval` has elapsed since the last refresh.
async fn refresh_ring<D>(app_state: &Arc<AppState<D>>, ring_id: &str) -> Result<(), DkgError>
where
    D: Dkg<
            ShareValue = Fr,
            PublicKey = GroupAffine,
            PolynomialCommitment = PolynomialCommitmentImpl,
        > + Clone
        + Send
        + Sync
        + 'static,
{
    // Load ring info from local storage (written during Phase 4 of the last DKG/refresh).
    let ring_payload_bytes = app_state
        .local_storage
        .get(LocalStorageKeys::RingPkMapping(ring_id.to_string()))
        .map_err(|e| DkgError::Storage(format!("PSS: failed to read ring {}: {}", ring_id, e)))?
        .ok_or_else(|| {
            DkgError::Storage(format!("PSS: ring {} not found in local storage", ring_id))
        })?;

    let ring_payload: RingPayload = serde_json::from_slice(&ring_payload_bytes)
        .map_err(|e| DkgError::Deserialization(format!("PSS: bad ring payload: {}", e)))?;

    // Skip rings that have no automatic refresh interval configured.
    let pss_interval_secs = match ring_payload.pss_interval {
        Some(v) if v > 0 => v,
        _ => {
            tracing::debug!(ring_id = %ring_id, "PSS: no pss_interval set, skipping");
            return Ok(());
        }
    };

    // Check whether enough time has elapsed since the last refresh.
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // `ring_id` is aggregate_pk.to_string() — same key the bundle is stored under.
    // Fall back to epoch (0) if no bundle exists yet (ring not yet initialized on this node).
    let last_refresh_secs: u64 =
        RingShareBundle::load_by_ring_key(&app_state.local_storage, ring_id)
            .map(|b| b.refreshed_at)
            .unwrap_or(0);

    let elapsed = now_secs.saturating_sub(last_refresh_secs);
    if elapsed < pss_interval_secs {
        tracing::debug!(
            ring_id = %ring_id,
            elapsed_secs = elapsed,
            pss_interval_secs = pss_interval_secs,
            "PSS: refresh not yet due"
        );
        return Ok(());
    }

    let peer_ids = &ring_payload.peer_ids;
    let threshold = ring_payload.threshold as usize;

    // Only the peer with the smallest node-part acts as initiator
    let our_peer_id_hex = hex::encode(app_state.network.local_peer_id().as_bytes());
    let our_node_part = extract_node_part(&our_peer_id_hex);

    let mut sorted_peers = peer_ids.clone();
    sorted_peers.sort();

    // Debug: log how this node sees the ring and initiator election inputs.
    tracing::info!(
        ring_id = %ring_id,
        ring_pk_hex = %ring_payload.ring_pk,
        our_peer_id_hex = %our_peer_id_hex,
        our_node_part = %our_node_part,
        sorted_peers = ?sorted_peers,
        "PSS: refresh debug - ring metadata before initiator check"
    );

    if extract_node_part(&sorted_peers[0]) != our_node_part {
        tracing::debug!(ring_id = %ring_id, "PSS: not the initiator, skipping");
        return Ok(());
    }

    // Resolve ring_pk before acquiring the in-progress lock so we can use the
    // same key (`ring_pk.to_string()`) that the cleanup/expiration workers use
    // to clear the flag via `state.refresh_ring_key`.
    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk)
        .map_err(|e| DkgError::Deserialization(format!("PSS: bad ring_pk hex: {}", e)))?;
    let ring_pk = <D::PublicKey as CryptoDeserialize>::from_bytes(&ring_pk_bytes).map_err(|e| {
        DkgError::Deserialization(format!("PSS: failed to deserialize ring_pk: {}", e))
    })?;
    let ring_pk_str = ring_pk.to_string();

    tracing::info!(
        ring_id = %ring_id,
        ring_pk_hex = %ring_payload.ring_pk,
        ring_pk_str = %ring_pk_str,
        initiator_peer_id_hex = %our_peer_id_hex,
        initiator_node_part = %our_node_part,
        "PSS: initiating refresh"
    );

    // Prevent duplicate refresh sessions on this node. The flag is cleared by
    // the cleanup/expiration workers (via `state.refresh_ring_key`) once the
    // session ends, or manually below if we fail before `set_refresh_ring_key`.
    if !app_state
        .dkg_session_state
        .try_mark_ring_refreshing(&ring_pk_str)
        .await
    {
        tracing::debug!(
            ring_id = %ring_id,
            ring_pk_str = %ring_pk_str,
            "PSS: refresh already in progress, skipping"
        );
        return Ok(());
    }

    // Build deterministic node_id assignments (sorted peer list → 1-indexed)
    let mut node_id_assignments: std::collections::HashMap<String, u32> =
        std::collections::HashMap::new();
    for (idx, peer_id) in sorted_peers.iter().enumerate() {
        node_id_assignments.insert(extract_node_part(peer_id), (idx + 1) as u32);
    }

    let our_node_id = *node_id_assignments
        .get(&our_node_part)
        .ok_or_else(|| DkgError::InvalidInput("PSS: our peer not in ring".to_string()))?;

    let total = peer_ids.len();
    let session_id: u64 = rand::random();

    let coordinator = DkgCoordinator::new(app_state.clone());

    // Create refresh session (Standard role — all nodes are symmetric in Refresh mode).
    // On failure we must unmark the ring ourselves — no session exists yet so the
    // cleanup workers won't do it.
    if let Err(e) = coordinator
        .create_session(session_id, our_node_id, threshold, total, DkgRole::Standard)
        .await
    {
        tracing::error!(
            ring_id = %ring_id,
            ring_pk_str = %ring_pk_str,
            session_id = session_id,
            error = %e,
            "PSS: failed to create refresh DKG session on initiator"
        );
        app_state
            .dkg_session_state
            .unmark_ring_refreshing(&ring_pk_str)
            .await;
        return Err(e);
    }

    // Mark as refresh so generate_polynomial uses DkgMode::Refresh
    app_state
        .dkg_session_state
        .mark_as_refresh(&session_id)
        .await;

    // Store the ring key in session state so Phase 4 / expiration workers can
    // clear `rings_refreshing`. But if we fail after this point we must clean
    // up explicitly — the expiration worker exempts Initializing sessions from
    // DKG_PHASE_TIMEOUT (only evicting them after SESSION_TTL = 30 min), which
    // would block PSS retries for the entire integration-test window.
    app_state
        .dkg_session_state
        .set_refresh_ring_key(&session_id, ring_pk_str.clone())
        .await;

    // Helper: clean up both the session and the rings_refreshing flag so the
    // PSS scheduler can retry on its next tick.
    let cleanup = |err: DkgError| {
        let state = Arc::clone(&app_state.dkg_session_state);
        let key = ring_pk_str.clone();
        tokio::spawn(async move {
            state.unmark_ring_refreshing(&key).await;
            state.remove_session(&session_id).await;
        });
        err
    };

    // Store peer_ids and node→peer mappings
    coordinator
        .set_peer_ids(&session_id, peer_ids.clone())
        .await;

    let mut node_id_to_peer_id = std::collections::HashMap::new();
    for (peer_key, node_id) in &node_id_assignments {
        let full_peer_id = peer_ids
            .iter()
            .find(|pid| extract_node_part(pid) == *peer_key)
            .cloned()
            .unwrap_or_else(|| peer_key.clone());
        node_id_to_peer_id.insert(*node_id, full_peer_id);
    }
    app_state
        .dkg_session_state
        .set_node_peer_mappings(&session_id, node_id_to_peer_id)
        .await;

    // Validate peer ID formats before sending messages
    if let Err((bad_peer, err)) = validate_all_peer_ids(peer_ids) {
        return Err(cleanup(DkgError::InvalidInput(format!(
            "PSS: invalid peer ID '{}': {}",
            bad_peer, err
        ))));
    }

    // let conn = connect_to_peers(&app_state.network, peer_ids.clone(), DKG).await;
    // if conn.successful < conn.total {
    //     return Err(DkgError::NetworkConnection(format!(
    //         "PSS: connected to {}/{} peers",
    //         conn.successful, conn.total
    // )));

    // Send RefreshSessionInit to all peers
    let init_msg = DkgMessage::SessionInit {
        session_id,
        threshold: threshold as u32,
        total_participants: total as u32,
        peer_ids: peer_ids.clone(),
        node_id_assignments,
        token_string: String::new(), // refresh sessions skip JWT
        is_refresh: true,
        refresh_ring_pk_hex: Some(ring_pk_str.clone()),
        pss_interval: ring_payload.pss_interval,
    };

    for peer_id_str in peer_ids {
        if extract_node_part(peer_id_str) == our_node_part {
            continue; // coordinator handles our own session internally
        }
        if let Err(e) = coordinator
            .send_message_to_peer(peer_id_str, init_msg.clone(), Some(session_id))
            .await
        {
            tracing::error!(peer = %peer_id_str, error = %e, "PSS: failed to send SessionInit");
        }
    }

    // Kick off Phase 1 (uses DkgMode::Refresh via session state)
    coordinator
        .initiate_phase1_commitments(session_id, peer_ids)
        .await
        .map_err(|e| cleanup(e))?;

    tracing::info!(
        session_id = session_id,
        ring_id = %ring_id,
        "PSS: refresh session initiated"
    );

    Ok(())
}
