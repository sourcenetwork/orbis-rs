//! PSS (Proactive Secret Sharing) — automatic refresh scheduler
//!
//! Periodically initiates a refresh ceremony for every ring this node belongs to,
//! rotating secret shares while preserving the distributed secret. The interval is
//! configurable at node startup and defaults to 24 hours.
//!
//! ## Protocol
//! On each tick the node with the lexicographically smallest peer ID in the ring acts
//! as the initiator. It sends a `SessionInit { is_refresh: true }` to all ring members
//! and runs the standard DKG commitment/share protocol using `DkgMode::Refresh`
//! (zero constant term — same secret, new shares).

#[cfg(test)]
mod tests;

use crate::app_state::AppState;
use crate::constants::BULLETIN_RING_NAMESPACE;
use crate::dkg::coordinator::DkgCoordinator;
use crate::dkg::error::DkgError;
use crate::dkg::messages::DkgMessage;
use crate::helpers::helpers::{connect_to_peers, extract_node_part, validate_all_peer_ids};
use bulletin::r#trait::RingPayload;
use crypto::r#trait::{Dkg, DkgRole};
use crypto::{CryptoDeserialize, GroupAffine, PolynomialCommitmentImpl, ScalarField as Fr};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use network::DKG;
use std::sync::Arc;
use std::time::Duration;

/// Spawn a background task that periodically triggers PSS refresh ceremonies.
///
/// A tick is skipped silently when no rings are known yet (e.g., on first boot
/// before any DKG has completed). Setting `interval` to zero disables the scheduler.
pub fn spawn_reshare_scheduler<D>(app_state: Arc<AppState<D>>, interval: Duration)
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
    if interval.is_zero() {
        tracing::info!("PSS refresh scheduler disabled (interval = 0)");
        return;
    }

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // skip the initial immediate tick at t=0
        loop {
            ticker.tick().await;
            tracing::info!("PSS refresh scheduler: tick");
            if let Err(e) = refresh_all_rings(&app_state).await {
                tracing::error!(error = %e, "PSS refresh scheduler: error");
            }
        }
    });
}

/// Iterate over every known ring and attempt a refresh.
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

/// Run one refresh ceremony for `ring_id`, but only if this node is the initiator.
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
    // Fetch ring info from the bulletin
    let ring_post = app_state
        .bulletin
        .read(BULLETIN_RING_NAMESPACE.to_string(), ring_id.to_string())
        .await
        .map_err(|e| DkgError::Storage(format!("PSS: failed to read ring {}: {}", ring_id, e)))?;

    let ring_payload: RingPayload = serde_json::from_slice(&ring_post.payload)
        .map_err(|e| DkgError::Deserialization(format!("PSS: bad ring payload: {}", e)))?;

    let peer_ids = &ring_payload.peer_ids;
    let threshold = ring_payload.threshold as usize;

    // Only the peer with the smallest node-part acts as initiator
    let our_peer_id_hex = hex::encode(app_state.network.local_peer_id().as_bytes());
    let our_node_part = extract_node_part(&our_peer_id_hex);

    let mut sorted_peers = peer_ids.clone();
    sorted_peers.sort();
    if extract_node_part(&sorted_peers[0]) != our_node_part {
        tracing::debug!(ring_id = %ring_id, "PSS: not the initiator, skipping");
        return Ok(());
    }

    tracing::info!(ring_id = %ring_id, "PSS: initiating refresh");

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

    // Create refresh session (Standard role — all nodes are symmetric in Refresh mode)
    coordinator
        .create_session(session_id, our_node_id, threshold, total, DkgRole::Standard)
        .await?;

    // Mark as refresh so generate_polynomial uses DkgMode::Refresh
    app_state
        .dkg_session_state
        .mark_as_refresh(&session_id)
        .await;

    // Resolve the local-storage key for the old share so Phase 4 can combine
    // the refresh delta with the existing share.
    let ring_pk_bytes = hex::decode(&ring_payload.ring_pk)
        .map_err(|e| DkgError::Deserialization(format!("PSS: bad ring_pk hex: {}", e)))?;
    let ring_pk = <D::PublicKey as CryptoDeserialize>::from_bytes(&ring_pk_bytes).map_err(|e| {
        DkgError::Deserialization(format!("PSS: failed to deserialize ring_pk: {}", e))
    })?;
    app_state
        .dkg_session_state
        .set_refresh_ring_key(&session_id, ring_pk.to_string())
        .await;

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

    // Validate and connect to all peers
    if let Err((bad_peer, err)) = validate_all_peer_ids(peer_ids) {
        return Err(DkgError::InvalidInput(format!(
            "PSS: invalid peer ID '{}': {}",
            bad_peer, err
        )));
    }
    let conn = connect_to_peers(&app_state.network, peer_ids.clone(), DKG).await;
    if conn.successful < conn.total {
        return Err(DkgError::NetworkConnection(format!(
            "PSS: connected to {}/{} peers",
            conn.successful, conn.total
        )));
    }

    // Send RefreshSessionInit to all peers
    let init_msg = DkgMessage::SessionInit {
        session_id,
        threshold: threshold as u32,
        total_participants: total as u32,
        peer_ids: peer_ids.clone(),
        node_id_assignments,
        token_string: String::new(), // refresh sessions skip JWT; TODO: add refresh-specific auth
        is_refresh: true,
        refresh_ring_pk_hex: Some(ring_pk.to_string()),
    };

    for peer_id_str in peer_ids {
        if let Err(e) = coordinator
            .send_message_to_peer(peer_id_str, init_msg.clone())
            .await
        {
            tracing::error!(peer = %peer_id_str, error = %e, "PSS: failed to send SessionInit");
        }
    }

    // Kick off Phase 1 (uses DkgMode::Refresh via session state)
    coordinator
        .initiate_phase1_commitments(session_id, peer_ids)
        .await?;

    tracing::info!(
        session_id = session_id,
        ring_id = %ring_id,
        "PSS: refresh session initiated"
    );

    Ok(())
}
