//! PSS (Proactive Secret Sharing) — automatic refresh and reshare scheduler
//!
//! Periodically checks every known ring and initiates a PSS ceremony when due.
//!
//! ## Refresh
//! When the bulletin `RingPayload` has no `new_peer_node_keys` or `new_threshold`, a
//! **refresh** ceremony runs once the ring's `pss_interval` has elapsed since the
//! last ceremony.  Same secret, new shares, same committee (zero constant term).
//!
//! ## Reshare
//! When the bulletin `RingPayload` carries `new_peer_node_keys` or `new_threshold` the ring
//! has been designated for committee rotation.  The scheduler bypasses the interval
//! check and immediately initiates a **reshare** (`SessionKind::Reshare`).
//! Fallback rules (agreed on construction):
//! - `new_peer_node_keys` absent → use current `peer_node_keys` (same committee, threshold change only).
//! - `new_threshold` absent → use current `threshold` (committee change only).
//!
//! Phase 4 posts the updated `RingPayload` with `new_peer_node_keys = None` so subsequent
//! ticks revert to the normal refresh cadence.
//!
//! In both cases any current old-committee node may attempt to start the ceremony.
//! Concurrent starters converge because they derive the same deterministic session ID
//! from the ring's current public polynomial and the authoritative transition data.
//!
//! Rings with `pss_interval = None` are skipped for refresh (reshare is unaffected);
//! `Some(0)` is a present interval and is due immediately.

#[cfg(test)]
mod tests;

use crate::app_state::AppState;
use crate::constants::PSS_GRACE_PERIOD_SECS;
use crate::dkg::v0::coordinator::DkgCoordinator;
use crate::dkg::v0::error::DkgError;
use crate::dkg::v0::helpers::{
    build_reshare_params, derive_refresh_session_id, derive_reshare_session_id,
    effective_new_peer_node_keys, ring_payload_matches_ring_key,
    validate_dkg_node_authorization_for_committee,
};
use crate::dkg::v0::messages::{DkgMessage, SessionKind};
use crate::dkg::v0::session_state::RingPssClaimOutcome;
use crate::helpers::helpers::{extract_node_part, installed_versions_label, validate_all_peer_ids};
use crate::helpers::node_routes::{
    canonical_node_id_assignments_from_node_keys, node_id_to_peer_id_from_routes,
    peer_ids_from_routes, resolve_node_routes, NodeRoute,
};
use crate::metrics;
use crate::ring_state::{RingIndexEntry, RingShareBundle};
use bulletin::r#trait::RingPayload;
use crypto::r#trait::{Dkg, DkgRole};
use crypto::{GroupAffine, PolynomialCommitmentImpl, PubPolyImpl, ScalarField as Fr};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Spawn a background task that periodically checks rings for due PSS ceremonies.
///
/// `check_interval` controls how often the scheduler wakes up to inspect all known
/// rings.  Each ring's own `pss_interval` (from the bulletin `RingPayload`) determines
/// whether a refresh is actually triggered on that tick; reshare bypasses this check.
///
/// Setting `check_interval` to zero disables the scheduler entirely.
pub fn spawn_pss_scheduler<D>(app_state: Arc<AppState<D>>, check_interval: Duration)
where
    D: Dkg<
            ShareValue = Fr,
            PublicKey = GroupAffine,
            PolynomialCommitment = PolynomialCommitmentImpl,
            PubPoly = PubPolyImpl,
        > + Clone
        + Send
        + Sync
        + 'static,
{
    if check_interval.is_zero() {
        tracing::info!("PSS scheduler disabled (check_interval = 0)");
        return;
    }

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(check_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await; // skip the initial immediate tick at t=0
        loop {
            ticker.tick().await;
            tracing::debug!("PSS scheduler: tick");
            let _ = pss_all_rings(&app_state).await.inspect_err(|error| {
                tracing::error!(error = %error, "PSS scheduler: error");
            });
        }
    });
}

/// Iterate over every known ring and trigger a PSS ceremony when due.
async fn pss_all_rings<D>(app_state: &Arc<AppState<D>>) -> Result<(), DkgError>
where
    D: Dkg<
            ShareValue = Fr,
            PublicKey = GroupAffine,
            PolynomialCommitment = PolynomialCommitmentImpl,
            PubPoly = PubPolyImpl,
        > + Clone
        + Send
        + Sync
        + 'static,
{
    let ring_index = read_ring_index(&app_state.local_storage)?;
    if ring_index.is_empty() {
        tracing::debug!("PSS: ring index empty, nothing to check");
        return Ok(());
    }

    for entry in &ring_index {
        let _ = pss_ring(app_state, entry).await.inspect_err(|error| {
            tracing::error!(
                ring_pk_str = %entry.ring_pk_str,
                error = %error,
                "PSS: ceremony failed for ring"
            );
        });
    }
    Ok(())
}

/// Check one ring and dispatch to `trigger_reshare` or `trigger_refresh` as appropriate.
async fn pss_ring<D>(app_state: &Arc<AppState<D>>, entry: &RingIndexEntry) -> Result<(), DkgError>
where
    D: Dkg<
            ShareValue = Fr,
            PublicKey = GroupAffine,
            PolynomialCommitment = PolynomialCommitmentImpl,
            PubPoly = PubPolyImpl,
        > + Clone
        + Send
        + Sync
        + 'static,
{
    let post_id = &entry.bulletin_post_id;
    let ring_pk_str = &entry.ring_pk_str;

    let (ring_payload, protocol_routes) =
        crate::helpers::helpers::read_ring_for_protocol(&*app_state.bulletin, post_id)
            .await
            .map_err(DkgError::ProtocolError)?;

    if ring_payload.ring_pk.is_empty() {
        return cleanup_pending_fresh_ring_if_due(app_state, entry, &ring_payload);
    }

    if !ring_payload_matches_ring_key(ring_pk_str, &ring_payload.ring_pk) {
        return Err(DkgError::Storage(format!(
            "PSS: bulletin post ring_pk mismatch (expected={}, got={})",
            ring_pk_str, ring_payload.ring_pk
        )));
    }

    // Reshare takes priority over refresh when the bulletin signals a committee transition.
    let is_reshare =
        ring_payload.new_peer_node_keys.is_some() || ring_payload.new_threshold.is_some();

    // Refresh requires pss_interval to be present; reshare bypasses this check.
    if !is_reshare {
        match ring_payload.pss_interval {
            Some(_) => {}
            _ => {
                tracing::debug!(ring_pk_str = %ring_pk_str, "PSS: no pss_interval set, skipping");
                return Ok(());
            }
        }
    }

    if ring_payload.peer_node_keys.is_empty() {
        return Err(DkgError::InvalidInput(format!(
            "PSS: ring {} has an empty committee",
            ring_pk_str
        )));
    }

    if !ring_payload
        .peer_node_keys
        .iter()
        .any(|node_key| node_key == &app_state.node_key)
    {
        return Err(DkgError::Unauthorized(format!(
            "PSS: local node {} is not a current member of ring {}",
            app_state.node_key, ring_pk_str
        )));
    }

    let routes = resolve_node_routes(&app_state.bulletin, &ring_payload.peer_node_keys)
        .await
        .map_err(DkgError::InvalidInput)?;
    let peer_ids = peer_ids_from_routes(&routes);
    let node_id_assignments =
        canonical_node_id_assignments_from_node_keys(&ring_payload.peer_node_keys)
            .map_err(DkgError::InvalidInput)?;
    let node_id_to_peer_id = node_id_to_peer_id_from_routes(&routes, &node_id_assignments)
        .map_err(DkgError::InvalidInput)?;

    // Dispatch to the correct protocol implementation based on the ring's effective version.
    // Add a new arm here when a v1/ folder is introduced.
    match protocol_routes.version {
        0 => {
            if is_reshare {
                return trigger_reshare(
                    app_state,
                    entry,
                    &ring_payload,
                    &routes,
                    &node_id_assignments,
                    &node_id_to_peer_id,
                    protocol_routes,
                )
                .await;
            }

            // Refresh: also check that enough time has elapsed since the last ceremony.
            let pss_interval_secs = ring_payload.pss_interval.unwrap(); // safe: checked above
            let now_secs = current_unix_secs();
            let last_refresh_secs =
                RingShareBundle::load_by_ring_key(&app_state.local_storage, ring_pk_str)
                    .map(|b| b.last_pss)
                    .unwrap_or(0);
            let elapsed = now_secs.saturating_sub(last_refresh_secs);
            if elapsed + PSS_GRACE_PERIOD_SECS < pss_interval_secs {
                tracing::debug!(
                    post_id = %post_id,
                    elapsed_secs = elapsed,
                    pss_interval_secs = pss_interval_secs,
                    "PSS: refresh not yet due"
                );
                return Ok(());
            }

            trigger_refresh(
                app_state,
                entry,
                &ring_payload,
                &peer_ids,
                &node_id_assignments,
                &node_id_to_peer_id,
                protocol_routes,
            )
            .await
        }
        v => Err(DkgError::ProtocolError(format!(
            "ring {} requires unsupported protocol version {}; installed versions: {}",
            post_id,
            v,
            installed_versions_label()
        ))),
    }
}

fn cleanup_pending_fresh_ring_if_due<D>(
    app_state: &Arc<AppState<D>>,
    entry: &RingIndexEntry,
    ring_payload: &RingPayload,
) -> Result<(), DkgError>
where
    D: Dkg<
            ShareValue = Fr,
            PublicKey = GroupAffine,
            PolynomialCommitment = PolynomialCommitmentImpl,
            PubPoly = PubPolyImpl,
        > + Clone
        + Send
        + Sync
        + 'static,
{
    let post_id = &entry.bulletin_post_id;
    let ring_pk_str = &entry.ring_pk_str;
    let pss_interval_secs = match ring_payload.pss_interval {
        Some(interval) => interval,
        None => {
            tracing::debug!(
                ring_id = %post_id,
                ring_pk_str = %ring_pk_str,
                "PSS: pending fresh DKG ring has no pss_interval, skipping local cleanup"
            );
            return Ok(());
        }
    };

    let now_secs = current_unix_secs();
    let elapsed_secs = now_secs.saturating_sub(entry.indexed_at_secs);

    if elapsed_secs < pss_interval_secs {
        tracing::debug!(
            ring_id = %post_id,
            ring_pk_str = %ring_pk_str,
            elapsed_secs = elapsed_secs,
            pss_interval_secs = pss_interval_secs,
            "PSS: pending fresh DKG cleanup not yet due"
        );
        return Ok(());
    }

    // TODO(sourcehub): consider adding a chain tx to expire/delete pending rings on-chain.
    app_state
        .local_storage
        .delete(LocalStorageKeys::RingKey(ring_pk_str.clone()))
        .map_err(|e| {
            DkgError::Storage(format!(
                "PSS: failed to delete expired pending fresh DKG bundle: {}",
                e
            ))
        })?;
    remove_ring_index_entry(&app_state.local_storage, entry)?;

    tracing::warn!(
        ring_id = %post_id,
        ring_pk_str = %ring_pk_str,
        elapsed_secs = elapsed_secs,
        pss_interval_secs = pss_interval_secs,
        "PSS: cleaned up expired pending fresh DKG ring locally"
    );

    Ok(())
}

fn remove_ring_index_entry(
    storage: &impl LocalStorage,
    entry: &RingIndexEntry,
) -> Result<(), DkgError> {
    let mut ring_index = read_ring_index(storage)?;
    ring_index.retain(|candidate| {
        candidate.ring_pk_str != entry.ring_pk_str
            || candidate.bulletin_post_id != entry.bulletin_post_id
    });
    let bytes = serde_json::to_vec(&ring_index).map_err(|e| {
        DkgError::Serialization(format!("PSS: failed to serialize RingIndex: {}", e))
    })?;
    storage
        .set(LocalStorageKeys::RingIndex, bytes)
        .map_err(|e| {
            DkgError::Storage(format!(
                "PSS: failed to write RingIndex after pending cleanup: {}",
                e
            ))
        })
}

fn read_ring_index(storage: &impl LocalStorage) -> Result<Vec<RingIndexEntry>, DkgError> {
    storage
        .get(LocalStorageKeys::RingIndex)
        .map_err(|e| DkgError::Storage(format!("PSS: failed to read RingIndex: {}", e)))?
        .map(|bytes| {
            serde_json::from_slice(&bytes).map_err(|e| {
                DkgError::Storage(format!("PSS: failed to deserialize RingIndex: {}", e))
            })
        })
        .transpose()
        .map(|index| index.unwrap_or_default())
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Initiate a Refresh ceremony (same secret, new shares, same committee).
async fn trigger_refresh<D>(
    app_state: &Arc<AppState<D>>,
    entry: &RingIndexEntry,
    ring_payload: &RingPayload,
    peer_ids: &[String],
    node_id_assignments: &std::collections::HashMap<String, u32>,
    node_id_to_peer_id: &std::collections::HashMap<u32, String>,
    protocol_routes: &'static network::ProtocolRoutes,
) -> Result<(), DkgError>
where
    D: Dkg<
            ShareValue = Fr,
            PublicKey = GroupAffine,
            PolynomialCommitment = PolynomialCommitmentImpl,
            PubPoly = PubPolyImpl,
        > + Clone
        + Send
        + Sync
        + 'static,
{
    let post_id = &entry.bulletin_post_id;
    let ring_pk_str = &entry.ring_pk_str;
    let threshold = ring_payload.threshold as usize;
    let our_peer_id_hex = hex::encode(app_state.network.local_peer_id().as_bytes());
    let our_node_part = extract_node_part(&our_peer_id_hex);

    let our_node_id = *node_id_assignments
        .get(&app_state.node_key)
        .ok_or_else(|| DkgError::InvalidInput("PSS: our node key not in ring".to_string()))?;

    let total = peer_ids.len();

    validate_all_peer_ids(peer_ids).map_err(|(bad_peer, error)| {
        DkgError::InvalidInput(format!("PSS: invalid peer ID '{}': {}", bad_peer, error))
    })?;

    let bundle =
        RingShareBundle::load_by_ring_key(&app_state.local_storage, ring_pk_str).map_err(|e| {
            DkgError::Storage(format!("PSS: failed to load current ring bundle: {}", e))
        })?;
    let session_id = derive_refresh_session_id(
        ring_pk_str,
        &ring_payload.peer_node_keys,
        ring_payload.threshold,
        &bundle.public_polynomial,
    )?;

    match app_state
        .dkg_session_state
        .claim_ring_pss_session(ring_pk_str, session_id)
        .await
    {
        RingPssClaimOutcome::Claimed => {}
        RingPssClaimOutcome::AlreadyClaimedBySameSession => {
            tracing::debug!(
                post_id = %post_id,
                ring_pk_str = %ring_pk_str,
                session_id = session_id,
                "PSS: refresh session already active locally, skipping duplicate start"
            );
            return Ok(());
        }
        RingPssClaimOutcome::Conflict { active_session_id } => {
            tracing::warn!(
                post_id = %post_id,
                ring_pk_str = %ring_pk_str,
                session_id = session_id,
                active_session_id = active_session_id,
                "PSS: conflicting refresh session already active locally, skipping"
            );
            return Ok(());
        }
    }

    let coordinator = DkgCoordinator::with_routes(app_state.clone(), protocol_routes);

    match coordinator
        .create_session(
            session_id,
            our_node_id,
            threshold,
            total,
            DkgRole::Standard,
            {
                let ring_pk_str = ring_pk_str.clone();
                let pss_interval = ring_payload.pss_interval;
                move |state| {
                    state.kind = SessionKind::Refresh {
                        ring_pk_hex: ring_pk_str,
                    };
                    state.pss_interval = pss_interval;
                }
            },
        )
        .await
    {
        Ok(()) => {}
        Err(DkgError::SessionAlreadyExists) => {
            tracing::debug!(
                post_id = %post_id,
                ring_pk_str = %ring_pk_str,
                session_id = session_id,
                "PSS: refresh session already exists locally, skipping duplicate start"
            );
            app_state
                .dkg_session_state
                .unmark_ring_pss_if_matches(ring_pk_str, session_id)
                .await;
            return Ok(());
        }
        Err(e) => {
            tracing::error!(
                post_id = %post_id,
                ring_pk_str = %ring_pk_str,
                session_id = session_id,
                error = %e,
                "PSS: failed to create refresh DKG session locally"
            );
            app_state
                .dkg_session_state
                .unmark_ring_pss_if_matches(ring_pk_str, session_id)
                .await;
            return Err(e);
        }
    }

    metrics::record_refresh_session_started();

    coordinator
        .set_peer_ids(&session_id, peer_ids.to_vec())
        .await;
    app_state
        .dkg_session_state
        .set_peer_node_keys(&session_id, ring_payload.peer_node_keys.clone())
        .await;
    app_state
        .dkg_session_state
        .set_ring_id(&session_id, post_id.clone())
        .await;
    app_state
        .dkg_session_state
        .set_node_peer_mappings(&session_id, node_id_to_peer_id.clone())
        .await;

    let init_msg = DkgMessage::SessionInit {
        session_id,
        threshold: threshold as u32,
        total_participants: total as u32,
        peer_ids: peer_ids.to_vec(),
        peer_node_keys: ring_payload.peer_node_keys.clone(),
        node_id_assignments: node_id_assignments.clone(),
        token_string: String::new(),
        kind: SessionKind::Refresh {
            ring_pk_hex: ring_pk_str.clone(),
        },
        pss_interval: ring_payload.pss_interval,
        policy_id: None,
        ring_id: post_id.clone(),
    };

    for peer_id_str in peer_ids {
        if extract_node_part(peer_id_str) == our_node_part {
            continue;
        }
        if let Err(e) = coordinator
            .send_message_to_peer(peer_id_str, init_msg.clone(), Some(session_id))
            .await
        {
            tracing::error!(peer = %peer_id_str, error = %e, "PSS: failed to send refresh SessionInit, aborting");
            app_state
                .dkg_session_state
                .remove_session(&session_id)
                .await;
            metrics::record_refresh_session_failed();
            return Err(DkgError::NetworkConnection(format!(
                "PSS: failed to send refresh SessionInit to {}: {}",
                peer_id_str, e
            )));
        }
    }

    if let Err(e) = coordinator
        .initiate_phase1_commitments(session_id, peer_ids)
        .await
    {
        app_state
            .dkg_session_state
            .remove_session(&session_id)
            .await;
        metrics::record_refresh_session_failed();
        return Err(e);
    }

    tracing::info!(
        session_id = session_id,
        post_id = %post_id,
        "PSS: refresh session initiated"
    );

    Ok(())
}

/// Initiate a Reshare ceremony (same secret, new shares, potentially different committee).
///
/// Fires whenever the bulletin `RingPayload` has `new_peer_node_keys` or `new_threshold` set,
/// bypassing the `pss_interval` timing gate.  Repeats on every scheduler tick until
/// Phase 4 posts the updated payload clearing those fields.
async fn trigger_reshare<D>(
    app_state: &Arc<AppState<D>>,
    entry: &RingIndexEntry,
    ring_payload: &RingPayload,
    old_routes: &[NodeRoute],
    old_node_id_assignments: &std::collections::HashMap<String, u32>,
    old_node_id_to_peer_id: &std::collections::HashMap<u32, String>,
    protocol_routes: &'static network::ProtocolRoutes,
) -> Result<(), DkgError>
where
    D: Dkg<
            ShareValue = Fr,
            PublicKey = GroupAffine,
            PolynomialCommitment = PolynomialCommitmentImpl,
            PubPoly = PubPolyImpl,
        > + Clone
        + Send
        + Sync
        + 'static,
{
    let post_id = &entry.bulletin_post_id;
    let ring_pk_str = &entry.ring_pk_str;
    let our_peer_id_hex = hex::encode(app_state.network.local_peer_id().as_bytes());
    let our_node_part = extract_node_part(&our_peer_id_hex);
    let old_peer_node_keys = &ring_payload.peer_node_keys;
    let old_peer_ids = peer_ids_from_routes(old_routes);
    let old_threshold = ring_payload.threshold as usize;

    // Fallbacks: absent field = keep current value.
    let new_peer_node_keys: Vec<String> = ring_payload
        .new_peer_node_keys
        .clone()
        .unwrap_or_else(|| old_peer_node_keys.clone());
    let new_routes = resolve_node_routes(&app_state.bulletin, &new_peer_node_keys)
        .await
        .map_err(DkgError::InvalidInput)?;
    let new_route_peer_ids = peer_ids_from_routes(&new_routes);
    let new_threshold: u32 = ring_payload.new_threshold.unwrap_or(ring_payload.threshold);

    if new_peer_node_keys
        .iter()
        .any(|node_key| node_key == &app_state.node_key)
    {
        validate_dkg_node_authorization_for_committee(
            &app_state.bulletin,
            &app_state.node_key,
            &our_peer_id_hex,
            post_id,
            ring_payload,
            effective_new_peer_node_keys(ring_payload),
            "Reshare",
        )
        .await?;
    }

    let (our_node_id, dkg_role, reshare_params) = build_reshare_params(
        ring_pk_str,
        old_peer_node_keys,
        &new_peer_node_keys,
        new_threshold,
        post_id,
        &app_state.node_key,
        &app_state.local_storage,
    )?;

    // sorted_new is already sorted inside reshare_params.new_peer_node_keys.
    let sorted_new_peer_node_keys = reshare_params.new_peer_node_keys.clone();

    // Build union(old, new) — all peers that must receive SessionInit.
    let mut union_peers = old_peer_ids.clone();
    for p in &new_route_peer_ids {
        if !union_peers.contains(p) {
            union_peers.push(p.clone());
        }
    }

    // node_id_assignments covers the OLD committee (1-based sorted node-key index).
    let node_id_assignments = old_node_id_assignments.clone();

    let session_id = derive_reshare_session_id(
        ring_pk_str,
        post_id,
        old_peer_node_keys,
        &sorted_new_peer_node_keys,
        new_threshold,
    )?;
    let total_old = old_peer_node_keys.len();

    let kind = SessionKind::Reshare {
        ring_pk_hex: ring_pk_str.clone(),
        new_peer_node_keys: sorted_new_peer_node_keys.clone(),
        new_threshold,
        bulletin_post_id: post_id.clone(),
    };

    let coordinator = DkgCoordinator::with_routes(app_state.clone(), protocol_routes);

    validate_all_peer_ids(&union_peers).map_err(|(bad_peer, error)| {
        DkgError::InvalidInput(format!(
            "PSS reshare: invalid peer ID '{}': {}",
            bad_peer, error
        ))
    })?;

    match app_state
        .dkg_session_state
        .claim_ring_pss_session(ring_pk_str, session_id)
        .await
    {
        RingPssClaimOutcome::Claimed => {}
        RingPssClaimOutcome::AlreadyClaimedBySameSession => {
            tracing::debug!(
                post_id = %post_id,
                ring_pk_str = %ring_pk_str,
                session_id = session_id,
                "PSS: reshare session already active locally, skipping duplicate start"
            );
            return Ok(());
        }
        RingPssClaimOutcome::Conflict { active_session_id } => {
            tracing::warn!(
                post_id = %post_id,
                ring_pk_str = %ring_pk_str,
                session_id = session_id,
                active_session_id = active_session_id,
                "PSS: conflicting reshare session already active locally, skipping"
            );
            return Ok(());
        }
    }

    let kind_for_init = kind.clone();
    match coordinator
        .create_session(
            session_id,
            our_node_id,
            old_threshold,
            total_old,
            dkg_role,
            move |state| {
                state.kind = kind_for_init;
                state.reshare_params = Some(reshare_params);
            },
        )
        .await
    {
        Ok(()) => {}
        Err(DkgError::SessionAlreadyExists) => {
            tracing::debug!(
                post_id = %post_id,
                ring_pk_str = %ring_pk_str,
                session_id = session_id,
                "PSS: reshare session already exists locally, skipping duplicate start"
            );
            app_state
                .dkg_session_state
                .unmark_ring_pss_if_matches(ring_pk_str, session_id)
                .await;
            return Ok(());
        }
        Err(e) => {
            tracing::error!(
                post_id = %post_id,
                ring_pk_str = %ring_pk_str,
                session_id = session_id,
                error = %e,
                "PSS: failed to create reshare DKG session locally"
            );
            app_state
                .dkg_session_state
                .unmark_ring_pss_if_matches(ring_pk_str, session_id)
                .await;
            return Err(e);
        }
    }

    metrics::record_reshare_session_started();

    app_state
        .dkg_session_state
        .set_pss_interval(&session_id, ring_payload.pss_interval)
        .await;

    coordinator
        .set_peer_ids(&session_id, new_route_peer_ids.clone())
        .await;
    app_state
        .dkg_session_state
        .set_peer_node_keys(&session_id, new_peer_node_keys.clone())
        .await;
    app_state
        .dkg_session_state
        .set_ring_id(&session_id, post_id.clone())
        .await;

    // Store old-committee node_id → peer_id mappings for sender validation.
    app_state
        .dkg_session_state
        .set_node_peer_mappings(&session_id, old_node_id_to_peer_id.clone())
        .await;

    let new_node_id_assignments = canonical_node_id_assignments_from_node_keys(&new_peer_node_keys)
        .map_err(DkgError::InvalidInput)?;
    let new_node_id_to_peer_id =
        node_id_to_peer_id_from_routes(&new_routes, &new_node_id_assignments)
            .map_err(DkgError::InvalidInput)?;
    app_state
        .dkg_session_state
        .set_reshare_new_peer_mappings(&session_id, new_node_id_to_peer_id)
        .await;

    let init_msg = DkgMessage::SessionInit {
        session_id,
        threshold: old_threshold as u32,
        total_participants: total_old as u32,
        peer_ids: old_peer_ids.clone(),
        peer_node_keys: old_peer_node_keys.clone(),
        node_id_assignments,
        token_string: String::new(),
        kind,
        pss_interval: ring_payload.pss_interval,
        policy_id: None,
        ring_id: post_id.clone(),
    };

    for peer_id_str in &union_peers {
        if extract_node_part(peer_id_str) == our_node_part {
            continue;
        }
        let _ = coordinator
            .send_message_to_peer(peer_id_str, init_msg.clone(), Some(session_id))
            .await
            .inspect_err(|error| {
                tracing::warn!(
                    peer = %peer_id_str,
                    error = %error,
                    "PSS: failed to send reshare SessionInit; continuing until threshold selection or timeout"
                );
            });
    }

    if let Err(e) = coordinator
        .initiate_phase1_commitments(session_id, &new_route_peer_ids)
        .await
    {
        app_state
            .dkg_session_state
            .remove_session(&session_id)
            .await;
        metrics::record_reshare_session_failed();
        return Err(e);
    }

    tracing::info!(
        session_id = session_id,
        post_id = %post_id,
        "PSS: reshare session initiated"
    );

    Ok(())
}
