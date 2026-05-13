//! PSS (Proactive Secret Sharing) — automatic refresh and reshare scheduler
//!
//! Periodically checks every known ring and initiates a PSS ceremony when due.
//!
//! ## Refresh
//! When the bulletin `RingPayload` has no `new_peer_ids` or `new_threshold`, a
//! **refresh** ceremony runs once the ring's `pss_interval` has elapsed since the
//! last ceremony.  Same secret, new shares, same committee (zero constant term).
//!
//! ## Reshare
//! When the bulletin `RingPayload` carries `new_peer_ids` or `new_threshold` the ring
//! has been designated for committee rotation.  The scheduler bypasses the interval
//! check and immediately initiates a **reshare** (`SessionKind::Reshare`).
//! Fallback rules (agreed on construction):
//! - `new_peer_ids` absent → use current `peer_ids` (same committee, threshold change only).
//! - `new_threshold` absent → use current `threshold` (committee change only).
//!
//! Phase 4 posts the updated `RingPayload` with `new_peer_ids = None` so subsequent
//! ticks revert to the normal refresh cadence.
//!
//! In both cases any current old-committee node may attempt to start the ceremony.
//! Concurrent starters converge because they derive the same deterministic session ID
//! from the ring's current public polynomial and the authoritative transition data.
//!
//! Rings with `pss_interval = None` are skipped for refresh (reshare is unaffected).

#[cfg(test)]
mod tests;

use crate::app_state::AppState;
use crate::constants::PSS_GRACE_PERIOD_SECS;
use crate::dkg::coordinator::DkgCoordinator;
use crate::dkg::error::DkgError;
use crate::dkg::helpers::{
    build_reshare_params, derive_refresh_session_id, derive_reshare_session_id,
    ring_payload_matches_ring_key,
};
use crate::dkg::messages::{DkgMessage, SessionKind};
use crate::dkg::session_state::RingPssClaimOutcome;
use crate::helpers::helpers::{extract_node_part, validate_all_peer_ids};
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
            if let Err(e) = pss_all_rings(&app_state).await {
                tracing::error!(error = %e, "PSS scheduler: error");
            }
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
    let ring_index: Vec<RingIndexEntry> =
        match app_state.local_storage.get(LocalStorageKeys::RingIndex) {
            Ok(Some(bytes)) => serde_json::from_slice(&bytes).unwrap_or_default(),
            _ => {
                tracing::debug!("PSS: ring index empty, nothing to check");
                return Ok(());
            }
        };

    for entry in &ring_index {
        if let Err(e) = pss_ring(app_state, entry).await {
            tracing::error!(ring_pk_str = %entry.ring_pk_str, error = %e, "PSS: ceremony failed for ring");
        }
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

    let bulletin_post = app_state
        .bulletin
        .read(entry.bulletin_namespace.clone(), post_id.to_string())
        .await
        .map_err(|e| {
            DkgError::Storage(format!(
                "PSS: failed to read RingPayload from bulletin (post_id={}): {}",
                post_id, e
            ))
        })?;

    let ring_payload: RingPayload = serde_json::from_slice(&bulletin_post.payload)
        .map_err(|e| DkgError::Deserialization(format!("PSS: bad ring payload: {}", e)))?;

    if !ring_payload_matches_ring_key(ring_pk_str, &ring_payload.ring_pk) {
        return Err(DkgError::Storage(format!(
            "PSS: bulletin post ring_pk mismatch (expected={}, got={})",
            ring_pk_str, ring_payload.ring_pk
        )));
    }

    // Reshare takes priority over refresh when the bulletin signals a committee transition.
    let is_reshare = ring_payload.new_peer_ids.is_some() || ring_payload.new_threshold.is_some();

    // Refresh requires pss_interval to be set; reshare bypasses this check.
    if !is_reshare {
        match ring_payload.pss_interval {
            Some(v) if v > 0 => {}
            _ => {
                tracing::debug!(ring_pk_str = %ring_pk_str, "PSS: no pss_interval set, skipping");
                return Ok(());
            }
        }
    }

    let our_peer_id_hex = hex::encode(app_state.network.local_peer_id().as_bytes());
    let our_node_part = extract_node_part(&our_peer_id_hex);

    if ring_payload.peer_ids.is_empty() {
        return Err(DkgError::InvalidInput(format!(
            "PSS: ring {} has an empty committee",
            ring_pk_str
        )));
    }

    let mut sorted_peers = ring_payload.peer_ids.clone();
    sorted_peers.sort();

    if !ring_payload
        .peer_ids
        .iter()
        .any(|peer_id| extract_node_part(peer_id) == our_node_part)
    {
        return Err(DkgError::Unauthorized(format!(
            "PSS: local node {} is not a current member of ring {}",
            our_node_part, ring_pk_str
        )));
    }

    if is_reshare {
        return trigger_reshare(app_state, entry, &ring_payload).await;
    }

    // Refresh: also check that enough time has elapsed since the last ceremony.
    let pss_interval_secs = ring_payload.pss_interval.unwrap(); // safe: checked above
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
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
        &sorted_peers,
        &our_node_part,
    )
    .await
}

/// Initiate a Refresh ceremony (same secret, new shares, same committee).
async fn trigger_refresh<D>(
    app_state: &Arc<AppState<D>>,
    entry: &RingIndexEntry,
    ring_payload: &RingPayload,
    sorted_peers: &[String],
    our_node_part: &str,
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
    let peer_ids = &ring_payload.peer_ids;
    let threshold = ring_payload.threshold as usize;

    // Build deterministic node_id assignments (sorted peer list → 1-indexed).
    let mut node_id_assignments: std::collections::HashMap<String, u32> =
        std::collections::HashMap::new();
    for (idx, peer_id) in sorted_peers.iter().enumerate() {
        node_id_assignments.insert(extract_node_part(peer_id), (idx + 1) as u32);
    }

    let our_node_id = *node_id_assignments
        .get(our_node_part)
        .ok_or_else(|| DkgError::InvalidInput("PSS: our peer not in ring".to_string()))?;

    let total = peer_ids.len();

    if let Err((bad_peer, err)) = validate_all_peer_ids(peer_ids) {
        return Err(DkgError::InvalidInput(format!(
            "PSS: invalid peer ID '{}': {}",
            bad_peer, err
        )));
    }

    let bundle =
        RingShareBundle::load_by_ring_key(&app_state.local_storage, ring_pk_str).map_err(|e| {
            DkgError::Storage(format!("PSS: failed to load current ring bundle: {}", e))
        })?;
    let session_id = derive_refresh_session_id(
        ring_pk_str,
        peer_ids,
        ring_payload.threshold,
        &bundle.public_polynomial,
    );

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

    let coordinator = DkgCoordinator::new(app_state.clone());

    match coordinator
        .create_session(
            session_id,
            our_node_id,
            threshold,
            total,
            DkgRole::Standard,
            |_| {},
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

    app_state
        .dkg_session_state
        .set_session_kind(
            &session_id,
            SessionKind::Refresh {
                ring_pk_hex: ring_pk_str.clone(),
            },
        )
        .await;
    app_state
        .dkg_session_state
        .set_pss_interval(&session_id, ring_payload.pss_interval)
        .await;
    app_state
        .dkg_session_state
        .set_namespace(&session_id, entry.bulletin_namespace.clone())
        .await;

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

    let init_msg = DkgMessage::SessionInit {
        session_id,
        threshold: threshold as u32,
        total_participants: total as u32,
        peer_ids: peer_ids.clone(),
        node_id_assignments,
        token_string: String::new(),
        kind: SessionKind::Refresh {
            ring_pk_hex: ring_pk_str.clone(),
        },
        pss_interval: ring_payload.pss_interval,
        namespace: entry.bulletin_namespace.clone(),
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
/// Fires whenever the bulletin `RingPayload` has `new_peer_ids` or `new_threshold` set,
/// bypassing the `pss_interval` timing gate.  Repeats on every scheduler tick until
/// Phase 4 posts the updated payload clearing those fields.
async fn trigger_reshare<D>(
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
    let old_peer_ids = &ring_payload.peer_ids;
    let old_threshold = ring_payload.threshold as usize;

    // Fallbacks: absent field = keep current value.
    let new_peer_ids: Vec<String> = ring_payload
        .new_peer_ids
        .clone()
        .unwrap_or_else(|| old_peer_ids.clone());
    let new_threshold: u32 = ring_payload.new_threshold.unwrap_or(ring_payload.threshold);

    let our_peer_id_hex = hex::encode(app_state.network.local_peer_id().as_bytes());
    let our_node_part = extract_node_part(&our_peer_id_hex);

    let (our_node_id, dkg_role, reshare_params) = match build_reshare_params(
        ring_pk_str,
        old_peer_ids,
        &new_peer_ids,
        new_threshold,
        post_id,
        &our_node_part,
        &app_state.local_storage,
    ) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    let bundle =
        RingShareBundle::load_by_ring_key(&app_state.local_storage, ring_pk_str).map_err(|e| {
            DkgError::Storage(format!("PSS: failed to load current ring bundle: {}", e))
        })?;

    // sorted_new is already sorted inside reshare_params.new_peer_ids.
    let sorted_new = reshare_params.new_peer_ids.clone();

    // Build union(old, new) — all peers that must receive SessionInit.
    let mut union_peers = old_peer_ids.clone();
    for p in &sorted_new {
        if !union_peers.contains(p) {
            union_peers.push(p.clone());
        }
    }

    // node_id_assignments covers the OLD committee (1-based sorted index).
    let mut sorted_old = old_peer_ids.clone();
    sorted_old.sort();
    let mut node_id_assignments: std::collections::HashMap<String, u32> =
        std::collections::HashMap::new();
    for (idx, peer_id) in sorted_old.iter().enumerate() {
        node_id_assignments.insert(extract_node_part(peer_id), (idx + 1) as u32);
    }

    let session_id = derive_reshare_session_id(
        ring_pk_str,
        post_id,
        old_peer_ids,
        &sorted_new,
        new_threshold,
        &bundle.public_polynomial,
    );
    let total_old = old_peer_ids.len();

    let kind = SessionKind::Reshare {
        ring_pk_hex: ring_pk_str.clone(),
        new_peer_ids: sorted_new.clone(),
        new_threshold,
        bulletin_post_id: post_id.clone(),
    };

    let coordinator = DkgCoordinator::new(app_state.clone());

    if let Err((bad_peer, err)) = validate_all_peer_ids(&union_peers) {
        return Err(DkgError::InvalidInput(format!(
            "PSS reshare: invalid peer ID '{}': {}",
            bad_peer, err
        )));
    }

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
    app_state
        .dkg_session_state
        .set_namespace(&session_id, entry.bulletin_namespace.clone())
        .await;

    coordinator
        .set_peer_ids(&session_id, sorted_new.clone())
        .await;

    // Store old-committee node_id → peer_id mappings for sender validation.
    let mut node_id_to_peer_id = std::collections::HashMap::new();
    for (peer_key, node_id) in &node_id_assignments {
        let full_peer_id = old_peer_ids
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

    let new_node_id_to_peer_id = sorted_new
        .iter()
        .enumerate()
        .map(|(idx, peer_id)| ((idx + 1) as u32, peer_id.clone()))
        .collect();
    app_state
        .dkg_session_state
        .set_reshare_new_peer_mappings(&session_id, new_node_id_to_peer_id)
        .await;

    let init_msg = DkgMessage::SessionInit {
        session_id,
        threshold: old_threshold as u32,
        total_participants: total_old as u32,
        peer_ids: old_peer_ids.clone(),
        node_id_assignments,
        token_string: String::new(),
        kind,
        pss_interval: ring_payload.pss_interval,
        namespace: entry.bulletin_namespace.clone(),
    };

    for peer_id_str in &union_peers {
        if extract_node_part(peer_id_str) == our_node_part {
            continue;
        }
        if let Err(e) = coordinator
            .send_message_to_peer(peer_id_str, init_msg.clone(), Some(session_id))
            .await
        {
            tracing::warn!(
                peer = %peer_id_str,
                error = %e,
                "PSS: failed to send reshare SessionInit; continuing until threshold selection or timeout"
            );
        }
    }

    if let Err(e) = coordinator
        .initiate_phase1_commitments(session_id, &sorted_new)
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
