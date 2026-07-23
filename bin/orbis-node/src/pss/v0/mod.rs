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
//! Reshare: every current member may forward a pending reshare to the lowest
//! canonical next-committee signing key. The receiver leader authenticates the
//! forwarder, rereads SourceHub, and creates the attempt. There is
//! intentionally no receiver-leader failover for reshare in protocol v0,
//! because every next-committee receiver is required regardless of who
//! triggers the attempt.
//!
//! Refresh: every current member walks the committee in a fixed deterministic
//! order (lowest node key first) once refresh is due, asking each candidate
//! in turn to lead with a short single-shot request; a candidate that doesn't
//! respond in time is skipped in favor of the next. Whichever committee
//! member actually answers becomes the ceremony leader and owns the gossip
//! topic. This gives refresh real availability against a down or partitioned
//! canonical leader without waiting on the (much slower) health-check/kick
//! pipeline.
//!
//! All rings carry a `pss_interval` (seconds); `0` means immediately due.
//! Reshare is always triggered regardless of elapsed time.

#[cfg(test)]
mod tests;

use crate::app_state::AppState;
use crate::constants::PSS_GRACE_PERIOD_SECS;
use crate::dkg::v0::error::DkgError;
use crate::dkg::v0::helpers::ring_payload_matches_ring_key;
use crate::helpers::auth::current_unix_time;
use crate::helpers::protocol_version::{installed_versions_label, resolve_ring_protocol_decision};
use crate::ring_state::{RingIndexEntry, RingShareBundle};
use bulletin::error::BulletinError;
use bulletin::r#trait::{BulletinKind, BulletinWriteKind, RingCancellationPayload, RingPayload};
use crypto::r#trait::Dkg;
use crypto::{GroupAffine, PolynomialCommitmentImpl, PubPolyImpl, ScalarField as Fr};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

pub struct PssSchedulerHandle {
    shutdown_tx: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl PssSchedulerHandle {
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
        let _ = self.task.await;
    }
}

/// Spawn a background task that periodically checks rings for due PSS ceremonies.
///
/// `check_interval` controls how often the scheduler wakes up to inspect all known
/// rings.  Each ring's own `pss_interval` (from the bulletin `RingPayload`) determines
/// whether a refresh is actually triggered on that tick; reshare bypasses this check.
///
/// Setting `check_interval` to zero disables the scheduler entirely.
pub fn spawn_pss_scheduler<D>(
    app_state: Arc<AppState<D>>,
    check_interval: Duration,
) -> Option<PssSchedulerHandle>
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
        return None;
    }

    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(check_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await; // skip the initial immediate tick at t=0
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    tracing::debug!("PSS scheduler: shutdown requested");
                    break;
                }
                _ = ticker.tick() => {
                    tracing::debug!("PSS scheduler: tick");
                    let _ = pss_all_rings(&app_state).await.inspect_err(|error| {
                        tracing::error!(error = %error, "PSS scheduler: error");
                    });
                }
            }
        }
    });
    Some(PssSchedulerHandle { shutdown_tx, task })
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

    let ring_post = match app_state
        .bulletin
        .read(post_id.clone(), BulletinKind::Ring)
        .await
    {
        Ok(post) => post,
        Err(BulletinError::NotFound { .. }) => {
            return cleanup_missing_pending_ring(app_state, entry).await;
        }
        Err(error) => {
            return Err(DkgError::ProtocolError(format!(
                "failed to read protocol state for ring {}: {}",
                post_id, error
            )));
        }
    };
    let ring_payload = RingPayload::try_from(ring_post).map_err(|error| {
        DkgError::ProtocolError(format!(
            "malformed ring payload for ring {}: {}",
            post_id, error
        ))
    })?;
    let (protocol_routes, _, _) =
        resolve_ring_protocol_decision(post_id, &ring_payload).map_err(DkgError::ProtocolError)?;

    if ring_payload.ring_pk.is_empty() {
        return cleanup_pending_fresh_ring_if_due(app_state, entry, &ring_payload).await;
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
        if !is_reshare {
            return reconcile_finalized_removed_member(app_state, entry).await;
        }
        return Err(DkgError::Unauthorized(format!(
            "PSS: local node {} is not a current member of ring {}",
            app_state.node_key, ring_pk_str
        )));
    }

    // Dispatch to the correct protocol implementation based on the ring's effective version.
    // Add a new arm here when a v1/ folder is introduced.
    match protocol_routes.version {
        0 => {
            if is_reshare {
                return match crate::dkg::v0::network::start_reshare(
                    app_state.clone(),
                    protocol_routes,
                    entry.bulletin_post_id.clone(),
                    entry.ring_pk_str.clone(),
                )
                .await?
                {
                    crate::dkg::v0::network::ReshareStartOutcome::Started(
                        ceremony_id,
                        attempt_id,
                    ) => {
                        tracing::info!(
                            session_id = ceremony_id.0,
                            attempt_id = %hex::encode(attempt_id.0),
                            ring_id = %entry.bulletin_post_id,
                            "PSS: reshare session initiated by canonical leader"
                        );
                        Ok(())
                    }
                    crate::dkg::v0::network::ReshareStartOutcome::AlreadyActive(
                        ceremony_id,
                        attempt_id,
                    ) => {
                        tracing::debug!(
                            session_id = ceremony_id.0,
                            attempt_id = %hex::encode(attempt_id.0),
                            "PSS: canonical reshare attempt remains active"
                        );
                        Ok(())
                    }
                    crate::dkg::v0::network::ReshareStartOutcome::Forwarded(
                        ceremony_id,
                        attempt_id,
                    ) => {
                        tracing::info!(
                            session_id = ceremony_id.0,
                            attempt_id = %hex::encode(attempt_id.0),
                            ring_id = %entry.bulletin_post_id,
                            "PSS: reshare start accepted by canonical next-committee leader"
                        );
                        Ok(())
                    }
                };
            }

            // Refresh: also check that enough time has elapsed since the last ceremony.
            let pss_interval_secs = ring_payload.pss_interval;
            let now_secs = current_unix_time().map_err(DkgError::SystemTime)?;
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
                protocol_routes,
                elapsed.saturating_sub(pss_interval_secs.saturating_sub(PSS_GRACE_PERIOD_SECS)),
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

async fn reconcile_finalized_removed_member<D>(
    app_state: &Arc<AppState<D>>,
    entry: &RingIndexEntry,
) -> Result<(), DkgError>
where
    D: Dkg + Clone + 'static,
{
    let _guard = app_state.ring_index_lock.lock().await;
    app_state
        .local_storage
        .delete(LocalStorageKeys::RingKey(entry.ring_pk_str.clone()))
        .map_err(|error| {
            DkgError::Storage(format!(
                "PSS: failed to securely remove stale finalized ring bundle: {error}"
            ))
        })?;
    remove_ring_index_entry(&app_state.local_storage, entry)?;
    tracing::info!(
        ring_id = %entry.bulletin_post_id,
        ring_pk = %entry.ring_pk_str,
        "PSS: reconciled stale local material after finalized committee removal"
    );
    Ok(())
}

async fn cleanup_pending_fresh_ring_if_due<D>(
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
    let pss_interval_secs = ring_payload.pss_interval;

    let now_secs = current_unix_time().map_err(DkgError::SystemTime)?;
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

    let has_local_bundle = app_state
        .local_storage
        .contains(LocalStorageKeys::RingKey(ring_pk_str.clone()))
        .map_err(|e| {
            DkgError::Storage(format!(
                "PSS: failed to check pending fresh DKG bundle: {}",
                e
            ))
        })?;

    if has_local_bundle {
        tracing::warn!(
            ring_id = %post_id,
            ring_pk_str = %ring_pk_str,
            elapsed_secs = elapsed_secs,
            pss_interval_secs = pss_interval_secs,
            "PSS: pending fresh DKG has a local share bundle; preserving state while bulletin finalization is pending"
        );
        return Ok(());
    }

    let payload = RingCancellationPayload {
        ring_id: post_id.clone(),
    };
    let payload_bytes: Vec<u8> = payload.try_into().map_err(|error| {
        DkgError::Serialization(format!(
            "PSS: failed to serialize pending ring cancellation: {}",
            error
        ))
    })?;
    let _ = app_state
        .bulletin
        .post(BulletinWriteKind::CancelPendingRing, payload_bytes)
        .await
        .inspect_err(|error| {
            tracing::warn!(
                ring_id = %post_id,
                ring_pk_str = %ring_pk_str,
                elapsed_secs = elapsed_secs,
                pss_interval_secs = pss_interval_secs,
                error = %error,
                "PSS: failed to cancel stale pending fresh DKG on bulletin; continuing local cleanup"
            );
        });

    tracing::warn!(
        ring_id = %post_id,
        ring_pk_str = %ring_pk_str,
        elapsed_secs = elapsed_secs,
        pss_interval_secs = pss_interval_secs,
        "PSS: cancelled stale pending fresh DKG on bulletin"
    );

    let _guard = app_state.ring_index_lock.lock().await;
    remove_ring_index_entry(&app_state.local_storage, entry)?;

    tracing::warn!(
        ring_id = %post_id,
        ring_pk_str = %ring_pk_str,
        elapsed_secs = elapsed_secs,
        pss_interval_secs = pss_interval_secs,
        "PSS: cleaned up dangling pending fresh DKG index entry"
    );

    Ok(())
}

async fn cleanup_missing_pending_ring<D>(
    app_state: &Arc<AppState<D>>,
    entry: &RingIndexEntry,
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
    let has_local_bundle = app_state
        .local_storage
        .contains(LocalStorageKeys::RingKey(entry.ring_pk_str.clone()))
        .map_err(|error| {
            DkgError::Storage(format!(
                "PSS: failed to check bundle for missing bulletin ring: {}",
                error
            ))
        })?;
    if has_local_bundle {
        tracing::warn!(
            ring_id = %entry.bulletin_post_id,
            ring_pk_str = %entry.ring_pk_str,
            "PSS: bulletin ring is missing but a local share bundle exists; preserving local state"
        );
        return Ok(());
    }

    let _guard = app_state.ring_index_lock.lock().await;
    remove_ring_index_entry(&app_state.local_storage, entry)?;
    tracing::warn!(
        ring_id = %entry.bulletin_post_id,
        ring_pk_str = %entry.ring_pk_str,
        "PSS: removed dangling local index for a ring already missing from the bulletin"
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

/// Initiate a Refresh ceremony (same secret, new shares, same committee).
async fn trigger_refresh<D>(
    app_state: &Arc<AppState<D>>,
    entry: &RingIndexEntry,
    ring_payload: &RingPayload,
    protocol_routes: &'static network::ProtocolRoutes,
    scheduler_delay_secs: u64,
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
    let outcome = crate::dkg::v0::network::start_refresh(
        app_state.clone(),
        protocol_routes,
        entry.bulletin_post_id.clone(),
        entry.ring_pk_str.clone(),
    )
    .await?;
    let (ceremony_id, attempt_id) = match outcome {
        crate::dkg::v0::network::RefreshStartOutcome::Started(ceremony_id, attempt_id) => {
            (ceremony_id, attempt_id)
        }
        crate::dkg::v0::network::RefreshStartOutcome::AlreadyActive(ceremony_id, attempt_id) => {
            tracing::debug!(
                session_id = ceremony_id.0,
                attempt_id = %hex::encode(attempt_id.0),
                ring_id = %entry.bulletin_post_id,
                "PSS: canonical refresh attempt remains active"
            );
            return Ok(());
        }
        crate::dkg::v0::network::RefreshStartOutcome::NotDue => {
            tracing::debug!(
                ring_id = %entry.bulletin_post_id,
                "PSS: refresh became not due while scheduler state was being resolved"
            );
            return Ok(());
        }
        crate::dkg::v0::network::RefreshStartOutcome::Forwarded(ceremony_id, attempt_id) => {
            tracing::info!(
                session_id = ceremony_id.0,
                attempt_id = %hex::encode(attempt_id.0),
                ring_id = %entry.bulletin_post_id,
                "PSS: refresh start accepted by a reachable committee peer"
            );
            return Ok(());
        }
    };
    crate::metrics::record_pss_scheduler_delay(scheduler_delay_secs as f64);
    tracing::info!(
        session_id = ceremony_id.0,
        attempt_id = %hex::encode(attempt_id.0),
        ring_id = %entry.bulletin_post_id,
        threshold = ring_payload.threshold,
        "PSS: refresh session initiated locally"
    );
    Ok(())
}
