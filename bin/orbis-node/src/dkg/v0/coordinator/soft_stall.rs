//! Drains Fresh DKG soft-stall events and performs the actual early abort.
//!
//! `SessionStateManager::expiration_worker`'s soft-stall scan only has access to the
//! session-state maps, so it can detect a stalled attempt but not broadcast `Abort` or reach the
//! bulletin. This module is the other half: the drain worker that does the real work with full
//! `AppState` access, mirroring `coordinator::reporting::spawn_pss_stall_reporter`'s shape.
//!
//! Deliberately kept separate from `reporting.rs`: this is a client-facing diagnostic only, never
//! wired into the on-chain `node_offline`/reputation reporting pipeline that module owns.

use crate::app_state::AppState;
use crate::dkg::v0::network::broadcast_attempt_abort;
use crate::dkg::v0::session_state::{
    AttemptStateError, DkgPhase, FailedDkgSessionRecord, SoftStalledDkgAttempt,
    TopicTaskDisposition,
};
use crate::dkg::v0::transport::{AttemptKey, CeremonyId};
use crypto::SignImpl;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::types::{CoordinatorDkg, CoordinatorReportSigner};

pub(crate) struct DkgSoftStallWorkerHandle {
    task: JoinHandle<()>,
}

impl DkgSoftStallWorkerHandle {
    pub(crate) async fn shutdown(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

/// Drain [`SoftStalledDkgAttempt`] events (published by the leader-only soft-stall scan in
/// `SessionStateManager::expiration_worker`) and, for each, abort the stalled Fresh DKG attempt
/// early and record a client-facing [`FailedDkgSessionRecord`] — instead of leaving the client
/// waiting out the full `DKG_ATTEMPT_TIMEOUT` to learn anything.
pub(crate) fn spawn_dkg_soft_stall_worker<D>(
    app_state: Arc<AppState<D>>,
    mut rx: mpsc::Receiver<SoftStalledDkgAttempt>,
) -> DkgSoftStallWorkerHandle
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let task = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            handle_soft_stalled_dkg_attempt(&app_state, event).await;
        }
        tracing::debug!("DKG soft-stall worker: channel closed, worker shutting down");
    });
    DkgSoftStallWorkerHandle { task }
}

async fn handle_soft_stalled_dkg_attempt<D>(
    app_state: &Arc<AppState<D>>,
    event: SoftStalledDkgAttempt,
) where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let Some(routes) = network::routes_for_version(event.protocol_version) else {
        tracing::warn!(
            protocol_version = event.protocol_version,
            session_id = %event.session_id,
            "DKG soft-stall worker: no protocol routes for version; dropping early-abort event"
        );
        return;
    };
    let attempt = AttemptKey::new(CeremonyId(event.session_id), event.attempt_id);
    // Re-check under lock: the session may have completed or already been torn down (e.g. hit
    // the hard deadline) between the detection tick queuing this event and this worker
    // processing it. Either outcome makes this event a no-op, not an error.
    let (participant_routes, phase) = match app_state
        .dkg_session_state
        .with_attempt_state(attempt, |state| {
            (state.transport.participant_routes.clone(), state.phase)
        })
        .await
    {
        Ok(result) => result,
        Err(AttemptStateError::MissingSession) | Err(AttemptStateError::StaleAttempt) => return,
    };
    // The stalled peer may have delivered just as this event was being drained — e.g. the
    // attempt has already moved into (or finished) Phase4's durable completion side effects.
    // Aborting a legitimately-completing attempt here would be far worse than a missed early
    // abort; let it finish and don't record a failure for it.
    if matches!(phase, DkgPhase::Phase4Completing | DkgPhase::Phase4Complete) {
        return;
    }

    app_state
        .dkg_session_state
        .record_failed_session(FailedDkgSessionRecord {
            session_id: event.session_id,
            ring_id: event.ring_id,
            attempt_id: Some(event.attempt_id),
            stage: event.stage,
            missing: event.missing,
            reason:
                "soft-stall: repair/private-exchange retries against the listed peers kept failing"
                    .to_string(),
            failed_at: SystemTime::now(),
        })
        .await;

    broadcast_attempt_abort(
        app_state,
        routes,
        participant_routes,
        CeremonyId(event.session_id),
        event.attempt_id,
        "leader detected soft stall".to_string(),
    )
    .await;

    app_state
        .dkg_session_state
        .abort_transport_attempt(attempt, TopicTaskDisposition::Abort)
        .await;
}
