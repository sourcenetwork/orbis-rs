use crate::app_state::AppState;
use crate::dkg::v0::error::{DkgError, Result};
use crate::dkg::v0::messages::SessionKind;
use crate::dkg::v0::session_state::AbandonedPssSession;
use crate::helpers::identity::extract_node_part;
use crate::helpers::node_routes::{peer_ids_from_routes, resolve_node_routes};
use crate::reporting::v0::observation::{offline_observation_from_peer_routes, ReportObservation};
use crate::reporting::v0::queue_report;
use crate::reporting::v0::types::CommitteeScope as ReportCommitteeScope;
use crate::ring_state::RingPolyState;
use bulletin::r#trait::{BulletinKind, RingPayload};
use crypto::r#trait::Dkg;
use crypto::{
    GroupAffine as G1Affine, PolynomialCommitmentImpl as PolynomialCommitment,
    PubPolyImpl as PubPoly, ScalarField as Fr, SignImpl,
};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::types::CoordinatorReportSigner;

pub(crate) async fn queue_pss_offline_report_task<D>(
    app_state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    peer_id: String,
    kind: SessionKind,
    stored_ring_id: String,
    session_id: String,
) -> Result<()>
where
    D: Dkg<
            ShareValue = Fr,
            PublicKey = G1Affine,
            PolynomialCommitment = PolynomialCommitment,
            PubPoly = PubPoly,
        > + Clone
        + Send
        + Sync
        + 'static,
    SignImpl: CoordinatorReportSigner<D>,
{
    let is_reshare = matches!(kind, SessionKind::Reshare { .. });
    let (origin_protocol, ring_id) = match &kind {
        SessionKind::Fresh => return Ok(()),
        SessionKind::Refresh { .. } => ("pss_refresh", stored_ring_id),
        SessionKind::Reshare {
            bulletin_post_id, ..
        } => (
            "pss_reshare",
            if stored_ring_id.is_empty() {
                bulletin_post_id.clone()
            } else {
                stored_ring_id
            },
        ),
    };
    if ring_id.is_empty() {
        tracing::debug!(
            peer_id = %peer_id,
            "Skipping PSS offline report because session has no authoritative ring ID"
        );
        return Ok(());
    }

    let ring_post = app_state
        .bulletin
        .read(ring_id.clone(), BulletinKind::Ring)
        .await
        .map_err(|error| {
            DkgError::Bulletin(format!(
                "failed to read ring {ring_id} while queueing PSS offline report: {error}"
            ))
        })?;
    let ring = RingPayload::try_from(ring_post).map_err(|error| {
        DkgError::Deserialization(format!(
            "failed to parse ring {ring_id} while queueing PSS offline report: {error}"
        ))
    })?;

    let current_routes = resolve_node_routes(&app_state.bulletin, &ring.peer_node_keys)
        .await
        .map_err(|error| {
            DkgError::InvalidState(format!(
                "failed to resolve current committee routes for ring {ring_id}: {error}"
            ))
        })?;
    let current_peer_ids = peer_ids_from_routes(&current_routes);

    let pending_node_keys = ring
        .new_peer_node_keys
        .clone()
        .unwrap_or_else(|| ring.peer_node_keys.clone());
    let pending_peer_ids = if is_reshare {
        let pending_routes = resolve_node_routes(&app_state.bulletin, &pending_node_keys)
            .await
            .map_err(|error| {
                DkgError::InvalidState(format!(
                    "failed to resolve pending-new committee routes for ring {ring_id}: {error}"
                ))
            })?;
        peer_ids_from_routes(&pending_routes)
    } else {
        Vec::new()
    };

    let (accused_scope, accused_peer_ids, accused_node_keys) =
        if is_reshare && peer_id_matches_any(&peer_id, &pending_peer_ids) {
            (
                ReportCommitteeScope::PendingNew,
                pending_peer_ids.as_slice(),
                pending_node_keys.as_slice(),
            )
        } else if peer_id_matches_any(&peer_id, &current_peer_ids) {
            (
                ReportCommitteeScope::Current,
                current_peer_ids.as_slice(),
                ring.peer_node_keys.as_slice(),
            )
        } else {
            tracing::debug!(
                ring_id = %ring_id,
                peer_id = %peer_id,
                "Skipping PSS offline report because failed peer is not in reportable committee"
            );
            return Ok(());
        };

    let signing_scope = if ring
        .peer_node_keys
        .iter()
        .any(|node_key| node_key == &app_state.node_key)
    {
        ReportCommitteeScope::Current
    } else if is_reshare
        && pending_node_keys
            .iter()
            .any(|node_key| node_key == &app_state.node_key)
    {
        ReportCommitteeScope::PendingNew
    } else {
        tracing::debug!(
            ring_id = %ring_id,
            peer_id = %peer_id,
            reporter_node_key = %app_state.node_key,
            "Skipping PSS offline report because reporter is not in current or pending-new committee"
        );
        return Ok(());
    };

    if signing_scope == ReportCommitteeScope::PendingNew {
        if let Err(error) =
            RingPolyState::load_from_ring_pk_hex(&app_state.local_storage, &ring.ring_pk)
        {
            tracing::debug!(
                ring_id = %ring_id,
                peer_id = %peer_id,
                reporter_node_key = %app_state.node_key,
                error = %error,
                "Skipping PSS offline report because pending-new reporter has no local reshare bundle yet"
            );
            return Ok(());
        }
    }

    let Some(observation) = offline_observation_from_peer_routes(
        &ring_id,
        accused_peer_ids,
        accused_node_keys,
        &peer_id,
        origin_protocol,
        routes.version,
        accused_scope,
        signing_scope,
        &session_id,
    ) else {
        return Ok(());
    };

    queue_report::<D, SignImpl>(
        app_state,
        routes,
        ReportObservation::NodeOffline(observation),
    )
    .await
    .map_err(|error| DkgError::Generic(error.to_string()))?;

    Ok(())
}

fn peer_id_matches_any(peer_id: &str, candidates: &[String]) -> bool {
    let peer_part = extract_node_part(peer_id);
    candidates
        .iter()
        .any(|candidate| extract_node_part(candidate) == peer_part)
}

/// Handle to the background worker that turns stalled refresh/reshare sessions into
/// `node_offline` reports for the dealers that went silent.
pub(crate) struct PssStallReporterHandle {
    task: JoinHandle<()>,
}

impl PssStallReporterHandle {
    pub(crate) async fn shutdown(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

/// Drain [`AbandonedPssSession`] events (published by the session-expiration sweep when a
/// refresh/reshare stalls while collecting commitments or Phase 2 shares) and attempt a
/// `node_offline` report for each dealer this node never heard from. Acceptance is gated by the
/// co-signer reachability probe (`require_peer_offline`), so a merely-slow or
/// reachable-but-withholding dealer is auto-exonerated — only a dealer that is genuinely
/// unreachable at probe time (crashed or partitioned mid-phase) is demerited. This makes the
/// necessarily-broad "silent dealer" set safe.
pub(crate) fn spawn_pss_stall_reporter<D>(
    app_state: Arc<AppState<D>>,
    mut rx: mpsc::UnboundedReceiver<AbandonedPssSession>,
) -> PssStallReporterHandle
where
    D: Dkg<
            ShareValue = Fr,
            PublicKey = G1Affine,
            PolynomialCommitment = PolynomialCommitment,
            PubPoly = PubPoly,
        > + Clone
        + Send
        + Sync
        + 'static,
    SignImpl: CoordinatorReportSigner<D>,
{
    let task = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            report_abandoned_pss_session(&app_state, event).await;
        }
        tracing::debug!("PSS stall reporter: channel closed, worker shutting down");
    });
    PssStallReporterHandle { task }
}

/// Attempt a `node_offline` report for each silent dealer in an [`AbandonedPssSession`]. Shared by
/// the drain worker ([`spawn_pss_stall_reporter`]) and the unsafe-testing injection hook so both
/// exercise the same path. Acceptance is gated by the co-signer reachability probe, so only dealers
/// that are genuinely unreachable at probe time are demerited.
pub(crate) async fn report_abandoned_pss_session<D>(
    app_state: &Arc<AppState<D>>,
    event: AbandonedPssSession,
) where
    D: Dkg<
            ShareValue = Fr,
            PublicKey = G1Affine,
            PolynomialCommitment = PolynomialCommitment,
            PubPoly = PubPoly,
        > + Clone
        + Send
        + Sync
        + 'static,
    SignImpl: CoordinatorReportSigner<D>,
{
    let Some(routes) = network::routes_for_version(event.protocol_version) else {
        tracing::warn!(
            protocol_version = event.protocol_version,
            session_id = %event.session_id,
            "PSS stall reporter: no protocol routes for version; dropping offline attribution"
        );
        return;
    };
    for peer_id in event.missing_peer_ids {
        if let Err(error) = queue_pss_offline_report_task(
            app_state.clone(),
            routes,
            peer_id.clone(),
            event.kind.clone(),
            event.ring_id.clone(),
            event.session_id.to_string(),
        )
        .await
        {
            tracing::warn!(
                peer_id = %peer_id,
                session_id = %event.session_id,
                error = %error,
                "PSS stall reporter: failed to queue offline report for silent dealer"
            );
        }
    }
}
