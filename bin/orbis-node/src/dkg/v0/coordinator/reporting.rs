use crate::app_state::AppState;
use crate::constants::DKG_ATTEMPT_TIMEOUT;
use crate::dkg::v0::error::{DkgError, Result};
use crate::dkg::v0::messages::SessionKind;
use crate::dkg::v0::session_state::AbandonedPssSession;
use crate::dkg::v0::transport::{
    AttemptId, CeremonyConfig, CeremonyId, CommitteeScope, ParticipantRef, PrepareSession,
    PssOfflineStage,
};
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
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::types::CoordinatorReportSigner;

/// Owned, attempt-scoped input captured at the transport failure boundary.
/// It intentionally contains no raw error strings or protocol payloads.
#[derive(Clone, Debug)]
pub(crate) struct PssOfflineObservationSeed {
    pub ceremony_id: CeremonyId,
    pub attempt_id: Option<AttemptId>,
    pub kind: SessionKind,
    pub ring_id: String,
    pub protocol_version: u64,
    pub stage: PssOfflineStage,
    /// Full committee context is retained only when a pure-new Reshare
    /// observer may need to relay the candidates to a current signer.
    pub committees: Option<CeremonyConfig>,
    /// Direct forwarding can observe a peer before an attempt exists. Keep
    /// the already-resolved route here so reporting never adds committee-wide
    /// route resolution to the protocol's start path.
    pub route_overrides: BTreeMap<ParticipantRef, String>,
    pub subject_overrides: BTreeMap<ParticipantRef, String>,
    pub accused: Vec<ParticipantRef>,
}

impl PssOfflineObservationSeed {
    pub(crate) fn from_prepare(
        prepare: &PrepareSession,
        protocol_version: u64,
        stage: PssOfflineStage,
        accused: impl IntoIterator<Item = ParticipantRef>,
    ) -> Self {
        Self::new(
            prepare.ceremony_id,
            Some(prepare.attempt_id),
            prepare.kind.clone(),
            prepare.ring_id.clone(),
            protocol_version,
            stage,
            prepare.committees.clone(),
            accused,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        ceremony_id: CeremonyId,
        attempt_id: Option<AttemptId>,
        kind: SessionKind,
        ring_id: String,
        protocol_version: u64,
        stage: PssOfflineStage,
        committees: CeremonyConfig,
        accused: impl IntoIterator<Item = ParticipantRef>,
    ) -> Self {
        let mut accused: Vec<_> = accused.into_iter().collect();
        accused.sort_unstable();
        accused.dedup();
        Self {
            ceremony_id,
            attempt_id,
            kind,
            ring_id,
            protocol_version,
            stage,
            committees: Some(committees),
            route_overrides: BTreeMap::new(),
            subject_overrides: BTreeMap::new(),
            accused,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn direct(
        ceremony_id: CeremonyId,
        kind: SessionKind,
        ring_id: String,
        protocol_version: u64,
        stage: PssOfflineStage,
        accused: impl IntoIterator<Item = (ParticipantRef, String, String)>,
    ) -> Self {
        let mut route_overrides = BTreeMap::new();
        let mut subject_overrides = BTreeMap::new();
        for (participant, node_key, route) in accused {
            route_overrides.insert(participant, route);
            subject_overrides.insert(participant, node_key);
        }
        let accused = route_overrides.keys().copied().collect();
        Self {
            ceremony_id,
            attempt_id: None,
            kind,
            ring_id,
            protocol_version,
            stage,
            committees: None,
            route_overrides,
            subject_overrides,
            accused,
        }
    }
}

const MAX_OFFLINE_CANDIDATE_CLAIMS: usize = 4096;

fn claim_new_offline_candidates<D>(app_state: &AppState<D>, seed: &mut PssOfflineObservationSeed)
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
{
    let now = tokio::time::Instant::now();
    let mut claims = app_state
        .dkg_offline_candidate_dedup
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    claims.retain(|_, recorded_at| now.duration_since(*recorded_at) <= DKG_ATTEMPT_TIMEOUT);
    seed.accused.retain(|participant| {
        let subject = seed
            .subject_overrides
            .get(participant)
            .cloned()
            .or_else(|| {
                seed.committees
                    .as_ref()
                    .and_then(|committees| committees.node_key(*participant))
                    .map(str::to_owned)
            });
        subject.is_some_and(|subject| {
            let key = (seed.ceremony_id, subject);
            if let Some(recorded_at) = claims.get_mut(&key) {
                *recorded_at = now;
                return false;
            }
            if claims.len() >= MAX_OFFLINE_CANDIDATE_CLAIMS {
                if let Some(oldest) = claims
                    .iter()
                    .min_by_key(|(_, recorded_at)| **recorded_at)
                    .map(|(key, _)| key.clone())
                {
                    claims.remove(&oldest);
                }
            }
            claims.insert(key, now);
            true
        })
    });
    seed.route_overrides
        .retain(|participant, _| seed.accused.binary_search(participant).is_ok());
    seed.subject_overrides
        .retain(|participant, _| seed.accused.binary_search(participant).is_ok());
}

/// Capture a terminal peer-liveness observation without coupling report
/// resolution, signing, or relay availability to the DKG outcome.
pub(crate) fn spawn_pss_offline_observations<D>(
    app_state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    mut seed: PssOfflineObservationSeed,
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
    if matches!(seed.kind, SessionKind::Fresh) || seed.accused.is_empty() {
        return;
    }
    if seed.protocol_version != routes.version {
        crate::metrics::record_pss_offline_observation(
            seed.stage.as_metric_label(),
            "version_mismatch",
        );
        return;
    }
    claim_new_offline_candidates(&app_state, &mut seed);
    if seed.accused.is_empty() {
        return;
    }
    crate::metrics::record_pss_offline_observation(seed.stage.as_metric_label(), "candidate");
    tokio::spawn(async move {
        report_or_relay_pss_offline_observations(app_state, routes, seed).await;
    });
}

async fn report_or_relay_pss_offline_observations<D>(
    app_state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    seed: PssOfflineObservationSeed,
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
    let is_pure_next = matches!(seed.kind, SessionKind::Reshare { .. })
        && seed.committees.as_ref().is_some_and(|committees| {
            !committees.current.node_keys.contains(&app_state.node_key)
                && committees
                    .next
                    .as_ref()
                    .is_some_and(|next| next.node_keys.contains(&app_state.node_key))
        });
    if let Some(attempt_id) = seed.attempt_id.filter(|_| is_pure_next) {
        crate::metrics::record_pss_offline_observation(
            seed.stage.as_metric_label(),
            "relay_candidate",
        );
        let Some(committees) = seed.committees.as_ref() else {
            return;
        };
        match crate::dkg::v0::network::relay_pss_offline_candidates(
            &app_state,
            routes,
            seed.ceremony_id,
            attempt_id,
            seed.stage,
            seed.accused,
            committees,
        )
        .await
        {
            Ok(()) => crate::metrics::record_pss_offline_observation(
                seed.stage.as_metric_label(),
                "relayed",
            ),
            Err(error) => {
                crate::metrics::record_pss_offline_observation(
                    seed.stage.as_metric_label(),
                    "relay_failed",
                );
                tracing::warn!(
                    session_id = seed.ceremony_id.0,
                    stage = seed.stage.as_metric_label(),
                    %error,
                    "no current-committee signer accepted terminal PSS offline candidates"
                );
            }
        }
        return;
    }

    crate::metrics::record_pss_offline_observation(
        seed.stage.as_metric_label(),
        "direct_candidate",
    );

    let context = match resolve_pss_offline_report_context(
        &app_state,
        &seed.kind,
        seed.ring_id.clone(),
    )
    .await
    {
        Ok(context) => context,
        Err(error) => {
            crate::metrics::record_pss_offline_observation(
                seed.stage.as_metric_label(),
                "report_failed",
            );
            tracing::warn!(
                session_id = seed.ceremony_id.0,
                stage = seed.stage.as_metric_label(),
                %error,
                "failed to resolve terminal PSS offline-report context"
            );
            return;
        }
    };

    if let Some(context) = context {
        let session_id = seed.ceremony_id.0.to_string();
        for participant in seed.accused.iter().copied() {
            let peer_id = seed.route_overrides.get(&participant).cloned().or_else(|| {
                seed.committees
                    .as_ref()
                    .and_then(|committees| committees.route(participant))
                    .map(str::to_owned)
            });
            let Some(peer_id) = peer_id else {
                continue;
            };
            match queue_pss_offline_report_for_peer(
                app_state.clone(),
                routes,
                &context,
                peer_id.clone(),
                Some(participant.scope),
                &session_id,
            )
            .await
            {
                Ok(()) => crate::metrics::record_pss_offline_observation(
                    seed.stage.as_metric_label(),
                    "direct",
                ),
                Err(error) => {
                    crate::metrics::record_pss_offline_observation(
                        seed.stage.as_metric_label(),
                        "report_failed",
                    );
                    tracing::warn!(
                        session_id = seed.ceremony_id.0,
                        stage = seed.stage.as_metric_label(),
                        peer_id = %peer_id,
                        %error,
                        "failed to queue terminal PSS offline report"
                    );
                }
            }
        }
        return;
    }

    crate::metrics::record_pss_offline_observation(seed.stage.as_metric_label(), "not_reportable");
}

/// Ring, committee-route, and signing-scope context shared by every accused peer
/// within one PSS offline-report event. Resolving this once per event (instead of
/// once per missing peer) avoids redundant bulletin reads and SourceHub route
/// resolutions when a stalled session has multiple silent dealers.
struct PssOfflineReportContext {
    origin_protocol: &'static str,
    ring_id: String,
    ring: RingPayload,
    is_reshare: bool,
    current_peer_ids: Vec<String>,
    pending_node_keys: Vec<String>,
    pending_peer_ids: Vec<String>,
    signing_scope: ReportCommitteeScope,
}

/// Resolve the shared reporting context for `kind`/`stored_ring_id`, or `Ok(None)`
/// when there is nothing reportable for this event: a fresh-DKG session, no
/// authoritative ring ID, this node not a member of either committee, or — for a
/// pending-new reporter — no local reshare bundle yet.
async fn resolve_pss_offline_report_context<D>(
    app_state: &Arc<AppState<D>>,
    kind: &SessionKind,
    stored_ring_id: String,
) -> Result<Option<PssOfflineReportContext>>
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
{
    let is_reshare = matches!(kind, SessionKind::Reshare { .. });
    let (origin_protocol, ring_id) = match kind {
        SessionKind::Fresh => return Ok(None),
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
        tracing::debug!("Skipping PSS offline report because session has no authoritative ring ID");
        return Ok(None);
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
            reporter_node_key = %app_state.node_key,
            "Skipping PSS offline report because reporter is not in current or pending-new committee"
        );
        return Ok(None);
    };

    if signing_scope == ReportCommitteeScope::PendingNew {
        if let Err(error) =
            RingPolyState::load_from_ring_pk_hex(&app_state.local_storage, &ring.ring_pk)
        {
            tracing::debug!(
                ring_id = %ring_id,
                reporter_node_key = %app_state.node_key,
                error = %error,
                "Skipping PSS offline report because pending-new reporter has no local reshare bundle yet"
            );
            return Ok(None);
        }
    }

    Ok(Some(PssOfflineReportContext {
        origin_protocol,
        ring_id,
        ring,
        is_reshare,
        current_peer_ids,
        pending_node_keys,
        pending_peer_ids,
        signing_scope,
    }))
}

/// Queue a `node_offline` report for one accused peer using an already-resolved
/// [`PssOfflineReportContext`]. Only accused-scope selection and report queuing are
/// peer specific; everything else in the context was resolved once for the whole
/// event.
async fn queue_pss_offline_report_for_peer<D>(
    app_state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    context: &PssOfflineReportContext,
    peer_id: String,
    accused_scope_hint: Option<CommitteeScope>,
    session_id: &str,
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
    let (accused_scope, accused_peer_ids, accused_node_keys) = match accused_scope_hint {
        Some(CommitteeScope::Next)
            if context.is_reshare && peer_id_matches_any(&peer_id, &context.pending_peer_ids) =>
        {
            (
                ReportCommitteeScope::PendingNew,
                context.pending_peer_ids.as_slice(),
                context.pending_node_keys.as_slice(),
            )
        }
        Some(CommitteeScope::Current)
            if peer_id_matches_any(&peer_id, &context.current_peer_ids) =>
        {
            (
                ReportCommitteeScope::Current,
                context.current_peer_ids.as_slice(),
                context.ring.peer_node_keys.as_slice(),
            )
        }
        None if context.is_reshare && peer_id_matches_any(&peer_id, &context.pending_peer_ids) => (
            ReportCommitteeScope::PendingNew,
            context.pending_peer_ids.as_slice(),
            context.pending_node_keys.as_slice(),
        ),
        None if peer_id_matches_any(&peer_id, &context.current_peer_ids) => (
            ReportCommitteeScope::Current,
            context.current_peer_ids.as_slice(),
            context.ring.peer_node_keys.as_slice(),
        ),
        _ => {
            tracing::debug!(
                ring_id = %context.ring_id,
                peer_id = %peer_id,
                "Skipping PSS offline report because failed peer is not in reportable committee"
            );
            return Ok(());
        }
    };

    let Some(observation) = offline_observation_from_peer_routes(
        &context.ring_id,
        accused_peer_ids,
        accused_node_keys,
        &peer_id,
        context.origin_protocol,
        routes.version,
        accused_scope,
        context.signing_scope,
        session_id,
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
    mut rx: mpsc::Receiver<AbandonedPssSession>,
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

    let context =
        match resolve_pss_offline_report_context(app_state, &event.kind, event.ring_id.clone())
            .await
        {
            Ok(Some(context)) => context,
            Ok(None) => return,
            Err(error) => {
                tracing::warn!(
                    session_id = %event.session_id,
                    error = %error,
                    "PSS stall reporter: failed to resolve reporting context for abandoned session"
                );
                return;
            }
        };

    let session_id = event.session_id.to_string();
    for peer_id in event.missing_peer_ids {
        if let Err(error) = queue_pss_offline_report_for_peer(
            app_state.clone(),
            routes,
            &context,
            peer_id.clone(),
            None,
            &session_id,
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
