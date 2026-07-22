//! Hybrid transport for fresh DKG and PSS refresh ceremonies.
//!
//! Control messages and private shares use authenticated direct QUIC streams.
//! Public contributions are individually endpoint-signed, collected by the
//! canonical leader, and relayed in canonical batches over a transient Gossip
//! topic. Reshare deliberately remains on the legacy DKG ALPN.

use async_trait::async_trait;
use bytes::Bytes;
use futures::{stream::FuturesUnordered, StreamExt};
use network::{Connection, Message, PeerId, ProtocolHandler, PubSubEvent, SignedPayload, Topic};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout, Duration, Instant};

use crate::app_state::AppState;
use crate::constants::{
    DKG_ATTEMPT_TIMEOUT, DKG_FORWARDED_START_RESPONSE_GRACE, DKG_GOSSIP_ISOLATION_GRACE,
    DKG_MAX_REPAIR_BACKOFF, DKG_PREPARATION_RETRY_MAX_BACKOFF, DKG_PREPARATION_TIMEOUT,
    DKG_REPAIR_STALL_INTERVAL, DKG_TOPOLOGY_PROBE_INTERVAL, PEER_RESPONSE_TIMEOUT,
};
use crate::dkg::v0::coordinator::message_handlers::{
    drive_private_share_completion, handle_session_init,
};
use crate::dkg::v0::coordinator::types::{CoordinatorDkg, CoordinatorReportSigner};
use crate::dkg::v0::coordinator::DkgCoordinator;
use crate::dkg::v0::error::{DkgError, Result};
use crate::dkg::v0::helpers::{
    derive_fresh_dkg_session_id, derive_refresh_session_id, ring_payload_matches_ring_key,
    validate_fresh_dkg_ring_payload,
};
use crate::dkg::v0::messages::{DkgMessage, SessionKind};
use crate::dkg::v0::session_state::{
    HybridActivationOutcome, PublicContributionRecordOutcome, TopologyAckRecordOutcome,
};
use crate::dkg::v0::transport::{
    self, AttemptId, CeremonyId, DkgControlMessage, DkgPrivateMessage, DkgPublicContribution,
    DkgPublicMessage, DkgPublicPayload, MessageId, PhaseManifest, PrepareSession, PublicPhase,
    PUBLIC_CONTRIBUTION_SIGNING_DOMAIN,
};
use crate::helpers::identity::{extract_node_part, is_self_peer_id};
use crate::helpers::node_routes::{
    canonical_node_id_assignments_from_node_keys, peer_ids_from_routes, resolve_node_routes,
};
use crate::helpers::protocol_version::read_ring_for_route;
use crate::metrics::{DkgCeremonyKind, PrivatePairMetricsGuard};
use crate::ring_state::RingShareBundle;
use crypto::SignImpl;

const MAX_CONTROL_MESSAGE_BYTES: usize = 2 * 1024 * 1024;
const MAX_PUBLIC_COMMIT_RECEIPTS: usize = 4096;
const INITIAL_CONTROL_RETRY_BACKOFF: Duration = Duration::from_millis(250);
const INITIAL_PRIVATE_RETRY_BACKOFF: Duration = Duration::from_millis(100);
const PRIVATE_BUSY_RETRY_AFTER: Duration = Duration::from_millis(250);
const PRIVATE_INBOUND_QUEUE_WAIT: Duration = Duration::from_millis(500);

#[derive(Default)]
struct GossipNeighborTracker {
    neighbors: BTreeSet<String>,
    ever_had_neighbor: bool,
    isolation_deadline: Option<Instant>,
}

impl GossipNeighborTracker {
    fn neighbor_up(&mut self, peer: &PeerId) {
        self.neighbors.insert(hex::encode(peer.as_bytes()));
        self.ever_had_neighbor = true;
        self.isolation_deadline = None;
    }

    fn neighbor_down(&mut self, peer: &PeerId, now: Instant) -> bool {
        let removed = self.neighbors.remove(&hex::encode(peer.as_bytes()));
        if removed
            && self.neighbors.is_empty()
            && self.ever_had_neighbor
            && self.isolation_deadline.is_none()
        {
            self.isolation_deadline = Some(now + DKG_GOSSIP_ISOLATION_GRACE);
        }
        removed
    }

    fn isolation_deadline(&self) -> Option<Instant> {
        self.isolation_deadline
    }

    fn is_isolated(&self) -> bool {
        self.neighbors.is_empty() && self.ever_had_neighbor
    }

    fn reset_after_rejoin(&mut self) {
        self.neighbors.clear();
        self.ever_had_neighbor = false;
        self.isolation_deadline = None;
    }

    fn neighbor_count(&self) -> usize {
        self.neighbors.len()
    }
}

fn missing_topology_peers(
    expected: &BTreeSet<String>,
    acknowledged: &BTreeSet<String>,
) -> Vec<String> {
    expected.difference(acknowledged).cloned().collect()
}

fn missing_topology_peer_prefixes(missing: &[String]) -> String {
    missing
        .iter()
        .map(|peer| peer.chars().take(12).collect::<String>())
        .collect::<Vec<_>>()
        .join(",")
}

fn control_request_scope(
    request: &DkgControlMessage,
) -> (&'static str, Option<CeremonyId>, Option<AttemptId>) {
    match request {
        DkgControlMessage::StartFresh { .. } => ("start-fresh", None, None),
        DkgControlMessage::Prepare(prepare) => (
            "prepare",
            Some(prepare.ceremony_id),
            Some(prepare.attempt_id),
        ),
        DkgControlMessage::TopologyProbeAck {
            ceremony_id,
            attempt_id,
            ..
        } => ("topology-probe-ack", Some(*ceremony_id), Some(*attempt_id)),
        DkgControlMessage::TopologyProbeStatus {
            ceremony_id,
            attempt_id,
            ..
        } => (
            "topology-probe-status",
            Some(*ceremony_id),
            Some(*attempt_id),
        ),
        DkgControlMessage::Activate {
            ceremony_id,
            attempt_id,
        } => ("activate", Some(*ceremony_id), Some(*attempt_id)),
        DkgControlMessage::Abort {
            ceremony_id,
            attempt_id,
            ..
        } => ("abort", Some(*ceremony_id), Some(*attempt_id)),
        DkgControlMessage::GetPublicContribution {
            ceremony_id,
            attempt_id,
            ..
        } => (
            "get-public-contribution",
            Some(*ceremony_id),
            Some(*attempt_id),
        ),
        DkgControlMessage::GetPublicPhase {
            ceremony_id,
            attempt_id,
            ..
        } => ("get-public-phase", Some(*ceremony_id), Some(*attempt_id)),
        _ => ("dkg-control", None, None),
    }
}

fn control_timeout_message(
    peer: &str,
    request: &DkgControlMessage,
    response_timeout: Duration,
) -> String {
    let (operation, ceremony_id, attempt_id) = control_request_scope(request);
    let peer = extract_node_part(peer);
    let peer_prefix: String = peer.chars().take(12).collect();
    format!(
        "control {operation} response timed out after {:.1}s for peer {peer_prefix} ceremony={} attempt={}",
        response_timeout.as_secs_f64(),
        ceremony_id.map_or_else(|| "-".into(), |id| id.0.to_string()),
        attempt_id.map_or_else(|| "-".into(), |id| hex::encode(&id.0[..6])),
    )
}

fn repairable_public_phases(kind: &SessionKind) -> &'static [PublicPhase] {
    const FRESH: &[PublicPhase] = &[PublicPhase::CommitmentHashes, PublicPhase::Commitments];
    const REFRESH: &[PublicPhase] = &[
        PublicPhase::Commitments,
        PublicPhase::CommitmentAudit,
        PublicPhase::RefreshHealthCheck,
    ];
    match kind {
        SessionKind::Fresh => FRESH,
        SessionKind::Refresh { .. } => REFRESH,
        SessionKind::Reshare { .. } => &[],
    }
}

fn wire_error(error: impl ToString) -> DkgControlMessage {
    DkgControlMessage::Error {
        ceremony_id: None,
        attempt_id: None,
        message: error.to_string(),
    }
}

fn peer_matches_route(peer: &PeerId, route: &str) -> bool {
    hex::encode(peer.as_bytes()) == extract_node_part(route).to_lowercase()
}

async fn lock_ceremony_start<D>(
    state: &Arc<AppState<D>>,
    ceremony_id: CeremonyId,
) -> tokio::sync::OwnedMutexGuard<()>
where
    D: CoordinatorDkg,
{
    let lock = {
        let mut locks = state.dkg_ceremony_start_locks.lock().await;
        locks
            .entry(ceremony_id.0)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    };
    lock.lock_owned().await
}

async fn control_request<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    peer: &str,
    request: DkgControlMessage,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
{
    control_request_with_timeout(state, routes, peer, request, PEER_RESPONSE_TIMEOUT).await
}

async fn control_request_with_timeout<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    peer: &str,
    request: DkgControlMessage,
    response_timeout: Duration,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
{
    let timeout_error = control_timeout_message(peer, &request, response_timeout);
    let response = timeout(response_timeout, async {
        let stream = state
            .peer_connection_pool
            .open_stream(&state.network, peer, routes.dkg_control_alpn)
            .await
            .map_err(|error| DkgError::NetworkConnection(error.to_string()))?;
        let encoded = transport::encode(&request).map_err(DkgError::Serialization)?;
        stream
            .send(Message::new(encoded, routes.dkg_control_alpn.to_vec()))
            .await
            .map_err(|error| DkgError::NetworkCommunication(error.to_string()))?;
        stream
            .recv()
            .await
            .map_err(|error| DkgError::NetworkCommunication(error.to_string()))
    })
    .await
    .map_err(|_| DkgError::NetworkConnection(timeout_error))??;
    let response = transport::decode(&response.data, MAX_CONTROL_MESSAGE_BYTES)
        .map_err(DkgError::Deserialization)?;
    match response {
        DkgControlMessage::Error { message, .. } => Err(DkgError::ProtocolError(message)),
        response => Ok(response),
    }
}

fn retryable_control_error(error: &DkgError) -> bool {
    matches!(
        error,
        DkgError::NetworkConnection(_) | DkgError::NetworkCommunication(_)
    )
}

async fn retry_preparation_control<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    peer: &str,
    request: DkgControlMessage,
    deadline: Instant,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
{
    let (operation, ceremony_id, attempt_id) = control_request_scope(&request);
    let mut backoff = INITIAL_CONTROL_RETRY_BACKOFF;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(DkgError::NetworkCommunication(format!(
                "{operation} exceeded the preparation deadline for peer {} ceremony={} attempt={}",
                extract_node_part(peer),
                ceremony_id.map_or_else(|| "-".into(), |id| id.0.to_string()),
                attempt_id.map_or_else(|| "-".into(), |id| hex::encode(&id.0[..6])),
            )));
        }
        let remaining = deadline.saturating_duration_since(now);
        match control_request_with_timeout(
            state,
            routes,
            peer,
            request.clone(),
            PEER_RESPONSE_TIMEOUT.min(remaining),
        )
        .await
        {
            Ok(response) => return Ok(response),
            Err(error) if retryable_control_error(&error) => {
                crate::metrics::record_dkg_hybrid_event("control", "preparation_retry");
                tracing::warn!(
                    %error,
                    operation,
                    peer = %extract_node_part(peer),
                    "preparation control request failed; retrying"
                );
            }
            Err(error) => return Err(error),
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            continue;
        }
        sleep(backoff.min(remaining)).await;
        backoff = (backoff * 2).min(DKG_PREPARATION_RETRY_MAX_BACKOFF);
    }
}

/// Inbound request/response handler for the direct control plane.
pub struct HybridControlHandler<D>
where
    D: CoordinatorDkg,
{
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
}

impl<D> HybridControlHandler<D>
where
    D: CoordinatorDkg,
{
    pub fn new(state: Arc<AppState<D>>, routes: &'static network::ProtocolRoutes) -> Self {
        Self { state, routes }
    }
}

#[async_trait]
impl<D> ProtocolHandler for HybridControlHandler<D>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    async fn handle(&self, connection: Box<dyn Connection>) -> network::Result<()> {
        let peer = connection.peer_id().clone();
        let request = connection.recv().await?;
        let response = match transport::decode::<DkgControlMessage>(
            &request.data,
            MAX_CONTROL_MESSAGE_BYTES,
        ) {
            Ok(request) => handle_control(self.state.clone(), self.routes, request, &peer)
                .await
                .unwrap_or_else(wire_error),
            Err(error) => wire_error(error),
        };
        let bytes =
            transport::encode(&response).map_err(network::error::NetworkError::Serialization)?;
        connection
            .send(Message::new(bytes, self.routes.dkg_control_alpn.to_vec()))
            .await
    }
}

async fn handle_control<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    request: DkgControlMessage,
    sender: &PeerId,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    match request {
        DkgControlMessage::StartFresh {
            ring_id,
            token_string,
        } => {
            let (ceremony_id, attempt_id) =
                coordinate_fresh(state, routes, ring_id, token_string).await?;
            Ok(DkgControlMessage::StartAccepted {
                ceremony_id,
                attempt_id,
            })
        }
        DkgControlMessage::Prepare(prepare) => {
            prepare_participant(state, routes, *prepare, sender).await
        }
        DkgControlMessage::TopologyProbeStatus {
            ceremony_id,
            attempt_id,
            nonce,
        } => {
            let seen = state
                .dkg_session_state
                .topology_probe_seen(&ceremony_id.0, attempt_id, nonce)
                .await;
            Ok(DkgControlMessage::TopologyProbeStatusResponse {
                ceremony_id,
                attempt_id,
                nonce,
                seen,
            })
        }
        DkgControlMessage::TopologyProbeAck {
            ceremony_id,
            attempt_id,
            nonce,
        } => {
            validate_leader_local(&state, ceremony_id.0).await?;
            let peer = canonical_committee_peer(&state, ceremony_id.0, sender).await?;
            match state
                .dkg_session_state
                .record_topology_probe_ack(&ceremony_id.0, attempt_id, nonce, peer)
                .await
            {
                TopologyAckRecordOutcome::Recorded => {
                    crate::metrics::record_dkg_hybrid_event("control", "probe_ack");
                }
                TopologyAckRecordOutcome::Duplicate => {}
                TopologyAckRecordOutcome::StaleAttempt => {
                    return Err(DkgError::ProtocolError(
                        "topology acknowledgement targets a stale attempt".into(),
                    ));
                }
                TopologyAckRecordOutcome::WrongNonce => {
                    return Err(DkgError::ProtocolError(
                        "topology acknowledgement has the wrong nonce".into(),
                    ));
                }
                TopologyAckRecordOutcome::MissingSession => {
                    return Err(DkgError::SessionNotFound(ceremony_id.0.to_string()));
                }
            }
            Ok(DkgControlMessage::TopologyProbeAck {
                ceremony_id,
                attempt_id,
                nonce,
            })
        }
        DkgControlMessage::Activate {
            ceremony_id,
            attempt_id,
        } => {
            validate_leader_sender(&state, ceremony_id.0, sender).await?;
            let activation = state
                .dkg_session_state
                .activate_hybrid_transport(&ceremony_id.0, attempt_id)
                .await;
            match activation {
                HybridActivationOutcome::AlreadyActivated => {
                    return Ok(DkgControlMessage::Activated {
                        ceremony_id,
                        attempt_id,
                    });
                }
                HybridActivationOutcome::Activated => {}
                HybridActivationOutcome::StaleAttempt | HybridActivationOutcome::MissingSession => {
                    return Err(DkgError::ProtocolError("activate for stale attempt".into()));
                }
            }
            let coordinator = DkgCoordinator::with_routes(state.clone(), routes);
            let peer_ids = state
                .dkg_session_state
                .get_peer_ids(&ceremony_id.0)
                .await
                .ok_or_else(|| DkgError::SessionNotFound(ceremony_id.0.to_string()))?;
            let kind = state
                .dkg_session_state
                .with_state(&ceremony_id.0, |session| session.kind.clone())
                .await
                .ok_or_else(|| DkgError::SessionNotFound(ceremony_id.0.to_string()))?;
            match kind {
                SessionKind::Fresh => {
                    coordinator
                        .initiate_phase0_commitment_hashes(ceremony_id.0, &peer_ids)
                        .await?;
                }
                SessionKind::Refresh { .. } => {
                    coordinator
                        .initiate_phase1_commitments(ceremony_id.0, &peer_ids)
                        .await?;
                }
                SessionKind::Reshare { .. } => {
                    return Err(DkgError::ProtocolError(
                        "reshare is not supported by hybrid transport".into(),
                    ));
                }
            }
            Ok(DkgControlMessage::Activated {
                ceremony_id,
                attempt_id,
            })
        }
        DkgControlMessage::PublicContribution(signed) => {
            if signed.origin.as_slice() != sender.as_bytes() {
                return Err(DkgError::Unauthorized(
                    "direct public contribution sender differs from embedded origin".into(),
                ));
            }
            let contribution = verify_signed_contribution(&state, &signed).await?;
            tracing::info!(
                session_id = contribution.ceremony_id.0,
                origin_node_id = contribution.origin_node_id,
                phase = ?contribution.payload.phase(),
                "leader received signed public DKG contribution"
            );
            validate_leader_local(&state, contribution.ceremony_id.0).await?;
            let recorded =
                record_public_contribution(&state, signed.clone(), &contribution).await?;
            publish_phase_if_complete(
                state.clone(),
                routes,
                contribution.ceremony_id.0,
                contribution.attempt_id,
                contribution.payload.phase(),
            )
            .await?;
            if recorded {
                // The direct ACK confirms authenticated retention by the leader,
                // not completion of the leader's local protocol transition. The
                // last contribution in a phase can enter Phase 2 and wait for
                // every private pair exchange; withholding the ACK until then
                // deadlocks the contributing follower before it can consume the
                // public batch and generate its reciprocal share.
                let dispatch_state = state.clone();
                let dispatch_contribution = contribution.clone();
                tokio::spawn(async move {
                    if let Err(error) = dispatch_public_contribution(
                        dispatch_state,
                        routes,
                        signed,
                        dispatch_contribution.clone(),
                    )
                    .await
                    {
                        tracing::warn!(
                            %error,
                            session_id = dispatch_contribution.ceremony_id.0,
                            origin_node_id = dispatch_contribution.origin_node_id,
                            phase = ?dispatch_contribution.payload.phase(),
                            "leader failed to apply retained public DKG contribution"
                        );
                    }
                });
            }
            Ok(DkgControlMessage::PublicContributionAck {
                ceremony_id: contribution.ceremony_id,
                attempt_id: contribution.attempt_id,
                message_id: contribution.message_id,
            })
        }
        DkgControlMessage::StageRefreshResult(signed) => {
            if signed.origin.as_slice() != sender.as_bytes() {
                return Err(DkgError::Unauthorized(
                    "staged refresh-result sender differs from embedded origin".into(),
                ));
            }
            let contribution = verify_signed_contribution(&state, &signed).await?;
            validate_leader_sender(&state, contribution.ceremony_id.0, sender).await?;
            if contribution.payload.phase() != PublicPhase::RefreshHealthCheck {
                return Err(DkgError::Unauthorized(
                    "only a refresh health-check result may use the result barrier".into(),
                ));
            }
            record_public_contribution(&state, signed, &contribution).await?;
            crate::metrics::record_dkg_hybrid_event("public", "result_staged");
            Ok(DkgControlMessage::PublicContributionAck {
                ceremony_id: contribution.ceremony_id,
                attempt_id: contribution.attempt_id,
                message_id: contribution.message_id,
            })
        }
        DkgControlMessage::CommitRefreshResult {
            ceremony_id,
            attempt_id,
            message_id,
        } => {
            let receipt_key = (ceremony_id, attempt_id, message_id);
            {
                let now = Instant::now();
                let mut receipts = state.dkg_public_commit_receipts.lock().await;
                receipts.retain(|_, (_, recorded_at)| {
                    now.duration_since(*recorded_at) <= DKG_ATTEMPT_TIMEOUT
                });
                if let Some((leader_peer, _)) = receipts.get(&receipt_key) {
                    if leader_peer.as_slice() != sender.as_bytes() {
                        return Err(DkgError::Unauthorized(
                            "refresh-result retry did not come from its original leader".into(),
                        ));
                    }
                    return Ok(DkgControlMessage::PublicContributionAck {
                        ceremony_id,
                        attempt_id,
                        message_id,
                    });
                }
            }

            validate_leader_sender(&state, ceremony_id.0, sender).await?;
            if state.dkg_session_state.hybrid_attempt(&ceremony_id.0).await != Some(attempt_id) {
                return Err(DkgError::ProtocolError(
                    "refresh-result commit targets a stale attempt".into(),
                ));
            }
            let retained = state
                .dkg_session_state
                .public_contributions(&ceremony_id.0, attempt_id, PublicPhase::RefreshHealthCheck)
                .await
                .unwrap_or_default();
            let mut selected = None;
            for signed in retained.into_values() {
                let contribution = verify_signed_contribution(&state, &signed).await?;
                if contribution.message_id == message_id {
                    selected = Some((signed, contribution));
                    break;
                }
            }
            let (signed, contribution) = selected.ok_or_else(|| {
                DkgError::InvalidState(
                    "refresh-result commit arrived before the exact result was staged".into(),
                )
            })?;
            apply_public_contribution(state.clone(), routes, signed, contribution).await?;

            let now = Instant::now();
            let mut receipts = state.dkg_public_commit_receipts.lock().await;
            if receipts.len() >= MAX_PUBLIC_COMMIT_RECEIPTS {
                if let Some(oldest) = receipts
                    .iter()
                    .min_by_key(|(_, (_, recorded_at))| *recorded_at)
                    .map(|(key, _)| *key)
                {
                    receipts.remove(&oldest);
                }
            }
            receipts.insert(receipt_key, (sender.as_bytes().to_vec(), now));
            crate::metrics::record_dkg_hybrid_event("public", "result_committed");
            Ok(DkgControlMessage::PublicContributionAck {
                ceremony_id,
                attempt_id,
                message_id,
            })
        }
        DkgControlMessage::GetPublicContribution {
            ceremony_id,
            attempt_id,
            phase,
            origin_node_id,
        } => {
            validate_committee_sender(&state, ceremony_id.0, sender).await?;
            let local_node_id = state
                .dkg_session_state
                .with_state(&ceremony_id.0, |session| session.node.node_id())
                .await
                .ok_or_else(|| DkgError::SessionNotFound(ceremony_id.0.to_string()))?;
            if local_node_id != origin_node_id {
                return Err(DkgError::Unauthorized(
                    "public origin repair must be requested from that origin".into(),
                ));
            }
            let contribution = state
                .dkg_session_state
                .public_contributions(&ceremony_id.0, attempt_id, phase)
                .await
                .and_then(|items| items.get(&origin_node_id).cloned());
            Ok(DkgControlMessage::PublicContributionResponse {
                ceremony_id,
                attempt_id,
                contribution,
            })
        }
        DkgControlMessage::GetPublicPhase {
            ceremony_id,
            attempt_id,
            phase,
        } => {
            validate_leader_local(&state, ceremony_id.0).await?;
            validate_committee_sender(&state, ceremony_id.0, sender).await?;
            let contributions = state
                .dkg_session_state
                .public_contributions(&ceremony_id.0, attempt_id, phase)
                .await
                .unwrap_or_default()
                .into_values()
                .collect();
            Ok(DkgControlMessage::PublicPhaseResponse {
                ceremony_id,
                attempt_id,
                phase,
                contributions,
            })
        }
        DkgControlMessage::Abort {
            ceremony_id,
            attempt_id,
            reason,
        } => {
            validate_leader_sender(&state, ceremony_id.0, sender).await?;
            if state.dkg_session_state.hybrid_attempt(&ceremony_id.0).await == Some(attempt_id) {
                tracing::warn!(session_id = ceremony_id.0, %reason, "hybrid DKG attempt aborted");
                state.dkg_session_state.remove_session(&ceremony_id.0).await;
            }
            Ok(DkgControlMessage::Abort {
                ceremony_id,
                attempt_id,
                reason,
            })
        }
        other => Err(DkgError::ProtocolError(format!(
            "unexpected control request: {other:?}"
        ))),
    }
}

async fn validate_leader_sender<D>(
    state: &Arc<AppState<D>>,
    session_id: u128,
    sender: &PeerId,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let leader = state
        .dkg_session_state
        .hybrid_transport_info(&session_id)
        .await
        .map(|(_, _, _, leader, _)| leader)
        .ok_or_else(|| DkgError::SessionNotFound(session_id.to_string()))?;
    let keys = state
        .dkg_session_state
        .get_peer_node_keys(&session_id)
        .await
        .unwrap_or_default();
    let peers = state
        .dkg_session_state
        .get_peer_ids(&session_id)
        .await
        .unwrap_or_default();
    let route = keys
        .iter()
        .zip(peers.iter())
        .find_map(|(key, peer)| (key == &leader).then_some(peer))
        .ok_or_else(|| DkgError::InvalidState("leader route is missing".into()))?;
    if !peer_matches_route(sender, route) {
        return Err(DkgError::Unauthorized(
            "control sender is not canonical leader".into(),
        ));
    }
    Ok(())
}

async fn validate_committee_sender<D>(
    state: &Arc<AppState<D>>,
    session_id: u128,
    sender: &PeerId,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    canonical_committee_peer(state, session_id, sender)
        .await
        .map(|_| ())
}

async fn canonical_committee_peer<D>(
    state: &Arc<AppState<D>>,
    session_id: u128,
    sender: &PeerId,
) -> Result<String>
where
    D: CoordinatorDkg,
{
    let peers = state
        .dkg_session_state
        .get_peer_ids(&session_id)
        .await
        .ok_or_else(|| DkgError::SessionNotFound(session_id.to_string()))?;
    peers
        .iter()
        .find(|peer| peer_matches_route(sender, peer))
        .map(|peer| extract_node_part(peer).to_lowercase())
        .ok_or_else(|| {
            DkgError::Unauthorized("direct repair requester is not in the committee".into())
        })
}

async fn validate_leader_local<D>(state: &Arc<AppState<D>>, session_id: u128) -> Result<()>
where
    D: CoordinatorDkg,
{
    let leader = state
        .dkg_session_state
        .hybrid_transport_info(&session_id)
        .await
        .map(|(_, _, _, leader, _)| leader)
        .ok_or_else(|| DkgError::SessionNotFound(session_id.to_string()))?;
    if leader != state.node_key {
        return Err(DkgError::Unauthorized(
            "public contribution sent to non-leader".into(),
        ));
    }
    Ok(())
}

/// Route a fresh-DKG start to the canonical leader, or coordinate it locally.
pub async fn start_fresh<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    ring_id: String,
    token_string: String,
) -> Result<(CeremonyId, AttemptId)>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let ring = read_ring_for_route(&*state.bulletin, &ring_id, routes.version)
        .await
        .map_err(DkgError::ProtocolError)?;
    validate_fresh_dkg_ring_payload(&ring_id, &ring)?;
    let leader = transport::canonical_leader(&ring.peer_node_keys)
        .ok_or_else(|| DkgError::InvalidParticipantCount(0))?
        .to_string();
    if leader == state.node_key {
        return coordinate_fresh(state, routes, ring_id, token_string).await;
    }
    let resolved = resolve_node_routes(&state.bulletin, &ring.peer_node_keys)
        .await
        .map_err(DkgError::Unauthorized)?;
    let leader_peer = resolved
        .iter()
        .find_map(|route| (route.node_key == leader).then_some(route.peer_id.as_str()))
        .ok_or_else(|| DkgError::InvalidState("canonical leader route is missing".into()))?;
    match control_request_with_timeout(
        &state,
        routes,
        leader_peer,
        DkgControlMessage::StartFresh {
            ring_id,
            token_string,
        },
        DKG_PREPARATION_TIMEOUT + DKG_FORWARDED_START_RESPONSE_GRACE,
    )
    .await?
    {
        DkgControlMessage::StartAccepted {
            ceremony_id,
            attempt_id,
        } => Ok((ceremony_id, attempt_id)),
        response => Err(DkgError::ProtocolError(format!(
            "leader returned unexpected start response: {response:?}"
        ))),
    }
}

/// Coordinate a due PSS refresh. Callers must be the canonical committee
/// leader; followers join only after receiving an authenticated Prepare.
pub async fn start_refresh<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    ring_id: String,
    ring_pk: String,
) -> Result<(CeremonyId, AttemptId)>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let ring = read_ring_for_route(&*state.bulletin, &ring_id, routes.version)
        .await
        .map_err(DkgError::ProtocolError)?;
    let leader = transport::canonical_leader(&ring.peer_node_keys)
        .ok_or_else(|| DkgError::InvalidParticipantCount(0))?
        .to_string();
    if leader != state.node_key {
        return Err(DkgError::Unauthorized(
            "only the canonical leader may schedule PSS refresh".into(),
        ));
    }
    if !ring_payload_matches_ring_key(&ring_pk, &ring.ring_pk) {
        return Err(DkgError::InvalidState(
            "refresh ring public key differs from SourceHub state".into(),
        ));
    }
    let bundle = RingShareBundle::load_by_ring_key(&state.local_storage, &ring_pk)
        .map_err(|error| DkgError::Storage(error.to_string()))?;
    let session_id = derive_refresh_session_id(
        &ring_pk,
        &ring.peer_node_keys,
        ring.threshold,
        &bundle.public_polynomial,
    )?;
    let _start_guard = lock_ceremony_start(&state, CeremonyId(session_id)).await;
    if let Some(attempt_id) = state.dkg_session_state.hybrid_attempt(&session_id).await {
        return Ok((CeremonyId(session_id), attempt_id));
    }
    let ceremony_id = CeremonyId(session_id);
    let attempt_id = AttemptId::random();
    let committee = transport::committee_digest(&ring.peer_node_keys);
    let resolved = resolve_node_routes(&state.bulletin, &ring.peer_node_keys)
        .await
        .map_err(DkgError::Unauthorized)?;
    let peer_ids = peer_ids_from_routes(&resolved);
    let assignments = canonical_node_id_assignments_from_node_keys(&ring.peer_node_keys)
        .map_err(DkgError::InvalidInput)?;
    let topic = transport::derive_topic_id(
        &state.bulletin.chain_id(),
        &ring_id,
        &committee,
        ceremony_id,
        attempt_id,
    );
    let mut prepare = PrepareSession {
        ceremony_id,
        attempt_id,
        config_digest: [0; 32],
        topic_id: *topic.as_bytes(),
        leader_node_key: leader,
        threshold: ring.threshold,
        total_participants: ring.peer_node_keys.len() as u32,
        peer_ids,
        peer_node_keys: ring.peer_node_keys,
        node_id_assignments: assignments,
        token_string: String::new(),
        kind: SessionKind::Refresh {
            ring_pk_hex: ring_pk,
        },
        pss_interval: ring.pss_interval,
        policy_id: ring.policy_id,
        ring_id,
    };
    prepare.config_digest = transport::config_digest(&prepare).map_err(DkgError::Serialization)?;
    coordinate_prepared(state, routes, prepare).await
}

async fn coordinate_fresh<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    ring_id: String,
    token_string: String,
) -> Result<(CeremonyId, AttemptId)>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let ring = read_ring_for_route(&*state.bulletin, &ring_id, routes.version)
        .await
        .map_err(DkgError::ProtocolError)?;
    validate_fresh_dkg_ring_payload(&ring_id, &ring)?;
    let leader = transport::canonical_leader(&ring.peer_node_keys)
        .ok_or_else(|| DkgError::InvalidParticipantCount(0))?
        .to_string();
    if leader != state.node_key {
        return Err(DkgError::Unauthorized(
            "StartFresh must be handled by the canonical leader".into(),
        ));
    }
    let session_id = derive_fresh_dkg_session_id(&ring_id)?;
    let _start_guard = lock_ceremony_start(&state, CeremonyId(session_id)).await;
    if let Some(attempt_id) = state.dkg_session_state.hybrid_attempt(&session_id).await {
        return Ok((CeremonyId(session_id), attempt_id));
    }
    let ceremony_id = CeremonyId(session_id);
    let attempt_id = AttemptId::random();
    let committee = transport::committee_digest(&ring.peer_node_keys);
    let resolved = resolve_node_routes(&state.bulletin, &ring.peer_node_keys)
        .await
        .map_err(DkgError::Unauthorized)?;
    let peer_ids = peer_ids_from_routes(&resolved);
    let assignments = canonical_node_id_assignments_from_node_keys(&ring.peer_node_keys)
        .map_err(DkgError::InvalidInput)?;
    let topic = transport::derive_topic_id(
        &state.bulletin.chain_id(),
        &ring_id,
        &committee,
        ceremony_id,
        attempt_id,
    );
    let mut prepare = PrepareSession {
        ceremony_id,
        attempt_id,
        config_digest: [0; 32],
        topic_id: *topic.as_bytes(),
        leader_node_key: leader,
        threshold: ring.threshold,
        total_participants: ring.peer_node_keys.len() as u32,
        peer_ids: peer_ids.clone(),
        peer_node_keys: ring.peer_node_keys.clone(),
        node_id_assignments: assignments,
        token_string,
        kind: SessionKind::Fresh,
        pss_interval: ring.pss_interval,
        policy_id: ring.policy_id.clone(),
        ring_id,
    };
    prepare.config_digest = transport::config_digest(&prepare).map_err(DkgError::Serialization)?;

    coordinate_prepared(state, routes, prepare).await
}

async fn coordinate_prepared<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: PrepareSession,
) -> Result<(CeremonyId, AttemptId)>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let result = coordinate_prepared_inner(state.clone(), routes, prepare.clone()).await;
    if let Err(error) = &result {
        abort_prepared_attempt(&state, routes, &prepare, error.to_string()).await;
        state
            .dkg_session_state
            .remove_session(&prepare.ceremony_id.0)
            .await;
    }
    result
}

async fn coordinate_prepared_inner<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: PrepareSession,
) -> Result<(CeremonyId, AttemptId)>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let readiness_start = Instant::now();
    let deadline = readiness_start + DKG_PREPARATION_TIMEOUT;
    let ceremony_kind = match &prepare.kind {
        SessionKind::Fresh => DkgCeremonyKind::Fresh,
        SessionKind::Refresh { .. } => DkgCeremonyKind::Refresh,
        SessionKind::Reshare { .. } => DkgCeremonyKind::Reshare,
    };
    let ceremony_id = prepare.ceremony_id;
    let attempt_id = prepare.attempt_id;
    let session_id = ceremony_id.0;
    let peer_ids = prepare.peer_ids.clone();

    // Prepare self first. This atomically claims the deterministic session ID,
    // preventing concurrent starts from creating competing attempts.
    let self_peer = state.network.local_peer_id();
    match prepare_participant(state.clone(), routes, prepare.clone(), &self_peer).await? {
        DkgControlMessage::Prepared { .. } => {}
        response => {
            return Err(DkgError::ProtocolError(format!(
                "local prepare returned unexpected response: {response:?}"
            )))
        }
    }

    let mut tasks = JoinSet::new();
    for peer in peer_ids
        .iter()
        .filter(|peer| !is_self_peer_id(&state.network, peer))
    {
        let state = state.clone();
        let peer = peer.clone();
        let prepare = prepare.clone();
        tasks.spawn(async move {
            let response = retry_preparation_control(
                &state,
                routes,
                &peer,
                DkgControlMessage::Prepare(Box::new(prepare)),
                deadline,
            )
            .await?;
            Ok::<_, DkgError>((peer, response))
        });
    }
    while let Some(result) = tasks.join_next().await {
        let (peer, response) =
            result.map_err(|error| DkgError::NetworkCommunication(error.to_string()))??;
        match response {
            DkgControlMessage::Prepared {
                ceremony_id: got_ceremony,
                attempt_id: got_attempt,
                config_digest,
            } if got_ceremony == ceremony_id
                && got_attempt == attempt_id
                && config_digest == prepare.config_digest => {}
            _ => {
                return Err(DkgError::ProtocolError(format!(
                    "peer {peer} returned invalid Prepared response"
                )))
            }
        }
    }

    let nonce: [u8; 32] = rand::random();
    let topic_handle = state
        .dkg_session_state
        .hybrid_topic(&session_id)
        .await
        .ok_or_else(|| DkgError::InvalidState("leader did not join transient topic".into()))?;
    let probe = transport::encode(&DkgPublicMessage::TopologyProbe {
        ceremony_id,
        attempt_id,
        nonce,
    })
    .map_err(DkgError::Serialization)?;
    let expected_peers: BTreeSet<String> = peer_ids
        .iter()
        .map(|peer| extract_node_part(peer).to_lowercase())
        .collect();
    let self_route = peer_ids
        .iter()
        .find(|peer| is_self_peer_id(&state.network, peer))
        .map(|peer| extract_node_part(peer).to_lowercase())
        .ok_or_else(|| {
            DkgError::InvalidState("leader route is absent from its committee".into())
        })?;
    let probe_notify = state
        .dkg_session_state
        .begin_topology_probe(&session_id, attempt_id, nonce, self_route)
        .await
        .ok_or_else(|| DkgError::InvalidState("leader cannot begin topology probe".into()))?;
    crate::metrics::record_dkg_hybrid_event("control", "probe_ack");
    let probe = Bytes::from(probe);
    let mut probe_tick = tokio::time::interval(DKG_TOPOLOGY_PROBE_INTERVAL);
    probe_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let missing = loop {
        let acknowledged = state
            .dkg_session_state
            .topology_probe_acknowledgements(&session_id, attempt_id, nonce)
            .await
            .ok_or_else(|| DkgError::InvalidState("topology probe attempt disappeared".into()))?;
        let missing = missing_topology_peers(&expected_peers, &acknowledged);
        if missing.is_empty() || Instant::now() >= deadline {
            break missing;
        }
        tokio::select! {
            _ = probe_notify.notified() => {}
            _ = probe_tick.tick() => {
                match topic_handle.broadcast(probe.clone()).await {
                    Ok(()) => {
                        crate::metrics::record_dkg_hybrid_event("public", "probe_broadcast");
                    }
                    Err(error) => {
                        crate::metrics::record_dkg_hybrid_event("public", "probe_broadcast_failure");
                        tracing::warn!(%error, session_id, "topology probe broadcast failed; retrying");
                    }
                }
            }
            _ = tokio::time::sleep_until(deadline) => {}
        }
    };
    if !missing.is_empty() {
        let missing_routes: Vec<String> = peer_ids
            .iter()
            .filter(|peer| missing.contains(&extract_node_part(peer).to_lowercase()))
            .cloned()
            .collect();
        tracing::error!(
            session_id,
            attempt_id = %hex::encode(attempt_id.0),
            missing_peers = ?missing_routes,
            "topology preparation barrier expired"
        );
        let prefixes = missing_topology_peer_prefixes(&missing);
        return Err(DkgError::NetworkCommunication(format!(
            "topology probe acknowledgement missing from {} participants before preparation deadline: {prefixes}",
            missing.len()
        )));
    }

    // Activate and start the leader before releasing followers. This preserves
    // the all-ready barrier while ensuring refresh contributions cannot reach
    // the leader before it has generated and retained its own polynomial.
    // Without this ordering, the legacy lazy-polynomial path can observe two
    // remote commitments and attempt Phase 2 before the hybrid attempt is
    // locally active.
    let leader_activation = state
        .dkg_session_state
        .activate_hybrid_transport(&session_id, attempt_id)
        .await;
    match leader_activation {
        HybridActivationOutcome::Activated => {
            let coordinator = DkgCoordinator::with_routes(state.clone(), routes);
            match &prepare.kind {
                SessionKind::Fresh => {
                    coordinator
                        .initiate_phase0_commitment_hashes(session_id, &peer_ids)
                        .await?;
                }
                SessionKind::Refresh { .. } => {
                    coordinator
                        .initiate_phase1_commitments(session_id, &peer_ids)
                        .await?;
                }
                SessionKind::Reshare { .. } => {
                    return Err(DkgError::ProtocolError(
                        "reshare is not supported by hybrid transport".into(),
                    ));
                }
            }
        }
        HybridActivationOutcome::AlreadyActivated => {}
        HybridActivationOutcome::StaleAttempt | HybridActivationOutcome::MissingSession => {
            return Err(DkgError::ProtocolError(
                "failed to activate the leader's hybrid attempt".into(),
            ));
        }
    }

    let mut activations = JoinSet::new();
    for peer in peer_ids
        .iter()
        .filter(|peer| !is_self_peer_id(&state.network, peer))
    {
        let state = state.clone();
        let peer = peer.clone();
        activations.spawn(async move {
            retry_preparation_control(
                &state,
                routes,
                &peer,
                DkgControlMessage::Activate {
                    ceremony_id,
                    attempt_id,
                },
                deadline,
            )
            .await
        });
    }
    while let Some(result) = activations.join_next().await {
        match result.map_err(|error| DkgError::NetworkCommunication(error.to_string()))?? {
            DkgControlMessage::Activated {
                ceremony_id: got_ceremony,
                attempt_id: got_attempt,
            } if got_ceremony == ceremony_id && got_attempt == attempt_id => {}
            response => {
                return Err(DkgError::ProtocolError(format!(
                    "invalid activation response: {response:?}"
                )))
            }
        }
    }
    crate::metrics::record_dkg_control_readiness(
        ceremony_kind,
        readiness_start.elapsed().as_secs_f64(),
    );
    crate::metrics::record_dkg_hybrid_event("control", "activated");
    Ok((ceremony_id, attempt_id))
}

async fn abort_prepared_attempt<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: &PrepareSession,
    reason: String,
) where
    D: CoordinatorDkg,
{
    let mut aborts = JoinSet::new();
    for peer in prepare
        .peer_ids
        .iter()
        .filter(|peer| !is_self_peer_id(&state.network, peer))
    {
        let state = state.clone();
        let peer = peer.clone();
        let reason = reason.clone();
        let ceremony_id = prepare.ceremony_id;
        let attempt_id = prepare.attempt_id;
        aborts.spawn(async move {
            timeout(
                Duration::from_secs(2),
                control_request(
                    &state,
                    routes,
                    &peer,
                    DkgControlMessage::Abort {
                        ceremony_id,
                        attempt_id,
                        reason,
                    },
                ),
            )
            .await
        });
    }
    while aborts.join_next().await.is_some() {}
    crate::metrics::record_dkg_hybrid_event("control", "abort");
}

async fn prepare_participant<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: PrepareSession,
    sender: &PeerId,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    if transport::canonical_leader(&prepare.peer_node_keys) != Some(&prepare.leader_node_key) {
        return Err(DkgError::Unauthorized(
            "Prepare names a non-canonical leader".into(),
        ));
    }
    let leader_route = prepare
        .peer_node_keys
        .iter()
        .zip(prepare.peer_ids.iter())
        .find_map(|(key, peer)| (key == &prepare.leader_node_key).then_some(peer))
        .ok_or_else(|| DkgError::InvalidInput("Prepare omits leader route".into()))?;
    if !peer_matches_route(sender, leader_route) {
        return Err(DkgError::Unauthorized(
            "Prepare sender is not canonical leader".into(),
        ));
    }
    let expected = transport::config_digest(&prepare).map_err(DkgError::Serialization)?;
    if expected != prepare.config_digest {
        return Err(DkgError::Unauthorized(
            "Prepare configuration digest mismatch".into(),
        ));
    }
    let coordinator = DkgCoordinator::with_routes(state.clone(), routes);
    handle_session_init(
        &coordinator,
        prepare.ceremony_id.0,
        prepare.threshold,
        prepare.total_participants,
        &prepare.peer_ids,
        &prepare.peer_node_keys,
        &prepare.node_id_assignments,
        &prepare.token_string,
        &prepare.kind,
        prepare.pss_interval,
        prepare.policy_id.clone(),
        prepare.ring_id.clone(),
        sender,
        false,
    )
    .await?;

    // A lost Prepared response may cause the leader to retry the exact request.
    // Do not create and immediately drop another Gossip subscription in that case;
    // doing so emits neighbor churn across the whole transient mesh.
    if let Some((ceremony_id, attempt_id, config_digest)) = state
        .dkg_session_state
        .hybrid_configuration(&prepare.ceremony_id.0)
        .await
    {
        if ceremony_id == prepare.ceremony_id
            && attempt_id == prepare.attempt_id
            && config_digest == prepare.config_digest
        {
            return Ok(DkgControlMessage::Prepared {
                ceremony_id: prepare.ceremony_id,
                attempt_id: prepare.attempt_id,
                config_digest: prepare.config_digest,
            });
        }
        return Err(DkgError::ProtocolError(
            "Prepare conflicts with the configured hybrid attempt".into(),
        ));
    }

    let pubsub = state.network.pubsub().ok_or_else(|| {
        DkgError::InvalidState("network backend does not provide authenticated pub-sub".into())
    })?;
    // The leader creates the topic without waiting for peers. Followers join
    // through the already-subscribed leader, avoiding a circular join barrier
    // during preparation.
    let bootstrap = if state.node_key == prepare.leader_node_key {
        Vec::new()
    } else {
        vec![PeerId::from_bytes(leader_route.as_bytes())]
    };
    let topic_id = network::TopicId::new(prepare.topic_id);
    let topic = pubsub
        .subscribe(topic_id, bootstrap)
        .await
        .map_err(|error| DkgError::NetworkCommunication(error.to_string()))?;
    let outcome = state
        .dkg_session_state
        .configure_hybrid_transport(
            &prepare.ceremony_id.0,
            prepare.ceremony_id,
            prepare.attempt_id,
            transport::committee_digest(&prepare.peer_node_keys),
            prepare.config_digest,
            topic_id,
            prepare.leader_node_key.clone(),
            topic.clone(),
        )
        .await;
    if matches!(
        outcome,
        crate::dkg::v0::session_state::HybridConfigureOutcome::ConflictingAttempt
            | crate::dkg::v0::session_state::HybridConfigureOutcome::MissingSession
    ) {
        return Err(DkgError::ProtocolError(format!(
            "cannot configure hybrid attempt: {outcome:?}"
        )));
    }
    if matches!(
        outcome,
        crate::dkg::v0::session_state::HybridConfigureOutcome::Configured
    ) {
        let task = tokio::spawn(topic_listener(
            state.clone(),
            routes,
            prepare.clone(),
            topic,
        ));
        state
            .dkg_session_state
            .set_hybrid_topic_task(&prepare.ceremony_id.0, task.abort_handle())
            .await;
    }
    Ok(DkgControlMessage::Prepared {
        ceremony_id: prepare.ceremony_id,
        attempt_id: prepare.attempt_id,
        config_digest: prepare.config_digest,
    })
}

async fn send_topology_probe_ack<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: PrepareSession,
    leader_route: String,
    nonce: [u8; 32],
) -> Result<[u8; 32]>
where
    D: CoordinatorDkg,
{
    let deadline = state
        .dkg_session_state
        .hybrid_preparation_deadline(&prepare.ceremony_id.0, prepare.attempt_id)
        .await
        .map(Instant::from_std)
        .ok_or_else(|| DkgError::SessionNotFound(prepare.ceremony_id.0.to_string()))?;
    let request = DkgControlMessage::TopologyProbeAck {
        ceremony_id: prepare.ceremony_id,
        attempt_id: prepare.attempt_id,
        nonce,
    };
    let mut backoff = INITIAL_CONTROL_RETRY_BACKOFF;
    loop {
        if state
            .dkg_session_state
            .hybrid_attempt(&prepare.ceremony_id.0)
            .await
            != Some(prepare.attempt_id)
        {
            return Err(DkgError::ProtocolError(
                "topology acknowledgement attempt was removed".into(),
            ));
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(DkgError::NetworkCommunication(
                "topology acknowledgement exceeded the preparation deadline".into(),
            ));
        }
        let remaining = deadline.saturating_duration_since(now);
        match control_request_with_timeout(
            &state,
            routes,
            &leader_route,
            request.clone(),
            PEER_RESPONSE_TIMEOUT.min(remaining),
        )
        .await
        {
            Ok(DkgControlMessage::TopologyProbeAck {
                ceremony_id,
                attempt_id,
                nonce: acknowledged_nonce,
            }) if ceremony_id == prepare.ceremony_id
                && attempt_id == prepare.attempt_id
                && acknowledged_nonce == nonce =>
            {
                return Ok(nonce)
            }
            Ok(response) => {
                return Err(DkgError::ProtocolError(format!(
                    "leader returned invalid topology acknowledgement response: {response:?}"
                )));
            }
            Err(error) if retryable_control_error(&error) => {
                crate::metrics::record_dkg_hybrid_event("control", "preparation_retry");
                tracing::warn!(
                    %error,
                    session_id = prepare.ceremony_id.0,
                    "topology acknowledgement failed; retrying identical bytes"
                );
            }
            Err(error) => return Err(error),
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            continue;
        }
        sleep(backoff.min(remaining)).await;
        backoff = (backoff * 2).min(DKG_PREPARATION_RETRY_MAX_BACKOFF);
    }
}

async fn topic_listener<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: PrepareSession,
    topic: Arc<dyn Topic>,
) where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let leader_route = prepare
        .peer_node_keys
        .iter()
        .zip(prepare.peer_ids.iter())
        .find_map(|(key, peer)| (key == &prepare.leader_node_key).then_some(peer))
        .cloned()
        .unwrap_or_default();
    let mut repair_tick = tokio::time::interval(DKG_REPAIR_STALL_INTERVAL);
    repair_tick.tick().await;
    let mut topic = topic;
    let mut neighbor_tracker = GossipNeighborTracker::default();
    let mut acknowledgement_tasks = JoinSet::new();
    let mut acknowledgement_in_flight = false;
    let mut acknowledged_nonce: Option<[u8; 32]> = None;
    loop {
        if state
            .dkg_session_state
            .hybrid_attempt(&prepare.ceremony_id.0)
            .await
            != Some(prepare.attempt_id)
        {
            // Completion/abort owns topic teardown and all listener-owned work.
            break;
        }
        let isolation_deadline = neighbor_tracker.isolation_deadline();
        let event = tokio::select! {
            acknowledgement = acknowledgement_tasks.join_next(), if !acknowledgement_tasks.is_empty() => {
                acknowledgement_in_flight = false;
                match acknowledgement {
                    Some(Ok(Ok(nonce))) => acknowledged_nonce = Some(nonce),
                    Some(Ok(Err(error))) => tracing::warn!(
                        %error,
                        session_id = prepare.ceremony_id.0,
                        "topology acknowledgement worker ended without acknowledgement"
                    ),
                    Some(Err(error)) => tracing::warn!(
                        %error,
                        session_id = prepare.ceremony_id.0,
                        "topology acknowledgement worker failed"
                    ),
                    None => {}
                }
                continue;
            }
            _ = async {
                match isolation_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                if neighbor_tracker.is_isolated() {
                    tracing::warn!(
                        session_id = prepare.ceremony_id.0,
                        "DKG Gossip topic remained isolated beyond grace period; rejoining"
                    );
                    match rejoin_public_topic_with_retry(
                        &state, &prepare, &leader_route, "rejoin_isolation",
                    ).await {
                        Ok(rejoined) => {
                            topic = rejoined;
                            neighbor_tracker.reset_after_rejoin();
                        }
                        Err(error) => {
                            tracing::warn!(%error, "failed to recover isolated DKG Gossip topic");
                            break;
                        }
                    }
                }
                continue;
            }
            event = topic.recv() => event,
            _ = repair_tick.tick() => {
                if state.dkg_session_state.hybrid_repair_due(
                    &prepare.ceremony_id.0,
                    prepare.attempt_id,
                    DKG_REPAIR_STALL_INTERVAL,
                ).await {
                    for &phase in repairable_public_phases(&prepare.kind) {
                        if let Err(error) = repair_public_phase(
                            state.clone(), routes, prepare.clone(), phase, false,
                        ).await {
                            tracing::debug!(%error, phase = ?phase,
                                "periodic public DKG completeness repair did not complete");
                        }
                    }
                }
                continue;
            }
        };
        match event {
            Ok(PubSubEvent::Received(message)) => {
                if !peer_matches_route(&message.origin, &leader_route) {
                    tracing::warn!("discarding DKG Gossip message not published by leader");
                    continue;
                }
                let Ok(public) =
                    transport::decode::<DkgPublicMessage>(&message.data, MAX_CONTROL_MESSAGE_BYTES)
                else {
                    tracing::warn!("discarding malformed DKG Gossip message");
                    continue;
                };
                match public {
                    DkgPublicMessage::TopologyProbe {
                        ceremony_id,
                        attempt_id,
                        nonce,
                    } if ceremony_id == prepare.ceremony_id && attempt_id == prepare.attempt_id => {
                        let accepted = state
                            .dkg_session_state
                            .record_topology_probe(&ceremony_id.0, attempt_id, nonce)
                            .await
                            == Some(true);
                        if !accepted {
                            tracing::warn!(
                                session_id = ceremony_id.0,
                                "discarding conflicting or stale topology probe"
                            );
                            continue;
                        }
                        if state.node_key != prepare.leader_node_key
                            && acknowledged_nonce != Some(nonce)
                            && !acknowledgement_in_flight
                        {
                            acknowledgement_in_flight = true;
                            acknowledgement_tasks.spawn(send_topology_probe_ack(
                                state.clone(),
                                routes,
                                prepare.clone(),
                                leader_route.clone(),
                                nonce,
                            ));
                        }
                    }
                    DkgPublicMessage::Chunk {
                        ceremony_id,
                        attempt_id,
                        phase,
                        phase_root,
                        contributions,
                        ..
                    } if ceremony_id == prepare.ceremony_id && attempt_id == prepare.attempt_id => {
                        for signed in contributions {
                            match verify_signed_contribution(&state, &signed).await {
                                Ok(contribution)
                                    if contribution.payload.phase() == phase
                                        && contribution.ceremony_id == ceremony_id
                                        && contribution.attempt_id == attempt_id =>
                                {
                                    // A refresh result uses a two-step control
                                    // barrier. Gossip reception retains the exact
                                    // signed result, but only the leader's Commit
                                    // message promotes the staged share. This
                                    // prevents subscriber timing from creating a
                                    // split refresh before every node is ready.
                                    let applied = if phase == PublicPhase::RefreshHealthCheck {
                                        record_public_contribution(&state, signed, &contribution)
                                            .await
                                            .map(|_| ())
                                    } else {
                                        apply_public_contribution(
                                            state.clone(),
                                            routes,
                                            signed,
                                            contribution,
                                        )
                                        .await
                                    };
                                    if let Err(error) = applied {
                                        tracing::warn!(%error, "failed to apply public DKG contribution");
                                    }
                                }
                                Ok(_) => tracing::warn!(
                                    "discarding contribution from wrong public phase"
                                ),
                                Err(error) => {
                                    tracing::warn!(%error, "discarding invalid signed contribution")
                                }
                            }
                        }
                        tracing::info!(
                            session_id = ceremony_id.0,
                            phase = ?phase,
                            "processed public DKG Gossip chunk"
                        );
                        if let Some(items) = state
                            .dkg_session_state
                            .public_contributions(&ceremony_id.0, attempt_id, phase)
                            .await
                        {
                            let expected = if phase == PublicPhase::RefreshHealthCheck {
                                1
                            } else {
                                prepare.total_participants as usize
                            };
                            if items.len() == expected {
                                let ids = contribution_ids(&items);
                                if transport::phase_root(ceremony_id, attempt_id, phase, &ids)
                                    != phase_root
                                {
                                    tracing::error!("public DKG phase root mismatch");
                                }
                            }
                        }
                    }
                    DkgPublicMessage::Manifest(manifest)
                        if manifest.ceremony_id == prepare.ceremony_id
                            && manifest.attempt_id == prepare.attempt_id =>
                    {
                        let expected_origins: BTreeSet<_> =
                            if manifest.phase == PublicPhase::RefreshHealthCheck {
                                prepare
                                    .node_id_assignments
                                    .get(&prepare.leader_node_key)
                                    .copied()
                                    .into_iter()
                                    .collect()
                            } else {
                                prepare.node_id_assignments.values().copied().collect()
                            };
                        if let Err(error) = manifest.validate(&expected_origins) {
                            tracing::warn!(%error, phase = ?manifest.phase,
                                "discarding invalid public DKG manifest");
                            continue;
                        }
                        tracing::debug!(phase = ?manifest.phase, chunks = manifest.chunk_count,
                            "received public DKG manifest");
                        let state = state.clone();
                        let prepare = prepare.clone();
                        tokio::spawn(async move {
                            sleep(DKG_REPAIR_STALL_INTERVAL).await;
                            if let Err(error) =
                                repair_public_phase(state, routes, prepare, manifest.phase, false)
                                    .await
                            {
                                tracing::warn!(%error, "public DKG completeness repair failed");
                            }
                        });
                    }
                    _ => tracing::debug!("discarding stale DKG Gossip message"),
                }
            }
            Ok(PubSubEvent::Lagged) => {
                tracing::warn!(
                    session_id = prepare.ceremony_id.0,
                    "DKG Gossip subscriber lagged; rejoining topic and running direct repair"
                );
                match rejoin_public_topic_with_retry(&state, &prepare, &leader_route, "rejoin_lag")
                    .await
                {
                    Ok(rejoined) => {
                        topic = rejoined;
                        neighbor_tracker.reset_after_rejoin();
                    }
                    Err(error) => {
                        tracing::warn!(%error, "failed to rejoin lagged DKG Gossip topic");
                        break;
                    }
                }
                for &phase in repairable_public_phases(&prepare.kind) {
                    let state = state.clone();
                    let prepare = prepare.clone();
                    tokio::spawn(async move {
                        if let Err(error) =
                            repair_public_phase(state, routes, prepare, phase, true).await
                        {
                            tracing::warn!(%error, "public DKG lag repair failed");
                        }
                    });
                }
            }
            Ok(PubSubEvent::NeighborUp(peer)) => {
                neighbor_tracker.neighbor_up(&peer);
            }
            Ok(PubSubEvent::NeighborDown(peer)) => {
                crate::metrics::record_dkg_hybrid_event("public", "neighbor_down");
                tracing::debug!(
                    session_id = prepare.ceremony_id.0,
                    peer = %hex::encode(peer.as_bytes()),
                    remaining_neighbors = neighbor_tracker.neighbor_count().saturating_sub(1),
                    "DKG Gossip neighbor disconnected"
                );
                neighbor_tracker.neighbor_down(&peer, Instant::now());
            }
            Err(error) => {
                tracing::warn!(%error, "DKG Gossip subscription ended; rejoining");
                match rejoin_public_topic_with_retry(
                    &state,
                    &prepare,
                    &leader_route,
                    "rejoin_subscription_error",
                )
                .await
                {
                    Ok(rejoined) => {
                        topic = rejoined;
                        neighbor_tracker.reset_after_rejoin();
                    }
                    Err(error) => {
                        tracing::warn!(%error, "failed to recover ended DKG Gossip subscription");
                        break;
                    }
                }
            }
        }
    }
}

async fn rejoin_public_topic<D>(
    state: &Arc<AppState<D>>,
    prepare: &PrepareSession,
    leader_route: &str,
) -> Result<Arc<dyn Topic>>
where
    D: CoordinatorDkg,
{
    let pubsub = state.network.pubsub().ok_or_else(|| {
        DkgError::InvalidState("network backend does not provide authenticated pub-sub".into())
    })?;
    let bootstrap = if state.node_key == prepare.leader_node_key {
        Vec::new()
    } else {
        vec![PeerId::from_bytes(leader_route.as_bytes())]
    };
    let topic = pubsub
        .subscribe(network::TopicId::new(prepare.topic_id), bootstrap)
        .await
        .map_err(|error| DkgError::NetworkCommunication(error.to_string()))?;
    if state
        .dkg_session_state
        .replace_hybrid_topic(&prepare.ceremony_id.0, prepare.attempt_id, topic.clone())
        .await
        != Some(true)
    {
        return Err(DkgError::ProtocolError(
            "cannot rejoin a stale DKG attempt".into(),
        ));
    }
    Ok(topic)
}

async fn rejoin_public_topic_with_retry<D>(
    state: &Arc<AppState<D>>,
    prepare: &PrepareSession,
    leader_route: &str,
    metric_event: &'static str,
) -> Result<Arc<dyn Topic>>
where
    D: CoordinatorDkg,
{
    let hard_deadline = state
        .dkg_session_state
        .hybrid_hard_deadline(&prepare.ceremony_id.0, prepare.attempt_id)
        .await
        .map(Instant::from_std)
        .ok_or_else(|| DkgError::SessionNotFound(prepare.ceremony_id.0.to_string()))?;
    let mut backoff = INITIAL_CONTROL_RETRY_BACKOFF;
    loop {
        if state
            .dkg_session_state
            .hybrid_attempt(&prepare.ceremony_id.0)
            .await
            != Some(prepare.attempt_id)
        {
            return Err(DkgError::ProtocolError(
                "cannot rejoin a stale DKG attempt".into(),
            ));
        }
        match rejoin_public_topic(state, prepare, leader_route).await {
            Ok(topic) => {
                crate::metrics::record_dkg_hybrid_event("public", metric_event);
                return Ok(topic);
            }
            Err(error) => {
                crate::metrics::record_dkg_hybrid_event("public", "rejoin_failure");
                tracing::warn!(
                    %error,
                    session_id = prepare.ceremony_id.0,
                    metric_event,
                    "DKG Gossip topic rejoin failed; retrying"
                );
            }
        }
        let remaining = hard_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(DkgError::NetworkCommunication(
                "DKG Gossip rejoin reached the hard attempt deadline".into(),
            ));
        }
        sleep(backoff.min(remaining)).await;
        backoff = (backoff * 2).min(DKG_MAX_REPAIR_BACKOFF);
    }
}

async fn repair_public_phase<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: PrepareSession,
    phase: PublicPhase,
    force_after_lag: bool,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    if !state
        .dkg_session_state
        .session_exists(&prepare.ceremony_id.0)
        .await
    {
        return Ok(());
    }
    let activated = state
        .dkg_session_state
        .hybrid_transport_info(&prepare.ceremony_id.0)
        .await
        .is_some_and(|(_, attempt_id, _, _, activated)| {
            attempt_id == prepare.attempt_id && activated
        });
    if !activated {
        return Ok(());
    }
    if !force_after_lag
        && !state
            .dkg_session_state
            .hybrid_repair_due(
                &prepare.ceremony_id.0,
                prepare.attempt_id,
                DKG_REPAIR_STALL_INTERVAL,
            )
            .await
    {
        return Ok(());
    }
    let expected = if phase == PublicPhase::RefreshHealthCheck {
        1
    } else {
        prepare.total_participants as usize
    };
    let present = state
        .dkg_session_state
        .public_contributions(&prepare.ceremony_id.0, prepare.attempt_id, phase)
        .await
        .map_or(0, |items| items.len());
    if prepare.leader_node_key == state.node_key {
        return Ok(());
    }
    if present >= expected {
        // Refresh results are promoted only by the explicit Commit control
        // barrier. Completeness repair may retain their signed bytes but must
        // never race that barrier by applying them on its own.
        if phase == PublicPhase::RefreshHealthCheck {
            return Ok(());
        }
        if let Some(items) = state
            .dkg_session_state
            .public_contributions(&prepare.ceremony_id.0, prepare.attempt_id, phase)
            .await
        {
            for signed in items.into_values() {
                let contribution = verify_signed_contribution(&state, &signed).await?;
                dispatch_public_contribution(state.clone(), routes, signed, contribution).await?;
            }
        }
        return Ok(());
    }
    tracing::info!(
        session_id = prepare.ceremony_id.0,
        phase = ?phase,
        present,
        expected,
        "requesting direct public DKG completeness repair"
    );
    let leader_peer = prepare
        .peer_node_keys
        .iter()
        .zip(prepare.peer_ids.iter())
        .find_map(|(key, peer)| (key == &prepare.leader_node_key).then_some(peer))
        .ok_or_else(|| DkgError::InvalidState("leader repair route is missing".into()))?;
    let response = control_request(
        &state,
        routes,
        leader_peer,
        DkgControlMessage::GetPublicPhase {
            ceremony_id: prepare.ceremony_id,
            attempt_id: prepare.attempt_id,
            phase,
        },
    )
    .await?;
    let DkgControlMessage::PublicPhaseResponse {
        ceremony_id,
        attempt_id,
        phase: response_phase,
        contributions,
    } = response
    else {
        return Err(DkgError::ProtocolError(
            "leader returned invalid public repair response".into(),
        ));
    };
    if ceremony_id != prepare.ceremony_id
        || attempt_id != prepare.attempt_id
        || response_phase != phase
    {
        return Err(DkgError::Unauthorized(
            "public repair response scope mismatch".into(),
        ));
    }
    // Some public phases are conditional (for example commitment audit on a
    // failed refresh) or have not started yet. An empty authenticated leader
    // response is not an omission claim; the periodic repair tick will ask
    // again if that phase later becomes active. Partial responses below still
    // trigger direct authenticated-origin repair for every missing item.
    if contributions.is_empty() {
        return Ok(());
    }
    for signed in contributions {
        let contribution = verify_signed_contribution(&state, &signed).await?;
        if contribution.payload.phase() != phase {
            return Err(DkgError::Unauthorized(
                "public repair returned wrong-phase contribution".into(),
            ));
        }
        if phase == PublicPhase::RefreshHealthCheck {
            record_public_contribution(&state, signed, &contribution).await?;
        } else {
            apply_public_contribution(state.clone(), routes, signed, contribution).await?;
        }
    }

    // A correct leader normally returns the complete phase. If it omitted an
    // item, fetch that exact signed contribution from its authenticated origin
    // rather than trusting the relay as the sole source of truth.
    let retained = state
        .dkg_session_state
        .public_contributions(&prepare.ceremony_id.0, prepare.attempt_id, phase)
        .await
        .unwrap_or_default();
    let expected_origins: Vec<u32> = if phase == PublicPhase::RefreshHealthCheck {
        vec![1]
    } else {
        (1..=prepare.total_participants).collect()
    };
    for origin_node_id in expected_origins {
        if retained.contains_key(&origin_node_id) {
            continue;
        }
        let origin_node_key = prepare
            .node_id_assignments
            .iter()
            .find_map(|(node_key, node_id)| (*node_id == origin_node_id).then_some(node_key))
            .ok_or_else(|| DkgError::InvalidState("origin repair node ID is unmapped".into()))?;
        let origin_peer = prepare
            .peer_node_keys
            .iter()
            .zip(prepare.peer_ids.iter())
            .find_map(|(node_key, peer)| (node_key == origin_node_key).then_some(peer))
            .ok_or_else(|| DkgError::InvalidState("origin repair peer route is missing".into()))?;
        let response = control_request(
            &state,
            routes,
            origin_peer,
            DkgControlMessage::GetPublicContribution {
                ceremony_id: prepare.ceremony_id,
                attempt_id: prepare.attempt_id,
                phase,
                origin_node_id,
            },
        )
        .await?;
        let DkgControlMessage::PublicContributionResponse {
            ceremony_id,
            attempt_id,
            contribution: Some(signed),
        } = response
        else {
            return Err(DkgError::ProtocolError(format!(
                "origin {origin_node_id} did not return its retained public contribution"
            )));
        };
        if ceremony_id != prepare.ceremony_id || attempt_id != prepare.attempt_id {
            return Err(DkgError::Unauthorized(
                "public origin repair response scope mismatch".into(),
            ));
        }
        let contribution = verify_signed_contribution(&state, &signed).await?;
        if contribution.origin_node_id != origin_node_id || contribution.payload.phase() != phase {
            return Err(DkgError::Unauthorized(
                "public origin repair returned the wrong contribution".into(),
            ));
        }
        if phase == PublicPhase::RefreshHealthCheck {
            record_public_contribution(&state, signed, &contribution).await?;
        } else {
            apply_public_contribution(state.clone(), routes, signed, contribution).await?;
        }
        crate::metrics::record_dkg_hybrid_event("public", "origin_repair");
    }

    let repaired = state
        .dkg_session_state
        .public_contributions(&prepare.ceremony_id.0, prepare.attempt_id, phase)
        .await
        .map_or(0, |items| items.len());
    if repaired < expected {
        return Err(DkgError::NetworkCommunication(format!(
            "public phase repair retained {repaired} of {expected} contributions"
        )));
    }
    crate::metrics::record_dkg_hybrid_event("public", "repair");
    tracing::info!(
        session_id = prepare.ceremony_id.0,
        phase = ?phase,
        "applied direct public DKG completeness repair"
    );
    Ok(())
}

async fn verify_signed_contribution<D>(
    state: &Arc<AppState<D>>,
    signed: &SignedPayload,
) -> Result<DkgPublicContribution>
where
    D: CoordinatorDkg,
{
    let pubsub = state.network.pubsub().ok_or_else(|| {
        DkgError::InvalidState("network backend does not provide authenticated pub-sub".into())
    })?;
    let verified = pubsub
        .verify(PUBLIC_CONTRIBUTION_SIGNING_DOMAIN, signed)
        .await
        .map_err(|error| DkgError::Unauthorized(error.to_string()))?;
    let contribution: DkgPublicContribution =
        transport::decode(&verified.data, MAX_CONTROL_MESSAGE_BYTES)
            .map_err(DkgError::Deserialization)?;
    contribution
        .validate_message_id()
        .map_err(DkgError::Unauthorized)?;
    let info = state
        .dkg_session_state
        .hybrid_transport_info(&contribution.ceremony_id.0)
        .await
        .ok_or_else(|| DkgError::SessionNotFound(contribution.ceremony_id.0.to_string()))?;
    if info.1 != contribution.attempt_id || info.2 != contribution.committee_digest {
        return Err(DkgError::Unauthorized(
            "stale or foreign public contribution".into(),
        ));
    }
    let expected_peer = state
        .dkg_session_state
        .get_peer_id_for_node(&contribution.ceremony_id.0, contribution.origin_node_id)
        .await
        .ok_or_else(|| {
            DkgError::Unauthorized("public contribution origin is not in committee".into())
        })?;
    if !peer_matches_route(&verified.origin, &expected_peer) {
        return Err(DkgError::Unauthorized(
            "public contribution endpoint identity does not match SourceHub NodeInfo".into(),
        ));
    }
    Ok(contribution)
}

async fn apply_public_contribution<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    signed: SignedPayload,
    contribution: DkgPublicContribution,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let _ = record_public_contribution(&state, signed.clone(), &contribution).await?;
    dispatch_public_contribution(state, routes, signed, contribution).await
}

async fn record_public_contribution<D>(
    state: &Arc<AppState<D>>,
    signed: SignedPayload,
    contribution: &DkgPublicContribution,
) -> Result<bool>
where
    D: CoordinatorDkg,
{
    let outcome = state
        .dkg_session_state
        .record_public_contribution(
            &contribution.ceremony_id.0,
            contribution.attempt_id,
            contribution.payload.phase(),
            contribution.origin_node_id,
            signed.clone(),
        )
        .await;
    match outcome {
        PublicContributionRecordOutcome::DuplicateSame => return Ok(false),
        PublicContributionRecordOutcome::Recorded => {}
        PublicContributionRecordOutcome::ConflictingDuplicate => {
            return Err(DkgError::ProtocolError(
                "conflicting duplicate public contribution".into(),
            ))
        }
        PublicContributionRecordOutcome::MissingSession => {
            return Err(DkgError::SessionNotFound(
                contribution.ceremony_id.0.to_string(),
            ))
        }
    }
    crate::metrics::record_dkg_hybrid_event("public", "contribution");
    Ok(true)
}

async fn dispatch_public_contribution<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    signed: SignedPayload,
    contribution: DkgPublicContribution,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let local_node_id = state
        .dkg_session_state
        .with_state(&contribution.ceremony_id.0, |session| {
            session.node.node_id()
        })
        .await
        .ok_or_else(|| DkgError::SessionNotFound(contribution.ceremony_id.0.to_string()))?;
    if local_node_id == contribution.origin_node_id {
        return Ok(());
    }
    let message = match contribution.payload {
        DkgPublicPayload::CommitmentHash { commitment_hash } => DkgMessage::CommitmentHash {
            session_id: contribution.ceremony_id.0,
            from_node_id: contribution.origin_node_id,
            commitment_hash,
        },
        DkgPublicPayload::Commitment {
            commitment,
            report_evidence,
        } => DkgMessage::Commitment {
            session_id: contribution.ceremony_id.0,
            from_node_id: contribution.origin_node_id,
            commitment,
            report_evidence,
        },
        DkgPublicPayload::CommitmentAudit { revealed } => DkgMessage::CommitmentAudit {
            session_id: contribution.ceremony_id.0,
            revealer_node_id: contribution.origin_node_id,
            revealed,
        },
        DkgPublicPayload::RefreshHealthCheckResult {
            statement,
            signature,
        } => DkgMessage::RefreshHealthCheckResult {
            session_id: contribution.ceremony_id.0,
            from_node_id: contribution.origin_node_id,
            statement,
            signature,
        },
    };
    Box::pin(
        DkgCoordinator::with_routes(state, routes)
            .handle_message(message, &signed.origin_peer_id()),
    )
    .await?;
    Ok(())
}

fn contribution_ids(items: &BTreeMap<u32, SignedPayload>) -> BTreeMap<u32, transport::MessageId> {
    items
        .iter()
        .filter_map(|(origin, signed)| {
            transport::decode::<DkgPublicContribution>(&signed.data, MAX_CONTROL_MESSAGE_BYTES)
                .ok()
                .map(|contribution| (*origin, contribution.message_id))
        })
        .collect()
}

async fn publish_phase_if_complete<D>(
    state: Arc<AppState<D>>,
    _routes: &'static network::ProtocolRoutes,
    session_id: u128,
    attempt_id: AttemptId,
    phase: PublicPhase,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let expected = if phase == PublicPhase::RefreshHealthCheck {
        1
    } else {
        state
            .dkg_session_state
            .with_state(&session_id, |session| session.node.total_nodes())
            .await
            .ok_or_else(|| DkgError::SessionNotFound(session_id.to_string()))?
    };
    if !state
        .dkg_session_state
        .claim_public_phase_publish(&session_id, attempt_id, phase, expected)
        .await
    {
        return Ok(());
    }
    if let Some(elapsed) = state
        .dkg_session_state
        .public_phase_collection_elapsed(&session_id, attempt_id, phase)
        .await
    {
        crate::metrics::record_dkg_public_transport(
            phase.as_metric_label(),
            "collection",
            elapsed.as_secs_f64(),
        );
    }
    let dissemination_start = Instant::now();
    let items = state
        .dkg_session_state
        .public_contributions(&session_id, attempt_id, phase)
        .await
        .ok_or_else(|| DkgError::SessionNotFound(session_id.to_string()))?;
    let ids = contribution_ids(&items);
    let ceremony_id = CeremonyId(session_id);
    let root = transport::phase_root(ceremony_id, attempt_id, phase, &ids);
    let chunks = transport::chunk_public_contributions(ceremony_id, attempt_id, phase, root, items)
        .map_err(DkgError::Serialization)?;
    let topic = state
        .dkg_session_state
        .hybrid_topic(&session_id)
        .await
        .ok_or_else(|| DkgError::InvalidState("hybrid topic is missing".into()))?;
    let manifest = DkgPublicMessage::Manifest(PhaseManifest {
        ceremony_id,
        attempt_id,
        phase,
        phase_root: root,
        contribution_ids: ids,
        chunk_count: chunks.len() as u32,
    });
    topic
        .broadcast(Bytes::from(
            transport::encode(&manifest).map_err(DkgError::Serialization)?,
        ))
        .await
        .map_err(|error| DkgError::NetworkCommunication(error.to_string()))?;
    for chunk in chunks {
        topic
            .broadcast(Bytes::from(
                transport::encode(&chunk).map_err(DkgError::Serialization)?,
            ))
            .await
            .map_err(|error| DkgError::NetworkCommunication(error.to_string()))?;
    }
    crate::metrics::record_dkg_public_transport(
        phase.as_metric_label(),
        "dissemination",
        dissemination_start.elapsed().as_secs_f64(),
    );
    crate::metrics::record_dkg_hybrid_event("public", "batch_published");
    tracing::info!(
        session_id,
        phase = ?phase,
        contribution_count = expected,
        "leader published canonical public DKG batch"
    );
    Ok(())
}

async fn send_refresh_result_barrier<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    peers: Vec<String>,
    request: DkgControlMessage,
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    message_id: MessageId,
    hard_deadline: Instant,
    step: &'static str,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let mut requests = JoinSet::new();
    for peer in peers {
        let state = state.clone();
        let request = request.clone();
        requests.spawn(async move {
            let mut backoff = INITIAL_CONTROL_RETRY_BACKOFF;
            let mut attempt = 0u32;
            loop {
                attempt = attempt.saturating_add(1);
                let now = Instant::now();
                if now >= hard_deadline {
                    return Err(DkgError::NetworkCommunication(format!(
                        "refresh-result {step} barrier reached the hard attempt deadline for peer {peer}"
                    )));
                }
                let remaining = hard_deadline.saturating_duration_since(now);
                let response = timeout(
                    remaining,
                    control_request(&state, routes, &peer, request.clone()),
                )
                .await;
                match response {
                    Ok(Ok(DkgControlMessage::PublicContributionAck {
                        ceremony_id: got_ceremony,
                        attempt_id: got_attempt,
                        message_id: got_message,
                    })) if got_ceremony == ceremony_id
                        && got_attempt == attempt_id
                        && got_message == message_id =>
                    {
                        return Ok(())
                    }
                    Ok(Ok(other)) => tracing::warn!(
                        peer = %peer,
                        step,
                        attempt,
                        response = ?other,
                        "refresh-result barrier received an invalid acknowledgement"
                    ),
                    Ok(Err(error)) => tracing::warn!(
                        peer = %peer,
                        step,
                        attempt,
                        %error,
                        "refresh-result barrier control request failed; retrying"
                    ),
                    Err(_) => {
                        return Err(DkgError::NetworkCommunication(format!(
                            "refresh-result {step} barrier reached the hard attempt deadline for peer {peer}"
                        )))
                    }
                }
                crate::metrics::record_dkg_hybrid_event("control", "retry");
                let remaining = hard_deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    continue;
                }
                sleep(backoff.min(remaining)).await;
                backoff = (backoff * 2).min(DKG_MAX_REPAIR_BACKOFF);
            }
        });
    }
    while let Some(result) = requests.join_next().await {
        result.map_err(|error| DkgError::NetworkCommunication(error.to_string()))??;
    }
    Ok(())
}

async fn distribute_refresh_result<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    session_id: u128,
    signed: SignedPayload,
    contribution: &DkgPublicContribution,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let peers = state
        .dkg_session_state
        .get_peer_ids(&session_id)
        .await
        .ok_or_else(|| DkgError::SessionNotFound(session_id.to_string()))?
        .into_iter()
        .filter(|peer| !is_self_peer_id(&state.network, peer))
        .collect::<Vec<_>>();
    let hard_deadline = state
        .dkg_session_state
        .hybrid_hard_deadline(&session_id, contribution.attempt_id)
        .await
        .ok_or_else(|| DkgError::InvalidState("hybrid hard deadline is missing".into()))?
        .into();

    send_refresh_result_barrier(
        state.clone(),
        routes,
        peers.clone(),
        DkgControlMessage::StageRefreshResult(signed),
        contribution.ceremony_id,
        contribution.attempt_id,
        contribution.message_id,
        hard_deadline,
        "stage",
    )
    .await?;
    crate::metrics::record_dkg_hybrid_event("public", "result_stage_barrier");

    publish_phase_if_complete(
        state.clone(),
        routes,
        session_id,
        contribution.attempt_id,
        PublicPhase::RefreshHealthCheck,
    )
    .await?;

    send_refresh_result_barrier(
        state,
        routes,
        peers,
        DkgControlMessage::CommitRefreshResult {
            ceremony_id: contribution.ceremony_id,
            attempt_id: contribution.attempt_id,
            message_id: contribution.message_id,
        },
        contribution.ceremony_id,
        contribution.attempt_id,
        contribution.message_id,
        hard_deadline,
        "commit",
    )
    .await?;
    crate::metrics::record_dkg_hybrid_event("public", "result_commit_barrier");
    Ok(())
}

/// Sign and submit one public contribution, retaining exact bytes until the
/// leader acknowledges it.
pub(crate) async fn submit_public_contribution<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    payload: DkgPublicPayload,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let (ceremony_id, attempt_id, committee_digest, leader, activated) = coord
        .app_state
        .dkg_session_state
        .hybrid_transport_info(&session_id)
        .await
        .ok_or_else(|| DkgError::InvalidState("session is not using hybrid transport".into()))?;
    if !activated {
        return Err(DkgError::ProtocolError(
            "public contribution generated before attempt activation".into(),
        ));
    }
    let node_id = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |session| session.node.node_id())
        .await
        .ok_or_else(|| DkgError::SessionNotFound(session_id.to_string()))?;
    let ring_id = coord
        .app_state
        .dkg_session_state
        .ring_id_for_session(&session_id)
        .await
        .ok_or_else(|| DkgError::InvalidState("session ring ID is missing".into()))?;
    let contribution = DkgPublicContribution::new(
        ceremony_id,
        attempt_id,
        ring_id,
        committee_digest,
        node_id,
        payload,
    )
    .map_err(DkgError::Serialization)?;
    let encoded = transport::encode(&contribution).map_err(DkgError::Serialization)?;
    let pubsub = coord.app_state.network.pubsub().ok_or_else(|| {
        DkgError::InvalidState("network backend does not provide authenticated pub-sub".into())
    })?;
    let signed = pubsub
        .sign(PUBLIC_CONTRIBUTION_SIGNING_DOMAIN, Bytes::from(encoded))
        .await
        .map_err(|error| DkgError::NetworkCommunication(error.to_string()))?;
    tracing::info!(
        session_id,
        node_id,
        phase = ?contribution.payload.phase(),
        leader = %leader,
        "submitting signed public DKG contribution"
    );
    // Retain the exact signed bytes in the same phase index used for direct
    // repair. This lets an origin serve its own contribution even if the
    // leader omits a chunk or the local subscriber never receives the relay.
    record_public_contribution(&coord.app_state, signed.clone(), &contribution).await?;
    if leader == coord.app_state.node_key {
        if contribution.payload.phase() == PublicPhase::RefreshHealthCheck {
            return distribute_refresh_result(
                coord.app_state.clone(),
                coord.routes,
                session_id,
                signed,
                &contribution,
            )
            .await;
        }
        apply_public_contribution(
            coord.app_state.clone(),
            coord.routes,
            signed,
            contribution.clone(),
        )
        .await?;
        return publish_phase_if_complete(
            coord.app_state.clone(),
            coord.routes,
            session_id,
            attempt_id,
            contribution.payload.phase(),
        )
        .await;
    }
    let keys = coord
        .app_state
        .dkg_session_state
        .get_peer_node_keys(&session_id)
        .await
        .unwrap_or_default();
    let peers = coord
        .app_state
        .dkg_session_state
        .get_peer_ids(&session_id)
        .await
        .unwrap_or_default();
    let leader_peer = keys
        .iter()
        .zip(peers.iter())
        .find_map(|(key, peer)| (key == &leader).then_some(peer))
        .ok_or_else(|| DkgError::InvalidState("leader peer route is missing".into()))?;
    match control_request(
        &coord.app_state,
        coord.routes,
        leader_peer,
        DkgControlMessage::PublicContribution(signed),
    )
    .await?
    {
        DkgControlMessage::PublicContributionAck {
            ceremony_id: got_ceremony,
            attempt_id: got_attempt,
            message_id,
        } if got_ceremony == ceremony_id
            && got_attempt == attempt_id
            && message_id == contribution.message_id =>
        {
            Ok(())
        }
        response => Err(DkgError::ProtocolError(format!(
            "invalid public contribution ACK: {response:?}"
        ))),
    }
}

/// Inbound handler for one deterministic bidirectional private pair exchange.
pub struct HybridPrivateHandler<D>
where
    D: CoordinatorDkg,
{
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
}

impl<D> HybridPrivateHandler<D>
where
    D: CoordinatorDkg,
{
    pub fn new(state: Arc<AppState<D>>, routes: &'static network::ProtocolRoutes) -> Self {
        Self { state, routes }
    }
}

#[async_trait]
impl<D> ProtocolHandler for HybridPrivateHandler<D>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    async fn handle(&self, connection: Box<dyn Connection>) -> network::Result<()> {
        let peer = connection.peer_id().clone();
        let peer_prefix: String = String::from_utf8_lossy(peer.as_bytes())
            .chars()
            .take(12)
            .collect();
        let first = timeout(PEER_RESPONSE_TIMEOUT, recv_private(&*connection))
            .await
            .map_err(|_| {
                network::error::NetworkError::Protocol(format!(
                    "private pair opener {peer_prefix} did not send its first message within {}ms",
                    PEER_RESPONSE_TIMEOUT.as_millis()
                ))
            })??;
        let DkgPrivateMessage::ShareDelivery {
            ceremony_id,
            attempt_id,
            message_id: incoming_id,
            from_node_id,
            to_node_id,
            share_value,
            nonce,
            report_evidence,
        } = first
        else {
            return Err(network::error::NetworkError::Protocol(
                "private pair exchange must start with ShareDelivery".into(),
            ));
        };
        let session_id = ceremony_id.0;
        if !transport::is_canonical_pair_opener(from_node_id, to_node_id) {
            return Err(network::error::NetworkError::Protocol(
                "private pair exchange was opened by the non-canonical endpoint".into(),
            ));
        }
        let incoming = DkgPrivateMessage::ShareDelivery {
            ceremony_id,
            attempt_id,
            message_id: incoming_id,
            from_node_id,
            to_node_id,
            share_value,
            nonce,
            report_evidence,
        };
        validate_private_delivery(&self.state, &incoming, &peer)
            .await
            .map_err(|error| network::error::NetworkError::Protocol(error.to_string()))?;
        let semaphore = self.state.dkg_private_exchange_permits.clone();
        let permit = match timeout(PRIVATE_INBOUND_QUEUE_WAIT, semaphore.acquire_owned()).await {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => {
                return Err(network::error::NetworkError::Protocol(
                    "private exchange semaphore closed".into(),
                ));
            }
            Err(_) => {
                crate::metrics::record_dkg_hybrid_event("private", "busy");
                send_private_busy(
                    &*connection,
                    self.routes.dkg_private_alpn,
                    ceremony_id,
                    attempt_id,
                )
                .await?;
                return Ok(());
            }
        };
        let pair_metrics = PrivatePairMetricsGuard::new();
        tracing::info!(
            session_id,
            from_node_id,
            to_node_id,
            "accepted inbound private DKG pair exchange"
        );
        let Some(outgoing_bytes) = self
            .state
            .dkg_session_state
            .private_message_for_recipient(&session_id, from_node_id)
            .await
        else {
            send_private_busy(
                &*connection,
                self.routes.dkg_private_alpn,
                ceremony_id,
                attempt_id,
            )
            .await?;
            return Ok(());
        };
        let outgoing: DkgPrivateMessage =
            transport::decode(&outgoing_bytes, MAX_CONTROL_MESSAGE_BYTES)
                .map_err(network::error::NetworkError::Serialization)?;
        let completion = timeout(PEER_RESPONSE_TIMEOUT, async {
            send_private(&*connection, self.routes.dkg_private_alpn, &outgoing).await?;
            let ack = recv_private(&*connection).await?;
            validate_share_ack(&outgoing, &ack).map_err(network::error::NetworkError::Protocol)?;
            if let DkgPrivateMessage::ShareAck { message_id, .. } = ack {
                self.state
                    .dkg_session_state
                    .acknowledge_private_message(&session_id, attempt_id, message_id)
                    .await;
            }
            let completion =
                accept_private_delivery(self.state.clone(), self.routes, &incoming, &peer)
                    .await
                    .map_err(|error| network::error::NetworkError::Protocol(error.to_string()))?;
            let incoming_ack =
                share_ack_for(&incoming).map_err(network::error::NetworkError::Protocol)?;
            send_private(&*connection, self.routes.dkg_private_alpn, &incoming_ack).await?;
            Ok::<PrivateShareCompletion, network::error::NetworkError>(completion)
        })
        .await
        .map_err(|_| {
            crate::metrics::record_dkg_hybrid_event("private", "inbound_timeout");
            network::error::NetworkError::Protocol(format!(
                "inbound private pair exchange with {peer_prefix} timed out after {}ms",
                PEER_RESPONSE_TIMEOUT.as_millis()
            ))
        })??;
        drop(permit);
        pair_metrics.complete();
        crate::metrics::record_dkg_hybrid_event("private", "pair_completed");
        drive_private_completion(self.state.clone(), self.routes, completion)
            .await
            .map_err(|error| network::error::NetworkError::Protocol(error.to_string()))?;
        Ok(())
    }
}

async fn send_private(
    connection: &dyn Connection,
    alpn: &[u8],
    message: &DkgPrivateMessage,
) -> network::Result<()> {
    let bytes = transport::encode(message).map_err(network::error::NetworkError::Serialization)?;
    connection.send(Message::new(bytes, alpn.to_vec())).await
}

async fn send_private_busy(
    connection: &dyn Connection,
    alpn: &[u8],
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
) -> network::Result<()> {
    timeout(
        PEER_RESPONSE_TIMEOUT,
        send_private(
            connection,
            alpn,
            &DkgPrivateMessage::Busy {
                ceremony_id,
                attempt_id,
                retry_after_ms: PRIVATE_BUSY_RETRY_AFTER.as_millis() as u64,
            },
        ),
    )
    .await
    .map_err(|_| {
        network::error::NetworkError::Protocol(format!(
            "sending private Busy response timed out after {}ms",
            PEER_RESPONSE_TIMEOUT.as_millis()
        ))
    })?
}

async fn recv_private(connection: &dyn Connection) -> network::Result<DkgPrivateMessage> {
    let message = connection.recv().await?;
    transport::decode(&message.data, MAX_CONTROL_MESSAGE_BYTES)
        .map_err(network::error::NetworkError::Serialization)
}

fn share_ack_for(message: &DkgPrivateMessage) -> std::result::Result<DkgPrivateMessage, String> {
    let DkgPrivateMessage::ShareDelivery {
        ceremony_id,
        attempt_id,
        message_id,
        from_node_id,
        to_node_id,
        share_value,
        nonce,
        ..
    } = message
    else {
        return Err("cannot acknowledge a non-share private message".into());
    };
    Ok(DkgPrivateMessage::ShareAck {
        ceremony_id: *ceremony_id,
        attempt_id: *attempt_id,
        message_id: *message_id,
        share_digest: transport::share_digest(
            *ceremony_id,
            *attempt_id,
            *from_node_id,
            *to_node_id,
            share_value,
            nonce,
        ),
    })
}

fn validate_share_ack(
    delivery: &DkgPrivateMessage,
    ack: &DkgPrivateMessage,
) -> std::result::Result<(), String> {
    let expected = share_ack_for(delivery)?;
    if &expected != ack {
        return Err("private share acknowledgement digest or attempt did not match".into());
    }
    Ok(())
}

async fn validate_private_delivery<D>(
    state: &Arc<AppState<D>>,
    message: &DkgPrivateMessage,
    sender: &PeerId,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let DkgPrivateMessage::ShareDelivery {
        ceremony_id,
        attempt_id,
        message_id,
        from_node_id,
        to_node_id,
        share_value,
        nonce,
        ..
    } = message
    else {
        return Err(DkgError::ProtocolError(
            "expected private ShareDelivery".into(),
        ));
    };
    let (expected_ceremony, expected_attempt, _, _, activated) = state
        .dkg_session_state
        .hybrid_transport_info(&ceremony_id.0)
        .await
        .ok_or_else(|| DkgError::SessionNotFound(ceremony_id.0.to_string()))?;
    if expected_ceremony != *ceremony_id || expected_attempt != *attempt_id || !activated {
        return Err(DkgError::Unauthorized(
            "stale or inactive private exchange".into(),
        ));
    }
    let local_node_id = state
        .dkg_session_state
        .with_state(&ceremony_id.0, |session| session.node.node_id())
        .await
        .ok_or_else(|| DkgError::SessionNotFound(ceremony_id.0.to_string()))?;
    if local_node_id != *to_node_id {
        return Err(DkgError::Unauthorized(
            "private share delivered to wrong recipient".into(),
        ));
    }
    let expected_sender = state
        .dkg_session_state
        .get_peer_id_for_node(&ceremony_id.0, *from_node_id)
        .await
        .ok_or_else(|| DkgError::Unauthorized("private share sender is not in committee".into()))?;
    if !peer_matches_route(sender, &expected_sender) {
        return Err(DkgError::Unauthorized(
            "private share sender does not match SourceHub NodeInfo".into(),
        ));
    }
    let expected_id = transport::derive_private_message_id(
        *ceremony_id,
        *attempt_id,
        *from_node_id,
        *to_node_id,
        share_value,
        nonce,
    );
    if expected_id != *message_id {
        return Err(DkgError::Unauthorized(
            "private share message ID mismatch".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct PrivateShareCompletion {
    session_id: u128,
    from_node_id: u32,
    should_drive: bool,
}

async fn accept_private_delivery<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    message: &DkgPrivateMessage,
    sender: &PeerId,
) -> Result<PrivateShareCompletion>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let DkgPrivateMessage::ShareDelivery {
        ceremony_id,
        from_node_id,
        to_node_id,
        share_value,
        nonce,
        report_evidence,
        ..
    } = message.clone()
    else {
        return Err(DkgError::ProtocolError(
            "expected private ShareDelivery".into(),
        ));
    };
    let should_drive = DkgCoordinator::with_routes(state, routes)
        .accept_private_share(
            DkgMessage::Share {
                session_id: ceremony_id.0,
                from_node_id,
                to_node_id,
                share_value,
                nonce,
                report_evidence,
            },
            sender,
        )
        .await?;
    Ok(PrivateShareCompletion {
        session_id: ceremony_id.0,
        from_node_id,
        should_drive,
    })
}

async fn drive_private_completion<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    completion: PrivateShareCompletion,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    if completion.should_drive {
        drive_private_share_completion(
            &DkgCoordinator::with_routes(state, routes),
            completion.session_id,
            completion.from_node_id,
        )
        .await?;
    }
    Ok(())
}

/// Return a retry delay that is stable for one pair/attempt but changes for the
/// next retry. Busy responses are treated as a minimum wait, while the growing
/// local backoff supplies a widening jitter window. This prevents a committee
/// burst from repeatedly hitting the same recipient in synchronized waves.
fn private_retry_delay(
    message_id: MessageId,
    retry_attempt: u32,
    backoff: Duration,
    busy_retry_after: Option<Duration>,
    remaining: Duration,
) -> Duration {
    let (floor, ceiling) = if let Some(retry_after) = busy_retry_after {
        let floor = retry_after.min(DKG_MAX_REPAIR_BACKOFF);
        (
            floor,
            floor.saturating_add(backoff).min(DKG_MAX_REPAIR_BACKOFF),
        )
    } else {
        (backoff / 2, backoff)
    };
    let floor_ms = floor.as_millis() as u64;
    let ceiling_ms = ceiling.as_millis() as u64;
    let spread_ms = ceiling_ms.saturating_sub(floor_ms);

    let mut seed_bytes = [0_u8; 8];
    seed_bytes.copy_from_slice(&message_id.0[..8]);
    let mut value = u64::from_le_bytes(seed_bytes)
        ^ u64::from(retry_attempt).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    // SplitMix64 gives a deterministic, well-distributed word without adding a
    // random generator to the hot path or making retry tests nondeterministic.
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^= value >> 31;

    let jitter_ms = if spread_ms == 0 {
        0
    } else {
        value % (spread_ms + 1)
    };
    Duration::from_millis(floor_ms.saturating_add(jitter_ms)).min(remaining)
}

async fn open_private_pair<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    peer: String,
    outgoing_bytes: Vec<u8>,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let outgoing: DkgPrivateMessage = transport::decode(&outgoing_bytes, MAX_CONTROL_MESSAGE_BYTES)
        .map_err(DkgError::Deserialization)?;
    let DkgPrivateMessage::ShareDelivery {
        ceremony_id,
        attempt_id,
        message_id,
        ..
    } = outgoing.clone()
    else {
        return Err(DkgError::InvalidState(
            "cached private message is not a share".into(),
        ));
    };
    let deadline: Instant = state
        .dkg_session_state
        .hybrid_hard_deadline(&ceremony_id.0, attempt_id)
        .await
        .ok_or_else(|| DkgError::InvalidState("hybrid hard deadline is missing".into()))?
        .into();
    let mut backoff = INITIAL_PRIVATE_RETRY_BACKOFF;
    let mut retry_attempt = 0_u32;
    loop {
        if Instant::now() >= deadline {
            return Err(DkgError::NetworkCommunication(format!(
                "private pair exchange with {peer} exceeded hard attempt deadline"
            )));
        }
        let semaphore = state.dkg_private_exchange_permits.clone();
        let remaining = deadline.saturating_duration_since(Instant::now());
        let permit = timeout(remaining, semaphore.acquire_owned())
            .await
            .map_err(|_| {
                DkgError::NetworkCommunication(format!(
                    "private pair exchange with {peer} exceeded hard attempt deadline"
                ))
            })?
            .map_err(|_| DkgError::InvalidState("private exchange semaphore closed".into()))?;
        let pair_metrics = PrivatePairMetricsGuard::new();
        tracing::info!(
            session_id = ceremony_id.0,
            %peer,
            "opening private DKG pair exchange"
        );
        // A connect or response can disappear without producing an I/O error.  Bound
        // each individual stream attempt so the cached share is retried long before
        // the ceremony's hard deadline.  The outer loop retains the exact serialized
        // bytes and exponential backoff, so a retry never regenerates crypto material.
        let attempt_timeout =
            PEER_RESPONSE_TIMEOUT.min(deadline.saturating_duration_since(Instant::now()));
        let mut busy_retry_after = None;
        let exchange = timeout(attempt_timeout, async {
            let stream = state
                .peer_connection_pool
                .open_stream(&state.network, &peer, routes.dkg_private_alpn)
                .await
                .map_err(|error| DkgError::NetworkConnection(error.to_string()))?;
            let remote = stream.peer_id().clone();
            stream
                .send(Message::new(
                    outgoing_bytes.clone(),
                    routes.dkg_private_alpn.to_vec(),
                ))
                .await
                .map_err(|error| DkgError::NetworkCommunication(error.to_string()))?;
            let response = recv_private(&*stream)
                .await
                .map_err(|error| DkgError::NetworkCommunication(error.to_string()))?;
            if let DkgPrivateMessage::Busy {
                ceremony_id: busy_ceremony_id,
                attempt_id: busy_attempt_id,
                retry_after_ms,
            } = response
            {
                if busy_ceremony_id != ceremony_id || busy_attempt_id != attempt_id {
                    return Err(DkgError::ProtocolError(
                        "private Busy response did not match the active attempt".into(),
                    ));
                }
                busy_retry_after = Some(Duration::from_millis(retry_after_ms.max(1)));
                return Err(DkgError::NetworkCommunication("private peer busy".into()));
            }
            validate_private_delivery(&state, &response, &remote).await?;
            let completion =
                accept_private_delivery(state.clone(), routes, &response, &remote).await?;
            let ack = share_ack_for(&response).map_err(DkgError::ProtocolError)?;
            send_private(&*stream, routes.dkg_private_alpn, &ack)
                .await
                .map_err(|error| DkgError::NetworkCommunication(error.to_string()))?;
            let final_ack = recv_private(&*stream)
                .await
                .map_err(|error| DkgError::NetworkCommunication(error.to_string()))?;
            validate_share_ack(&outgoing, &final_ack).map_err(DkgError::ProtocolError)?;
            state
                .dkg_session_state
                .acknowledge_private_message(&ceremony_id.0, attempt_id, message_id)
                .await;
            Ok(completion)
        })
        .await
        .unwrap_or_else(|_| {
            Err(DkgError::NetworkCommunication(format!(
                "private pair exchange with {peer} timed out after {}ms",
                attempt_timeout.as_millis()
            )))
        });
        drop(permit);
        match exchange {
            Ok(completion) => {
                pair_metrics.complete();
                crate::metrics::record_dkg_hybrid_event("private", "pair_completed");
                tracing::info!(
                    session_id = ceremony_id.0,
                    %peer,
                    "private DKG pair exchange completed"
                );
                drive_private_completion(state.clone(), routes, completion).await?;
                return Ok(());
            }
            Err(error) => {
                drop(pair_metrics);
                crate::metrics::record_dkg_hybrid_event("private", "retry");
                let remaining = deadline.saturating_duration_since(Instant::now());
                let retry_delay = private_retry_delay(
                    message_id,
                    retry_attempt,
                    backoff,
                    busy_retry_after,
                    remaining,
                );
                tracing::debug!(%peer, %error, backoff_ms = backoff.as_millis(),
                    retry_delay_ms = retry_delay.as_millis(),
                    retry_attempt,
                    "retrying private pair exchange with identical cached share");
                sleep(retry_delay).await;
                retry_attempt = retry_attempt.saturating_add(1);
                backoff = (backoff * 2).min(DKG_MAX_REPAIR_BACKOFF);
            }
        }
    }
}

/// Exchange every cached recipient-specific share through one deterministic
/// bidirectional stream per unordered pair. The lower node ID opens the stream;
/// both directions are digest-acknowledged before the stream closes.
pub(crate) async fn exchange_private_shares<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    outgoing: Vec<(u32, String, MessageId, Vec<u8>)>,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let local_node_id = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |session| session.node.node_id())
        .await
        .ok_or_else(|| DkgError::SessionNotFound(session_id.to_string()))?;
    let mut openers = FuturesUnordered::new();
    let all_message_ids: Vec<_> = outgoing.iter().map(|(_, _, id, _)| *id).collect();
    for (to_node_id, peer, _, bytes) in outgoing {
        if transport::is_canonical_pair_opener(local_node_id, to_node_id) {
            let state = coord.app_state.clone();
            let routes = coord.routes;
            openers.push(async move { open_private_pair(state, routes, peer, bytes).await });
        }
    }
    while let Some(result) = openers.next().await {
        result?;
    }
    let attempt_id = coord
        .app_state
        .dkg_session_state
        .hybrid_attempt(&session_id)
        .await
        .ok_or_else(|| DkgError::InvalidState("hybrid attempt is missing".into()))?;
    let deadline: Instant = coord
        .app_state
        .dkg_session_state
        .hybrid_hard_deadline(&session_id, attempt_id)
        .await
        .ok_or_else(|| DkgError::InvalidState("hybrid hard deadline is missing".into()))?
        .into();
    loop {
        let mut missing = 0usize;
        for message_id in &all_message_ids {
            if !coord
                .app_state
                .dkg_session_state
                .private_message_acknowledged(&session_id, *message_id)
                .await
            {
                missing += 1;
            }
        }
        if missing == 0 {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(DkgError::NetworkCommunication(format!(
                "{missing} private pair exchanges were not acknowledged before hard deadline"
            )));
        }
        sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(test)]
mod stability_tests {
    use super::*;

    #[test]
    fn neighbor_churn_only_schedules_rejoin_after_sustained_full_isolation() {
        let peer_a = PeerId::from_bytes(b"peer-a");
        let peer_b = PeerId::from_bytes(b"peer-b");
        let now = Instant::now();
        let mut tracker = GossipNeighborTracker::default();

        tracker.neighbor_up(&peer_a);
        tracker.neighbor_up(&peer_b);
        assert!(tracker.neighbor_down(&peer_a, now));
        assert_eq!(tracker.neighbor_count(), 1);
        assert_eq!(tracker.isolation_deadline(), None);

        assert!(tracker.neighbor_down(&peer_b, now));
        assert!(tracker.is_isolated());
        assert_eq!(
            tracker.isolation_deadline(),
            Some(now + DKG_GOSSIP_ISOLATION_GRACE)
        );

        tracker.neighbor_up(&peer_a);
        assert!(!tracker.is_isolated());
        assert_eq!(tracker.isolation_deadline(), None);
    }

    #[test]
    fn rejoin_reset_does_not_treat_initial_empty_topic_as_isolated() {
        let peer = PeerId::from_bytes(b"peer");
        let mut tracker = GossipNeighborTracker::default();
        tracker.neighbor_up(&peer);
        tracker.neighbor_down(&peer, Instant::now());
        assert!(tracker.is_isolated());

        tracker.reset_after_rejoin();
        assert!(!tracker.is_isolated());
        assert_eq!(tracker.neighbor_count(), 0);
        assert_eq!(tracker.isolation_deadline(), None);
    }

    #[test]
    fn control_timeout_includes_operation_peer_and_attempt_scope() {
        let request = DkgControlMessage::TopologyProbeAck {
            ceremony_id: CeremonyId(42),
            attempt_id: AttemptId([7; 32]),
            nonce: [9; 32],
        };
        let message = control_timeout_message(
            "0123456789abcdef@127.0.0.1:9000",
            &request,
            PEER_RESPONSE_TIMEOUT,
        );
        assert!(message.contains("topology-probe-ack"));
        assert!(message.contains("0123456789ab"));
        assert!(message.contains("ceremony=42"));
        assert!(message.contains("attempt=070707070707"));
    }

    #[test]
    fn missing_topology_members_are_exact_and_prefixes_are_bounded() {
        let expected = BTreeSet::from([
            "aaaaaaaaaaaaaaaa".to_string(),
            "bbbbbbbbbbbbbbbb".to_string(),
            "cccccccccccccccc".to_string(),
        ]);
        let acknowledged = BTreeSet::from([
            "aaaaaaaaaaaaaaaa".to_string(),
            "cccccccccccccccc".to_string(),
        ]);
        let missing = missing_topology_peers(&expected, &acknowledged);
        assert_eq!(missing, vec!["bbbbbbbbbbbbbbbb"]);
        assert_eq!(missing_topology_peer_prefixes(&missing), "bbbbbbbbbbbb");
    }

    #[test]
    fn private_busy_retries_honor_hint_and_desynchronize_pairs() {
        let backoff = Duration::from_secs(1);
        let busy_hint = Duration::from_millis(250);
        let remaining = Duration::from_secs(30);
        let first = private_retry_delay(MessageId([1; 32]), 0, backoff, Some(busy_hint), remaining);
        let second_pair =
            private_retry_delay(MessageId([2; 32]), 0, backoff, Some(busy_hint), remaining);
        let next_attempt =
            private_retry_delay(MessageId([1; 32]), 1, backoff, Some(busy_hint), remaining);

        assert!(first >= busy_hint);
        assert!(first <= busy_hint + backoff);
        assert_ne!(first, second_pair);
        assert_ne!(first, next_attempt);
    }

    #[test]
    fn private_retry_delay_never_exceeds_deadline_or_global_cap() {
        let remaining = Duration::from_millis(17);
        assert_eq!(
            private_retry_delay(
                MessageId([3; 32]),
                99,
                DKG_MAX_REPAIR_BACKOFF,
                Some(Duration::from_secs(300)),
                remaining,
            ),
            remaining
        );
    }
}
