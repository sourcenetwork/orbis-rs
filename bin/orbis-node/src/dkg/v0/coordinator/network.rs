use crate::app_state::AppState;
use crate::dkg::v0::error::{DkgError, Result};
use crate::dkg::v0::helpers::session_not_found;
use crate::dkg::v0::messages::{DkgMessage, SessionKind};
use crate::helpers::identity::extract_node_part;
use crate::helpers::node_routes::{peer_ids_from_routes, resolve_node_routes};
use crate::metrics;
use crate::reporting::v0::observation::{
    is_reportable_dkg_offline_error, offline_observation_from_peer_routes, ReportObservation,
};
use crate::reporting::v0::queue_report;
use crate::reporting::v0::types::CommitteeScope as ReportCommitteeScope;
use crate::ring_state::RingPolyState;
use bulletin::r#trait::{BulletinKind, RingPayload};
use crypto::r#trait::{DistKeyShare, Dkg, PubShare, ThresholdSigner};
use crypto::{
    GroupAffine as G1Affine, PolynomialCommitmentImpl as PolynomialCommitment,
    PubPolyImpl as PubPoly, ScalarField as Fr, SigShareInner, SignImpl, SignaturePoint,
};
use network::{Connection as NetworkConnection, Message as NetworkMessage};
use std::sync::Arc;

use super::DkgCoordinator;

async fn send_on_stream(
    stream: &Arc<dyn NetworkConnection>,
    peer_id_str: &str,
    message_data: &[u8],
    alpn: &'static [u8],
) -> Result<()> {
    stream
        .send(NetworkMessage::new(message_data.to_vec(), alpn))
        .await
        .map_err(|e| {
            DkgError::NetworkCommunication(format!("Failed to send to peer {}: {}", peer_id_str, e))
        })
}

async fn get_cached_or_open_stream<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    peer_id_str: &str,
) -> Result<(Arc<dyn NetworkConnection>, bool)>
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
    SignImpl: ThresholdSigner<
            ShareValue = Fr,
            PublicKey = G1Affine,
            DistKeyShare = DistKeyShare<Fr>,
            PubPoly = D::PubPoly,
            Signature = SignaturePoint,
            SigShare = PubShare<SigShareInner>,
        > + Send
        + Sync
        + 'static,
{
    if let Some(cached) = coord
        .app_state
        .dkg_session_state
        .get_peer_stream(&session_id, peer_id_str)
        .await
    {
        Ok((cached, true))
    } else {
        Ok((
            Arc::from(coord.open_stream_to_peer(peer_id_str).await?),
            false,
        ))
    }
}

async fn ensure_session_generation<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    generation: u64,
) -> Result<()>
where
    D: Dkg<
            ShareValue = Fr,
            PublicKey = G1Affine,
            PolynomialCommitment = PolynomialCommitment,
            PubPoly = PubPoly,
        > + Clone
        + 'static,
{
    let session_identity = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| {
            (state.generation, state.protocol_version)
        })
        .await;
    match session_identity {
        Some((current_generation, protocol_version))
            if current_generation == generation && protocol_version == coord.routes.version =>
        {
            Ok(())
        }
        Some((_, protocol_version)) if protocol_version != coord.routes.version => {
            Err(DkgError::ProtocolError(format!(
                "DKG session {} is pinned to protocol version {}, but outbound message used version {}",
                session_id, protocol_version, coord.routes.version
            )))
        }
        _ => Err(session_not_found(session_id)),
    }
}

/// Send a DKG message to a peer.
///
/// When `session_id` is `Some`, the stream is cached in the session state so that
/// messages to the same peer normally travel on the same QUIC stream under one
/// per-peer send lock. This preserves local send order for that peer, but a stream
/// replacement or cross-peer delivery can still make valid messages arrive before
/// dependent local state is visible.
///
/// When `session_id` is `None`, a fresh stream is opened and dropped after the send.
///
/// On connection-open failure the cached connection is evicted and a new one
/// is established before retrying.
pub(super) async fn send_message_to_peer<D>(
    coord: &DkgCoordinator<D>,
    peer_id_str: &str,
    message: DkgMessage,
    session_id: Option<u128>,
) -> Result<()>
where
    D: Dkg<
            ShareValue = Fr,
            PublicKey = G1Affine,
            PolynomialCommitment = PolynomialCommitment,
            PubPoly = PubPoly,
        > + Clone
        + 'static,
{
    let message_type = match &message {
        DkgMessage::SessionInit { .. } => "session_init",
        DkgMessage::Commitment { .. } => "commitment",
        DkgMessage::Share { .. } => "share",
        DkgMessage::ReshareShareAck { .. } => "reshare_share_ack",
        DkgMessage::ReshareParticipantSet { .. } => "reshare_participant_set",
        DkgMessage::RefreshHealthCheckResult { .. } => "refresh_health_check_result",
        DkgMessage::Complaint { .. } => "complaint",
        DkgMessage::Error { .. } => "error",
    };

    let message_data = serde_json::to_vec(&message)
        .map_err(|e| DkgError::Serialization(format!("Failed to serialize message: {}", e)))?;

    let session_state = &coord.app_state.dkg_session_state;

    if let Some(sid) = session_id {
        let (send_lock, session_generation) = session_state
            .get_or_create_peer_send_lock(&sid, peer_id_str)
            .await
            .ok_or_else(|| session_not_found(sid))?;
        let _guard = send_lock.lock().await;
        ensure_session_generation(coord, sid, session_generation).await?;

        let (stream, was_cached) = match get_cached_or_open_stream(coord, sid, peer_id_str).await {
            Ok(stream) => stream,
            Err(error) => {
                queue_pss_offline_report(coord, sid, peer_id_str, &error).await;
                return Err(error);
            }
        };
        ensure_session_generation(coord, sid, session_generation).await?;

        match send_on_stream(&stream, peer_id_str, &message_data, coord.routes.dkg_alpn).await {
            Ok(()) => {
                if !was_cached {
                    ensure_session_generation(coord, sid, session_generation).await?;
                    session_state
                        .store_peer_stream(&sid, peer_id_str.to_string(), stream)
                        .await;
                }
            }
            Err(first_error) => {
                tracing::warn!(
                    session_id = sid,
                    peer_id = %peer_id_str,
                    message_type = message_type,
                    used_cached_stream = was_cached,
                    error = %first_error,
                    "DKG send failed; evicting cached stream and retrying once on a fresh stream"
                );

                session_state.remove_peer_stream(&sid, peer_id_str).await;
                ensure_session_generation(coord, sid, session_generation).await?;

                let replacement = match coord.open_stream_to_peer(peer_id_str).await {
                    Ok(stream) => Arc::from(stream),
                    Err(error) => {
                        queue_pss_offline_report(coord, sid, peer_id_str, &error).await;
                        return Err(error);
                    }
                };
                ensure_session_generation(coord, sid, session_generation).await?;
                if let Err(retry_error) = send_on_stream(
                    &replacement,
                    peer_id_str,
                    &message_data,
                    coord.routes.dkg_alpn,
                )
                .await
                {
                    tracing::error!(
                        session_id = sid,
                        peer_id = %peer_id_str,
                        message_type = message_type,
                        error = %retry_error,
                        "DKG send retry on a fresh stream failed"
                    );
                    queue_pss_offline_report(coord, sid, peer_id_str, &retry_error).await;
                    return Err(retry_error);
                }
                ensure_session_generation(coord, sid, session_generation).await?;
                session_state
                    .store_peer_stream(&sid, peer_id_str.to_string(), replacement)
                    .await;
                tracing::debug!(
                    session_id = sid,
                    peer_id = %peer_id_str,
                    message_type = message_type,
                    "DKG send recovered after replacing cached stream"
                );
            }
        }
    } else {
        let stream: Arc<dyn NetworkConnection> =
            Arc::from(coord.open_stream_to_peer(peer_id_str).await?);
        send_on_stream(&stream, peer_id_str, &message_data, coord.routes.dkg_alpn).await?;
    }

    metrics::record_dkg_message_sent(message_type);
    Ok(())
}

// Reads session kind and ring ID while the session still exists, then spawns
// the actual report work so callers are not blocked on the full reporting pipeline.
// Must be awaited before the session is removed so the session data can be captured.
async fn queue_pss_offline_report<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    peer_id: &str,
    error: &DkgError,
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
    SignImpl: ThresholdSigner<
            ShareValue = Fr,
            PublicKey = G1Affine,
            DistKeyShare = DistKeyShare<Fr>,
            PubPoly = D::PubPoly,
            Signature = SignaturePoint,
            SigShare = PubShare<SigShareInner>,
        > + Send
        + Sync
        + 'static,
{
    if !is_reportable_dkg_offline_error(error) {
        return;
    }

    // Capture session data NOW while the session still exists. Callers (e.g.
    // trigger_refresh) remove the session synchronously after this returns, so a
    // spawned task that reads session state later would find nothing and silently
    // skip the report.
    let Some((kind, stored_ring_id)) = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| {
            (state.kind.clone(), state.routing.ring_id.clone())
        })
        .await
    else {
        return;
    };

    let app_state = coord.app_state.clone();
    let routes = coord.routes;
    let peer_id = peer_id.to_string();

    let _handle = tokio::spawn(async move {
        if let Err(error) = queue_pss_offline_report_task::<D>(
            app_state,
            routes,
            peer_id.clone(),
            kind,
            stored_ring_id,
        )
        .await
        {
            tracing::warn!(
                peer_id = %peer_id,
                error = %error,
                "Failed to queue PSS offline report observation"
            );
        }
    });
}

async fn queue_pss_offline_report_task<D>(
    app_state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    peer_id: String,
    kind: SessionKind,
    stored_ring_id: String,
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
    SignImpl: ThresholdSigner<
            ShareValue = Fr,
            PublicKey = G1Affine,
            DistKeyShare = DistKeyShare<Fr>,
            PubPoly = D::PubPoly,
            Signature = SignaturePoint,
            SigShare = PubShare<SigShareInner>,
        > + Send
        + Sync
        + 'static,
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

/// Open a QUIC stream to a peer, evicting and reconnecting the cached connection on failure.
pub(super) async fn open_stream_to_peer<D>(
    coord: &DkgCoordinator<D>,
    peer_id_str: &str,
) -> Result<Box<dyn network::Connection>>
where
    D: Dkg<
            ShareValue = Fr,
            PublicKey = G1Affine,
            PolynomialCommitment = PolynomialCommitment,
            PubPoly = PubPoly,
        > + Clone
        + 'static,
{
    coord
        .app_state
        .peer_connection_pool
        .open_stream(&coord.app_state.network, peer_id_str, coord.routes.dkg_alpn)
        .await
        .map_err(|e| {
            DkgError::NetworkConnection(format!(
                "Failed to open stream to peer {}: {}",
                peer_id_str, e
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_state::AppState;
    use crate::dkg::v0::coordinator::DkgCoordinator;
    use crate::dkg::v0::messages::DkgMessage;
    use crate::helpers::test_helpers::{cleanup_db, test_db_path};
    use async_trait::async_trait;
    use authz::dummy::DummyAuthZ;
    use authz::r#trait::Authz;
    use bulletin::dummy::DummyBulletin;
    use bulletin::r#trait::Bulletin;
    use crypto::DkgImpl;
    use local_storage::r#trait::LocalStorage;
    use local_storage::LocalStorageImpl;
    use network::error::NetworkError;
    use network::{Network, PeerConnection, PeerId, ProtocolHandler, RouterBuilder};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Mutex;
    use tokio::time::{sleep, Duration};

    #[derive(Default)]
    struct FakeNetworkState {
        next_stream_id: AtomicUsize,
        connect_calls: AtomicUsize,
        successful_commitments: Mutex<Vec<u8>>,
    }

    struct FakeStream {
        peer_id: PeerId,
        stream_id: usize,
        state: Arc<FakeNetworkState>,
    }

    #[async_trait]
    impl NetworkConnection for FakeStream {
        async fn send(&self, message: NetworkMessage) -> network::Result<()> {
            let dkg_message: DkgMessage =
                serde_json::from_slice(message.data.as_ref()).map_err(|e| {
                    NetworkError::Serialization(format!("failed to decode test message: {}", e))
                })?;

            if self.stream_id == 1 {
                sleep(Duration::from_millis(50)).await;
                return Err(NetworkError::Connection(
                    "forced send failure on first stream".to_string(),
                ));
            }

            if let DkgMessage::Commitment { commitment, .. } = dkg_message {
                self.state
                    .successful_commitments
                    .lock()
                    .await
                    .push(commitment[0]);
            } else {
                return Err(NetworkError::Protocol(
                    "expected commitment message in test".to_string(),
                ));
            }

            Ok(())
        }

        async fn recv(&self) -> network::Result<NetworkMessage> {
            Err(NetworkError::Protocol(
                "recv not used in fake DKG stream test".to_string(),
            ))
        }

        fn peer_id(&self) -> &PeerId {
            &self.peer_id
        }
    }

    struct FakePeerConnection {
        peer_id: PeerId,
        state: Arc<FakeNetworkState>,
    }

    #[async_trait]
    impl PeerConnection for FakePeerConnection {
        async fn open_stream(&self) -> network::Result<Box<dyn NetworkConnection>> {
            let stream_id = self.state.next_stream_id.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(Box::new(FakeStream {
                peer_id: self.peer_id.clone(),
                stream_id,
                state: self.state.clone(),
            }))
        }

        fn peer_id(&self) -> &PeerId {
            &self.peer_id
        }

        async fn close(&self) -> network::Result<()> {
            Ok(())
        }
    }

    struct FakeNetwork {
        local_peer_id: PeerId,
        state: Arc<FakeNetworkState>,
    }

    #[async_trait]
    impl Network for FakeNetwork {
        async fn connect(
            &self,
            peer_id: &PeerId,
            _protocol: &[u8],
        ) -> network::Result<Box<dyn PeerConnection>> {
            self.state.connect_calls.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(FakePeerConnection {
                peer_id: peer_id.clone(),
                state: self.state.clone(),
            }))
        }

        async fn listen(
            &mut self,
            _protocol: &[u8],
            _handler: Box<dyn ProtocolHandler>,
        ) -> network::Result<()> {
            Err(NetworkError::Protocol(
                "listen not used in fake DKG stream test".to_string(),
            ))
        }

        fn local_peer_id(&self) -> PeerId {
            self.local_peer_id.clone()
        }

        fn local_address(&self) -> network::Result<String> {
            Ok("fake-local".to_string())
        }

        fn bound_addresses(&self) -> Vec<std::net::SocketAddr> {
            Vec::new()
        }

        fn create_router_builder(&self) -> network::Result<Box<dyn RouterBuilder>> {
            Err(NetworkError::Protocol(
                "router builder not used in fake DKG stream test".to_string(),
            ))
        }
    }

    async fn make_fake_app_state(
        db_name: &str,
        state: Arc<FakeNetworkState>,
    ) -> (Arc<AppState<DkgImpl>>, String) {
        let local_peer_id = PeerId::from_bytes(b"local-peer");
        let remote_peer_id = PeerId::from_bytes(b"remote-peer");
        let remote_peer_id_str = String::from_utf8(remote_peer_id.as_bytes().to_vec())
            .expect("fake remote peer id should be valid utf-8");

        let bulletin: Arc<dyn Bulletin + Send + Sync> =
            Arc::new(DummyBulletin::new().await.expect("DummyBulletin::new"));
        let authz: Arc<dyn Authz + Send + Sync> =
            Arc::new(DummyAuthZ::new().await.expect("DummyAuthZ::new"));
        let local_storage =
            LocalStorageImpl::new(None, test_db_path(db_name)).expect("create test storage");
        let network: Arc<dyn Network> = Arc::new(FakeNetwork {
            local_peer_id,
            state,
        });

        (
            Arc::new(AppState::<DkgImpl>::new(
                "test-node-key".to_string(),
                network,
                local_storage,
                authz,
                bulletin,
            )),
            remote_peer_id_str,
        )
    }

    #[tokio::test]
    async fn test_send_message_replaces_failed_cached_stream_and_preserves_order() {
        let db_path = test_db_path("dkg_send_retry_replaces_stream");
        let shared_state = Arc::new(FakeNetworkState::default());
        let (app_state, remote_peer_id) =
            make_fake_app_state("dkg_send_retry_replaces_stream", shared_state.clone()).await;
        let coordinator = Arc::new(DkgCoordinator::with_routes(
            app_state.clone(),
            &::network::V0,
        ));
        let session_id = 42_u128;

        coordinator
            .create_session(
                session_id,
                1,
                1,
                1,
                crypto::r#trait::DkgRole::Standard,
                |_| {},
            )
            .await
            .expect("create DKG session");

        let (send_lock, _) = coordinator
            .app_state
            .dkg_session_state
            .get_or_create_peer_send_lock(&session_id, &remote_peer_id)
            .await
            .expect("session send lock");
        let test_guard = send_lock.lock().await;

        let first = {
            let coordinator = coordinator.clone();
            let remote_peer_id = remote_peer_id.clone();
            tokio::spawn(async move {
                coordinator
                    .send_message_to_peer(
                        &remote_peer_id,
                        DkgMessage::Commitment {
                            session_id,
                            from_node_id: 1,
                            commitment: vec![1],
                        },
                        Some(session_id),
                    )
                    .await
            })
        };

        // Hold the same per-peer send lock used by the coordinator so the first
        // sender queues before we spawn the second sender.
        tokio::time::sleep(Duration::from_millis(25)).await;

        let second = {
            let coordinator = coordinator.clone();
            let remote_peer_id = remote_peer_id.clone();
            tokio::spawn(async move {
                coordinator
                    .send_message_to_peer(
                        &remote_peer_id,
                        DkgMessage::Commitment {
                            session_id,
                            from_node_id: 1,
                            commitment: vec![2],
                        },
                        Some(session_id),
                    )
                    .await
            })
        };

        drop(test_guard);

        first
            .await
            .expect("first send task panicked")
            .expect("first send should recover");
        second
            .await
            .expect("second send task panicked")
            .expect("second send should succeed");

        assert_eq!(
            shared_state.next_stream_id.load(Ordering::SeqCst),
            2,
            "a failed cached stream should be replaced once and then reused"
        );
        assert_eq!(
            *shared_state.successful_commitments.lock().await,
            vec![1, 2],
            "per-peer session send lock should preserve message order across stream repair"
        );
        assert_eq!(
            shared_state.connect_calls.load(Ordering::SeqCst),
            1,
            "stream repair should reuse the pooled peer connection when it remains healthy"
        );

        cleanup_db(&db_path);
    }

    #[tokio::test]
    async fn test_send_message_aborts_if_session_is_recreated_while_waiting_on_old_lock() {
        let db_path = test_db_path("dkg_send_stale_session_generation");
        let shared_state = Arc::new(FakeNetworkState::default());
        let (app_state, remote_peer_id) =
            make_fake_app_state("dkg_send_stale_session_generation", shared_state.clone()).await;
        let coordinator = Arc::new(DkgCoordinator::with_routes(
            app_state.clone(),
            &::network::V0,
        ));
        let session_id = 84_u128;

        coordinator
            .create_session(
                session_id,
                1,
                1,
                1,
                crypto::r#trait::DkgRole::Standard,
                |_| {},
            )
            .await
            .expect("create initial DKG session");

        let (stale_lock, initial_generation) = coordinator
            .app_state
            .dkg_session_state
            .get_or_create_peer_send_lock(&session_id, &remote_peer_id)
            .await
            .expect("initial session lock");
        let stale_guard = stale_lock.lock().await;

        let send_task = {
            let coordinator = coordinator.clone();
            let remote_peer_id = remote_peer_id.clone();
            tokio::spawn(async move {
                coordinator
                    .send_message_to_peer(
                        &remote_peer_id,
                        DkgMessage::Commitment {
                            session_id,
                            from_node_id: 1,
                            commitment: vec![9],
                        },
                        Some(session_id),
                    )
                    .await
            })
        };

        tokio::time::sleep(Duration::from_millis(25)).await;

        coordinator.remove_session(session_id).await;
        coordinator
            .create_session(
                session_id,
                1,
                1,
                1,
                crypto::r#trait::DkgRole::Standard,
                |_| {},
            )
            .await
            .expect("recreate DKG session with same session_id");

        let recreated_generation = coordinator
            .app_state
            .dkg_session_state
            .get_session_generation(&session_id)
            .await
            .expect("recreated session generation");
        assert_ne!(
            initial_generation, recreated_generation,
            "recreated session should have a distinct in-memory generation"
        );

        drop(stale_guard);

        let result = send_task.await.expect("send task panicked");
        assert!(
            matches!(result, Err(DkgError::SessionNotFound(_))),
            "stale sender should bail out instead of sending into the recreated session: {:?}",
            result
        );
        assert_eq!(
            shared_state.connect_calls.load(Ordering::SeqCst),
            0,
            "stale sender should not open a stream after its session was recreated"
        );
        assert!(
            shared_state.successful_commitments.lock().await.is_empty(),
            "stale sender should not deliver protocol messages for an abandoned session"
        );

        cleanup_db(&db_path);
    }

    #[tokio::test]
    async fn test_session_rejects_cross_version_continuation() {
        static V1_ROUTES: network::ProtocolRoutes = network::ProtocolRoutes {
            version: 1,
            dkg_alpn: b"orbis/dkg/1",
            reencrypt_alpn: b"orbis/reencrypt/1",
            sign_alpn: b"orbis/sign/1",
            reporting_health_alpn: b"orbis/reporting/health/1",
        };

        let db_path = test_db_path("dkg_cross_version_continuation");
        let shared_state = Arc::new(FakeNetworkState::default());
        let (app_state, remote_peer_id) =
            make_fake_app_state("dkg_cross_version_continuation", shared_state).await;
        let v0 = DkgCoordinator::with_routes(app_state.clone(), &network::V0);
        let session_id = 99_u128;
        v0.create_session(
            session_id,
            1,
            1,
            1,
            crypto::r#trait::DkgRole::Standard,
            |_| {},
        )
        .await
        .expect("create v0 session");

        let stored_version = app_state
            .dkg_session_state
            .with_state(&session_id, |state| state.protocol_version)
            .await;
        assert_eq!(stored_version, Some(0));

        let v1 = DkgCoordinator::with_routes(app_state, &V1_ROUTES);
        let error = v1
            .handle_message(
                DkgMessage::Commitment {
                    session_id,
                    from_node_id: 1,
                    commitment: vec![1],
                },
                &PeerId::new(remote_peer_id.into_bytes()),
            )
            .await
            .expect_err("cross-version continuation must fail");
        assert!(
            matches!(error, DkgError::ProtocolError(message) if message.contains("pinned to protocol version 0"))
        );

        cleanup_db(&db_path);
    }
}
