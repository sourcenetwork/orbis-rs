use super::*;

pub(super) fn control_request_scope(
    request: &DkgControlMessage,
) -> (&'static str, Option<CeremonyId>, Option<AttemptId>) {
    match request {
        DkgControlMessage::StartFresh { .. } => ("start-fresh", None, None),
        DkgControlMessage::StartReshare { .. } => ("start-reshare", None, None),
        DkgControlMessage::StartRefresh { .. } => ("start-refresh", None, None),
        DkgControlMessage::GetSessionStatus { .. } => ("get-session-status", None, None),
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
        DkgControlMessage::Activate {
            ceremony_id,
            attempt_id,
            ..
        } => ("activate", Some(*ceremony_id), Some(*attempt_id)),
        DkgControlMessage::Begin {
            ceremony_id,
            attempt_id,
            ..
        } => ("begin", Some(*ceremony_id), Some(*attempt_id)),
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

pub(super) fn control_timeout_message(
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

pub(super) async fn control_request_with_timeout<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    peer: &str,
    request: DkgControlMessage,
    response_timeout: Duration,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
{
    control_request_with_timeout_classified(state, routes, peer, request, response_timeout)
        .await
        .map_err(PeerRequestFailure::into_error)
}

/// A direct request can fail before a peer is reached, after the peer has
/// demonstrably replied, or because of local work. Keeping those cases typed
/// prevents terminal PSS paths from treating protocol errors or local pressure
/// as evidence that a peer is offline.
#[derive(Debug)]
pub(super) enum PeerRequestFailure {
    Unreachable(DkgError),
    Reachable(DkgError),
    Local(DkgError),
}

impl PeerRequestFailure {
    pub(super) fn is_unreachable(&self) -> bool {
        matches!(self, Self::Unreachable(_))
    }

    pub(super) fn error(&self) -> &DkgError {
        match self {
            Self::Unreachable(error) | Self::Reachable(error) | Self::Local(error) => error,
        }
    }

    pub(super) fn proves_reachable(&self) -> bool {
        matches!(self, Self::Reachable(_))
    }

    pub(super) fn into_error(self) -> DkgError {
        match self {
            Self::Unreachable(error) | Self::Reachable(error) | Self::Local(error) => error,
        }
    }
}

pub(super) async fn control_request_with_timeout_classified<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    peer: &str,
    request: DkgControlMessage,
    response_timeout: Duration,
) -> std::result::Result<DkgControlMessage, PeerRequestFailure>
where
    D: CoordinatorDkg,
{
    crate::metrics::record_dkg_transport_message("control", request.metric_label(), "sent");
    let timeout_error = control_timeout_message(peer, &request, response_timeout);
    let encoded = transport::encode(&request)
        .map_err(DkgError::Serialization)
        .map_err(PeerRequestFailure::Local)?;
    let mut attempt_connection = None;
    let exchange = timeout(response_timeout, async {
        let (stream, parent_connection) = state
            .peer_connection_pool
            .open_stream_with_connection(&state.network, peer, routes.dkg_control_alpn)
            .await
            .map_err(|error| DkgError::NetworkConnection(error.to_string()))?;
        attempt_connection = Some(parent_connection);
        stream
            .send(Message::new(encoded, routes.dkg_control_alpn.to_vec()))
            .await
            .map_err(|error| DkgError::NetworkCommunication(error.to_string()))?;
        stream
            .recv()
            .await
            .map_err(|error| DkgError::NetworkCommunication(error.to_string()))
    })
    .await;
    let response = match exchange {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            invalidate_failed_control_connection(
                state,
                routes,
                peer,
                attempt_connection.as_ref(),
                &error,
            )
            .await;
            return Err(PeerRequestFailure::Unreachable(error));
        }
        Err(_) => {
            let error = DkgError::NetworkConnection(timeout_error);
            invalidate_failed_control_connection(
                state,
                routes,
                peer,
                attempt_connection.as_ref(),
                &error,
            )
            .await;
            return Err(PeerRequestFailure::Unreachable(error));
        }
    };
    let response = transport::decode(&response.data, MAX_CONTROL_MESSAGE_BYTES)
        .map_err(DkgError::Deserialization)
        .map_err(PeerRequestFailure::Reachable)?;
    match response {
        DkgControlMessage::Error { message, .. } => Err(PeerRequestFailure::Reachable(
            DkgError::ProtocolError(message),
        )),
        response => Ok(response),
    }
}

pub(super) async fn invalidate_failed_control_connection<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    peer: &str,
    connection: Option<&Arc<dyn network::PeerConnection>>,
    error: &DkgError,
) where
    D: CoordinatorDkg,
{
    if !retryable_control_error(error) {
        return;
    }
    let Some(connection) = connection else {
        return;
    };
    if state
        .peer_connection_pool
        .invalidate_if_same(peer, routes.dkg_control_alpn, connection)
        .await
    {
        crate::metrics::record_dkg_transport_event("control", "connection_invalidated");
        tracing::warn!(
            peer = %extract_node_part(peer),
            %error,
            "invalidated failed DKG control connection"
        );
    }
}

pub(super) fn retryable_control_error(error: &DkgError) -> bool {
    matches!(
        error,
        DkgError::NetworkConnection(_) | DkgError::NetworkCommunication(_)
    )
}

pub(super) async fn retry_preparation_control_classified<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    peer: &str,
    request: DkgControlMessage,
    deadline: Instant,
) -> std::result::Result<DkgControlMessage, PeerRequestFailure>
where
    D: CoordinatorDkg,
{
    let (operation, ceremony_id, attempt_id) = control_request_scope(&request);
    let mut backoff = INITIAL_CONTROL_RETRY_BACKOFF;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(PeerRequestFailure::Unreachable(
                DkgError::NetworkCommunication(format!(
                "{operation} exceeded the preparation deadline for peer {} ceremony={} attempt={}",
                extract_node_part(peer),
                ceremony_id.map_or_else(|| "-".into(), |id| id.0.to_string()),
                attempt_id.map_or_else(|| "-".into(), |id| hex::encode(&id.0[..6])),
                )),
            ));
        }
        let remaining = deadline.saturating_duration_since(now);
        match control_request_with_timeout_classified(
            state,
            routes,
            peer,
            request.clone(),
            PEER_RESPONSE_TIMEOUT.min(remaining),
        )
        .await
        {
            Ok(response) => return Ok(response),
            Err(error @ PeerRequestFailure::Unreachable(_)) => {
                crate::metrics::record_dkg_transport_event("control", "preparation_retry");
                tracing::warn!(
                    error = %error.error(),
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
