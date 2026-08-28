use super::*;

const INITIAL_PRIVATE_RETRY_BACKOFF: Duration = Duration::from_millis(100);

const PRIVATE_BUSY_RETRY_AFTER: Duration = Duration::from_millis(250);

const PRIVATE_INBOUND_QUEUE_WAIT: Duration = Duration::from_millis(500);

/// Inbound handler for one deterministic bidirectional private pair exchange.
pub struct DkgPrivateHandler<D>
where
    D: CoordinatorDkg,
{
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
}

impl<D> DkgPrivateHandler<D>
where
    D: CoordinatorDkg,
{
    pub fn new(state: Arc<AppState<D>>, routes: &'static network::ProtocolRoutes) -> Self {
        Self { state, routes }
    }
}

#[async_trait]
impl<D> ProtocolHandler for DkgPrivateHandler<D>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    async fn handle(&self, connection: Box<dyn Connection>) -> network::Result<()> {
        let peer = connection.peer_id().clone();
        let peer_prefix: String = hex::encode(peer.as_bytes()).chars().take(12).collect();
        let first = timeout(PEER_RESPONSE_TIMEOUT, recv_private(&*connection))
            .await
            .map_err(|_| {
                network::error::NetworkError::Protocol(format!(
                    "private pair opener {peer_prefix} did not send its first message within {}ms",
                    PEER_RESPONSE_TIMEOUT.as_millis()
                ))
            })??;
        if matches!(first, DkgPrivateMessage::PairHello { .. }) {
            return handle_inbound_pair_hello(
                self.state.clone(),
                self.routes,
                &*connection,
                &peer,
                first,
            )
            .await;
        }
        let DkgPrivateMessage::ShareDelivery {
            ceremony_id,
            attempt_id,
            message_id: incoming_id,
            from,
            to,
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
        if let Some(committees) = self
            .state
            .dkg_session_state
            .transport_committees(&session_id)
            .await
        {
            let authenticated_route = hex::encode(peer.as_bytes());
            if let Some(participant) =
                participant_for_transport_peer(&committees, &authenticated_route)
            {
                let _ = self
                    .state
                    .dkg_session_state
                    .record_private_peer_response(
                        AttemptKey::new(ceremony_id, attempt_id),
                        participant,
                    )
                    .await;
            }
        }
        let is_reshare_delivery =
            from.scope == CommitteeScope::Current && to.scope == CommitteeScope::Next;
        if !is_reshare_delivery
            && (from.scope != CommitteeScope::Current
                || to.scope != CommitteeScope::Current
                || !transport::is_canonical_pair_opener(from.node_id, to.node_id))
        {
            return Err(network::error::NetworkError::Protocol(
                "private pair exchange was opened by the non-canonical endpoint".into(),
            ));
        }
        let incoming = DkgPrivateMessage::ShareDelivery {
            ceremony_id,
            attempt_id,
            message_id: incoming_id,
            from,
            to,
            share_value,
            nonce,
            report_evidence,
        };
        validate_private_delivery(&self.state, &incoming, &peer)
            .await
            .map_err(|error| network::error::NetworkError::Protocol(error.to_string()))?;
        if is_reshare_delivery {
            validate_reshare_pair_opener(&self.state, session_id, from, to, from)
                .await
                .map_err(|error| network::error::NetworkError::Protocol(error.to_string()))?;
        }
        let semaphore = self.state.dkg_session_state.private_exchange_permits();
        let permit = match timeout(PRIVATE_INBOUND_QUEUE_WAIT, semaphore.acquire_owned()).await {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => {
                return Err(network::error::NetworkError::Protocol(
                    "private exchange semaphore closed".into(),
                ));
            }
            Err(_) => {
                crate::metrics::record_dkg_transport_event("private", "busy");
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
            from = ?from,
            to = ?to,
            "accepted inbound private DKG pair exchange"
        );
        if is_reshare_delivery {
            let reciprocal_recipient =
                reciprocal_reshare_recipient(&self.state, session_id, from, to)
                    .await
                    .map_err(|error| network::error::NetworkError::Protocol(error.to_string()))?;
            let reciprocal = match reciprocal_recipient {
                Some(recipient) => {
                    let Some(bytes) = self
                        .state
                        .dkg_session_state
                        .private_message_for_recipient(&session_id, recipient)
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
                    Some(
                        transport::decode::<DkgPrivateMessage>(&bytes, MAX_CONTROL_MESSAGE_BYTES)
                            .map_err(network::error::NetworkError::Serialization)?,
                    )
                }
                None => None,
            };
            let completion = timeout(PEER_RESPONSE_TIMEOUT, async {
                if let Some(outgoing) = &reciprocal {
                    send_private(&*connection, self.routes.dkg_private_alpn, outgoing).await?;
                    let ack = recv_private(&*connection).await?;
                    validate_share_ack(outgoing, &ack)
                        .map_err(network::error::NetworkError::Protocol)?;
                    if let DkgPrivateMessage::ShareAck { message_id, .. } = ack {
                        self.state
                            .dkg_session_state
                            .acknowledge_private_message(&session_id, attempt_id, message_id)
                            .await;
                    }
                }
                let completion =
                    accept_private_delivery(self.state.clone(), self.routes, &incoming, &peer)
                        .await
                        .map_err(|error| {
                            network::error::NetworkError::Protocol(error.to_string())
                        })?;
                let ack =
                    share_ack_for(&incoming).map_err(network::error::NetworkError::Protocol)?;
                send_private(&*connection, self.routes.dkg_private_alpn, &ack).await?;
                Ok::<PrivateShareCompletion, network::error::NetworkError>(completion)
            })
            .await
            .map_err(|_| {
                crate::metrics::record_dkg_transport_event("private", "inbound_timeout");
                network::error::NetworkError::Protocol(format!(
                    "inbound reshare delivery from {peer_prefix} timed out after {}ms",
                    PEER_RESPONSE_TIMEOUT.as_millis()
                ))
            })??;
            drop(permit);
            pair_metrics.complete();
            crate::metrics::record_dkg_transport_event("private", "pair_completed");
            drive_private_completion(self.state.clone(), self.routes, completion)
                .await
                .map_err(|error| network::error::NetworkError::Protocol(error.to_string()))?;
            return Ok(());
        }
        let Some(outgoing_bytes) = self
            .state
            .dkg_session_state
            .private_message_for_recipient(&session_id, from)
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
            crate::metrics::record_dkg_transport_event("private", "inbound_timeout");
            network::error::NetworkError::Protocol(format!(
                "inbound private pair exchange with {peer_prefix} timed out after {}ms",
                PEER_RESPONSE_TIMEOUT.as_millis()
            ))
        })??;
        drop(permit);
        pair_metrics.complete();
        crate::metrics::record_dkg_transport_event("private", "pair_completed");
        drive_private_completion(self.state.clone(), self.routes, completion)
            .await
            .map_err(|error| network::error::NetworkError::Protocol(error.to_string()))?;
        Ok(())
    }
}

pub(super) async fn validate_reshare_pair_opener<D>(
    state: &Arc<AppState<D>>,
    session_id: u128,
    first: ParticipantRef,
    second: ParticipantRef,
    actual_opener: ParticipantRef,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let committees = state
        .dkg_session_state
        .transport_committees(&session_id)
        .await
        .ok_or_else(|| {
            DkgError::InvalidState("ceremony committee configuration is missing".into())
        })?;
    if committees.canonical_pair_opener(first, second) != Some(actual_opener) {
        return Err(DkgError::Unauthorized(
            "reshare private stream was opened by the non-canonical node key".into(),
        ));
    }
    Ok(())
}

pub(super) async fn reciprocal_reshare_recipient<D>(
    state: &Arc<AppState<D>>,
    session_id: u128,
    remote_dealer: ParticipantRef,
    _local_receiver: ParticipantRef,
) -> Result<Option<ParticipantRef>>
where
    D: CoordinatorDkg,
{
    let committees = state
        .dkg_session_state
        .transport_committees(&session_id)
        .await
        .ok_or_else(|| {
            DkgError::InvalidState("ceremony committee configuration is missing".into())
        })?;
    let remote_key = committees.node_key(remote_dealer).ok_or_else(|| {
        DkgError::Unauthorized("remote dealer is outside current committee".into())
    })?;
    let Some(next) = committees.next.as_ref() else {
        return Ok(None);
    };
    let Some(remote_receiver) = next.participant(CommitteeScope::Next, remote_key) else {
        return Ok(None);
    };
    let Some(local_dealer) = committees
        .current
        .participant(CommitteeScope::Current, &state.node_key)
    else {
        return Ok(None);
    };
    let active = state
        .dkg_session_state
        .transport_active_dealers(&session_id)
        .await
        .unwrap_or_default();
    Ok(active.contains(&local_dealer).then_some(remote_receiver))
}

pub(super) async fn handle_inbound_pair_hello<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    connection: &dyn Connection,
    peer: &PeerId,
    hello: DkgPrivateMessage,
) -> network::Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let DkgPrivateMessage::PairHello {
        ceremony_id,
        attempt_id,
        pair_id,
        opener,
        responder,
    } = hello
    else {
        unreachable!("caller accepts only PairHello");
    };
    if opener.scope != CommitteeScope::Next || responder.scope != CommitteeScope::Current {
        return Err(network::error::NetworkError::Protocol(
            "reshare PairHello must be next-receiver to current-dealer".into(),
        ));
    }
    let session_id = ceremony_id.0;
    let (_, active_attempt, _, _, activated) = state
        .dkg_session_state
        .transport_info(&session_id)
        .await
        .ok_or_else(|| network::error::NetworkError::Protocol("pair session is missing".into()))?;
    if active_attempt != attempt_id || !activated {
        return Err(network::error::NetworkError::Protocol(
            "PairHello targets a stale or inactive attempt".into(),
        ));
    }
    if pair_id != transport::derive_pair_hello_id(ceremony_id, attempt_id, opener, responder) {
        return Err(network::error::NetworkError::Protocol(
            "PairHello idempotency key is invalid".into(),
        ));
    }
    let committees = state
        .dkg_session_state
        .transport_committees(&session_id)
        .await
        .ok_or_else(|| {
            network::error::NetworkError::Protocol(
                "ceremony committee configuration is missing".into(),
            )
        })?;
    let authenticated_route = hex::encode(peer.as_bytes());
    if let Some(participant) = participant_for_transport_peer(&committees, &authenticated_route) {
        let _ = state
            .dkg_session_state
            .record_private_peer_response(AttemptKey::new(ceremony_id, attempt_id), participant)
            .await;
    }
    if committees.node_key(responder) != Some(state.node_key.as_str())
        || committees
            .route(opener)
            .is_none_or(|route| !peer_matches_route(peer, route))
    {
        return Err(network::error::NetworkError::Protocol(
            "PairHello identities do not match authenticated routes".into(),
        ));
    }
    validate_reshare_pair_opener(&state, session_id, opener, responder, opener)
        .await
        .map_err(|error| network::error::NetworkError::Protocol(error.to_string()))?;
    let active_dealers = state
        .dkg_session_state
        .transport_active_dealers(&session_id)
        .await
        .unwrap_or_default();
    if !active_dealers.contains(&responder) {
        return Err(network::error::NetworkError::Protocol(
            "PairHello targets an inactive dealer".into(),
        ));
    }
    let semaphore = state.dkg_session_state.private_exchange_permits();
    let permit = match timeout(PRIVATE_INBOUND_QUEUE_WAIT, semaphore.acquire_owned()).await {
        Ok(Ok(permit)) => permit,
        Ok(Err(_)) => {
            return Err(network::error::NetworkError::Protocol(
                "private exchange semaphore closed".into(),
            ));
        }
        Err(_) => {
            send_private_busy(connection, routes.dkg_private_alpn, ceremony_id, attempt_id).await?;
            return Ok(());
        }
    };
    let Some(outgoing_bytes) = state
        .dkg_session_state
        .private_message_for_recipient(&session_id, opener)
        .await
    else {
        send_private_busy(connection, routes.dkg_private_alpn, ceremony_id, attempt_id).await?;
        return Ok(());
    };
    let outgoing: DkgPrivateMessage = transport::decode(&outgoing_bytes, MAX_CONTROL_MESSAGE_BYTES)
        .map_err(network::error::NetworkError::Serialization)?;
    timeout(PEER_RESPONSE_TIMEOUT, async {
        send_private(connection, routes.dkg_private_alpn, &outgoing).await?;
        let ack = recv_private(connection).await?;
        validate_share_ack(&outgoing, &ack).map_err(network::error::NetworkError::Protocol)?;
        if let DkgPrivateMessage::ShareAck { message_id, .. } = ack {
            state
                .dkg_session_state
                .acknowledge_private_message(&session_id, attempt_id, message_id)
                .await;
        }
        Ok::<(), network::error::NetworkError>(())
    })
    .await
    .map_err(|_| {
        network::error::NetworkError::Protocol(
            "responder-only private pair exchange timed out".into(),
        )
    })??;
    drop(permit);
    crate::metrics::record_dkg_transport_event("private", "pair_completed");
    Ok(())
}

pub(super) async fn send_private(
    connection: &dyn Connection,
    alpn: &[u8],
    message: &DkgPrivateMessage,
) -> network::Result<()> {
    crate::metrics::record_dkg_transport_message("private", message.metric_label(), "sent");
    let bytes = transport::encode(message).map_err(network::error::NetworkError::Serialization)?;
    connection.send(Message::new(bytes, alpn.to_vec())).await
}

pub(super) async fn send_private_busy(
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

pub(super) async fn recv_private(
    connection: &dyn Connection,
) -> network::Result<DkgPrivateMessage> {
    let message = connection.recv().await?;
    let decoded: DkgPrivateMessage = transport::decode(&message.data, MAX_CONTROL_MESSAGE_BYTES)
        .map_err(network::error::NetworkError::Serialization)?;
    crate::metrics::record_dkg_transport_message("private", decoded.metric_label(), "received");
    Ok(decoded)
}

pub(super) fn share_ack_for(
    message: &DkgPrivateMessage,
) -> std::result::Result<DkgPrivateMessage, String> {
    let DkgPrivateMessage::ShareDelivery {
        ceremony_id,
        attempt_id,
        message_id,
        from,
        to,
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
            *from,
            *to,
            share_value,
            nonce,
        ),
    })
}

pub(super) fn validate_share_ack(
    delivery: &DkgPrivateMessage,
    ack: &DkgPrivateMessage,
) -> std::result::Result<(), String> {
    let expected = share_ack_for(delivery)?;
    if &expected != ack {
        return Err("private share acknowledgement digest or attempt did not match".into());
    }
    Ok(())
}

pub(super) async fn validate_private_delivery<D>(
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
        from,
        to,
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
        .transport_info(&ceremony_id.0)
        .await
        .ok_or_else(|| DkgError::SessionNotFound(ceremony_id.0.to_string()))?;
    if expected_ceremony != *ceremony_id || expected_attempt != *attempt_id || !activated {
        return Err(DkgError::Unauthorized(format!(
            "stale or inactive private exchange: expected ceremony={} attempt={} activated={activated}, got ceremony={} attempt={}",
            expected_ceremony.0,
            hex::encode(expected_attempt.0),
            ceremony_id.0,
            hex::encode(attempt_id.0),
        )));
    }
    let local_node_id = state
        .dkg_session_state
        .with_state(&ceremony_id.0, |session| session.node.node_id())
        .await
        .ok_or_else(|| DkgError::SessionNotFound(ceremony_id.0.to_string()))?;
    let expected_local_id = if to.scope == CommitteeScope::Next {
        state
            .dkg_session_state
            .with_state(&ceremony_id.0, |session| {
                session
                    .reshare
                    .params
                    .as_ref()
                    .and_then(|params| params.new_node_id)
            })
            .await
            .flatten()
    } else {
        Some(local_node_id)
    };
    if expected_local_id != Some(to.node_id) {
        return Err(DkgError::Unauthorized(
            "private share delivered to wrong recipient".into(),
        ));
    }
    let expected_sender = state
        .dkg_session_state
        .get_peer_id_for_node(&ceremony_id.0, from.node_id)
        .await
        .ok_or_else(|| DkgError::Unauthorized("private share sender is not in committee".into()))?;
    if !peer_matches_route(sender, &expected_sender) {
        return Err(DkgError::Unauthorized(
            "private share sender does not match Vera NodeInfo".into(),
        ));
    }
    let expected_id = transport::derive_private_message_id(
        *ceremony_id,
        *attempt_id,
        *from,
        *to,
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
pub(super) struct PrivateShareCompletion {
    attempt: AttemptKey,
    from_node_id: u32,
    should_drive: bool,
}

pub(super) async fn accept_private_delivery<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    message: &DkgPrivateMessage,
    _sender: &PeerId,
) -> Result<PrivateShareCompletion>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let DkgPrivateMessage::ShareDelivery {
        ceremony_id,
        attempt_id,
        message_id,
        from,
        to,
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
        .accept_transport_share(
            AttemptKey::new(ceremony_id, attempt_id),
            message_id,
            from.node_id,
            to.node_id,
            share_value,
            nonce,
            report_evidence.map(|evidence| *evidence),
        )
        .await?;
    Ok(PrivateShareCompletion {
        attempt: AttemptKey::new(ceremony_id, attempt_id),
        from_node_id: from.node_id,
        should_drive,
    })
}

pub(super) async fn drive_private_completion<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    completion: PrivateShareCompletion,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    if completion.should_drive {
        drive_accepted_share(
            &DkgCoordinator::with_routes(state, routes),
            completion.attempt,
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
pub(super) fn private_retry_delay(
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

pub(super) async fn open_private_pair_hello<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    peer: String,
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    opener: ParticipantRef,
    responder: ParticipantRef,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let pair_id = transport::derive_pair_hello_id(ceremony_id, attempt_id, opener, responder);
    let hello = DkgPrivateMessage::PairHello {
        ceremony_id,
        attempt_id,
        pair_id,
        opener,
        responder,
    };
    let exact_hello = transport::encode(&hello).map_err(DkgError::Serialization)?;
    let deadline: Instant = state
        .dkg_session_state
        .transport_hard_deadline(&ceremony_id.0, attempt_id)
        .await
        .ok_or_else(|| DkgError::InvalidState("transport hard deadline is missing".into()))?
        .into();
    let mut backoff = INITIAL_PRIVATE_RETRY_BACKOFF;
    let mut retry_attempt = 0_u32;
    let mut last_failure_was_unreachable = false;
    let mut peer_proved_reachable = false;
    loop {
        if Instant::now() >= deadline {
            if terminal_offline_candidate(last_failure_was_unreachable, peer_proved_reachable) {
                spawn_pss_offline_for_attempt(
                    &state,
                    routes,
                    AttemptKey::new(ceremony_id, attempt_id),
                    PssOfflineStage::PrivatePair,
                    [responder],
                )
                .await;
            }
            return Err(DkgError::NetworkCommunication(format!(
                "responder-only private pair exchange with {peer} exceeded hard attempt deadline"
            )));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let permit = timeout(
            remaining,
            state
                .dkg_session_state
                .private_exchange_permits()
                .acquire_owned(),
        )
        .await
        .map_err(|_| DkgError::InvalidState("private pair permit timed out".into()))?
        .map_err(|_| DkgError::InvalidState("private exchange semaphore closed".into()))?;
        let attempt_timeout = PEER_RESPONSE_TIMEOUT.min(remaining);
        let mut busy_retry_after = None;
        let mut attempt_connection = None;
        let mut io_failed = false;
        let mut received_response = false;
        let exchange = timeout(attempt_timeout, async {
            let (stream, parent) = state
                .peer_connection_pool
                .open_stream_with_connection(&state.network, &peer, routes.dkg_private_alpn)
                .await
                .map_err(|error| {
                    io_failed = true;
                    DkgError::NetworkConnection(error.to_string())
                })?;
            attempt_connection = Some(parent);
            stream
                .send(Message::new(
                    exact_hello.clone(),
                    routes.dkg_private_alpn.to_vec(),
                ))
                .await
                .map_err(|error| {
                    io_failed = true;
                    DkgError::NetworkCommunication(error.to_string())
                })?;
            let response = recv_private(&*stream).await.map_err(|error| {
                io_failed = true;
                DkgError::NetworkCommunication(error.to_string())
            })?;
            received_response = true;
            if let DkgPrivateMessage::Busy {
                ceremony_id: busy_ceremony,
                attempt_id: busy_attempt,
                retry_after_ms,
            } = response
            {
                if busy_ceremony != ceremony_id || busy_attempt != attempt_id {
                    return Err(DkgError::ProtocolError(
                        "private Busy response did not match PairHello attempt".into(),
                    ));
                }
                busy_retry_after = Some(Duration::from_millis(retry_after_ms.max(1)));
                return Err(DkgError::NetworkCommunication("private peer busy".into()));
            }
            validate_private_delivery(&state, &response, stream.peer_id()).await?;
            let DkgPrivateMessage::ShareDelivery { from, to, .. } = response.clone() else {
                return Err(DkgError::ProtocolError(
                    "PairHello responder did not return ShareDelivery".into(),
                ));
            };
            if from != responder || to != opener {
                return Err(DkgError::Unauthorized(
                    "PairHello responder returned the wrong directional obligation".into(),
                ));
            }
            let completion =
                accept_private_delivery(state.clone(), routes, &response, stream.peer_id()).await?;
            let ack = share_ack_for(&response).map_err(DkgError::ProtocolError)?;
            send_private(&*stream, routes.dkg_private_alpn, &ack)
                .await
                .map_err(|error| {
                    io_failed = true;
                    DkgError::NetworkCommunication(error.to_string())
                })?;
            Ok(completion)
        })
        .await;
        let exchange = match exchange {
            Ok(result) => result,
            Err(_) => {
                io_failed = true;
                Err(DkgError::NetworkCommunication(format!(
                    "responder-only private pair exchange with {peer} timed out"
                )))
            }
        };
        drop(permit);
        match exchange {
            Ok(completion) => {
                drive_private_completion(state.clone(), routes, completion).await?;
                crate::metrics::record_dkg_transport_event("private", "pair_completed");
                return Ok(());
            }
            Err(error) => {
                last_failure_was_unreachable =
                    private_failure_is_unreachable(io_failed, busy_retry_after);
                peer_proved_reachable |= received_response;
                if busy_retry_after.is_none() {
                    if let Some(connection) = attempt_connection.as_ref() {
                        state
                            .peer_connection_pool
                            .invalidate_if_same(&peer, routes.dkg_private_alpn, connection)
                            .await;
                    }
                }
                crate::metrics::record_dkg_transport_event("private", "retry");
                let remaining = deadline.saturating_duration_since(Instant::now());
                let delay = private_retry_delay(
                    pair_id,
                    retry_attempt,
                    backoff,
                    busy_retry_after,
                    remaining,
                );
                tracing::debug!(%peer, %error, "retrying responder-only private pair exchange");
                sleep(delay).await;
                retry_attempt = retry_attempt.saturating_add(1);
                backoff = (backoff * 2).min(DKG_MAX_REPAIR_BACKOFF);
            }
        }
    }
}

pub(super) fn spawn_reshare_receiver_pair_openers<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    attempt: AttemptKey,
) where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    tokio::spawn(async move {
        let session_id = attempt.session_id();
        let Ok((committees, active_dealers)) = state
            .dkg_session_state
            .with_attempt_state(attempt, |session| {
                (
                    session.transport.committees.clone(),
                    session.transport.active_dealers.clone(),
                )
            })
            .await
        else {
            return;
        };
        let Some(committees) = committees else {
            return;
        };
        let Some(next) = committees.next.as_ref() else {
            return;
        };
        let Some(local_receiver) = next.participant(CommitteeScope::Next, &state.node_key) else {
            return;
        };
        let attempt_id = attempt.attempt_id;
        let mut tasks = FuturesUnordered::new();
        for dealer in active_dealers {
            if committees.canonical_pair_opener(local_receiver, dealer) != Some(local_receiver) {
                continue;
            }
            let Some(peer) = committees.route(dealer).map(str::to_string) else {
                continue;
            };
            let state = state.clone();
            tasks.push(async move {
                open_private_pair_hello(
                    state,
                    routes,
                    peer,
                    attempt.ceremony_id,
                    attempt_id,
                    local_receiver,
                    dealer,
                )
                .await
            });
        }
        while let Some(result) = tasks.next().await {
            if let Err(error) = result {
                tracing::warn!(session_id, %error, "reshare responder-only pair exchange failed");
            }
        }
    });
}

pub(super) async fn open_private_pair<D>(
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
        to: remote_participant,
        ..
    } = outgoing.clone()
    else {
        return Err(DkgError::InvalidState(
            "cached private message is not a share".into(),
        ));
    };
    let deadline: Instant = state
        .dkg_session_state
        .transport_hard_deadline(&ceremony_id.0, attempt_id)
        .await
        .ok_or_else(|| DkgError::InvalidState("transport hard deadline is missing".into()))?
        .into();
    let mut backoff = INITIAL_PRIVATE_RETRY_BACKOFF;
    let mut retry_attempt = 0_u32;
    let mut last_failure_was_unreachable = false;
    let mut peer_proved_reachable = false;
    loop {
        if Instant::now() >= deadline {
            if terminal_offline_candidate(last_failure_was_unreachable, peer_proved_reachable) {
                spawn_pss_offline_for_attempt(
                    &state,
                    routes,
                    AttemptKey::new(ceremony_id, attempt_id),
                    PssOfflineStage::PrivatePair,
                    [remote_participant],
                )
                .await;
            }
            return Err(DkgError::NetworkCommunication(format!(
                "private pair exchange with {peer} exceeded hard attempt deadline"
            )));
        }
        let semaphore = state.dkg_session_state.private_exchange_permits();
        let remaining = deadline.saturating_duration_since(Instant::now());
        let permit = timeout(remaining, semaphore.acquire_owned())
            .await
            .map_err(|_| DkgError::InvalidState("private pair permit timed out".into()))?
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
        let mut attempt_connection = None;
        let mut io_failed = false;
        let mut received_response = false;
        let exchange = timeout(attempt_timeout, async {
            let (stream, parent_connection) = state
                .peer_connection_pool
                .open_stream_with_connection(&state.network, &peer, routes.dkg_private_alpn)
                .await
                .map_err(|error| {
                    io_failed = true;
                    DkgError::NetworkConnection(error.to_string())
                })?;
            attempt_connection = Some(parent_connection);
            let remote = stream.peer_id().clone();
            stream
                .send(Message::new(
                    outgoing_bytes.clone(),
                    routes.dkg_private_alpn.to_vec(),
                ))
                .await
                .map_err(|error| {
                    io_failed = true;
                    DkgError::NetworkCommunication(error.to_string())
                })?;
            let response = recv_private(&*stream).await.map_err(|error| {
                io_failed = true;
                DkgError::NetworkCommunication(error.to_string())
            })?;
            received_response = true;
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
            if let DkgPrivateMessage::ShareAck { .. } = response {
                validate_share_ack(&outgoing, &response).map_err(DkgError::ProtocolError)?;
                state
                    .dkg_session_state
                    .acknowledge_private_message(&ceremony_id.0, attempt_id, message_id)
                    .await;
                return Ok(None);
            }
            validate_private_delivery(&state, &response, &remote).await?;
            let completion =
                accept_private_delivery(state.clone(), routes, &response, &remote).await?;
            let ack = share_ack_for(&response).map_err(DkgError::ProtocolError)?;
            send_private(&*stream, routes.dkg_private_alpn, &ack)
                .await
                .map_err(|error| {
                    io_failed = true;
                    DkgError::NetworkCommunication(error.to_string())
                })?;
            let final_ack = recv_private(&*stream).await.map_err(|error| {
                io_failed = true;
                DkgError::NetworkCommunication(error.to_string())
            })?;
            validate_share_ack(&outgoing, &final_ack).map_err(DkgError::ProtocolError)?;
            state
                .dkg_session_state
                .acknowledge_private_message(&ceremony_id.0, attempt_id, message_id)
                .await;
            Ok(Some(completion))
        })
        .await;
        let exchange = match exchange {
            Ok(result) => result,
            Err(_) => {
                io_failed = true;
                Err(DkgError::NetworkCommunication(format!(
                    "private pair exchange with {peer} timed out after {}ms",
                    attempt_timeout.as_millis()
                )))
            }
        };
        drop(permit);
        match exchange {
            Ok(completion) => {
                pair_metrics.complete();
                crate::metrics::record_dkg_transport_event("private", "pair_completed");
                tracing::info!(
                    session_id = ceremony_id.0,
                    %peer,
                    "private DKG pair exchange completed"
                );
                state
                    .dkg_session_state
                    .clear_peer_no_progress(
                        AttemptKey::new(ceremony_id, attempt_id),
                        remote_participant.node_id,
                    )
                    .await;
                if let Some(completion) = completion {
                    drive_private_completion(state.clone(), routes, completion).await?;
                }
                return Ok(());
            }
            Err(error) => {
                last_failure_was_unreachable =
                    private_failure_is_unreachable(io_failed, busy_retry_after);
                peer_proved_reachable |= received_response;
                drop(pair_metrics);
                // `open_stream` may succeed on a cached QUIC connection whose
                // subsequent request/response path is no longer making progress.
                // Never retain that connection across a timeout: Iroh can otherwise
                // keep returning new streams on it until its much longer path-health
                // transition expires. A valid Busy response proves the transport is
                // live and intentionally retains the connection.
                if busy_retry_after.is_none() {
                    if let Some(connection) = attempt_connection.as_ref() {
                        if state
                            .peer_connection_pool
                            .invalidate_if_same(&peer, routes.dkg_private_alpn, connection)
                            .await
                        {
                            crate::metrics::record_dkg_transport_event(
                                "private",
                                "connection_invalidated",
                            );
                            tracing::warn!(
                                session_id = ceremony_id.0,
                                %peer,
                                %error,
                                "invalidated stalled private DKG connection"
                            );
                        }
                    }
                }
                crate::metrics::record_dkg_transport_event("private", "retry");
                // Soft-stall gate: unlike `last_failure_was_unreachable`/`peer_proved_reachable`
                // above (local to this one retry loop, used only for the terminal
                // node_offline-report decision at the hard deadline), this streak persists in
                // session state across the whole attempt so the leader's soft-stall scan can
                // detect a genuinely failing peer well before that deadline. A valid Busy
                // response (see the connection-retention comment above) proves the peer is
                // live and just temporarily overloaded — that's a reachable deferral, not the
                // no-progress signal this streak is meant to capture, so it must not count.
                if busy_retry_after.is_none() {
                    state
                        .dkg_session_state
                        .record_peer_no_progress(
                            AttemptKey::new(ceremony_id, attempt_id),
                            remote_participant.node_id,
                        )
                        .await;
                }
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
    attempt: AttemptKey,
    outgoing: Vec<(u32, String, MessageId, Vec<u8>)>,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let (local_node_id, committees, deadline) = coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |session| {
            (
                session.node.node_id(),
                session.transport.committees.clone(),
                session.transport.hard_deadline,
            )
        })
        .await
        .map_err(|error| crate::dkg::v0::coordinator::attempt_state_error(attempt, error))?;
    let committees = committees.ok_or_else(|| {
        DkgError::InvalidState("ceremony committee configuration is missing".into())
    })?;
    let deadline = deadline
        .ok_or_else(|| DkgError::InvalidState("transport hard deadline is missing".into()))?;
    let mut openers = FuturesUnordered::new();
    let mut message_obligations = Vec::with_capacity(outgoing.len());
    for (to_node_id, peer, _, bytes) in outgoing {
        let decoded = transport::decode::<DkgPrivateMessage>(&bytes, MAX_CONTROL_MESSAGE_BYTES)
            .map_err(DkgError::Deserialization)?;
        if let DkgPrivateMessage::ShareDelivery { message_id, to, .. } = &decoded {
            message_obligations.push((*message_id, *to));
        }
        let should_open = match decoded {
            DkgPrivateMessage::ShareDelivery { from, to, .. }
                if to.scope == CommitteeScope::Next =>
            {
                committees.canonical_pair_opener(from, to) == Some(from)
            }
            DkgPrivateMessage::ShareDelivery { .. } => {
                transport::is_canonical_pair_opener(local_node_id, to_node_id)
            }
            _ => false,
        };
        if should_open {
            let state = coord.app_state.clone();
            let routes = coord.routes;
            openers.push(async move { open_private_pair(state, routes, peer, bytes).await });
        }
    }
    while let Some(result) = openers.next().await {
        result?;
    }
    loop {
        let mut missing_participants = Vec::new();
        for (message_id, remote) in &message_obligations {
            if !coord
                .app_state
                .dkg_session_state
                .private_message_acknowledged_for_attempt(attempt, *message_id)
                .await
                .map_err(|error| crate::dkg::v0::coordinator::attempt_state_error(attempt, error))?
            {
                missing_participants.push(*remote);
            }
        }
        if missing_participants.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline.into() {
            let missing = missing_participants.len();
            let reachable = coord
                .app_state
                .dkg_session_state
                .private_peer_responses_for_attempt(attempt)
                .await
                .map_err(|error| {
                    crate::dkg::v0::coordinator::attempt_state_error(attempt, error)
                })?;
            missing_participants.retain(|participant| !reachable.contains(participant));
            spawn_pss_offline_for_attempt(
                &coord.app_state,
                coord.routes,
                attempt,
                PssOfflineStage::PrivateInbound,
                missing_participants,
            )
            .await;
            return Err(DkgError::NetworkCommunication(format!(
                "{missing} private pair exchanges were not acknowledged before hard deadline"
            )));
        }
        sleep(Duration::from_millis(100)).await;
    }
}
