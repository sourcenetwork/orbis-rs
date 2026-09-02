use super::*;

/// Stable, non-revealing category for a [`DkgError`] sent back to a peer over
/// the control plane. The full error (which frequently interpolates ceremony
/// IDs, attempt IDs, peer prefixes, thresholds, or other internal state) is
/// logged locally instead; only this fixed category name crosses the wire.
/// `retryable_control_error` classifies wire-crossing errors purely by their
/// `DkgError::ProtocolError` wrapper type, not by message content, so
/// coarsening this text does not change retry behavior.
pub(super) fn dkg_error_category(error: &DkgError) -> &'static str {
    match error {
        DkgError::Unauthorized(_) => "unauthorized",
        DkgError::SessionNotFound(_) => "session_not_found",
        DkgError::StaleAttempt { .. } => "stale_attempt",
        DkgError::SessionAlreadyExists => "session_already_exists",
        DkgError::MaxSessionsReached => "max_sessions_reached",
        DkgError::MaxLocalRingsReached { .. } => "max_local_rings_reached",
        DkgError::InvalidInput(_) | DkgError::InvalidParticipantCount(_) => "invalid_input",
        DkgError::InvalidState(_) => "invalid_state",
        DkgError::ProtocolError(_) => "protocol_error",
        DkgError::CommitmentVerificationFailed(_) => "commitment_verification_failed",
        DkgError::ShareVerificationFailed(_) => "share_verification_failed",
        DkgError::InsufficientPeers { .. } => "insufficient_peers",
        DkgError::NetworkConnection(_) | DkgError::NetworkCommunication(_) => "network_error",
        DkgError::BarrierFailure { .. } => "barrier_failure",
        DkgError::Serialization(_) | DkgError::Deserialization(_) => "serialization_error",
        DkgError::Crypto(_)
        | DkgError::Storage(_)
        | DkgError::Bulletin(_)
        | DkgError::Generic(_)
        | DkgError::SystemTime(_)
        | DkgError::HashConversion(_) => "internal_error",
    }
}

pub(super) fn wire_error(peer: &PeerId, error: &DkgError) -> DkgControlMessage {
    tracing::warn!(
        peer = %hex::encode(peer.as_bytes()),
        %error,
        "DKG control request failed"
    );
    DkgControlMessage::Error {
        ceremony_id: None,
        attempt_id: None,
        message: dkg_error_category(error).to_string(),
    }
}

/// `StartFresh`/`StartReshare`/`StartRefresh` are not ceremony-internal
/// peer traffic like Prepare or SessionInit: a nonleader forwards one of
/// these to the canonical leader on behalf of its own API caller and relays
/// the leader's response straight back as that caller's `StartDkg`/etc.
/// result. Coarsening the leader's error here would silently turn a concrete,
/// actionable preparation failure into an opaque category for the client
/// that asked for it, with no ceremony-internal peer ever seeing the detail
/// either way — so these keep the full error text on the wire.
pub(super) fn is_client_forwarded_start_request(request: &DkgControlMessage) -> bool {
    matches!(
        request,
        DkgControlMessage::StartFresh { .. }
            | DkgControlMessage::StartReshare { .. }
            | DkgControlMessage::StartRefresh { .. }
            | DkgControlMessage::GetSessionStatus { .. }
    )
}

pub(super) fn wire_error_for_request(
    peer: &PeerId,
    request: &DkgControlMessage,
    error: &DkgError,
) -> DkgControlMessage {
    if !is_client_forwarded_start_request(request) {
        return wire_error(peer, error);
    }
    tracing::warn!(
        peer = %hex::encode(peer.as_bytes()),
        %error,
        "DKG ceremony-start forwarding failed"
    );
    DkgControlMessage::Error {
        ceremony_id: None,
        attempt_id: None,
        message: error.to_string(),
    }
}

/// Sibling of [`wire_error`] for a request that failed to decode before it
/// could even be dispatched to `handle_control`; there is no typed
/// [`DkgError`] to categorize, so the raw decode failure is logged locally
/// and a single fixed category crosses the wire.
pub(super) fn wire_decode_error(peer: &PeerId, error: String) -> DkgControlMessage {
    tracing::warn!(
        peer = %hex::encode(peer.as_bytes()),
        error = %error,
        "failed to decode DKG control request"
    );
    DkgControlMessage::Error {
        ceremony_id: None,
        attempt_id: None,
        message: "malformed_request".to_string(),
    }
}

/// Inbound request/response handler for the direct control plane.
pub struct DkgControlHandler<D>
where
    D: CoordinatorDkg,
{
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
}

impl<D> DkgControlHandler<D>
where
    D: CoordinatorDkg,
{
    pub fn new(state: Arc<AppState<D>>, routes: &'static network::ProtocolRoutes) -> Self {
        Self { state, routes }
    }
}

#[async_trait]
impl<D> ProtocolHandler for DkgControlHandler<D>
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
            Ok(request) => {
                crate::metrics::record_dkg_transport_message(
                    "control",
                    request.metric_label(),
                    "received",
                );
                let request_for_error = request.clone();
                handle_control(self.state.clone(), self.routes, request, &peer)
                    .await
                    .unwrap_or_else(|error| {
                        wire_error_for_request(&peer, &request_for_error, &error)
                    })
            }
            Err(error) => wire_decode_error(&peer, error),
        };
        let bytes =
            transport::encode(&response).map_err(network::error::NetworkError::Serialization)?;
        connection
            .send(Message::new(bytes, self.routes.dkg_control_alpn.to_vec()))
            .await
    }
}

pub(super) async fn handle_control<D>(
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
        DkgControlMessage::StartFresh { ring_id } => on_start_fresh(state, routes, ring_id).await,
        DkgControlMessage::GetSessionStatus { ring_id } => {
            coordinate_dkg_session_status(state, routes, ring_id).await
        }
        DkgControlMessage::StartReshare {
            ring_id,
            expected_ring_pk,
        } => on_start_reshare(state, routes, sender, ring_id, expected_ring_pk).await,
        DkgControlMessage::StartRefresh {
            ring_id,
            expected_ring_pk,
            requester_node_key,
        } => {
            on_start_refresh(
                state,
                routes,
                sender,
                ring_id,
                expected_ring_pk,
                requester_node_key,
            )
            .await
        }
        DkgControlMessage::Prepare(prepare) => {
            prepare_participant(state, routes, *prepare, sender).await
        }
        DkgControlMessage::TopologyProbeAck {
            ceremony_id,
            attempt_id,
            nonce,
        } => on_topology_probe_ack(state, sender, ceremony_id, attempt_id, nonce).await,
        DkgControlMessage::Activate {
            ceremony_id,
            attempt_id,
            activation_digest,
            active_dealers,
            report_signature: _,
        } => {
            on_activate(
                state,
                sender,
                ceremony_id,
                attempt_id,
                activation_digest,
                active_dealers,
            )
            .await
        }
        DkgControlMessage::Begin {
            ceremony_id,
            attempt_id,
            activation_digest,
            report_signature: _,
        } => {
            on_begin(
                state,
                routes,
                sender,
                ceremony_id,
                attempt_id,
                activation_digest,
            )
            .await
        }
        DkgControlMessage::PublicContribution(signed) => {
            on_public_contribution(state, routes, sender, signed).await
        }
        DkgControlMessage::StageRefreshResult(signed) => {
            on_stage_refresh_result(state, routes, sender, signed).await
        }
        DkgControlMessage::CommitRefreshResult {
            ceremony_id,
            attempt_id,
            message_id,
        } => {
            on_commit_refresh_result(state, routes, sender, ceremony_id, attempt_id, message_id)
                .await
        }
        DkgControlMessage::ReshareShareAck {
            ceremony_id,
            attempt_id,
            idempotency_key,
            receiver,
            dealer,
        } => {
            on_reshare_share_ack(
                state,
                routes,
                sender,
                ceremony_id,
                attempt_id,
                idempotency_key,
                receiver,
                dealer,
            )
            .await
        }
        DkgControlMessage::RelayInvalidShareEvidence {
            ceremony_id,
            attempt_id,
            idempotency_key,
            evidence,
        } => {
            on_relay_invalid_share_evidence(
                state,
                routes,
                sender,
                ceremony_id,
                attempt_id,
                idempotency_key,
                evidence,
            )
            .await
        }
        DkgControlMessage::RelayInvalidCommitmentEvidence {
            ceremony_id,
            attempt_id,
            idempotency_key,
            commitment_a,
            commitment_b,
        } => {
            on_relay_invalid_commitment_evidence(
                state,
                routes,
                sender,
                ceremony_id,
                attempt_id,
                idempotency_key,
                commitment_a,
                commitment_b,
            )
            .await
        }
        DkgControlMessage::RelayPublicOriginFaultEvidence {
            ceremony_id,
            attempt_id,
            idempotency_key,
            fault_kind,
            contribution_a,
            contribution_b,
        } => {
            on_relay_public_origin_fault_evidence(
                state,
                routes,
                sender,
                ceremony_id,
                attempt_id,
                idempotency_key,
                fault_kind,
                contribution_a,
                contribution_b,
            )
            .await
        }
        DkgControlMessage::RelayLeaderEquivocationEvidence {
            ceremony_id,
            attempt_id,
            idempotency_key,
            delivery_id_a,
            delivery_a,
            delivery_id_b,
            delivery_b,
        } => {
            on_relay_leader_equivocation_evidence(
                state,
                routes,
                sender,
                ceremony_id,
                attempt_id,
                idempotency_key,
                delivery_id_a,
                delivery_a,
                delivery_id_b,
                delivery_b,
            )
            .await
        }
        DkgControlMessage::RelayLeaderBatchMismatchEvidence {
            ceremony_id,
            attempt_id,
            idempotency_key,
            delivery_id_a,
            delivery_a,
            delivery_id_b,
            delivery_b,
        } => {
            on_relay_leader_batch_mismatch_evidence(
                state,
                routes,
                sender,
                ceremony_id,
                attempt_id,
                idempotency_key,
                delivery_id_a,
                delivery_a,
                delivery_id_b,
                delivery_b,
            )
            .await
        }
        DkgControlMessage::RelayLeaderPublicFaultEvidence {
            ceremony_id,
            attempt_id,
            idempotency_key,
            fault_kind,
            delivery_id,
            delivery,
        } => {
            on_relay_leader_public_fault_evidence(
                state,
                routes,
                sender,
                ceremony_id,
                attempt_id,
                idempotency_key,
                fault_kind,
                delivery_id,
                delivery,
            )
            .await
        }
        DkgControlMessage::RelayControlMessageFaultEvidence {
            ceremony_id,
            attempt_id,
            idempotency_key,
            accused_node_key,
            message_kind,
            fault_kind,
            artifact_a,
            artifact_b,
        } => {
            on_relay_control_message_fault_evidence(
                state,
                routes,
                sender,
                ceremony_id,
                attempt_id,
                idempotency_key,
                accused_node_key,
                message_kind,
                fault_kind,
                artifact_a,
                artifact_b,
            )
            .await
        }
        DkgControlMessage::RelayOfflineCandidates {
            ceremony_id,
            attempt_id,
            idempotency_key,
            stage,
            accused,
        } => {
            on_relay_offline_candidates(
                state,
                routes,
                sender,
                ceremony_id,
                attempt_id,
                idempotency_key,
                stage,
                accused,
            )
            .await
        }
        DkgControlMessage::GetPublicContribution {
            ceremony_id,
            attempt_id,
            phase,
            origin,
        } => {
            on_get_public_contribution(state, sender, ceremony_id, attempt_id, phase, origin).await
        }
        DkgControlMessage::GetPublicPhase {
            ceremony_id,
            attempt_id,
            phase,
            after,
        } => on_get_public_phase(state, sender, ceremony_id, attempt_id, phase, after).await,
        DkgControlMessage::Abort {
            ceremony_id,
            attempt_id,
            reason,
        } => on_abort(state, sender, ceremony_id, attempt_id, reason).await,
        other => Err(DkgError::ProtocolError(format!(
            "unexpected control request: {other:?}"
        ))),
    }
}

#[cfg(test)]
pub(crate) async fn handle_control_for_test<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    request: DkgControlMessage,
    sender: &PeerId,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    handle_control(state, routes, request, sender).await
}

async fn on_start_fresh<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    ring_id: String,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let (ceremony_id, attempt_id) = coordinate_fresh(state, routes, ring_id).await?;
    Ok(DkgControlMessage::StartAccepted {
        ceremony_id,
        attempt_id,
    })
}

async fn on_start_reshare<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    sender: &PeerId,
    ring_id: String,
    expected_ring_pk: String,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    validate_reshare_start_sender(&state, routes, &ring_id, &expected_ring_pk, sender).await?;
    let outcome = coordinate_reshare(state, routes, ring_id, expected_ring_pk).await?;
    let (ceremony_id, attempt_id) = match outcome {
        ReshareStartOutcome::Started(ceremony_id, attempt_id)
        | ReshareStartOutcome::AlreadyActive(ceremony_id, attempt_id) => (ceremony_id, attempt_id),
        ReshareStartOutcome::Forwarded(_, _) => {
            return Err(DkgError::InvalidState(
                "canonical next-committee leader forwarded a reshare start".into(),
            ));
        }
    };
    Ok(DkgControlMessage::ReshareStartAccepted {
        ceremony_id,
        attempt_id,
    })
}

async fn on_start_refresh<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    sender: &PeerId,
    ring_id: String,
    expected_ring_pk: String,
    requester_node_key: String,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    validate_refresh_start_sender(
        &state,
        routes,
        &ring_id,
        &expected_ring_pk,
        &requester_node_key,
        sender,
    )
    .await?;
    let outcome = coordinate_refresh(state, routes, ring_id, expected_ring_pk).await?;
    match outcome {
        RefreshStartOutcome::Started(ceremony_id, attempt_id)
        | RefreshStartOutcome::AlreadyActive(ceremony_id, attempt_id) => {
            Ok(DkgControlMessage::RefreshStartAccepted {
                ceremony_id,
                attempt_id,
            })
        }
        RefreshStartOutcome::NotDue => Ok(DkgControlMessage::RefreshNotDue),
        RefreshStartOutcome::Forwarded(_, _) => Err(DkgError::InvalidState(
            "coordinate_refresh unexpectedly forwarded a refresh start".into(),
        )),
    }
}

async fn on_topology_probe_ack<D>(
    state: Arc<AppState<D>>,
    sender: &PeerId,
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    nonce: [u8; 32],
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    validate_leader_local(&state, ceremony_id.0).await?;
    let peer = canonical_committee_peer(&state, ceremony_id.0, sender).await?;
    match state
        .dkg_session_state
        .record_topology_probe_ack(&ceremony_id.0, attempt_id, nonce, peer)
        .await
    {
        TopologyAckRecordOutcome::Recorded => {
            crate::metrics::record_dkg_transport_event("control", "probe_ack");
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

async fn on_activate<D>(
    state: Arc<AppState<D>>,
    sender: &PeerId,
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    activation_digest: [u8; 32],
    active_dealers: Vec<ParticipantRef>,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    validate_leader_sender(&state, ceremony_id.0, sender).await?;
    let (_, configured_attempt, config_digest) = state
        .dkg_session_state
        .transport_configuration(&ceremony_id.0)
        .await
        .ok_or_else(|| DkgError::SessionNotFound(ceremony_id.0.to_string()))?;
    if configured_attempt != attempt_id
        || transport::activation_digest(config_digest, &active_dealers)
            .map_err(DkgError::ProtocolError)?
            != activation_digest
    {
        return Err(DkgError::Unauthorized(
            "activation digest or dealer set does not match prepared attempt".into(),
        ));
    }
    let activation = state
        .dkg_session_state
        .activate_transport(
            &ceremony_id.0,
            attempt_id,
            activation_digest,
            active_dealers,
        )
        .await;
    match activation {
        TransportActivationOutcome::AlreadyActivated => {
            let report_signature = Some(sign_control_message(
                &state,
                ceremony_id,
                attempt_id,
                "activated",
                activation_digest,
            )?);
            return Ok(DkgControlMessage::Activated {
                ceremony_id,
                attempt_id,
                activation_digest,
                report_signature,
            });
        }
        TransportActivationOutcome::Activated => {}
        TransportActivationOutcome::StaleAttempt | TransportActivationOutcome::MissingSession => {
            return Err(DkgError::ProtocolError("activate for stale attempt".into()));
        }
    }
    let report_signature = Some(sign_control_message(
        &state,
        ceremony_id,
        attempt_id,
        "activated",
        activation_digest,
    )?);
    Ok(DkgControlMessage::Activated {
        ceremony_id,
        attempt_id,
        activation_digest,
        report_signature,
    })
}

async fn on_begin<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    sender: &PeerId,
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    activation_digest: [u8; 32],
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    validate_leader_sender(&state, ceremony_id.0, sender).await?;
    match state
        .dkg_session_state
        .begin_transport(&ceremony_id.0, attempt_id, activation_digest)
        .await
    {
        TransportBeginOutcome::Begun => {
            spawn_cryptographic_attempt(
                state.clone(),
                routes,
                AttemptKey::new(ceremony_id, attempt_id),
            );
        }
        TransportBeginOutcome::AlreadyBegun => {}
        TransportBeginOutcome::NotActivated => {
            return Err(DkgError::InvalidState(
                "begin received before transport activation".into(),
            ));
        }
        TransportBeginOutcome::StaleAttempt | TransportBeginOutcome::MissingSession => {
            return Err(DkgError::ProtocolError("begin for stale attempt".into()));
        }
    }
    let report_signature = Some(sign_control_message(
        &state,
        ceremony_id,
        attempt_id,
        "begun",
        activation_digest,
    )?);
    Ok(DkgControlMessage::Begun {
        ceremony_id,
        attempt_id,
        activation_digest,
        report_signature,
    })
}

async fn on_public_contribution<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    sender: &PeerId,
    signed: SignedPayload,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    if signed.origin.as_slice() != sender.as_bytes() {
        return Err(DkgError::Unauthorized(
            "direct public contribution sender differs from embedded origin".into(),
        ));
    }
    let contribution = verify_signed_contribution(&state, &signed).await?;
    tracing::info!(
        session_id = contribution.ceremony_id.0,
        origin = ?contribution.origin,
        phase = ?contribution.payload.phase(),
        "leader received signed public DKG contribution"
    );
    validate_leader_local(&state, contribution.ceremony_id.0).await?;
    if let Err(error) =
        preflight_public_contribution_if_new(&state, routes, &signed, &contribution).await
    {
        if attributable_public_preflight_error(&error) {
            let attempt = AttemptKey::new(contribution.ceremony_id, contribution.attempt_id);
            let participant_routes = state
                .dkg_session_state
                .with_attempt_state(attempt, |session| {
                    session.transport.participant_routes.clone()
                })
                .await
                .unwrap_or_default();
            tracing::error!(
                session_id = contribution.ceremony_id.0,
                attempt_id = %hex::encode(contribution.attempt_id.0),
                phase = ?contribution.payload.phase(),
                origin = ?contribution.origin,
                message_id = %hex::encode(contribution.message_id.0),
                %error,
                "leader aborting DKG attempt after direct-origin payload failed preflight"
            );
            crate::metrics::record_dkg_transport_event("public", "protocol_violation_abort");
            report_public_origin_fault_best_effort(
                &state,
                routes,
                attempt,
                Some(&PublicOriginFaultEvidence {
                    fault_kind: DkgPublicOriginFaultKind::InvalidPayload,
                    contribution_a: signed.clone(),
                    contribution_b: None,
                }),
            )
            .await;
            state
                .dkg_session_state
                .abort_transport_attempt(attempt, TopicTaskDisposition::Abort)
                .await;
            broadcast_attempt_abort(
                &state,
                routes,
                participant_routes,
                contribution.ceremony_id,
                contribution.attempt_id,
                format!("direct-origin public contribution failed preflight: {error}"),
            )
            .await;
        }
        return Err(error);
    }
    record_public_contribution_at_leader(&state, routes, signed.clone(), &contribution).await?;
    publish_phase_if_complete(
        state.clone(),
        routes,
        contribution.ceremony_id.0,
        contribution.attempt_id,
        contribution.payload.phase(),
    )
    .await?;
    // The direct ACK confirms authenticated retention by the leader,
    // not completion of the leader's local protocol transition. The
    // last contribution in a phase can enter Phase 2 and wait for
    // every private pair exchange; withholding the ACK until then
    // deadlocks the contributing follower before it can consume the
    // public batch and generate its reciprocal share. Dispatch is
    // attempt-scoped and idempotent, so a retry may safely schedule it
    // again after an earlier application failure.
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
                origin = ?dispatch_contribution.origin,
                phase = ?dispatch_contribution.payload.phase(),
                "leader failed to apply retained public DKG contribution"
            );
        }
    });
    Ok(DkgControlMessage::PublicContributionAck {
        ceremony_id: contribution.ceremony_id,
        attempt_id: contribution.attempt_id,
        message_id: contribution.message_id,
    })
}

async fn on_stage_refresh_result<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    sender: &PeerId,
    signed: SignedPayload,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
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
    if let Err(error) =
        preflight_public_contribution_if_new(&state, routes, &signed, &contribution).await
    {
        if attributable_public_preflight_error(&error) {
            let attempt = AttemptKey::new(contribution.ceremony_id, contribution.attempt_id);
            tracing::error!(
                session_id = contribution.ceremony_id.0,
                attempt_id = %hex::encode(contribution.attempt_id.0),
                message_id = %hex::encode(contribution.message_id.0),
                %error,
                "aborting DKG attempt after staged leader result failed preflight"
            );
            report_public_origin_fault_best_effort(
                &state,
                routes,
                attempt,
                Some(&PublicOriginFaultEvidence {
                    fault_kind: DkgPublicOriginFaultKind::InvalidPayload,
                    contribution_a: signed.clone(),
                    contribution_b: None,
                }),
            )
            .await;
            state
                .dkg_session_state
                .abort_transport_attempt(attempt, TopicTaskDisposition::Abort)
                .await;
        }
        return Err(error);
    }
    record_public_contribution(&state, routes, signed, &contribution).await?;
    crate::metrics::record_dkg_transport_event("public", "result_staged");
    Ok(DkgControlMessage::PublicContributionAck {
        ceremony_id: contribution.ceremony_id,
        attempt_id: contribution.attempt_id,
        message_id: contribution.message_id,
    })
}

async fn on_commit_refresh_result<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    sender: &PeerId,
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    message_id: MessageId,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let receipt_key = (ceremony_id, attempt_id, message_id);
    if let Some(leader_peer) = state
        .dkg_session_state
        .public_commit_receipt(receipt_key)
        .await
    {
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

    validate_leader_sender(&state, ceremony_id.0, sender).await?;
    if state
        .dkg_session_state
        .transport_attempt(&ceremony_id.0)
        .await
        != Some(attempt_id)
    {
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
    // StageRefreshResult already retained this exact signed message.
    // Commit is the authorization to apply it, so bypass the generic
    // record-and-deduplicate helper: treating the retained record as a
    // completed application would leave followers staged forever.
    let retained_signed = signed.clone();
    if let Err(error) =
        dispatch_public_contribution(state.clone(), routes, signed, contribution.clone()).await
    {
        if attributable_public_preflight_error(&error) {
            tracing::error!(
                session_id = ceremony_id.0,
                attempt_id = %hex::encode(attempt_id.0),
                message_id = %hex::encode(message_id.0),
                %error,
                "aborting DKG attempt after committed leader result failed validation"
            );
            crate::metrics::record_dkg_transport_event("public", "protocol_violation_abort");
            report_public_origin_fault_best_effort(
                &state,
                routes,
                AttemptKey::new(ceremony_id, attempt_id),
                Some(&PublicOriginFaultEvidence {
                    fault_kind: DkgPublicOriginFaultKind::InvalidPayload,
                    contribution_a: retained_signed,
                    contribution_b: None,
                }),
            )
            .await;
            state
                .dkg_session_state
                .abort_transport_attempt(
                    AttemptKey::new(ceremony_id, attempt_id),
                    TopicTaskDisposition::Abort,
                )
                .await;
        }
        return Err(error);
    }

    state
        .dkg_session_state
        .record_public_commit_receipt(receipt_key, sender.as_bytes().to_vec())
        .await;
    crate::metrics::record_dkg_transport_event("public", "result_committed");
    Ok(DkgControlMessage::PublicContributionAck {
        ceremony_id,
        attempt_id,
        message_id,
    })
}

async fn on_reshare_share_ack<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    sender: &PeerId,
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    idempotency_key: MessageId,
    receiver: ParticipantRef,
    dealer: ParticipantRef,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let attempt = AttemptKey::new(ceremony_id, attempt_id);
    if receiver.scope != CommitteeScope::Next
        || dealer.scope != CommitteeScope::Current
        || receiver.node_id == 0
        || dealer.node_id == 0
    {
        return Err(DkgError::Unauthorized(
            "reshare acknowledgement has invalid scoped participants".into(),
        ));
    }
    let expected_sender = state
        .dkg_session_state
        .peer_id_for_participant(&ceremony_id.0, receiver)
        .await
        .ok_or_else(|| DkgError::Unauthorized("receiver route is missing".into()))?;
    if !peer_matches_route(sender, &expected_sender) {
        return Err(DkgError::Unauthorized(
            "reshare acknowledgement sender is not its named receiver".into(),
        ));
    }
    let expected_key = transport::derive_control_message_id(
        ceremony_id,
        attempt_id,
        "reshare-share-ack",
        receiver,
        ParticipantRef::next(1),
        &dealer,
    )
    .map_err(DkgError::Serialization)?;
    if expected_key != idempotency_key
        || state
            .dkg_session_state
            .transport_attempt(&ceremony_id.0)
            .await
            != Some(attempt_id)
    {
        return Err(DkgError::Unauthorized(
            "reshare acknowledgement key or attempt is invalid".into(),
        ));
    }
    loop {
        match state
            .dkg_session_state
            .claim_transport_message(attempt, idempotency_key)
            .await
        {
            MessageProcessingClaim::Claimed => break,
            MessageProcessingClaim::AlreadyProcessed => {
                return Ok(DkgControlMessage::ReshareShareAcked {
                    ceremony_id,
                    attempt_id,
                    idempotency_key,
                });
            }
            MessageProcessingClaim::AlreadyProcessing => {
                sleep(Duration::from_millis(10)).await;
            }
            MessageProcessingClaim::MissingSession => {
                return Err(DkgError::SessionNotFound(ceremony_id.0.to_string()));
            }
            MessageProcessingClaim::StaleAttempt => {
                return Err(DkgError::Unauthorized(
                    "reshare acknowledgement targets a stale attempt".into(),
                ));
            }
        }
    }
    let coordinator = DkgCoordinator::with_routes(state.clone(), routes);
    let result =
        handle_reshare_share_ack(&coordinator, attempt, receiver.node_id, dealer.node_id).await;
    state
        .dkg_session_state
        .finish_transport_message(attempt, idempotency_key, result.is_ok())
        .await;
    result?;
    Ok(DkgControlMessage::ReshareShareAcked {
        ceremony_id,
        attempt_id,
        idempotency_key,
    })
}

async fn on_relay_invalid_share_evidence<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    sender: &PeerId,
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    idempotency_key: MessageId,
    evidence: SignedDkgShare,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let attempt = AttemptKey::new(ceremony_id, attempt_id);
    let origin = ParticipantRef::next(evidence.statement.to_node_id);
    let expected_sender = state
        .dkg_session_state
        .peer_id_for_participant(&ceremony_id.0, origin)
        .await
        .ok_or_else(|| DkgError::Unauthorized("evidence sender route is missing".into()))?;
    if !peer_matches_route(sender, &expected_sender) {
        return Err(DkgError::Unauthorized(
            "invalid-share evidence sender is not its named receiver".into(),
        ));
    }
    let local_id = state
        .dkg_session_state
        .with_state(&ceremony_id.0, |session| session.node.node_id())
        .await
        .ok_or_else(|| DkgError::SessionNotFound(ceremony_id.0.to_string()))?;
    let recipient = ParticipantRef::current(local_id);
    let expected_key = transport::derive_control_message_id(
        ceremony_id,
        attempt_id,
        "invalid-share-evidence",
        origin,
        recipient,
        &evidence,
    )
    .map_err(DkgError::Serialization)?;
    if expected_key != idempotency_key
        || state
            .dkg_session_state
            .transport_attempt(&ceremony_id.0)
            .await
            != Some(attempt_id)
    {
        return Err(DkgError::Unauthorized(
            "evidence idempotency key or attempt mismatch".into(),
        ));
    }
    if !claim_control_message(&state, attempt, idempotency_key).await? {
        return Ok(DkgControlMessage::EvidenceAccepted {
            ceremony_id,
            attempt_id,
            idempotency_key,
        });
    }
    let coordinator = DkgCoordinator::with_routes(state.clone(), routes);
    let result = handle_invalid_share_evidence_relay(&coordinator, attempt, evidence).await;
    state
        .dkg_session_state
        .finish_transport_message(attempt, idempotency_key, result.is_ok())
        .await;
    result?;
    Ok(DkgControlMessage::EvidenceAccepted {
        ceremony_id,
        attempt_id,
        idempotency_key,
    })
}

/// Shared body for the six pending-new-reshare-member -> current-committee
/// fault-evidence relays (`RelayInvalidCommitmentEvidence` /
/// `RelayPublicOriginFaultEvidence` / `RelayLeaderEquivocationEvidence` /
/// `RelayLeaderBatchMismatchEvidence` / `RelayLeaderPublicFaultEvidence` /
/// `RelayControlMessageFaultEvidence`). Resolves the next-committee origin
/// from the authenticated `sender` via the reshare routing map, re-derives
/// and checks the idempotency key against `payload`, claims the message,
/// runs the caller's specific `handle_*_relay` via `run`, and replies
/// `EvidenceAccepted`. `RelayInvalidShareEvidence` is deliberately NOT
/// routed through here: it resolves its origin from the nested statement's
/// `to_node_id`, not the routing map.
#[allow(clippy::too_many_arguments)]
async fn relay_next_committee_evidence<D, P, Fut>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    sender: &PeerId,
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    idempotency_key: MessageId,
    message_kind: &str,
    origin_missing_detail: &str,
    key_mismatch_detail: &str,
    payload: &P,
    run: impl FnOnce(DkgCoordinator<D>, AttemptKey) -> Fut,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
    P: serde::Serialize,
    Fut: std::future::Future<Output = Result<()>>,
{
    let attempt = AttemptKey::new(ceremony_id, attempt_id);
    let (origin, recipient) = state
        .dkg_session_state
        .with_state(&ceremony_id.0, |session| {
            let origin = session
                .routing
                .reshare_new_node_id_to_peer_id
                .iter()
                .find_map(|(node_id, peer)| {
                    peer_matches_route(sender, peer).then_some(ParticipantRef::next(*node_id))
                });
            (origin, ParticipantRef::current(session.node.node_id()))
        })
        .await
        .ok_or_else(|| DkgError::SessionNotFound(ceremony_id.0.to_string()))?;
    let origin = origin.ok_or_else(|| DkgError::Unauthorized(origin_missing_detail.to_string()))?;
    let expected_key = transport::derive_control_message_id(
        ceremony_id,
        attempt_id,
        message_kind,
        origin,
        recipient,
        payload,
    )
    .map_err(DkgError::Serialization)?;
    if expected_key != idempotency_key
        || state
            .dkg_session_state
            .transport_attempt(&ceremony_id.0)
            .await
            != Some(attempt_id)
    {
        return Err(DkgError::Unauthorized(key_mismatch_detail.to_string()));
    }
    if !claim_control_message(&state, attempt, idempotency_key).await? {
        return Ok(DkgControlMessage::EvidenceAccepted {
            ceremony_id,
            attempt_id,
            idempotency_key,
        });
    }
    let coordinator = DkgCoordinator::with_routes(state.clone(), routes);
    let result = run(coordinator, attempt).await;
    state
        .dkg_session_state
        .finish_transport_message(attempt, idempotency_key, result.is_ok())
        .await;
    result?;
    Ok(DkgControlMessage::EvidenceAccepted {
        ceremony_id,
        attempt_id,
        idempotency_key,
    })
}

async fn on_relay_invalid_commitment_evidence<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    sender: &PeerId,
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    idempotency_key: MessageId,
    commitment_a: SignedDkgCommitment,
    commitment_b: SignedDkgCommitment,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let payload = (commitment_a.clone(), commitment_b.clone());
    relay_next_committee_evidence(
        state,
        routes,
        sender,
        ceremony_id,
        attempt_id,
        idempotency_key,
        "invalid-commitment-evidence",
        "equivocation evidence sender is not in next committee",
        "evidence idempotency key or attempt mismatch",
        &payload,
        move |coordinator, attempt| async move {
            handle_invalid_commitment_evidence_relay(
                &coordinator,
                attempt,
                commitment_a,
                commitment_b,
            )
            .await
        },
    )
    .await
}

async fn on_relay_public_origin_fault_evidence<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    sender: &PeerId,
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    idempotency_key: MessageId,
    fault_kind: DkgPublicOriginFaultKind,
    contribution_a: SignedPayload,
    contribution_b: Option<SignedPayload>,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let payload = (fault_kind, contribution_a.clone(), contribution_b.clone());
    relay_next_committee_evidence(
        state,
        routes,
        sender,
        ceremony_id,
        attempt_id,
        idempotency_key,
        "public-origin-fault-evidence",
        "public-origin evidence sender is not in next committee",
        "public-origin evidence idempotency key or attempt mismatch",
        &payload,
        move |coordinator, attempt| async move {
            handle_public_origin_fault_evidence_relay(
                &coordinator,
                attempt,
                fault_kind,
                contribution_a,
                contribution_b,
            )
            .await
        },
    )
    .await
}

async fn on_relay_leader_equivocation_evidence<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    sender: &PeerId,
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    idempotency_key: MessageId,
    delivery_id_a: [u8; 16],
    delivery_a: SignedPayload,
    delivery_id_b: [u8; 16],
    delivery_b: SignedPayload,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let payload = (
        delivery_id_a,
        delivery_a.clone(),
        delivery_id_b,
        delivery_b.clone(),
    );
    relay_next_committee_evidence(
        state,
        routes,
        sender,
        ceremony_id,
        attempt_id,
        idempotency_key,
        "leader-equivocation-evidence",
        "leader-equivocation evidence sender is not in next committee",
        "leader-equivocation evidence idempotency key or attempt mismatch",
        &payload,
        move |coordinator, attempt| async move {
            handle_leader_equivocation_evidence_relay(
                &coordinator,
                attempt,
                delivery_id_a,
                delivery_a,
                delivery_id_b,
                delivery_b,
            )
            .await
        },
    )
    .await
}

async fn on_relay_leader_batch_mismatch_evidence<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    sender: &PeerId,
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    idempotency_key: MessageId,
    delivery_id_a: [u8; 16],
    delivery_a: SignedPayload,
    delivery_id_b: [u8; 16],
    delivery_b: SignedPayload,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let payload = (
        delivery_id_a,
        delivery_a.clone(),
        delivery_id_b,
        delivery_b.clone(),
    );
    relay_next_committee_evidence(
        state,
        routes,
        sender,
        ceremony_id,
        attempt_id,
        idempotency_key,
        "leader-batch-mismatch-evidence",
        "leader batch-mismatch evidence sender is not in next committee",
        "leader batch-mismatch evidence idempotency key or attempt mismatch",
        &payload,
        move |coordinator, attempt| async move {
            handle_leader_batch_mismatch_evidence_relay(
                &coordinator,
                attempt,
                delivery_id_a,
                delivery_a,
                delivery_id_b,
                delivery_b,
            )
            .await
        },
    )
    .await
}

async fn on_relay_leader_public_fault_evidence<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    sender: &PeerId,
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    idempotency_key: MessageId,
    fault_kind: DkgLeaderPublicFaultKind,
    delivery_id: [u8; 16],
    delivery: SignedPayload,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let payload = (fault_kind, delivery_id, delivery.clone());
    relay_next_committee_evidence(
        state,
        routes,
        sender,
        ceremony_id,
        attempt_id,
        idempotency_key,
        "leader-public-fault-evidence",
        "leader public-fault evidence sender is not in next committee",
        "leader public-fault evidence idempotency key or attempt mismatch",
        &payload,
        move |coordinator, attempt| async move {
            handle_leader_public_fault_evidence_relay(
                &coordinator,
                attempt,
                fault_kind,
                delivery_id,
                delivery,
            )
            .await
        },
    )
    .await
}

async fn on_relay_control_message_fault_evidence<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    sender: &PeerId,
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    idempotency_key: MessageId,
    accused_node_key: String,
    message_kind: String,
    fault_kind: DkgControlMessageFaultKind,
    artifact_a: ControlMessageArtifact,
    artifact_b: Option<ControlMessageArtifact>,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let payload = (
        accused_node_key.clone(),
        message_kind.clone(),
        fault_kind,
        artifact_a.clone(),
        artifact_b.clone(),
    );
    relay_next_committee_evidence(
        state,
        routes,
        sender,
        ceremony_id,
        attempt_id,
        idempotency_key,
        "control-message-fault-evidence",
        "control-message fault evidence sender is not in next committee",
        "control-message fault evidence idempotency key or attempt mismatch",
        &payload,
        move |coordinator, attempt| async move {
            handle_control_message_fault_evidence_relay(
                &coordinator,
                attempt,
                accused_node_key,
                message_kind,
                fault_kind,
                artifact_a,
                artifact_b,
            )
            .await
        },
    )
    .await
}

async fn on_relay_offline_candidates<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    sender: &PeerId,
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    idempotency_key: MessageId,
    stage: PssOfflineStage,
    accused: Vec<ParticipantRef>,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let mut relay_rejection = OfflineRelayRejectionGuard::new(stage);
    let attempt = AttemptKey::new(ceremony_id, attempt_id);
    let receipt = state
        .dkg_session_state
        .offline_relay_receipt(attempt)
        .await
        .ok_or_else(|| {
            DkgError::Unauthorized(
                "offline-candidate relay targets an unknown or expired attempt".into(),
            )
        })?;
    let kind = receipt.kind;
    let ring_id = receipt.ring_id;
    let protocol_version = receipt.protocol_version;
    let committees = receipt.committees;
    let leader_node_key = receipt.leader_node_key;
    validate_offline_relay_transition(&state, routes, ceremony_id, &kind, &ring_id).await?;
    validate_offline_relay_claim(
        &committees,
        &leader_node_key,
        &state.node_key,
        sender,
        stage,
        &accused,
    )?;
    let canonical_accused = accused;
    let expected_key = transport::derive_offline_candidates_id(
        ceremony_id,
        attempt_id,
        sender.as_bytes(),
        stage,
        &canonical_accused,
    )
    .map_err(DkgError::Serialization)?;
    if expected_key != idempotency_key {
        return Err(DkgError::Unauthorized(
            "offline-candidate idempotency key mismatch".into(),
        ));
    }
    let claimed = state
        .dkg_session_state
        .claim_offline_relay_idempotency(attempt, idempotency_key)
        .await
        .ok_or_else(|| DkgError::Unauthorized("offline-candidate relay receipt expired".into()))?;
    if !claimed {
        relay_rejection.accept();
        return Ok(DkgControlMessage::OfflineCandidatesAccepted {
            ceremony_id,
            attempt_id,
            idempotency_key,
        });
    }
    spawn_pss_offline_observations(
        state.clone(),
        routes,
        PssOfflineObservationSeed::new(
            ceremony_id,
            Some(attempt_id),
            kind,
            ring_id,
            protocol_version,
            stage,
            committees,
            canonical_accused,
        ),
    );
    crate::metrics::record_pss_offline_observation(stage.as_metric_label(), "relay_accepted");
    relay_rejection.accept();
    Ok(DkgControlMessage::OfflineCandidatesAccepted {
        ceremony_id,
        attempt_id,
        idempotency_key,
    })
}

async fn on_get_public_contribution<D>(
    state: Arc<AppState<D>>,
    sender: &PeerId,
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    phase: PublicPhase,
    origin: ParticipantRef,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    canonical_committee_peer(&state, ceremony_id.0, sender).await?;
    state
        .dkg_session_state
        .with_state(&ceremony_id.0, |_| ())
        .await
        .ok_or_else(|| DkgError::SessionNotFound(ceremony_id.0.to_string()))?;
    let committees = state
        .dkg_session_state
        .transport_committees(&ceremony_id.0)
        .await
        .ok_or_else(|| {
            DkgError::InvalidState("ceremony committee configuration is missing".into())
        })?;
    if committees.node_key(origin) != Some(state.node_key.as_str()) {
        return Err(DkgError::Unauthorized(
            "public origin repair must be requested from that origin".into(),
        ));
    }
    let contribution = state
        .dkg_session_state
        .public_contributions(&ceremony_id.0, attempt_id, phase)
        .await
        .and_then(|items| items.get(&origin).cloned());
    Ok(DkgControlMessage::PublicContributionResponse {
        ceremony_id,
        attempt_id,
        contribution,
    })
}

async fn on_get_public_phase<D>(
    state: Arc<AppState<D>>,
    sender: &PeerId,
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    phase: PublicPhase,
    after: Option<ParticipantRef>,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    validate_leader_local(&state, ceremony_id.0).await?;
    canonical_committee_peer(&state, ceremony_id.0, sender).await?;
    if state
        .dkg_session_state
        .transport_attempt(&ceremony_id.0)
        .await
        != Some(attempt_id)
    {
        return Err(DkgError::ProtocolError(
            "public phase repair targets a stale attempt".into(),
        ));
    }
    let retained = state
        .dkg_session_state
        .public_contributions(&ceremony_id.0, attempt_id, phase)
        .await
        .ok_or_else(|| DkgError::SessionNotFound(ceremony_id.0.to_string()))?;
    let response = public_phase_response_page(ceremony_id, attempt_id, phase, &retained, after)?;
    let response = sign_public_phase_response(&state, response)?;
    let encoded_len = transport::encode(&response)
        .map_err(DkgError::Serialization)?
        .len();
    let (contribution_count, next_cursor) = match &response {
        DkgControlMessage::PublicPhaseResponse {
            contributions,
            next_cursor,
            ..
        } => (contributions.len(), *next_cursor),
        _ => unreachable!("public repair page builder returned a different message"),
    };
    crate::metrics::record_dkg_transport_event("public", "repair_page_served");
    tracing::debug!(
        session_id = ceremony_id.0,
        attempt_id = %hex::encode(attempt_id.0),
        phase = ?phase,
        after = ?after,
        next_cursor = ?next_cursor,
        contribution_count,
        encoded_len,
        "served byte-bounded public DKG repair page"
    );
    Ok(response)
}

async fn on_abort<D>(
    state: Arc<AppState<D>>,
    sender: &PeerId,
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    reason: String,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let attempt = AttemptKey::new(ceremony_id, attempt_id);
    validate_leader_sender_for_attempt(&state, attempt, sender).await?;
    tracing::warn!(
        session_id = ceremony_id.0,
        attempt_id = %hex::encode(attempt_id.0),
        %reason,
        "transport DKG attempt aborted"
    );
    state
        .dkg_session_state
        .abort_transport_attempt(attempt, TopicTaskDisposition::Abort)
        .await;
    Ok(DkgControlMessage::Abort {
        ceremony_id,
        attempt_id,
        reason,
    })
}
