use super::*;

/// Begin cryptographic work only after the leader has observed an activation
/// acknowledgement from every active participant. Keeping this separate from
/// `Activate` prevents fast incremental reshare traffic from reaching a peer
/// whose matching attempt is prepared but not active yet.
pub(super) async fn begin_cryptographic_attempt<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    attempt: AttemptKey,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let coordinator = DkgCoordinator::with_routes(state.clone(), routes);
    let (peer_ids, kind) = state
        .dkg_session_state
        .with_attempt_state(attempt, |session| {
            (session.routing.peer_ids.clone(), session.kind.clone())
        })
        .await
        .map_err(|error| crate::dkg::v0::coordinator::attempt_state_error(attempt, error))?;
    match kind {
        SessionKind::Fresh => {
            coordinator
                .initiate_phase0_commitment_hashes(attempt, &peer_ids)
                .await?;
        }
        SessionKind::Refresh { .. } => {
            coordinator
                .initiate_phase1_commitments(attempt, &peer_ids)
                .await?;
        }
        SessionKind::Reshare { .. } => {
            coordinator
                .initiate_phase1_commitments(attempt, &peer_ids)
                .await?;
            spawn_reshare_receiver_pair_openers(state, routes, attempt);
        }
    }
    Ok(())
}

pub(super) fn spawn_cryptographic_attempt<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    attempt: AttemptKey,
) where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    tokio::spawn(async move {
        let Ok(mut cancelled) = state.dkg_session_state.attempt_cancellation(attempt).await else {
            return;
        };
        let result = tokio::select! {
            result = begin_cryptographic_attempt(state.clone(), routes, attempt) => Some(result),
            _ = cancelled.changed() => None,
        };
        let Some(Err(error)) = result else {
            return;
        };
        tracing::error!(
            session_id = attempt.session_id(),
            attempt_id = %hex::encode(attempt.attempt_id.0),
            %error,
            "activated DKG attempt failed while beginning cryptographic work"
        );
        state
            .dkg_session_state
            .abort_transport_attempt(attempt, TopicTaskDisposition::Abort)
            .await;
    });
}

/// Claim an attempt-scoped control idempotency key. A completed duplicate is
/// acknowledged without re-running its side effects; a concurrent duplicate
/// waits for the first handler to publish its outcome.
pub(super) async fn claim_control_message<D>(
    state: &Arc<AppState<D>>,
    attempt: AttemptKey,
    message_id: MessageId,
) -> Result<bool>
where
    D: CoordinatorDkg,
{
    loop {
        match state
            .dkg_session_state
            .claim_transport_message(attempt, message_id)
            .await
        {
            MessageProcessingClaim::Claimed => return Ok(true),
            MessageProcessingClaim::AlreadyProcessed => {
                return Ok(false);
            }
            MessageProcessingClaim::AlreadyProcessing => {
                sleep(Duration::from_millis(10)).await;
            }
            MessageProcessingClaim::MissingSession => {
                return Err(DkgError::SessionNotFound(attempt.session_id().to_string()));
            }
            MessageProcessingClaim::StaleAttempt => {
                return Err(DkgError::Unauthorized(
                    "control message targets a stale attempt".into(),
                ));
            }
        }
    }
}

pub(super) async fn validate_leader_sender<D>(
    state: &Arc<AppState<D>>,
    session_id: u128,
    sender: &PeerId,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    state
        .dkg_session_state
        .transport_info(&session_id)
        .await
        .ok_or_else(|| DkgError::SessionNotFound(session_id.to_string()))?;
    let route = state
        .dkg_session_state
        .transport_leader_route(&session_id)
        .await
        .ok_or_else(|| DkgError::InvalidState("leader route is missing".into()))?;
    if !peer_matches_route(sender, &route) {
        return Err(DkgError::Unauthorized(
            "control sender is not canonical leader".into(),
        ));
    }
    Ok(())
}

pub(super) async fn validate_leader_sender_for_attempt<D>(
    state: &Arc<AppState<D>>,
    attempt: AttemptKey,
    sender: &PeerId,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let route = state
        .dkg_session_state
        .with_attempt_state(attempt, |session| {
            session.transport.leader_peer_route.clone()
        })
        .await
        .map_err(|error| crate::dkg::v0::coordinator::attempt_state_error(attempt, error))?
        .ok_or_else(|| DkgError::InvalidState("leader route is missing".into()))?;
    if !peer_matches_route(sender, &route) {
        return Err(DkgError::Unauthorized(
            "control sender is not canonical leader".into(),
        ));
    }
    Ok(())
}

pub(super) async fn canonical_committee_peer<D>(
    state: &Arc<AppState<D>>,
    session_id: u128,
    sender: &PeerId,
) -> Result<String>
where
    D: CoordinatorDkg,
{
    let peers = state
        .dkg_session_state
        .transport_participant_routes(&session_id)
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

pub(super) async fn validate_leader_local<D>(
    state: &Arc<AppState<D>>,
    session_id: u128,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let leader = state
        .dkg_session_state
        .transport_info(&session_id)
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

pub(super) async fn prepare_participant<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: PrepareSession,
    sender: &PeerId,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let leader_authorized =
        prepare.canonical_leader_node_key() == Some(prepare.leader_node_key.as_str());
    if !leader_authorized {
        if !matches!(prepare.kind, SessionKind::Fresh) {
            report_leader_prepare_fault_best_effort(&state, routes, &prepare).await;
            crate::metrics::record_dkg_transport_event("control", "refresh_start_rejected");
        }
        return Err(DkgError::Unauthorized(
            "Prepare names an unauthorized leader".into(),
        ));
    }
    let leader_route = prepare
        .leader_route()
        .ok_or_else(|| DkgError::InvalidInput("Prepare omits leader route".into()))?;
    if !peer_matches_route(sender, leader_route) {
        return Err(DkgError::Unauthorized(
            "Prepare sender is not canonical leader".into(),
        ));
    }
    let expected = transport::config_digest(&prepare).map_err(DkgError::Serialization)?;
    if expected != prepare.config_digest {
        // Not reported: a signature only covers config_digest, so a
        // self-inconsistent Prepare (digest doesn't match its own fields)
        // could equally be a relay tampering with fields post-signature as
        // the real signer's own mistake — report_leader_prepare_fault_best_effort
        // itself refuses to attribute this ambiguous case.
        return Err(DkgError::Unauthorized(
            "Prepare configuration digest mismatch".into(),
        ));
    }

    // A lost Prepared response may cause the leader to retry the exact request.
    // Check this cheap, session-local fast path before paying for Vera
    // reshare route resolution or session-init validation below: both make
    // live chain reads, and retries must stay cheap or preparation cannot
    // tolerate the network hiccups it exists to survive. `transport_configuration`
    // safely returns `None` when no session has been created yet, so this is
    // sound to check before `handle_session_init` creates one.
    if let Some((ceremony_id, attempt_id, config_digest)) = state
        .dkg_session_state
        .transport_configuration(&prepare.ceremony_id.0)
        .await
    {
        if ceremony_id == prepare.ceremony_id
            && attempt_id == prepare.attempt_id
            && config_digest == prepare.config_digest
        {
            let report_signature = Some(sign_control_message(
                &state,
                prepare.ceremony_id,
                prepare.attempt_id,
                "prepared",
                prepare.config_digest,
            )?);
            return Ok(DkgControlMessage::Prepared {
                ceremony_id: prepare.ceremony_id,
                attempt_id: prepare.attempt_id,
                config_digest: prepare.config_digest,
                report_signature,
            });
        }
        return Err(DkgError::ProtocolError(
            "Prepare conflicts with the configured transport attempt".into(),
        ));
    }

    if let Err(error) = validate_reshare_transport_routes(&state, &prepare).await {
        // Reached only after leader_authorized, sender-route, and
        // config_digest all already matched, so `prepare` is confirmed
        // self-consistent and genuinely signed by the real canonical
        // leader — unlike the digest-mismatch branch above, there is no
        // tampering ambiguity here.
        report_leader_prepare_fault_best_effort(&state, routes, &prepare).await;
        return Err(error);
    }
    let coordinator = DkgCoordinator::with_routes(state.clone(), routes);
    handle_session_init(
        &coordinator,
        AttemptKey::new(prepare.ceremony_id, prepare.attempt_id),
        prepare.committees.current.threshold,
        prepare.committees.current.len() as u32,
        &prepare.committees.current.peer_routes,
        &prepare.committees.current.node_keys,
        &prepare.committees.current.node_id_assignments,
        &prepare.kind,
        prepare.pss_interval,
        prepare.policy_id.clone(),
        prepare.ring_id.clone(),
        sender,
        Some(&prepare),
    )
    .await?;

    // Do not create and immediately drop another Gossip subscription for a
    // retried Prepare; doing so emits neighbor churn across the whole
    // transient mesh. This second check catches the case where session_init
    // ran concurrently (e.g. two in-flight retries) and the transport got
    // configured by the other task while this one was awaiting Vera.
    if let Some((ceremony_id, attempt_id, config_digest)) = state
        .dkg_session_state
        .transport_configuration(&prepare.ceremony_id.0)
        .await
    {
        if ceremony_id == prepare.ceremony_id
            && attempt_id == prepare.attempt_id
            && config_digest == prepare.config_digest
        {
            let report_signature = Some(sign_control_message(
                &state,
                prepare.ceremony_id,
                prepare.attempt_id,
                "prepared",
                prepare.config_digest,
            )?);
            return Ok(DkgControlMessage::Prepared {
                ceremony_id: prepare.ceremony_id,
                attempt_id: prepare.attempt_id,
                config_digest: prepare.config_digest,
                report_signature,
            });
        }
        return Err(DkgError::ProtocolError(
            "Prepare conflicts with the configured transport attempt".into(),
        ));
    }

    let pubsub = state.network.pubsub().ok_or_else(|| {
        DkgError::InvalidState("network backend does not provide authenticated pub-sub".into())
    })?;
    // The leader creates the topic without waiting for peers. Followers join
    // through the already-subscribed leader, avoiding a circular join barrier
    // during preparation.
    let bootstrap = leader_bootstrap(&state.node_key, &prepare.leader_node_key, leader_route)?;
    let topic_id = network::TopicId::new(prepare.topic_id);
    let topic = pubsub
        .subscribe(topic_id, bootstrap)
        .await
        .map_err(|error| DkgError::NetworkCommunication(error.to_string()))?;
    let outcome = state
        .dkg_session_state
        .configure_transport(
            &prepare.ceremony_id.0,
            prepare.ceremony_id,
            prepare.attempt_id,
            prepare.committee_digest(),
            prepare.config_digest,
            topic_id,
            prepare.leader_node_key.clone(),
            leader_route.to_string(),
            prepare.participant_routes(),
            prepare.committees.clone(),
            topic.clone(),
        )
        .await;
    if matches!(
        outcome,
        TransportConfigureOutcome::ConflictingAttempt | TransportConfigureOutcome::MissingSession
    ) {
        return Err(DkgError::ProtocolError(format!(
            "cannot configure transport attempt: {outcome:?}"
        )));
    }
    if matches!(outcome, TransportConfigureOutcome::Configured) {
        if !matches!(prepare.kind, SessionKind::Fresh) {
            state
                .dkg_session_state
                .record_offline_relay_receipt(
                    AttemptKey::new(prepare.ceremony_id, prepare.attempt_id),
                    DkgOfflineRelayReceipt {
                        kind: prepare.kind.clone(),
                        ring_id: prepare.ring_id.clone(),
                        protocol_version: routes.version,
                        committees: prepare.committees.clone(),
                        leader_node_key: prepare.leader_node_key.clone(),
                        recorded_at: tokio::time::Instant::now(),
                        processed: Default::default(),
                    },
                )
                .await;
        }
        let task = tokio::spawn(topic_listener(
            state.clone(),
            routes,
            prepare.clone(),
            topic,
        ));
        state
            .dkg_session_state
            .set_transport_topic_task(&prepare.ceremony_id.0, task.abort_handle())
            .await;
    }
    let report_signature = Some(sign_control_message(
        &state,
        prepare.ceremony_id,
        prepare.attempt_id,
        "prepared",
        prepare.config_digest,
    )?);
    Ok(DkgControlMessage::Prepared {
        ceremony_id: prepare.ceremony_id,
        attempt_id: prepare.attempt_id,
        config_digest: prepare.config_digest,
        report_signature,
    })
}

pub(super) async fn send_topology_probe_ack<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: PrepareSession,
    leader_route: String,
    nonce: [u8; 32],
) -> Result<[u8; 32]>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let deadline = state
        .dkg_session_state
        .transport_preparation_deadline(&prepare.ceremony_id.0, prepare.attempt_id)
        .await
        .map(Instant::from_std)
        .ok_or_else(|| DkgError::SessionNotFound(prepare.ceremony_id.0.to_string()))?;
    let request = DkgControlMessage::TopologyProbeAck {
        ceremony_id: prepare.ceremony_id,
        attempt_id: prepare.attempt_id,
        nonce,
    };
    let mut backoff = INITIAL_CONTROL_RETRY_BACKOFF;
    let mut last_failure_was_unreachable = false;
    loop {
        if state
            .dkg_session_state
            .transport_attempt(&prepare.ceremony_id.0)
            .await
            != Some(prepare.attempt_id)
        {
            return Err(DkgError::ProtocolError(
                "topology acknowledgement attempt was removed".into(),
            ));
        }
        let now = Instant::now();
        if now >= deadline {
            if last_failure_was_unreachable {
                if let Some(leader) =
                    participant_for_transport_peer(&prepare.committees, &leader_route)
                {
                    spawn_pss_offline_observations(
                        state.clone(),
                        routes,
                        PssOfflineObservationSeed::from_prepare(
                            &prepare,
                            routes.version,
                            PssOfflineStage::TopologyAck,
                            [leader],
                        ),
                    );
                }
            }
            return Err(DkgError::NetworkCommunication(
                "topology acknowledgement exceeded the preparation deadline".into(),
            ));
        }
        let remaining = deadline.saturating_duration_since(now);
        match control_request_with_timeout_classified(
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
            Err(error @ PeerRequestFailure::Unreachable(_)) => {
                last_failure_was_unreachable = true;
                crate::metrics::record_dkg_transport_event("control", "preparation_retry");
                tracing::warn!(
                    error = %error.error(),
                    session_id = prepare.ceremony_id.0,
                    "topology acknowledgement failed; retrying identical bytes"
                );
            }
            Err(error) => return Err(error.into_error()),
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            continue;
        }
        sleep(backoff.min(remaining)).await;
        backoff = (backoff * 2).min(DKG_PREPARATION_RETRY_MAX_BACKOFF);
    }
}
