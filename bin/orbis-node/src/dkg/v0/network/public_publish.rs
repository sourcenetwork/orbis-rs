use super::*;

pub(super) async fn publish_phase_if_complete<D>(
    state: Arc<AppState<D>>,
    _routes: &'static network::ProtocolRoutes,
    session_id: u128,
    attempt_id: AttemptId,
    phase: PublicPhase,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let attempt = AttemptKey::new(CeremonyId(session_id), attempt_id);
    let kind = state
        .dkg_session_state
        .with_attempt_state(attempt, |session| session.kind.clone())
        .await
        .map_err(|error| crate::dkg::v0::coordinator::attempt_state_error(attempt, error))?;
    let mode = public_batch_mode(&kind, phase).ok_or_else(|| {
        DkgError::ProtocolError(format!(
            "public phase {phase:?} is not valid for ceremony kind {kind:?}"
        ))
    })?;
    if mode == PublicBatchMode::Incremental {
        return publish_incremental_public_contributions(state, session_id, attempt_id, phase)
            .await;
    }
    let expected = if matches!(
        phase,
        PublicPhase::RefreshHealthCheck | PublicPhase::ReshareParticipantSet
    ) {
        1
    } else {
        state
            .dkg_session_state
            .with_state(&session_id, |session| session.node.total_nodes())
            .await
            .ok_or_else(|| DkgError::SessionNotFound(session_id.to_string()))?
    };
    let items = state
        .dkg_session_state
        .public_contributions(&session_id, attempt_id, phase)
        .await
        .ok_or_else(|| DkgError::SessionNotFound(session_id.to_string()))?;
    if items.len() != expected {
        return Ok(());
    }
    let hard_deadline = state
        .dkg_session_state
        .transport_hard_deadline(&session_id, attempt_id)
        .await
        .ok_or_else(|| DkgError::InvalidState("transport hard deadline is missing".into()))?
        .into();
    let batch = prepare_public_batch(CeremonyId(session_id), attempt_id, phase, items, true)?;
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
    publish_claimed_public_batches(
        state,
        session_id,
        attempt_id,
        phase,
        PublicPublishClaim::CompletePhase,
        vec![batch],
        hard_deadline,
        dissemination_start,
    )
    .await
}

pub(super) async fn publish_incremental_public_contributions<D>(
    state: Arc<AppState<D>>,
    session_id: u128,
    attempt_id: AttemptId,
    phase: PublicPhase,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    // Coalesce contributions that arrive in the same short relay window. Every
    // caller observes the same retained map; attempt-scoped publish claims make
    // exactly one caller responsible for each contribution.
    sleep(Duration::from_millis(50)).await;
    let items = state
        .dkg_session_state
        .public_contributions(&session_id, attempt_id, phase)
        .await
        .ok_or_else(|| DkgError::SessionNotFound(session_id.to_string()))?;
    let hard_deadline = state
        .dkg_session_state
        .transport_hard_deadline(&session_id, attempt_id)
        .await
        .ok_or_else(|| DkgError::InvalidState("transport hard deadline is missing".into()))?
        .into();
    let mut decoded = Vec::with_capacity(items.len());
    for (origin, signed) in items {
        let contribution =
            transport::decode::<DkgPublicContribution>(&signed.data, MAX_CONTROL_MESSAGE_BYTES)
                .map_err(DkgError::Deserialization)?;
        decoded.push((origin, signed, contribution.message_id));
    }
    let message_ids = decoded
        .iter()
        .map(|(_, _, message_id)| *message_id)
        .collect::<Vec<_>>();
    let claimed = state
        .dkg_session_state
        .claim_public_messages_publish(&session_id, attempt_id, &message_ids)
        .await
        .into_iter()
        .collect::<BTreeSet<_>>();
    if claimed.is_empty() {
        return Ok(());
    }
    let mut pending = decoded
        .into_iter()
        .filter(|(_, _, message_id)| claimed.contains(message_id))
        .map(|(origin, signed, _)| (origin, signed))
        .collect::<BTreeMap<_, _>>();
    if pending.is_empty() {
        return Ok(());
    }

    let ceremony_id = CeremonyId(session_id);
    let prepared = (|| {
        let mut batches = Vec::new();
        let mut current = BTreeMap::new();
        for (origin, signed) in std::mem::take(&mut pending) {
            let mut candidate = current.clone();
            candidate.insert(origin, signed.clone());
            let candidate_ids = contribution_ids(&candidate);
            let candidate_root =
                transport::phase_root(ceremony_id, attempt_id, phase, &candidate_ids);
            // Sizing probe only — `chunks` here is just measured (`.len()`) to
            // decide batch boundaries; the real broadcast batch (and its real
            // `signed_at`) is built by `prepare_public_batch` below.
            let chunks = transport::chunk_public_contributions(
                ceremony_id,
                attempt_id,
                phase,
                candidate_root,
                candidate.clone(),
                now_unix_secs()?,
            )
            .map_err(DkgError::Serialization)?;
            if chunks.len() > 1 && !current.is_empty() {
                batches.push(current);
                current = BTreeMap::from([(origin, signed)]);
            } else {
                current = candidate;
            }
        }
        if !current.is_empty() {
            batches.push(current);
        }
        batches
            .into_iter()
            .map(|batch| prepare_public_batch(ceremony_id, attempt_id, phase, batch, false))
            .collect::<Result<Vec<_>>>()
    })();
    let prepared = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            state
                .dkg_session_state
                .finish_public_messages_publish(
                    &session_id,
                    attempt_id,
                    &claimed.iter().copied().collect::<Vec<_>>(),
                    false,
                )
                .await;
            return Err(error);
        }
    };
    publish_claimed_public_batches(
        state,
        session_id,
        attempt_id,
        phase,
        PublicPublishClaim::IncrementalMessages(claimed.into_iter().collect()),
        prepared,
        hard_deadline,
        Instant::now(),
    )
    .await
}

#[derive(Clone)]
pub(super) struct PreparedPublicBatch {
    pub(super) root: [u8; 32],
    pub(super) contribution_count: usize,
    pub(super) messages: Vec<Bytes>,
}

#[derive(Clone)]
pub(super) enum PublicPublishClaim {
    CompletePhase,
    IncrementalMessages(Vec<MessageId>),
}

pub(super) fn prepare_public_batch(
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    phase: PublicPhase,
    contributions: BTreeMap<ParticipantRef, SignedPayload>,
    complete: bool,
) -> Result<PreparedPublicBatch> {
    let contribution_count = contributions.len();
    let ids = contribution_ids(&contributions);
    let root = transport::phase_root(ceremony_id, attempt_id, phase, &ids);
    let signed_at = now_unix_secs()?;
    let chunks = transport::chunk_public_contributions(
        ceremony_id,
        attempt_id,
        phase,
        root,
        contributions,
        signed_at,
    )
    .map_err(DkgError::Serialization)?;
    let manifest = DkgPublicMessage::Manifest(PhaseManifest {
        ceremony_id,
        attempt_id,
        phase,
        phase_root: root,
        contribution_ids: ids,
        chunk_count: chunks.len() as u32,
        complete,
        signed_at,
    });
    let mut messages = Vec::with_capacity(chunks.len() + 1);
    messages.push(Bytes::from(
        transport::encode(&manifest).map_err(DkgError::Serialization)?,
    ));
    for chunk in chunks {
        messages.push(Bytes::from(
            transport::encode(&chunk).map_err(DkgError::Serialization)?,
        ));
    }
    Ok(PreparedPublicBatch {
        root,
        contribution_count,
        messages,
    })
}

pub(super) async fn broadcast_public_batches(
    topic: &dyn Topic,
    batches: &[PreparedPublicBatch],
) -> network::Result<()> {
    for batch in batches {
        for message in &batch.messages {
            topic.broadcast(message.clone()).await?;
        }
    }
    Ok(())
}

pub(super) async fn finish_public_publish_claim<D>(
    state: &Arc<AppState<D>>,
    session_id: u128,
    attempt_id: AttemptId,
    phase: PublicPhase,
    claim: &PublicPublishClaim,
    published: bool,
) -> bool
where
    D: CoordinatorDkg,
{
    match claim {
        PublicPublishClaim::CompletePhase => {
            state
                .dkg_session_state
                .finish_public_phase_publish(&session_id, attempt_id, phase, published)
                .await
        }
        PublicPublishClaim::IncrementalMessages(message_ids) => {
            state
                .dkg_session_state
                .finish_public_messages_publish(&session_id, attempt_id, message_ids, published)
                .await
        }
    }
}

pub(super) fn record_public_batches_published(
    session_id: u128,
    attempt_id: AttemptId,
    phase: PublicPhase,
    batches: &[PreparedPublicBatch],
    dissemination_start: Instant,
) {
    crate::metrics::record_dkg_public_transport(
        phase.as_metric_label(),
        "dissemination",
        dissemination_start.elapsed().as_secs_f64(),
    );
    for _ in batches {
        crate::metrics::record_dkg_transport_event("public", "batch_published");
    }
    tracing::info!(
        session_id,
        attempt = %hex::encode(attempt_id.0),
        phase = ?phase,
        roots = ?batches
            .iter()
            .map(|batch| hex::encode(batch.root))
            .collect::<Vec<_>>(),
        contribution_count = batches
            .iter()
            .map(|batch| batch.contribution_count)
            .sum::<usize>(),
        batch_count = batches.len(),
        "leader published canonical public DKG batch"
    );
}

pub(super) async fn broadcast_public_batches_for_attempt<D>(
    state: &Arc<AppState<D>>,
    session_id: u128,
    attempt_id: AttemptId,
    batches: &[PreparedPublicBatch],
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let topic = state
        .dkg_session_state
        .transport_topic_for_attempt(&session_id, attempt_id)
        .await
        .ok_or_else(|| {
            DkgError::InvalidState("transport topic is missing or attempt is stale".into())
        })?;
    broadcast_public_batches(&*topic, batches)
        .await
        .map_err(|error| DkgError::NetworkCommunication(error.to_string()))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn retry_claimed_public_batches<D>(
    weak_state: Weak<AppState<D>>,
    session_id: u128,
    attempt_id: AttemptId,
    phase: PublicPhase,
    claim: PublicPublishClaim,
    batches: Vec<PreparedPublicBatch>,
    hard_deadline: Instant,
    dissemination_start: Instant,
) where
    D: CoordinatorDkg,
{
    let mut backoff = INITIAL_CONTROL_RETRY_BACKOFF;
    let mut retry = 0u32;
    loop {
        let Some(state) = weak_state.upgrade() else {
            return;
        };
        if state.dkg_session_state.transport_attempt(&session_id).await != Some(attempt_id) {
            return;
        }
        let remaining = hard_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            finish_public_publish_claim(&state, session_id, attempt_id, phase, &claim, false).await;
            crate::metrics::record_dkg_transport_event("public", "batch_publish_abandoned");
            tracing::warn!(
                session_id,
                attempt = %hex::encode(attempt_id.0),
                phase = ?phase,
                "public DKG batch publication reached the hard attempt deadline"
            );
            return;
        }
        drop(state);
        sleep(backoff.min(remaining)).await;
        if Instant::now() >= hard_deadline {
            continue;
        }
        let Some(state) = weak_state.upgrade() else {
            return;
        };
        if state.dkg_session_state.transport_attempt(&session_id).await != Some(attempt_id) {
            return;
        }
        retry = retry.saturating_add(1);
        match broadcast_public_batches_for_attempt(&state, session_id, attempt_id, &batches).await {
            Ok(()) => {
                if finish_public_publish_claim(&state, session_id, attempt_id, phase, &claim, true)
                    .await
                {
                    record_public_batches_published(
                        session_id,
                        attempt_id,
                        phase,
                        &batches,
                        dissemination_start,
                    );
                }
                return;
            }
            Err(error) => {
                crate::metrics::record_dkg_transport_event("public", "batch_publish_retry");
                tracing::warn!(
                    %error,
                    session_id,
                    attempt = %hex::encode(attempt_id.0),
                    phase = ?phase,
                    retry,
                    "public DKG batch publication failed; retrying"
                );
                backoff = (backoff * 2).min(DKG_MAX_REPAIR_BACKOFF);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn publish_claimed_public_batches<D>(
    state: Arc<AppState<D>>,
    session_id: u128,
    attempt_id: AttemptId,
    phase: PublicPhase,
    claim: PublicPublishClaim,
    batches: Vec<PreparedPublicBatch>,
    hard_deadline: Instant,
    dissemination_start: Instant,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    match broadcast_public_batches_for_attempt(&state, session_id, attempt_id, &batches).await {
        Ok(()) => {
            if finish_public_publish_claim(&state, session_id, attempt_id, phase, &claim, true)
                .await
            {
                record_public_batches_published(
                    session_id,
                    attempt_id,
                    phase,
                    &batches,
                    dissemination_start,
                );
            }
        }
        Err(error) => {
            crate::metrics::record_dkg_transport_event("public", "batch_publish_retry");
            tracing::warn!(
                %error,
                session_id,
                attempt = %hex::encode(attempt_id.0),
                phase = ?phase,
                "initial public DKG batch publication failed; retrying in background"
            );
            tokio::spawn(retry_claimed_public_batches(
                Arc::downgrade(&state),
                session_id,
                attempt_id,
                phase,
                claim,
                batches,
                hard_deadline,
                dissemination_start,
            ));
        }
    }
    Ok(())
}

pub(super) async fn send_refresh_result_barrier<D>(
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
    SignImpl: CoordinatorReportSigner<D>,
{
    let attempt_key = AttemptKey::new(ceremony_id, attempt_id);
    let stage = match step {
        "stage" => PssOfflineStage::RefreshResultStage,
        "commit" => PssOfflineStage::RefreshResultCommit,
        _ => {
            return Err(DkgError::InvalidInput(
                "unknown refresh-result barrier step".into(),
            ))
        }
    };
    let committees = state
        .dkg_session_state
        .with_attempt_state(attempt_key, |session| session.transport.committees.clone())
        .await
        .map_err(|error| crate::dkg::v0::coordinator::attempt_state_error(attempt_key, error))?
        .ok_or_else(|| DkgError::InvalidState("refresh barrier committees are missing".into()))?;
    let mut requests = JoinSet::new();
    for peer in peers {
        let state = state.clone();
        let request = request.clone();
        requests.spawn(async move {
            let mut backoff = INITIAL_CONTROL_RETRY_BACKOFF;
            let mut attempt = 0u32;
            let mut last_failure_was_unreachable = false;
            let mut peer_proved_reachable = false;
            loop {
                attempt = attempt.saturating_add(1);
                let now = Instant::now();
                if now >= hard_deadline {
                    return (
                        peer.clone(),
                        Err(DkgError::NetworkCommunication(format!(
                            "refresh-result {step} barrier reached the hard attempt deadline for peer {peer}"
                        ))),
                        terminal_offline_candidate(
                            last_failure_was_unreachable,
                            peer_proved_reachable,
                        ),
                    );
                }
                let remaining = hard_deadline.saturating_duration_since(now);
                let response = control_request_with_timeout_classified(
                    &state,
                    routes,
                    &peer,
                    request.clone(),
                    PEER_RESPONSE_TIMEOUT.min(remaining),
                )
                .await;
                match response {
                    Ok(DkgControlMessage::PublicContributionAck {
                        ceremony_id: got_ceremony,
                        attempt_id: got_attempt,
                        message_id: got_message,
                    }) if got_ceremony == ceremony_id
                        && got_attempt == attempt_id
                        && got_message == message_id =>
                    {
                        return (peer, Ok(()), false)
                    }
                    Ok(other) => {
                        last_failure_was_unreachable = false;
                        peer_proved_reachable = true;
                        tracing::warn!(
                            peer = %peer,
                            step,
                            attempt,
                            response = ?other,
                            "refresh-result barrier received an invalid acknowledgement"
                        );
                    }
                    Err(error) => {
                        last_failure_was_unreachable = error.is_unreachable();
                        peer_proved_reachable |= error.proves_reachable();
                        tracing::warn!(
                            peer = %peer,
                            step,
                            attempt,
                            error = %error.error(),
                            "refresh-result barrier control request failed; retrying"
                        );
                    }
                }
                crate::metrics::record_dkg_transport_event("control", "retry");
                let remaining = hard_deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    continue;
                }
                sleep(backoff.min(remaining)).await;
                backoff = (backoff * 2).min(DKG_MAX_REPAIR_BACKOFF);
            }
        });
    }
    let mut first_error = None;
    let mut offline = Vec::new();
    while let Some(result) = requests.join_next().await {
        let (peer, result, unreachable) =
            result.map_err(|error| DkgError::NetworkCommunication(error.to_string()))?;
        if unreachable {
            if let Some(participant) = participant_for_transport_peer(&committees, &peer) {
                offline.push(participant);
            }
        }
        if let Err(error) = result {
            first_error.get_or_insert(error);
        }
    }
    if !offline.is_empty() {
        spawn_pss_offline_for_attempt(&state, routes, attempt_key, stage, offline).await;
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    Ok(())
}

pub(super) async fn distribute_refresh_result<D>(
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
        .transport_hard_deadline(&session_id, contribution.attempt_id)
        .await
        .ok_or_else(|| DkgError::InvalidState("transport hard deadline is missing".into()))?
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
    crate::metrics::record_dkg_transport_event("public", "result_stage_barrier");

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
    crate::metrics::record_dkg_transport_event("public", "result_commit_barrier");
    Ok(())
}

/// Sign and submit one public contribution, retaining exact bytes until the
/// leader acknowledges it.
pub(crate) async fn submit_public_contribution<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    payload: DkgPublicPayload,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let session_id = attempt.session_id();
    let (
        committee_digest,
        leader,
        leader_peer,
        activated,
        node_id,
        is_reshare,
        next_node_id,
        ring_id,
        leader_participant,
    ) = coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |session| {
            (
                session.transport.committee_digest,
                session.transport.leader_node_key.clone(),
                session.transport.leader_peer_route.clone(),
                session.transport.activated,
                session.node.node_id(),
                matches!(session.kind, SessionKind::Reshare { .. }),
                session
                    .reshare
                    .params
                    .as_ref()
                    .and_then(|params| params.new_node_id),
                session.routing.ring_id.clone(),
                session
                    .transport
                    .committees
                    .as_ref()
                    .and_then(|committees| {
                        session
                            .transport
                            .leader_peer_route
                            .as_deref()
                            .and_then(|peer| participant_for_transport_peer(committees, peer))
                    }),
            )
        })
        .await
        .map_err(|error| crate::dkg::v0::coordinator::attempt_state_error(attempt, error))?;
    let committee_digest = committee_digest
        .ok_or_else(|| DkgError::InvalidState("committee digest is missing".into()))?;
    let leader =
        leader.ok_or_else(|| DkgError::InvalidState("leader node key is missing".into()))?;
    if !activated {
        return Err(DkgError::ProtocolError(
            "public contribution generated before attempt activation".into(),
        ));
    }
    let uses_next_identity = matches!(&payload, DkgPublicPayload::ReshareParticipantSet { .. })
        || (is_reshare && matches!(&payload, DkgPublicPayload::CommitmentAudit { .. }));
    let origin = if uses_next_identity {
        let next_node_id = next_node_id.ok_or_else(|| {
            DkgError::Unauthorized(
                "only a next-committee receiver may publish the participant set".into(),
            )
        })?;
        ParticipantRef::next(next_node_id)
    } else {
        ParticipantRef::current(node_id)
    };
    let ceremony_id = attempt.ceremony_id;
    let attempt_id = attempt.attempt_id;
    let contribution = DkgPublicContribution::new(
        ceremony_id,
        attempt_id,
        ring_id,
        committee_digest,
        origin,
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
    preflight_public_contribution_if_new(&coord.app_state, coord.routes, &signed, &contribution)
        .await?;
    // Retain the exact signed bytes in the same phase index used for direct
    // repair. This lets an origin serve its own contribution even if the
    // leader omits a chunk or the local subscriber never receives the relay.
    record_public_contribution(
        &coord.app_state,
        coord.routes,
        signed.clone(),
        &contribution,
    )
    .await?;
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
        dispatch_public_contribution(
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
    let leader_peer =
        leader_peer.ok_or_else(|| DkgError::InvalidState("leader peer route is missing".into()))?;
    let hard_deadline = coord
        .app_state
        .dkg_session_state
        .transport_hard_deadline(&session_id, attempt_id)
        .await
        .ok_or_else(|| DkgError::InvalidState("transport hard deadline is missing".into()))?
        .into();
    let request = DkgControlMessage::PublicContribution(signed);
    // Deadline-bounded retry, following the pattern used by
    // `send_refresh_result_barrier`: a lost ACK or a transient control
    // failure must not permanently drop this contribution before the leader
    // ever sees it.
    let mut backoff = INITIAL_CONTROL_RETRY_BACKOFF;
    let mut retry_attempt = 0u32;
    let mut last_failure_was_unreachable = false;
    let mut leader_proved_reachable = false;
    loop {
        retry_attempt = retry_attempt.saturating_add(1);
        let now = Instant::now();
        if now >= hard_deadline {
            if terminal_offline_candidate(last_failure_was_unreachable, leader_proved_reachable) {
                if let Some(leader_participant) = leader_participant {
                    spawn_pss_offline_for_attempt(
                        &coord.app_state,
                        coord.routes,
                        attempt,
                        PssOfflineStage::PublicContribution,
                        [leader_participant],
                    )
                    .await;
                }
            }
            return Err(DkgError::NetworkCommunication(format!(
                "public contribution submission reached the hard attempt deadline for peer {leader_peer}"
            )));
        }
        let remaining = hard_deadline.saturating_duration_since(now);
        let response = control_request_with_timeout_classified(
            &coord.app_state,
            coord.routes,
            &leader_peer,
            request.clone(),
            PEER_RESPONSE_TIMEOUT.min(remaining),
        )
        .await;
        match response {
            Ok(DkgControlMessage::PublicContributionAck {
                ceremony_id: got_ceremony,
                attempt_id: got_attempt,
                message_id,
            }) if got_ceremony == ceremony_id
                && got_attempt == attempt_id
                && message_id == contribution.message_id =>
            {
                return Ok(());
            }
            Ok(other) => {
                last_failure_was_unreachable = false;
                leader_proved_reachable = true;
                tracing::warn!(
                    peer = %leader_peer,
                    attempt = retry_attempt,
                    response = ?other,
                    "public contribution submission received an invalid acknowledgement"
                );
            }
            Err(error) => {
                last_failure_was_unreachable = error.is_unreachable();
                leader_proved_reachable |= error.proves_reachable();
                tracing::warn!(
                    peer = %leader_peer,
                    attempt = retry_attempt,
                    error = %error.error(),
                    "public contribution submission control request failed; retrying"
                );
            }
        }
        crate::metrics::record_dkg_transport_event("control", "retry");
        let remaining = hard_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            continue;
        }
        sleep(backoff.min(remaining)).await;
        backoff = (backoff * 2).min(DKG_MAX_REPAIR_BACKOFF);
    }
}
