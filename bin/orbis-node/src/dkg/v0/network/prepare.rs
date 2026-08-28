use super::*;

pub(super) fn missing_topology_peers(
    expected: &BTreeSet<String>,
    acknowledged: &BTreeSet<String>,
) -> Vec<String> {
    expected.difference(acknowledged).cloned().collect()
}

// Its one production caller was replaced by the structured `DkgError::BarrierFailure` per-peer
// list (see the topology-probe deadline branch), which no longer needs a pre-joined prefix
// string; kept for the unit test below that still exercises the truncation behavior.
#[cfg(test)]
pub(super) fn missing_topology_peer_prefixes(missing: &[String]) -> String {
    missing
        .iter()
        .map(|peer| peer.chars().take(12).collect::<String>())
        .collect::<Vec<_>>()
        .join(",")
}

pub(super) async fn coordinate_prepared<D>(
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
        if matches!(prepare.kind, SessionKind::Fresh) {
            if let DkgError::BarrierFailure { failed_peers, .. } = error {
                state
                    .dkg_session_state
                    .record_failed_session(FailedDkgSessionRecord {
                        session_id: prepare.ceremony_id.0,
                        ring_id: prepare.ring_id.clone(),
                        attempt_id: Some(prepare.attempt_id),
                        stage: DkgFailureStage::Preparing,
                        missing: resolve_barrier_failure_participants(&prepare, failed_peers),
                        // `BarrierFailure`'s own Display already includes "{barrier} barrier
                        // failed for N of the committee: ...", so this isn't reprefixed here.
                        reason: error.to_string(),
                        failed_at: std::time::SystemTime::now(),
                    })
                    .await;
            }
        }
        abort_prepared_attempt(&state, routes, &prepare, error.to_string()).await;
        state
            .dkg_session_state
            .abort_transport_preparation(
                &prepare.ceremony_id.0,
                prepare.attempt_id,
                TopicTaskDisposition::Abort,
            )
            .await;
    }
    result
}

/// Resolve barrier-fan-out failures (peer route + reason) to client-facing
/// participant identity via the current committee's index-aligned
/// `node_keys`/`peer_routes`/`node_id_assignments` — no extra bulletin I/O
/// needed since `prepare` already carries everything.
pub(super) fn resolve_barrier_failure_participants(
    prepare: &PrepareSession,
    failed_peers: &[(String, String)],
) -> Vec<MissingDkgParticipant> {
    failed_peers
        .iter()
        .filter_map(|(peer_route, _reason)| {
            let participant = participant_for_peer_route(
                &prepare.committees,
                CommitteeScope::Current,
                peer_route,
            );
            let Some(participant) = participant else {
                tracing::warn!(
                    peer = %extract_node_part(peer_route),
                    "barrier failure could not be resolved to a committee participant"
                );
                return None;
            };
            let node_key = prepare.committees.node_key(participant)?;
            Some(MissingDkgParticipant {
                node_id: participant.node_id,
                node_key: node_key.to_string(),
            })
        })
        .collect()
}

const RESHARE_DEALER_INCLUSION_GRACE: Duration = Duration::from_secs(3);

#[derive(Debug, Eq, PartialEq)]
pub(super) enum ResharePreparationErrorAction {
    Retry,
    ExcludeOld,
    Fail,
}

pub(super) fn reshare_preparation_error_action(
    is_next_member: bool,
    error: &DkgError,
) -> ResharePreparationErrorAction {
    if retryable_control_error(error) {
        ResharePreparationErrorAction::Retry
    } else if is_next_member {
        ResharePreparationErrorAction::Fail
    } else {
        ResharePreparationErrorAction::ExcludeOld
    }
}

pub(super) fn reshare_preparation_candidates(
    prepare: &PrepareSession,
    route_ids: impl IntoIterator<Item = String>,
) -> Vec<ParticipantRef> {
    let mut candidates = Vec::new();
    for route_id in route_ids {
        for scope in [CommitteeScope::Current, CommitteeScope::Next] {
            if let Some(committee) = prepare.committees.committee(scope) {
                if let Some((index, _)) = committee
                    .peer_routes
                    .iter()
                    .enumerate()
                    .find(|(_, route)| extract_node_part(route).to_lowercase() == route_id)
                {
                    if let Some(participant) = committee
                        .node_keys
                        .get(index)
                        .and_then(|node_key| committee.participant(scope, node_key))
                    {
                        candidates.push(participant);
                    }
                }
            }
        }
    }
    candidates.sort_unstable();
    candidates.dedup();
    candidates
}

pub(super) async fn prepare_transport_participants<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: &PrepareSession,
    deadline: Instant,
) -> Result<(Vec<String>, Vec<ParticipantRef>)>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let all_routes = prepare.participant_routes();
    if prepare.committees.next.is_none() {
        let mut tasks = JoinSet::new();
        for peer in all_routes
            .iter()
            .filter(|peer| !is_self_peer_id(&state.network, peer))
        {
            let state = state.clone();
            let peer = peer.clone();
            let prepare = prepare.clone();
            tasks.spawn(async move {
                let result = retry_preparation_control_classified(
                    &state,
                    routes,
                    &peer,
                    DkgControlMessage::Prepare(Box::new(prepare.clone())),
                    deadline,
                )
                .await;
                (peer, result)
            });
        }
        // Drain the whole JoinSet unconditionally instead of returning on the first
        // failure, so a second (or third) bad peer in the same barrier isn't silently
        // dropped — mirrors how the TopologyProbe barrier below already accumulates
        // every missing peer instead of stopping at the first.
        let mut failed: Vec<(String, String)> = Vec::new();
        let mut offline = Vec::new();
        while let Some(result) = tasks.join_next().await {
            let (peer, response) =
                result.map_err(|error| DkgError::NetworkCommunication(error.to_string()))?;
            match response {
                Ok(response) => {
                    if let Err(error) =
                        validate_prepared_response(state, routes, prepare, &peer, response).await
                    {
                        failed.push((peer, error.to_string()));
                    }
                }
                Err(error) => {
                    if error.is_unreachable() {
                        if let Some(participant) = participant_for_peer_route(
                            &prepare.committees,
                            CommitteeScope::Current,
                            &peer,
                        ) {
                            offline.push(participant);
                        }
                    }
                    failed.push((peer, error.into_error().to_string()));
                }
            }
        }
        if !offline.is_empty() {
            spawn_pss_offline_observations(
                state.clone(),
                routes,
                PssOfflineObservationSeed::from_prepare(
                    prepare,
                    routes.version,
                    PssOfflineStage::Prepare,
                    offline,
                ),
            );
        }
        if !failed.is_empty() {
            return Err(DkgError::BarrierFailure {
                barrier: "prepare",
                failed_peers: failed,
            });
        }
        let mut dealers: Vec<_> = prepare
            .committees
            .current
            .node_id_assignments
            .values()
            .copied()
            .map(ParticipantRef::current)
            .collect();
        dealers.sort();
        return Ok((all_routes, dealers));
    }

    let next = prepare
        .committees
        .next
        .as_ref()
        .expect("reshare branch checked above");
    let current = &prepare.committees.current;
    let normalize = |route: &str| extract_node_part(route).to_lowercase();
    let route_by_id: BTreeMap<String, String> = all_routes
        .iter()
        .map(|route| (normalize(route), route.clone()))
        .collect();
    let next_routes: BTreeSet<String> = next
        .peer_routes
        .iter()
        .map(|route| normalize(route))
        .collect();
    let current_routes: BTreeMap<String, u32> = current
        .node_keys
        .iter()
        .zip(&current.peer_routes)
        .filter_map(|(key, route)| {
            current
                .node_id_assignments
                .get(key)
                .copied()
                .map(|node_id| (normalize(route), node_id))
        })
        .collect();
    let mut prepared: BTreeSet<String> = all_routes
        .iter()
        .filter(|route| is_self_peer_id(&state.network, route))
        .map(|route| normalize(route))
        .collect();
    let mut excluded_old = BTreeSet::new();
    let mut unreachable = BTreeSet::new();
    let mut grace_started = None;

    loop {
        let now = Instant::now();
        let ready_old = current_routes
            .keys()
            .filter(|route| prepared.contains(*route))
            .count();
        let missing_new: Vec<_> = next_routes.difference(&prepared).cloned().collect();
        let threshold_ready = missing_new.is_empty() && ready_old >= current.threshold as usize;
        if threshold_ready {
            let grace = grace_started.get_or_insert(now);
            if ready_old == current.len()
                || now.duration_since(*grace) >= RESHARE_DEALER_INCLUSION_GRACE
            {
                break;
            }
        }
        if now >= deadline {
            let shortfall = (current.threshold as usize).saturating_sub(ready_old);
            let candidates = reshare_preparation_candidates(
                prepare,
                unreachable
                    .difference(&prepared)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            if !candidates.is_empty() {
                spawn_pss_offline_observations(
                    state.clone(),
                    routes,
                    PssOfflineObservationSeed::from_prepare(
                        prepare,
                        routes.version,
                        PssOfflineStage::Prepare,
                        candidates,
                    ),
                );
            }
            return Err(DkgError::NetworkCommunication(format!(
                "reshare preparation expired: missing_new=[{}], old_dealer_shortfall={shortfall}",
                missing_new
                    .iter()
                    .map(|peer| peer.chars().take(12).collect::<String>())
                    .collect::<Vec<_>>()
                    .join(",")
            )));
        }

        let request_timeout = PEER_RESPONSE_TIMEOUT.min(deadline.saturating_duration_since(now));
        let mut round = JoinSet::new();
        for (route_id, peer) in &route_by_id {
            if prepared.contains(route_id) || excluded_old.contains(route_id) {
                continue;
            }
            let state = state.clone();
            let peer = peer.clone();
            let route_id = route_id.clone();
            let request = DkgControlMessage::Prepare(Box::new(prepare.clone()));
            round.spawn(async move {
                (
                    route_id,
                    peer.clone(),
                    control_request_with_timeout_classified(
                        &state,
                        routes,
                        &peer,
                        request,
                        request_timeout,
                    )
                    .await,
                )
            });
        }
        while let Some(result) = round.join_next().await {
            let (route_id, peer, response) =
                result.map_err(|error| DkgError::NetworkCommunication(error.to_string()))?;
            let response = match response {
                Ok(response) => {
                    unreachable.remove(&route_id);
                    validate_prepared_response(state, routes, prepare, &peer, response).await
                }
                Err(error) => {
                    if error.is_unreachable() {
                        unreachable.insert(route_id.clone());
                    } else {
                        unreachable.remove(&route_id);
                    }
                    Err(error.into_error())
                }
            };
            match response {
                Ok(()) => {
                    prepared.insert(route_id);
                }
                Err(error) => {
                    match reshare_preparation_error_action(next_routes.contains(&route_id), &error)
                    {
                        ResharePreparationErrorAction::Retry => {
                            crate::metrics::record_dkg_transport_event(
                                "control",
                                "preparation_retry",
                            );
                        }
                        ResharePreparationErrorAction::ExcludeOld => {
                            tracing::warn!(
                                peer = %extract_node_part(&peer),
                                %error,
                                "excluding unprepared old dealer from reshare"
                            );
                            excluded_old.insert(route_id);
                        }
                        ResharePreparationErrorAction::Fail => return Err(error),
                    }
                }
            }
        }
        sleep(DKG_TOPOLOGY_PROBE_INTERVAL.min(deadline.saturating_duration_since(Instant::now())))
            .await;
    }

    let tolerated_offline = reshare_preparation_candidates(
        prepare,
        unreachable
            .difference(&prepared)
            .cloned()
            .collect::<Vec<_>>(),
    );
    if !tolerated_offline.is_empty() {
        spawn_pss_offline_observations(
            state.clone(),
            routes,
            PssOfflineObservationSeed::from_prepare(
                prepare,
                routes.version,
                PssOfflineStage::Prepare,
                tolerated_offline,
            ),
        );
    }

    let mut active_dealers: Vec<_> = current_routes
        .iter()
        .filter_map(|(route, node_id)| {
            prepared
                .contains(route)
                .then_some(ParticipantRef::current(*node_id))
        })
        .collect();
    active_dealers.sort();
    let active_route_ids: BTreeSet<_> = next_routes
        .iter()
        .cloned()
        .chain(
            current_routes
                .keys()
                .filter(|route| prepared.contains(*route))
                .cloned(),
        )
        .collect();
    let active_routes = active_route_ids
        .iter()
        .filter_map(|route| route_by_id.get(route).cloned())
        .collect();
    Ok((active_routes, active_dealers))
}

pub(super) async fn validate_prepared_response<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: &PrepareSession,
    peer: &str,
    response: DkgControlMessage,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    match response {
        DkgControlMessage::Prepared {
            ceremony_id,
            attempt_id,
            config_digest,
            report_signature,
        } if ceremony_id == prepare.ceremony_id && attempt_id == prepare.attempt_id => {
            record_control_ack_best_effort(
                state,
                routes,
                prepare,
                ceremony_id,
                attempt_id,
                "prepared",
                config_digest,
                peer,
                report_signature,
            )
            .await;
            if config_digest != prepare.config_digest {
                return Err(DkgError::ProtocolError(format!(
                    "peer {peer} returned invalid Prepared response"
                )));
            }
            Ok(())
        }
        _ => Err(DkgError::ProtocolError(format!(
            "peer {peer} returned invalid Prepared response"
        ))),
    }
}

pub(super) async fn cleanup_excluded_reshare_dealers<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: &PrepareSession,
    active_routes: &[String],
) where
    D: CoordinatorDkg,
{
    if prepare.committees.next.is_none() {
        return;
    }
    let active: BTreeSet<_> = active_routes
        .iter()
        .map(|route| extract_node_part(route).to_lowercase())
        .collect();
    let mut cleanups = JoinSet::new();
    for peer in &prepare.committees.current.peer_routes {
        if active.contains(&extract_node_part(peer).to_lowercase())
            || is_self_peer_id(&state.network, peer)
        {
            continue;
        }
        let state = state.clone();
        let peer = peer.clone();
        let ceremony_id = prepare.ceremony_id;
        let attempt_id = prepare.attempt_id;
        cleanups.spawn(async move {
            let _ = control_request_with_timeout(
                &state,
                routes,
                &peer,
                DkgControlMessage::Abort {
                    ceremony_id,
                    attempt_id,
                    reason: "old dealer excluded from frozen active set".into(),
                },
                Duration::from_secs(2),
            )
            .await;
        });
    }
    while cleanups.join_next().await.is_some() {}
}

pub(super) async fn coordinate_prepared_inner<D>(
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

    let (peer_ids, active_dealers) =
        prepare_transport_participants(&state, routes, &prepare, deadline).await?;
    cleanup_excluded_reshare_dealers(&state, routes, &prepare, &peer_ids).await;

    let nonce: [u8; 32] = rand::random();
    let topic_handle = state
        .dkg_session_state
        .transport_topic(&session_id)
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
    crate::metrics::record_dkg_transport_event("control", "probe_ack");
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
                        crate::metrics::record_dkg_transport_event("public", "probe_broadcast");
                    }
                    Err(error) => {
                        crate::metrics::record_dkg_transport_event("public", "probe_broadcast_failure");
                        tracing::warn!(%error, session_id, "topology probe broadcast failed; retrying");
                    }
                }
            }
            _ = tokio::time::sleep_until(deadline) => {}
        }
    };
    if !missing.is_empty() {
        let responded = state
            .dkg_session_state
            .topology_probe_responses(&session_id, attempt_id)
            .await
            .ok_or_else(|| DkgError::InvalidState("topology probe attempt disappeared".into()))?;
        let missing_routes: Vec<String> = peer_ids
            .iter()
            .filter(|peer| missing.contains(&extract_node_part(peer).to_lowercase()))
            .cloned()
            .collect();
        let offline_participants = missing_routes.iter().filter_map(|peer| {
            if responded.contains(&extract_node_part(peer).to_lowercase()) {
                return None;
            }
            participant_for_peer_route(&prepare.committees, CommitteeScope::Next, peer).or_else(
                || participant_for_peer_route(&prepare.committees, CommitteeScope::Current, peer),
            )
        });
        spawn_pss_offline_observations(
            state.clone(),
            routes,
            PssOfflineObservationSeed::from_prepare(
                &prepare,
                routes.version,
                PssOfflineStage::TopologyProbe,
                offline_participants,
            ),
        );
        tracing::error!(
            session_id,
            attempt_id = %hex::encode(attempt_id.0),
            missing_peers = ?missing_routes,
            "topology preparation barrier expired"
        );
        return Err(DkgError::BarrierFailure {
            barrier: "topology_probe",
            failed_peers: missing_routes
                .iter()
                .map(|route| {
                    (
                        route.clone(),
                        "acknowledgement missing before preparation deadline".to_string(),
                    )
                })
                .collect(),
        });
    }

    // Activation and cryptographic start are separate barriers. Every active
    // participant must first persist the same activation digest; only then may
    // any node generate a contribution or open a private exchange.
    let activation_digest = transport::activation_digest(prepare.config_digest, &active_dealers)
        .map_err(DkgError::ProtocolError)?;
    let leader_activation = state
        .dkg_session_state
        .activate_transport(
            &session_id,
            attempt_id,
            activation_digest,
            active_dealers.clone(),
        )
        .await;
    match leader_activation {
        TransportActivationOutcome::Activated | TransportActivationOutcome::AlreadyActivated => {}
        TransportActivationOutcome::StaleAttempt | TransportActivationOutcome::MissingSession => {
            return Err(DkgError::ProtocolError(
                "failed to activate the leader's transport attempt".into(),
            ));
        }
    }
    let activate_signature = Some(sign_control_message(
        &state,
        ceremony_id,
        attempt_id,
        "activate",
        activation_digest,
    )?);

    let mut activations = JoinSet::new();
    for peer in peer_ids
        .iter()
        .filter(|peer| !is_self_peer_id(&state.network, peer))
    {
        let state = state.clone();
        let peer = peer.clone();
        let active_dealers = active_dealers.clone();
        let activate_signature = activate_signature.clone();
        activations.spawn(async move {
            let result = retry_preparation_control_classified(
                &state,
                routes,
                &peer,
                DkgControlMessage::Activate {
                    ceremony_id,
                    attempt_id,
                    activation_digest,
                    active_dealers,
                    report_signature: activate_signature,
                },
                deadline,
            )
            .await;
            (peer, result)
        });
    }
    // Accumulate every failing peer instead of returning on the first (see the
    // matching comment on the Prepare fan-out above).
    let mut activation_failures: Vec<(String, String)> = Vec::new();
    let mut activation_offline = Vec::new();
    while let Some(result) = activations.join_next().await {
        let (peer, response) =
            result.map_err(|error| DkgError::NetworkCommunication(error.to_string()))?;
        match response {
            Ok(DkgControlMessage::Activated {
                ceremony_id: got_ceremony,
                attempt_id: got_attempt,
                activation_digest: got_activation,
                report_signature,
            }) if got_ceremony == ceremony_id
                && got_attempt == attempt_id
                && got_activation == activation_digest =>
            {
                record_control_ack_best_effort(
                    &state,
                    routes,
                    &prepare,
                    got_ceremony,
                    got_attempt,
                    "activated",
                    got_activation,
                    &peer,
                    report_signature,
                )
                .await;
            }
            Ok(response) => {
                activation_failures.push((
                    peer,
                    format!("invalid activation response: {}", response.metric_label()),
                ));
            }
            Err(error) => {
                if error.is_unreachable() {
                    if let Some(participant) =
                        participant_for_transport_peer(&prepare.committees, &peer)
                    {
                        activation_offline.push(participant);
                    }
                }
                activation_failures.push((peer, error.into_error().to_string()));
            }
        }
    }
    if !activation_offline.is_empty() {
        spawn_pss_offline_observations(
            state.clone(),
            routes,
            PssOfflineObservationSeed::from_prepare(
                &prepare,
                routes.version,
                PssOfflineStage::Activate,
                activation_offline,
            ),
        );
    }
    if !activation_failures.is_empty() {
        return Err(DkgError::BarrierFailure {
            barrier: "activate",
            failed_peers: activation_failures,
        });
    }

    match state
        .dkg_session_state
        .begin_transport(&session_id, attempt_id, activation_digest)
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
        TransportBeginOutcome::NotActivated
        | TransportBeginOutcome::StaleAttempt
        | TransportBeginOutcome::MissingSession => {
            return Err(DkgError::ProtocolError(
                "failed to begin the leader's activated transport attempt".into(),
            ));
        }
    }
    let begin_signature = Some(sign_control_message(
        &state,
        ceremony_id,
        attempt_id,
        "begin",
        activation_digest,
    )?);

    let mut beginnings = JoinSet::new();
    for peer in peer_ids
        .iter()
        .filter(|peer| !is_self_peer_id(&state.network, peer))
    {
        let state = state.clone();
        let peer = peer.clone();
        let begin_signature = begin_signature.clone();
        beginnings.spawn(async move {
            let result = retry_preparation_control_classified(
                &state,
                routes,
                &peer,
                DkgControlMessage::Begin {
                    ceremony_id,
                    attempt_id,
                    activation_digest,
                    report_signature: begin_signature,
                },
                deadline,
            )
            .await;
            (peer, result)
        });
    }
    // Accumulate every failing peer instead of returning on the first (see the
    // matching comment on the Prepare fan-out above).
    let mut begin_failures: Vec<(String, String)> = Vec::new();
    let mut begin_offline = Vec::new();
    while let Some(result) = beginnings.join_next().await {
        let (peer, response) =
            result.map_err(|error| DkgError::NetworkCommunication(error.to_string()))?;
        match response {
            Ok(DkgControlMessage::Begun {
                ceremony_id: got_ceremony,
                attempt_id: got_attempt,
                activation_digest: got_activation,
                report_signature,
            }) if got_ceremony == ceremony_id
                && got_attempt == attempt_id
                && got_activation == activation_digest =>
            {
                record_control_ack_best_effort(
                    &state,
                    routes,
                    &prepare,
                    got_ceremony,
                    got_attempt,
                    "begun",
                    got_activation,
                    &peer,
                    report_signature,
                )
                .await;
            }
            Ok(response) => {
                begin_failures.push((
                    peer,
                    format!("invalid begin response: {}", response.metric_label()),
                ));
            }
            Err(error) => {
                if error.is_unreachable() {
                    if let Some(participant) =
                        participant_for_transport_peer(&prepare.committees, &peer)
                    {
                        begin_offline.push(participant);
                    }
                }
                begin_failures.push((peer, error.into_error().to_string()));
            }
        }
    }
    if !begin_offline.is_empty() {
        spawn_pss_offline_observations(
            state.clone(),
            routes,
            PssOfflineObservationSeed::from_prepare(
                &prepare,
                routes.version,
                PssOfflineStage::Begin,
                begin_offline,
            ),
        );
    }
    if !begin_failures.is_empty() {
        return Err(DkgError::BarrierFailure {
            barrier: "begin",
            failed_peers: begin_failures,
        });
    }
    crate::metrics::record_dkg_control_readiness(
        ceremony_kind,
        readiness_start.elapsed().as_secs_f64(),
    );
    crate::metrics::record_dkg_transport_event("control", "activated");
    Ok((ceremony_id, attempt_id))
}

pub(super) async fn abort_prepared_attempt<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: &PrepareSession,
    reason: String,
) where
    D: CoordinatorDkg,
{
    broadcast_attempt_abort(
        state,
        routes,
        prepare.participant_routes(),
        prepare.ceremony_id,
        prepare.attempt_id,
        reason,
    )
    .await;
}

pub(crate) async fn broadcast_attempt_abort<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    participant_routes: Vec<String>,
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    reason: String,
) where
    D: CoordinatorDkg,
{
    let mut aborts = JoinSet::new();
    for peer in participant_routes
        .into_iter()
        .filter(|peer| !is_self_peer_id(&state.network, peer))
    {
        let state = state.clone();
        let reason = reason.clone();
        aborts.spawn(async move {
            timeout(
                Duration::from_secs(2),
                control_request_with_timeout(
                    &state,
                    routes,
                    &peer,
                    DkgControlMessage::Abort {
                        ceremony_id,
                        attempt_id,
                        reason,
                    },
                    PEER_RESPONSE_TIMEOUT,
                ),
            )
            .await
        });
    }
    while aborts.join_next().await.is_some() {}
    crate::metrics::record_dkg_transport_event("control", "abort");
}
