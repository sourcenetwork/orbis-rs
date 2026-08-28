use super::*;

#[derive(Default)]
pub(super) struct GossipNeighborTracker {
    neighbors: BTreeSet<String>,
    ever_had_neighbor: bool,
    isolation_deadline: Option<Instant>,
}

impl GossipNeighborTracker {
    pub(super) fn neighbor_up(&mut self, peer: &PeerId) {
        self.neighbors.insert(hex::encode(peer.as_bytes()));
        self.ever_had_neighbor = true;
        self.isolation_deadline = None;
    }

    pub(super) fn neighbor_down(&mut self, peer: &PeerId, now: Instant) -> bool {
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

    pub(super) fn isolation_deadline(&self) -> Option<Instant> {
        self.isolation_deadline
    }

    pub(super) fn is_isolated(&self) -> bool {
        self.neighbors.is_empty() && self.ever_had_neighbor
    }

    pub(super) fn reset_after_rejoin(&mut self) {
        self.neighbors.clear();
        self.ever_had_neighbor = false;
        self.isolation_deadline = None;
    }

    pub(super) fn neighbor_count(&self) -> usize {
        self.neighbors.len()
    }
}

pub(super) async fn abort_public_protocol_violation_from_listener<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: &PrepareSession,
    violation: &PublicProtocolViolation,
) where
    D: CoordinatorDkg,
{
    abort_public_protocol_violation(
        state,
        routes,
        prepare,
        violation,
        TopicTaskDisposition::DetachCurrent,
    )
    .await;
}

pub(super) async fn abort_public_protocol_violation<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: &PrepareSession,
    violation: &PublicProtocolViolation,
    topic_task: TopicTaskDisposition,
) where
    D: CoordinatorDkg,
{
    let root = violation.root.as_deref().map(hex::encode);
    let message_ids: Vec<_> = violation
        .message_ids
        .iter()
        .map(|message_id| hex::encode(message_id.0))
        .collect();
    tracing::error!(
        session_id = prepare.ceremony_id.0,
        attempt_id = %hex::encode(prepare.attempt_id.0),
        phase = ?violation.phase,
        root = ?root,
        message_ids = ?message_ids,
        accused = ?violation.accused,
        violation = ?violation.kind,
        detail = %violation.detail,
        "aborting DKG attempt after authenticated public protocol violation"
    );
    crate::metrics::record_dkg_transport_event("public", "protocol_violation_abort");
    report_public_commitment_equivocation_best_effort(
        state,
        routes,
        AttemptKey::new(prepare.ceremony_id, prepare.attempt_id),
        violation.commitment_equivocation.as_deref(),
    )
    .await;
    report_public_origin_fault_best_effort(
        state,
        routes,
        AttemptKey::new(prepare.ceremony_id, prepare.attempt_id),
        violation.public_origin_fault.as_deref(),
    )
    .await;
    report_leader_equivocation_best_effort(
        state,
        routes,
        AttemptKey::new(prepare.ceremony_id, prepare.attempt_id),
        violation.leader_equivocation.as_deref(),
    )
    .await;
    report_leader_public_fault_best_effort(
        state,
        routes,
        AttemptKey::new(prepare.ceremony_id, prepare.attempt_id),
        violation.leader_public_fault.as_deref(),
    )
    .await;
    report_leader_batch_mismatch_best_effort(
        state,
        routes,
        AttemptKey::new(prepare.ceremony_id, prepare.attempt_id),
        violation.leader_batch_mismatch.as_deref(),
    )
    .await;
    report_oversized_repair_page_best_effort(
        state,
        routes,
        AttemptKey::new(prepare.ceremony_id, prepare.attempt_id),
        &prepare.leader_node_key,
        violation.control_message_fault.as_deref(),
    )
    .await;
    state
        .dkg_session_state
        .abort_transport_attempt(
            AttemptKey::new(prepare.ceremony_id, prepare.attempt_id),
            topic_task,
        )
        .await;
}

pub(super) async fn apply_validated_public_batch<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: &PrepareSession,
    phase: PublicPhase,
    root: [u8; 32],
    contributions: Vec<VerifiedPublicContribution>,
) -> std::result::Result<bool, PublicProtocolViolation>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    for verified in &contributions {
        if let Err(error) = preflight_public_contribution_if_new(
            state,
            routes,
            &verified.signed,
            &verified.contribution,
        )
        .await
        {
            if state
                .dkg_session_state
                .transport_attempt(&prepare.ceremony_id.0)
                .await
                != Some(prepare.attempt_id)
            {
                return Ok(false);
            }
            if !attributable_public_preflight_error(&error) {
                tracing::warn!(
                    %error,
                    phase = ?phase,
                    root = %hex::encode(root),
                    origin = ?verified.contribution.origin,
                    "deferring public DKG batch after local payload preflight could not complete"
                );
                crate::metrics::record_dkg_transport_event("public", "batch_preflight_deferred");
                return Ok(true);
            }
            return Err(PublicProtocolViolation::leader(
                PublicProtocolViolationKind::InvalidContribution,
                Some(phase),
                Some(root),
                format!(
                    "origin {:?} contribution failed payload preflight: {error}",
                    verified.contribution.origin
                ),
            )
            .with_message_id(verified.contribution.message_id)
            .with_public_origin_fault(Some(PublicOriginFaultEvidence {
                fault_kind: DkgPublicOriginFaultKind::InvalidPayload,
                contribution_a: verified.signed.clone(),
                contribution_b: None,
            })));
        }
    }
    let retained: BTreeMap<_, _> = contributions
        .iter()
        .map(|verified| (verified.contribution.origin, verified.signed.clone()))
        .collect();
    match state
        .dkg_session_state
        .record_public_batch(&prepare.ceremony_id.0, prepare.attempt_id, phase, retained)
        .await
    {
        PublicBatchRecordOutcome::Recorded => {}
        PublicBatchRecordOutcome::DuplicateSame => {
            crate::metrics::record_dkg_transport_event("public", "batch_duplicate");
        }
        PublicBatchRecordOutcome::ConflictingDuplicate {
            origin,
            retained,
            conflicting,
        } => {
            return Err(PublicProtocolViolation::origin(
                phase,
                Some(root),
                origin,
                "manifest-validated batch conflicts with a retained signed contribution",
            )
            .with_commitment_equivocation((phase == PublicPhase::Commitments).then_some(
                PublicCommitmentEquivocation {
                    origin,
                    retained: retained.clone(),
                    conflicting: conflicting.clone(),
                },
            ))
            .with_public_origin_fault((phase != PublicPhase::Commitments).then_some(
                PublicOriginFaultEvidence {
                    fault_kind: DkgPublicOriginFaultKind::OriginEquivocation,
                    contribution_a: retained,
                    contribution_b: Some(conflicting),
                },
            )));
        }
        PublicBatchRecordOutcome::StaleAttempt | PublicBatchRecordOutcome::MissingSession => {
            return Ok(false);
        }
    }

    // A refresh result uses a two-step control barrier. Gossip reception retains
    // the exact validated result, but only CommitRefreshResult promotes it.
    if phase != PublicPhase::RefreshHealthCheck {
        for verified in contributions {
            let message_id = verified.contribution.message_id;
            if let Err(error) = dispatch_public_contribution(
                state.clone(),
                routes,
                verified.signed,
                verified.contribution,
            )
            .await
            {
                if state
                    .dkg_session_state
                    .transport_attempt(&prepare.ceremony_id.0)
                    .await
                    != Some(prepare.attempt_id)
                {
                    return Ok(false);
                }
                if matches!(
                    &error,
                    DkgError::Unauthorized(_)
                        | DkgError::Deserialization(_)
                        | DkgError::Crypto(_)
                        | DkgError::InvalidInput(_)
                        | DkgError::CommitmentVerificationFailed(_)
                ) {
                    return Err(PublicProtocolViolation::leader(
                        PublicProtocolViolationKind::InvalidContribution,
                        Some(phase),
                        Some(root),
                        format!("validated contribution failed protocol application: {error}"),
                    )
                    .with_message_id(message_id));
                }
                tracing::warn!(
                    %error,
                    phase = ?phase,
                    root = %hex::encode(root),
                    "failed to dispatch manifest-validated public DKG contribution"
                );
            }
        }
    }

    crate::metrics::record_dkg_transport_event("public", "batch_validated");
    tracing::info!(
        session_id = prepare.ceremony_id.0,
        attempt_id = %hex::encode(prepare.attempt_id.0),
        phase = ?phase,
        root = %hex::encode(root),
        "validated and applied public DKG Gossip batch"
    );
    Ok(true)
}

pub(super) async fn topic_listener<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: PrepareSession,
    topic: Arc<dyn Topic>,
) where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let leader_route = prepare
        .leader_route()
        .map(str::to_owned)
        .unwrap_or_default();
    let mut repair_tick = tokio::time::interval(DKG_REPAIR_STALL_INTERVAL);
    repair_tick.tick().await;
    let mut topic = topic;
    let mut neighbor_tracker = GossipNeighborTracker::default();
    let mut acknowledgement_tasks = JoinSet::new();
    let mut acknowledgement_in_flight = false;
    let mut acknowledged_nonce: Option<[u8; 32]> = None;
    let mut public_batches = PublicBatchAssembler::default();
    let mut manifest_repairs = ManifestRepairSchedule::default();
    let mut rejected_gossip_frames = 0u64;
    'listener: loop {
        if state
            .dkg_session_state
            .transport_attempt(&prepare.ceremony_id.0)
            .await
            != Some(prepare.attempt_id)
        {
            // Completion/abort owns topic teardown and all listener-owned work.
            break;
        }
        let isolation_deadline = neighbor_tracker.isolation_deadline();
        let manifest_repair_deadline = manifest_repairs.next_deadline();
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
            _ = async {
                match manifest_repair_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                for phase in manifest_repairs.take_due(Instant::now()) {
                    if let Err(error) = repair_public_phase(
                        state.clone(),
                        routes,
                        prepare.clone(),
                        phase,
                        false,
                        TopicTaskDisposition::DetachCurrent,
                    ).await {
                        tracing::warn!(
                            %error,
                            phase = ?phase,
                            "scheduled public DKG completeness repair failed"
                        );
                    }
                }
                continue;
            }
            event = topic.recv() => event,
            _ = repair_tick.tick() => {
                if state.dkg_session_state.transport_repair_due(
                    &prepare.ceremony_id.0,
                    prepare.attempt_id,
                    DKG_REPAIR_STALL_INTERVAL,
                ).await {
                    for &phase in repairable_public_phases(&prepare.kind) {
                        if let Err(error) = repair_public_phase(
                            state.clone(),
                            routes,
                            prepare.clone(),
                            phase,
                            false,
                            TopicTaskDisposition::DetachCurrent,
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
                let event_digest = authenticated_public_event_digest(&message.data);
                let public = match transport::decode::<DkgPublicMessage>(
                    &message.data,
                    MAX_CONTROL_MESSAGE_BYTES,
                ) {
                    Ok(public) => public,
                    Err(error) => {
                        let violation = PublicProtocolViolation::leader(
                            PublicProtocolViolationKind::MalformedLeaderMessage,
                            None,
                            None,
                            error,
                        );
                        abort_public_protocol_violation_from_listener(
                            &state, routes, &prepare, &violation,
                        )
                        .await;
                        break 'listener;
                    }
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
                        index,
                        contributions,
                        signed_at: _,
                    } if ceremony_id == prepare.ceremony_id && attempt_id == prepare.attempt_id => {
                        let Some(mode) = public_batch_mode(&prepare.kind, phase) else {
                            let violation = PublicProtocolViolation::leader(
                                PublicProtocolViolationKind::InvalidChunk,
                                Some(phase),
                                Some(phase_root),
                                "public chunk is not allowed for this ceremony kind",
                            );
                            abort_public_protocol_violation_from_listener(
                                &state, routes, &prepare, &violation,
                            )
                            .await;
                            break 'listener;
                        };
                        if message.data.len() > transport::MAX_PUBLIC_CHUNK_BYTES {
                            let violation = PublicProtocolViolation::leader(
                                PublicProtocolViolationKind::BufferLimit,
                                Some(phase),
                                Some(phase_root),
                                format!(
                                    "encoded chunk is {} bytes, exceeding the {}-byte limit",
                                    message.data.len(),
                                    transport::MAX_PUBLIC_CHUNK_BYTES
                                ),
                            )
                            .with_leader_public_fault(
                                DkgLeaderPublicFaultKind::OversizedChunk,
                                public_leader_delivery_from_message(&message),
                            );
                            abort_public_protocol_violation_from_listener(
                                &state, routes, &prepare, &violation,
                            )
                            .await;
                            break 'listener;
                        }

                        let mut verified = Vec::with_capacity(contributions.len());
                        for signed in contributions {
                            match verify_signed_contribution(&state, &signed).await {
                                Ok(contribution)
                                    if contribution.payload.phase() == phase
                                        && contribution.ceremony_id == ceremony_id
                                        && contribution.attempt_id == attempt_id =>
                                {
                                    verified.push(VerifiedPublicContribution {
                                        signed,
                                        contribution,
                                    });
                                }
                                Ok(contribution) => {
                                    let violation = PublicProtocolViolation::leader(
                                        PublicProtocolViolationKind::InvalidContribution,
                                        Some(phase),
                                        Some(phase_root),
                                        format!(
                                            "chunk contribution {:?} has the wrong public scope",
                                            contribution.origin
                                        ),
                                    );
                                    abort_public_protocol_violation_from_listener(
                                        &state, routes, &prepare, &violation,
                                    )
                                    .await;
                                    break 'listener;
                                }
                                Err(error) => {
                                    if state
                                        .dkg_session_state
                                        .transport_attempt(&ceremony_id.0)
                                        .await
                                        != Some(attempt_id)
                                    {
                                        break 'listener;
                                    }
                                    let violation = PublicProtocolViolation::leader(
                                        PublicProtocolViolationKind::InvalidContribution,
                                        Some(phase),
                                        Some(phase_root),
                                        error.to_string(),
                                    );
                                    abort_public_protocol_violation_from_listener(
                                        &state, routes, &prepare, &violation,
                                    )
                                    .await;
                                    break 'listener;
                                }
                            }
                        }

                        let expected_origins =
                            expected_public_origins(&state, &prepare, phase).await;
                        let assembly = public_batches.insert_chunk(
                            mode,
                            phase,
                            phase_root,
                            index,
                            verified,
                            event_digest,
                            expected_origins.len(),
                            public_leader_delivery_from_message(&message),
                        );
                        match assembly {
                            Ok(PublicBatchAssembly::Pending { .. }) => {
                                crate::metrics::record_dkg_transport_event(
                                    "public",
                                    "batch_buffered",
                                );
                            }
                            Ok(PublicBatchAssembly::Duplicate) => {
                                crate::metrics::record_dkg_transport_event(
                                    "public",
                                    "batch_duplicate",
                                );
                            }
                            Ok(PublicBatchAssembly::Complete {
                                phase,
                                root,
                                contributions,
                            }) => {
                                if mode == PublicBatchMode::Complete {
                                    manifest_repairs.cancel(phase);
                                }
                                match apply_validated_public_batch(
                                    &state,
                                    routes,
                                    &prepare,
                                    phase,
                                    root,
                                    contributions,
                                )
                                .await
                                {
                                    Ok(true) => {}
                                    Ok(false) => break 'listener,
                                    Err(violation) => {
                                        abort_public_protocol_violation_from_listener(
                                            &state, routes, &prepare, &violation,
                                        )
                                        .await;
                                        break 'listener;
                                    }
                                }
                            }
                            Err(violation) => {
                                abort_public_protocol_violation_from_listener(
                                    &state, routes, &prepare, &violation,
                                )
                                .await;
                                break 'listener;
                            }
                        }
                    }
                    DkgPublicMessage::Manifest(manifest)
                        if manifest.ceremony_id == prepare.ceremony_id
                            && manifest.attempt_id == prepare.attempt_id =>
                    {
                        let expected_origins =
                            expected_public_origins(&state, &prepare, manifest.phase).await;
                        let phase = manifest.phase;
                        let Some(mode) = public_batch_mode(&prepare.kind, phase) else {
                            let violation = PublicProtocolViolation::leader(
                                PublicProtocolViolationKind::InvalidManifest,
                                Some(phase),
                                Some(manifest.phase_root),
                                "public manifest is not allowed for this ceremony kind",
                            );
                            abort_public_protocol_violation_from_listener(
                                &state, routes, &prepare, &violation,
                            )
                            .await;
                            break 'listener;
                        };
                        match public_batches.insert_manifest(
                            mode,
                            manifest,
                            event_digest,
                            &expected_origins,
                            public_leader_delivery_from_message(&message),
                        ) {
                            Ok(PublicBatchAssembly::Pending {
                                manifest_added: true,
                            }) => {
                                tracing::debug!(phase = ?phase,
                                    "received public DKG manifest; awaiting chunks");
                                let event = if manifest_repairs
                                    .arm(phase, Instant::now() + DKG_REPAIR_STALL_INTERVAL)
                                {
                                    "manifest_repair_scheduled"
                                } else {
                                    "manifest_repair_coalesced"
                                };
                                crate::metrics::record_dkg_transport_event("public", event);
                            }
                            Ok(PublicBatchAssembly::Pending {
                                manifest_added: false,
                            }) => {}
                            Ok(PublicBatchAssembly::Duplicate) => {
                                crate::metrics::record_dkg_transport_event(
                                    "public",
                                    "batch_duplicate",
                                );
                            }
                            Ok(PublicBatchAssembly::Complete {
                                phase,
                                root,
                                contributions,
                            }) => {
                                if mode == PublicBatchMode::Complete {
                                    manifest_repairs.cancel(phase);
                                }
                                match apply_validated_public_batch(
                                    &state,
                                    routes,
                                    &prepare,
                                    phase,
                                    root,
                                    contributions,
                                )
                                .await
                                {
                                    Ok(true) => {}
                                    Ok(false) => break 'listener,
                                    Err(violation) => {
                                        abort_public_protocol_violation_from_listener(
                                            &state, routes, &prepare, &violation,
                                        )
                                        .await;
                                        break 'listener;
                                    }
                                }
                            }
                            Err(violation) => {
                                abort_public_protocol_violation_from_listener(
                                    &state, routes, &prepare, &violation,
                                )
                                .await;
                                break 'listener;
                            }
                        }
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
                        if let Err(error) = repair_public_phase(
                            state,
                            routes,
                            prepare,
                            phase,
                            true,
                            TopicTaskDisposition::Abort,
                        )
                        .await
                        {
                            tracing::warn!(%error, "public DKG lag repair failed");
                        }
                    });
                }
            }
            Ok(PubSubEvent::Rejected {
                delivered_from: _,
                reason,
            }) => {
                rejected_gossip_frames = rejected_gossip_frames.saturating_add(1);
                crate::metrics::record_dkg_transport_event("public", "gossip_frame_rejected");
                // Invalid outer envelopes are not attributable to their claimed
                // publisher. `delivered_from` may only be an honest Gossip relay.
                // Keep the healthy subscription and let the listener service its
                // normal timers between rejected frames.
                if rejected_gossip_frames == 1 || rejected_gossip_frames.is_power_of_two() {
                    tracing::warn!(
                        session_id = prepare.ceremony_id.0,
                        attempt_id = %hex::encode(prepare.attempt_id.0),
                        %reason,
                        rejected_frames = rejected_gossip_frames,
                        "discarding unauthenticated DKG Gossip frame"
                    );
                }
            }
            Ok(PubSubEvent::IngressDropped {
                delivered_from: _,
                reason: _,
            }) => {
                // Ingress overload is ordinary availability loss. The network
                // adapter already records bounded metrics/logs; keep this
                // subscription and let manifest/periodic repair recover gaps.
            }
            Ok(PubSubEvent::NeighborUp(peer)) => {
                neighbor_tracker.neighbor_up(&peer);
            }
            Ok(PubSubEvent::NeighborDown(peer)) => {
                crate::metrics::record_dkg_transport_event("public", "neighbor_down");
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

pub(super) async fn rejoin_public_topic<D>(
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
    let bootstrap = leader_bootstrap(&state.node_key, &prepare.leader_node_key, leader_route)?;
    let topic = pubsub
        .subscribe(network::TopicId::new(prepare.topic_id), bootstrap)
        .await
        .map_err(|error| DkgError::NetworkCommunication(error.to_string()))?;
    if state
        .dkg_session_state
        .replace_transport_topic(&prepare.ceremony_id.0, prepare.attempt_id, topic.clone())
        .await
        != Some(true)
    {
        return Err(DkgError::ProtocolError(
            "cannot rejoin a stale DKG attempt".into(),
        ));
    }
    Ok(topic)
}

pub(super) async fn rejoin_public_topic_with_retry<D>(
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
        .transport_hard_deadline(&prepare.ceremony_id.0, prepare.attempt_id)
        .await
        .map(Instant::from_std)
        .ok_or_else(|| DkgError::SessionNotFound(prepare.ceremony_id.0.to_string()))?;
    let mut backoff = INITIAL_CONTROL_RETRY_BACKOFF;
    loop {
        if state
            .dkg_session_state
            .transport_attempt(&prepare.ceremony_id.0)
            .await
            != Some(prepare.attempt_id)
        {
            return Err(DkgError::ProtocolError(
                "cannot rejoin a stale DKG attempt".into(),
            ));
        }
        match rejoin_public_topic(state, prepare, leader_route).await {
            Ok(topic) => {
                crate::metrics::record_dkg_transport_event("public", metric_event);
                return Ok(topic);
            }
            Err(error) => {
                crate::metrics::record_dkg_transport_event("public", "rejoin_failure");
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
