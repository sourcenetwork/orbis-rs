use super::*;

pub(super) fn leader_bootstrap(
    local_node_key: &str,
    leader_node_key: &str,
    leader_route: &str,
) -> Result<Vec<PeerId>> {
    if local_node_key == leader_node_key {
        return Ok(Vec::new());
    }
    validate_peer_id(leader_route)
        .map_err(|error| DkgError::InvalidInput(format!("invalid leader route: {error}")))?;
    // Preserve the authoritative direct address. The pub-sub adapter pins the
    // connection to the node ID while registering the address with Iroh's
    // static provider, which is required when discovery and relays are disabled.
    Ok(vec![PeerId::from_bytes(leader_route.as_bytes())])
}

pub(super) fn validate_reshare_next_transport_committee(
    next: &CommitteeConfig,
    expected_node_keys: &[String],
    expected_threshold: u32,
    resolved_routes: &[NodeRoute],
) -> Result<()> {
    let expected_assignments = canonical_node_id_assignments_from_node_keys(expected_node_keys)
        .map_err(DkgError::InvalidInput)?;
    let expected_keys: BTreeSet<_> = expected_node_keys.iter().collect();
    let supplied_keys: BTreeSet<_> = next.node_keys.iter().collect();
    if supplied_keys.len() != next.node_keys.len() || supplied_keys != expected_keys {
        return Err(DkgError::Unauthorized(
            "Reshare next transport committee does not match the announced next committee".into(),
        ));
    }
    if next.threshold != expected_threshold {
        return Err(DkgError::Unauthorized(format!(
            "Reshare next transport threshold {} does not match announced threshold {}",
            next.threshold, expected_threshold
        )));
    }
    if next.node_id_assignments != expected_assignments {
        return Err(DkgError::Unauthorized(
            "Reshare next transport node-ID assignments are not canonical".into(),
        ));
    }

    let expected_routes: BTreeMap<_, _> = resolved_routes
        .iter()
        .map(|route| (route.node_key.as_str(), route.peer_id.as_str()))
        .collect();
    if expected_routes.len() != expected_node_keys.len()
        || expected_node_keys
            .iter()
            .any(|node_key| !expected_routes.contains_key(node_key.as_str()))
    {
        return Err(DkgError::InvalidState(
            "resolved Vera routes do not cover the reshare next committee".into(),
        ));
    }
    if let Err(detail) =
        validate_node_route_bindings(&next.node_keys, &next.peer_routes, resolved_routes)
    {
        // Reported: this function's only caller, `validate_reshare_transport_
        // routes`, has its own error wrapped by `prepare_participant` in a
        // `report_leader_prepare_fault_best_effort` call — no separate
        // reporting needed here.
        return Err(DkgError::Unauthorized(format!(
            "Reshare next transport routes do not match resolved Vera NodeInfo routes: {detail}"
        )));
    }
    Ok(())
}

pub(super) async fn validate_reshare_transport_routes<D>(
    state: &Arc<AppState<D>>,
    prepare: &PrepareSession,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let SessionKind::Reshare {
        new_peer_node_keys,
        new_threshold,
        ..
    } = &prepare.kind
    else {
        return Ok(());
    };
    let next = prepare.committees.next.as_ref().ok_or_else(|| {
        DkgError::Unauthorized("Reshare Prepare omits the next transport committee".into())
    })?;
    let resolved_routes = resolve_node_routes(&state.bulletin, new_peer_node_keys)
        .await
        .map_err(DkgError::Unauthorized)?;
    validate_reshare_next_transport_committee(
        next,
        new_peer_node_keys,
        *new_threshold,
        &resolved_routes,
    )
}

pub(super) struct CeremonyStartGuard {
    ceremony_id: u128,
    lock: Weak<tokio::sync::Mutex<()>>,
    locks: Arc<tokio::sync::Mutex<HashMap<u128, Arc<tokio::sync::Mutex<()>>>>>,
    guard: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl Drop for CeremonyStartGuard {
    fn drop(&mut self) {
        drop(self.guard.take());
        let ceremony_id = self.ceremony_id;
        let lock = self.lock.clone();
        let locks = self.locks.clone();
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        runtime.spawn(async move {
            let mut locks = locks.lock().await;
            let remove = locks.get(&ceremony_id).is_some_and(|current| {
                Weak::ptr_eq(&lock, &Arc::downgrade(current)) && Arc::strong_count(current) == 1
            });
            if remove {
                locks.remove(&ceremony_id);
            }
        });
    }
}

pub(super) async fn lock_ceremony_start<D>(
    state: &Arc<AppState<D>>,
    ceremony_id: CeremonyId,
) -> CeremonyStartGuard
where
    D: CoordinatorDkg,
{
    let locks = state.dkg_session_state.ceremony_start_locks();
    let lock = {
        let mut locks = locks.lock().await;
        locks
            .entry(ceremony_id.0)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    };
    let weak_lock = Arc::downgrade(&lock);
    let guard = lock.lock_owned().await;
    CeremonyStartGuard {
        ceremony_id: ceremony_id.0,
        lock: weak_lock,
        locks,
        guard: Some(guard),
    }
}

/// Route a fresh-DKG start to the canonical leader, or coordinate it locally.
pub async fn start_fresh<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    ring_id: String,
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
        .ok_or(DkgError::InvalidParticipantCount(0))?
        .to_string();
    if leader == state.node_key {
        return coordinate_fresh(state, routes, ring_id).await;
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
        DkgControlMessage::StartFresh { ring_id },
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

/// Fresh-DKG-only status query for a client that called `start_fresh`/`StartDkg` and wants to
/// know what happened to a ceremony that failed after the RPC already returned "started" (or
/// during the barrier, if the caller's own connection dropped before receiving that error).
/// Forwards to the canonical leader exactly like `start_fresh`, since only the leader ever
/// observes a barrier-phase failure and only the leader's `failed_sessions` record is
/// authoritative — a follower has no way to know why a ceremony it never led failed.
pub async fn fetch_dkg_session_status<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    ring_id: String,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
{
    let ring = read_ring_for_route(&*state.bulletin, &ring_id, routes.version)
        .await
        .map_err(DkgError::ProtocolError)?;
    let leader = transport::canonical_leader(&ring.peer_node_keys)
        .ok_or(DkgError::InvalidParticipantCount(0))?
        .to_string();
    if leader == state.node_key {
        return coordinate_dkg_session_status(state, routes, ring_id).await;
    }
    let resolved = resolve_node_routes(&state.bulletin, &ring.peer_node_keys)
        .await
        .map_err(DkgError::Unauthorized)?;
    let leader_peer = resolved
        .iter()
        .find_map(|route| (route.node_key == leader).then_some(route.peer_id.as_str()))
        .ok_or_else(|| DkgError::InvalidState("canonical leader route is missing".into()))?;
    control_request_with_timeout(
        &state,
        routes,
        leader_peer,
        DkgControlMessage::GetSessionStatus { ring_id },
        PEER_RESPONSE_TIMEOUT,
    )
    .await
}

/// Leader-local status lookup: a queryable failure record takes priority (it's only ever
/// written for an attempt that is no longer live), then a still-live session in `states`, then
/// `NotFound` for anything neither knows about (never started, or aged out of both).
///
/// No caller-credential check here, for the same reason `start_dkg` has none: a self-issued DID
/// JWT proves nothing about who is allowed to ask about a given ring, so it adds no real
/// access-control boundary — see `get_dkg_session_status`'s doc comment in `service.rs`.
/// `ring_id` is deliberately NOT checked against `validate_fresh_dkg_ring_payload` (which
/// rejects a ring whose `ring_pk` is already set): unlike starting a ceremony, querying its
/// status must still work for a ring whose Fresh DKG has already completed.
pub(super) async fn coordinate_dkg_session_status<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    ring_id: String,
) -> Result<DkgControlMessage>
where
    D: CoordinatorDkg,
{
    // Confirms the ring exists and this leader is still authoritative for its protocol
    // version — the narrower check the plan called for, deliberately not
    // `validate_fresh_dkg_ring_payload`'s "must still be pending" rule.
    read_ring_for_route(&*state.bulletin, &ring_id, routes.version)
        .await
        .map_err(DkgError::ProtocolError)?;

    let session_id = derive_fresh_dkg_session_id(&ring_id)?;
    if let Some(record) = state.dkg_session_state.failed_session(&session_id).await {
        tracing::debug!(
            session_id,
            ring_id = %record.ring_id,
            attempt_id = ?record.attempt_id.map(|id| hex::encode(id.0)),
            stage = record.stage.as_str(),
            "returning queryable Fresh DKG failure record"
        );
        return Ok(DkgControlMessage::SessionStatusResponse {
            session_id: Some(session_id),
            status: transport::DkgSessionStatusValue::Failed,
            stage: record.stage.as_str().to_string(),
            missing: record
                .missing
                .into_iter()
                .map(|p| (p.node_id, p.node_key))
                .collect(),
            reason: record.reason,
            failed_at: record
                .failed_at
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs() as i64),
        });
    }
    if let Some(phase) = state
        .dkg_session_state
        .with_state(&session_id, |s| s.phase)
        .await
    {
        let status = if phase == DkgPhase::Phase4Complete {
            transport::DkgSessionStatusValue::Completed
        } else {
            transport::DkgSessionStatusValue::InProgress
        };
        return Ok(DkgControlMessage::SessionStatusResponse {
            session_id: Some(session_id),
            status,
            stage: String::new(),
            missing: Vec::new(),
            reason: String::new(),
            failed_at: None,
        });
    }
    Ok(DkgControlMessage::SessionStatusResponse {
        session_id: None,
        status: transport::DkgSessionStatusValue::NotFound,
        stage: String::new(),
        missing: Vec::new(),
        reason: String::new(),
        failed_at: None,
    })
}

/// Coordinate a due PSS refresh. Any current-committee member may call
/// `start_refresh`; nonleaders forward to the one canonical leader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RefreshStartOutcome {
    Started(CeremonyId, AttemptId),
    AlreadyActive(CeremonyId, AttemptId),
    /// The canonical leader accepted a request forwarded by this member.
    Forwarded(CeremonyId, AttemptId),
    NotDue,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReshareStartOutcome {
    Started(CeremonyId, AttemptId),
    AlreadyActive(CeremonyId, AttemptId),
    Forwarded(CeremonyId, AttemptId),
}

pub(super) fn pending_reshare_parameters(
    ring: &RingPayload,
    expected_ring_pk: &str,
) -> Result<(Vec<String>, u32)> {
    if !ring_payload_matches_ring_key(expected_ring_pk, &ring.ring_pk) {
        return Err(DkgError::InvalidState(
            "reshare ring public key differs from Vera state".into(),
        ));
    }
    let next_keys = ring
        .new_peer_node_keys
        .clone()
        .unwrap_or_else(|| ring.peer_node_keys.clone());
    let next_threshold = ring.new_threshold.unwrap_or(ring.threshold);
    if next_keys == ring.peer_node_keys && next_threshold == ring.threshold {
        return Err(DkgError::InvalidState(
            "Vera ring has no pending reshare transition".into(),
        ));
    }
    Ok((next_keys, next_threshold))
}

/// Observe a pending transition as a current member and route it to the
/// canonical next-committee leader. Any current member may forward; the next
/// leader independently authenticates the sender and Vera state.
pub(crate) async fn start_reshare<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    ring_id: String,
    ring_pk: String,
) -> Result<ReshareStartOutcome>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let ring = read_ring_for_route(&*state.bulletin, &ring_id, routes.version)
        .await
        .map_err(DkgError::ProtocolError)?;
    let (next_keys, next_threshold) = pending_reshare_parameters(&ring, &ring_pk)?;
    if !ring.peer_node_keys.contains(&state.node_key) {
        return Err(DkgError::Unauthorized(
            "only a current-committee member may request reshare start".into(),
        ));
    }
    let ceremony = CeremonyId(derive_reshare_session_id(
        &ring_pk,
        &ring_id,
        &ring.peer_node_keys,
        &next_keys,
        next_threshold,
    )?);
    if let Some(attempt) = state.dkg_session_state.transport_attempt(&ceremony.0).await {
        crate::metrics::record_dkg_transport_event("control", "reshare_start_duplicate");
        return Ok(ReshareStartOutcome::AlreadyActive(ceremony, attempt));
    }

    let leader = transport::canonical_leader(&next_keys)
        .ok_or(DkgError::InvalidParticipantCount(0))?
        .to_string();
    crate::metrics::record_dkg_transport_event("control", "reshare_next_leader_selected");
    if leader == state.node_key {
        return coordinate_reshare(state, routes, ring_id, ring_pk).await;
    }

    let next_routes = resolve_node_routes(&state.bulletin, &next_keys)
        .await
        .map_err(DkgError::Unauthorized)?;
    let leader_peer = next_routes
        .iter()
        .find_map(|route| (route.node_key == leader).then_some(route.peer_id.clone()))
        .ok_or_else(|| DkgError::InvalidState("next-committee leader route is missing".into()))?;
    crate::metrics::record_dkg_transport_event("control", "reshare_start_forwarded");
    tracing::info!(
        ring_id = %ring_id,
        leader = %leader,
        "forwarding pending reshare to canonical next-committee leader"
    );
    let next_assignments =
        canonical_node_id_assignments_from_node_keys(&next_keys).map_err(DkgError::InvalidInput)?;
    let leader_participant = next_assignments
        .get(&leader)
        .copied()
        .map(ParticipantRef::next)
        .ok_or_else(|| DkgError::InvalidState("next leader assignment is missing".into()))?;
    let kind = SessionKind::Reshare {
        ring_pk_hex: ring_pk.clone(),
        new_peer_node_keys: next_keys,
        new_threshold: next_threshold,
        bulletin_post_id: ring_id.clone(),
    };
    let forwarding_deadline =
        Instant::now() + DKG_PREPARATION_TIMEOUT + DKG_FORWARDED_START_RESPONSE_GRACE;
    let response = retry_preparation_control_classified(
        &state,
        routes,
        &leader_peer,
        DkgControlMessage::StartReshare {
            ring_id: ring_id.clone(),
            expected_ring_pk: ring_pk,
        },
        forwarding_deadline,
    )
    .await;
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            if error.is_unreachable() {
                spawn_pss_offline_observations(
                    state.clone(),
                    routes,
                    PssOfflineObservationSeed::direct(
                        ceremony,
                        kind,
                        ring_id,
                        routes.version,
                        PssOfflineStage::StartForward,
                        [(leader_participant, leader, leader_peer)],
                    ),
                );
            }
            return Err(error.into_error());
        }
    };
    match response {
        DkgControlMessage::ReshareStartAccepted {
            ceremony_id,
            attempt_id,
        } if ceremony_id == ceremony => Ok(ReshareStartOutcome::Forwarded(ceremony_id, attempt_id)),
        response => Err(DkgError::ProtocolError(format!(
            "next-committee leader returned unexpected reshare start response: {response:?}"
        ))),
    }
}

pub(super) async fn validate_reshare_start_sender<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    ring_id: &str,
    expected_ring_pk: &str,
    sender: &PeerId,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let ring = read_ring_for_route(&*state.bulletin, ring_id, routes.version)
        .await
        .map_err(DkgError::ProtocolError)?;
    let (next_keys, _) = pending_reshare_parameters(&ring, expected_ring_pk)?;
    let expected_leader =
        transport::canonical_leader(&next_keys).ok_or(DkgError::InvalidParticipantCount(0))?;
    if expected_leader != state.node_key {
        crate::metrics::record_dkg_transport_event("control", "reshare_start_rejected");
        return Err(DkgError::Unauthorized(
            "StartReshare reached a nonleader next-committee receiver".into(),
        ));
    }
    let current_routes = resolve_node_routes(&state.bulletin, &ring.peer_node_keys)
        .await
        .map_err(DkgError::Unauthorized)?;
    if current_routes
        .iter()
        .all(|route| !peer_matches_route(sender, &route.peer_id))
    {
        crate::metrics::record_dkg_transport_event("control", "reshare_start_rejected");
        return Err(DkgError::Unauthorized(
            "StartReshare sender is not in the current committee".into(),
        ));
    }
    Ok(())
}

/// Coordinate the pending Vera transition as the canonical next-committee
/// receiver. Only this function creates an attempt ID.
pub(super) async fn coordinate_reshare<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    ring_id: String,
    ring_pk: String,
) -> Result<ReshareStartOutcome>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let ring = read_ring_for_route(&*state.bulletin, &ring_id, routes.version)
        .await
        .map_err(DkgError::ProtocolError)?;
    let (next_keys, next_threshold) = pending_reshare_parameters(&ring, &ring_pk)?;
    let leader = transport::canonical_leader(&next_keys)
        .ok_or(DkgError::InvalidParticipantCount(0))?
        .to_string();
    if leader != state.node_key {
        return Err(DkgError::Unauthorized(
            "only the canonical next-committee leader may coordinate reshare".into(),
        ));
    }
    let ceremony = CeremonyId(derive_reshare_session_id(
        &ring_pk,
        &ring_id,
        &ring.peer_node_keys,
        &next_keys,
        next_threshold,
    )?);
    if let Some(attempt) = state.dkg_session_state.transport_attempt(&ceremony.0).await {
        crate::metrics::record_dkg_transport_event("control", "reshare_start_duplicate");
        return Ok(ReshareStartOutcome::AlreadyActive(ceremony, attempt));
    }
    let _start_guard = lock_ceremony_start(&state, ceremony).await;
    if let Some(attempt) = state.dkg_session_state.transport_attempt(&ceremony.0).await {
        crate::metrics::record_dkg_transport_event("control", "reshare_start_duplicate");
        return Ok(ReshareStartOutcome::AlreadyActive(ceremony, attempt));
    }

    let current_routes = resolve_node_routes(&state.bulletin, &ring.peer_node_keys)
        .await
        .map_err(DkgError::Unauthorized)?;
    let next_routes = resolve_node_routes(&state.bulletin, &next_keys)
        .await
        .map_err(DkgError::Unauthorized)?;
    let current_assignments = canonical_node_id_assignments_from_node_keys(&ring.peer_node_keys)
        .map_err(DkgError::InvalidInput)?;
    let next_assignments =
        canonical_node_id_assignments_from_node_keys(&next_keys).map_err(DkgError::InvalidInput)?;
    let attempt = AttemptId::random();
    let transition_digest =
        transport::ceremony_committee_digest(&ring.peer_node_keys, Some(&next_keys));
    let topic = transport::derive_topic_id(
        &state.bulletin.chain_id(),
        &ring_id,
        &transition_digest,
        ceremony,
        attempt,
    );
    let mut prepare = PrepareSession {
        ceremony_id: ceremony,
        attempt_id: attempt,
        config_digest: [0; 32],
        topic_id: *topic.as_bytes(),
        leader_node_key: leader,
        committees: CeremonyConfig {
            current: CommitteeConfig {
                node_keys: ring.peer_node_keys.clone(),
                peer_routes: peer_ids_from_routes(&current_routes),
                node_id_assignments: current_assignments,
                threshold: ring.threshold,
            },
            next: Some(CommitteeConfig {
                node_keys: next_keys.clone(),
                peer_routes: peer_ids_from_routes(&next_routes),
                node_id_assignments: next_assignments,
                threshold: next_threshold,
            }),
        },
        kind: SessionKind::Reshare {
            ring_pk_hex: ring_pk,
            new_peer_node_keys: next_keys,
            new_threshold: next_threshold,
            bulletin_post_id: ring_id.clone(),
        },
        pss_interval: ring.pss_interval,
        policy_id: ring.policy_id,
        ring_id,
        report_signature: None,
    };
    prepare.config_digest = transport::config_digest(&prepare).map_err(DkgError::Serialization)?;
    prepare.report_signature = Some(sign_control_message(
        &state,
        prepare.ceremony_id,
        prepare.attempt_id,
        "prepare",
        prepare.config_digest,
    )?);
    let (ceremony, attempt) = coordinate_prepared(state, routes, prepare).await?;
    crate::metrics::record_dkg_transport_event("control", "reshare_start_accepted");
    Ok(ReshareStartOutcome::Started(ceremony, attempt))
}

pub(super) async fn validate_refresh_start_sender<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    ring_id: &str,
    expected_ring_pk: &str,
    requester_node_key: &str,
    sender: &PeerId,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let ring = read_ring_for_route(&*state.bulletin, ring_id, routes.version)
        .await
        .map_err(DkgError::ProtocolError)?;
    if !ring_payload_matches_ring_key(expected_ring_pk, &ring.ring_pk) {
        return Err(DkgError::InvalidState(
            "refresh ring public key differs from Vera state".into(),
        ));
    }
    let canonical_leader = transport::canonical_leader(&ring.peer_node_keys)
        .ok_or(DkgError::InvalidParticipantCount(0))?;
    if canonical_leader != state.node_key {
        crate::metrics::record_dkg_transport_event("control", "refresh_start_rejected");
        return Err(DkgError::Unauthorized(
            "StartRefresh must be handled by the canonical leader".into(),
        ));
    }
    if !ring
        .peer_node_keys
        .iter()
        .any(|node_key| node_key == requester_node_key)
    {
        crate::metrics::record_dkg_transport_event("control", "refresh_start_rejected");
        return Err(DkgError::Unauthorized(
            "StartRefresh requester is not in the current committee".into(),
        ));
    }
    let requester_routes = resolve_node_routes(&state.bulletin, &[requester_node_key.to_string()])
        .await
        .map_err(DkgError::Unauthorized)?;
    if requester_routes
        .first()
        .is_none_or(|route| !peer_matches_route(sender, &route.peer_id))
    {
        crate::metrics::record_dkg_transport_event("control", "refresh_start_rejected");
        return Err(DkgError::Unauthorized(
            "StartRefresh sender does not match the requester Vera route".into(),
        ));
    }
    Ok(())
}

/// Coordinate a due PSS refresh as the canonical current-committee leader.
/// Callable both by the leader's local scheduler and by its `StartRefresh`
/// control handler after authenticating a current-committee requester.
pub(super) async fn coordinate_refresh<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    ring_id: String,
    ring_pk: String,
) -> Result<RefreshStartOutcome>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let ring = read_ring_for_route(&*state.bulletin, &ring_id, routes.version)
        .await
        .map_err(DkgError::ProtocolError)?;
    if !ring_payload_matches_ring_key(&ring_pk, &ring.ring_pk) {
        return Err(DkgError::InvalidState(
            "refresh ring public key differs from Vera state".into(),
        ));
    }
    let canonical_leader = transport::canonical_leader(&ring.peer_node_keys)
        .ok_or(DkgError::InvalidParticipantCount(0))?;
    if canonical_leader != state.node_key {
        return Err(DkgError::Unauthorized(
            "only the canonical current-committee leader may coordinate PSS refresh".into(),
        ));
    }
    coordinate_refresh_as_claimed_leader(state, routes, ring_id, ring_pk, ring).await
}

/// Build, sign, and broadcast a refresh `Prepare` as this node, claiming the
/// leader role — everything `coordinate_refresh` does *after* verifying the
/// caller is the canonical leader and loading+validating `ring`. Split out so
/// `submit_organic_noncanonical_prepare` (`unsafe_testing`) can drive the exact
/// same real signing/broadcast path from a non-canonical node, organically
/// exercising the *other* nodes' unmodified `leader_prepare_fault` detection
/// instead of injecting evidence directly. Callers are responsible for their
/// own ring-load + `ring_payload_matches_ring_key` check before calling in, so
/// this never re-reads the chain.
pub(crate) async fn coordinate_refresh_as_claimed_leader<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    ring_id: String,
    ring_pk: String,
    ring: RingPayload,
) -> Result<RefreshStartOutcome>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    if let Some(session_id) = state
        .dkg_session_state
        .active_ring_pss_session(&ring_pk)
        .await
    {
        if let Some(attempt_id) = state.dkg_session_state.transport_attempt(&session_id).await {
            return Ok(RefreshStartOutcome::AlreadyActive(
                CeremonyId(session_id),
                attempt_id,
            ));
        }
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
    // The scheduler's first due check precedes an asynchronous Vera read.
    // A previous refresh can complete during that read and advance `last_pss`.
    // Re-read under the start singleflight before creating an attempt so each
    // completion cannot produce a guaranteed-too-early follow-up attempt.
    let current_bundle = RingShareBundle::load_by_ring_key(&state.local_storage, &ring_pk)
        .map_err(|error| DkgError::Storage(error.to_string()))?;
    let now = current_unix_time().map_err(DkgError::SystemTime)?;
    let elapsed = now.saturating_sub(current_bundle.last_pss);
    if elapsed + PSS_GRACE_PERIOD_SECS < ring.pss_interval {
        return Ok(RefreshStartOutcome::NotDue);
    }
    if let Some(attempt_id) = state.dkg_session_state.transport_attempt(&session_id).await {
        return Ok(RefreshStartOutcome::AlreadyActive(
            CeremonyId(session_id),
            attempt_id,
        ));
    }
    let ceremony_id = CeremonyId(session_id);
    let attempt_id = AttemptId::random();
    let committee = transport::ceremony_committee_digest(&ring.peer_node_keys, None);
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
        leader_node_key: state.node_key.clone(),
        committees: CeremonyConfig {
            current: CommitteeConfig {
                node_keys: ring.peer_node_keys,
                peer_routes: peer_ids,
                node_id_assignments: assignments,
                threshold: ring.threshold,
            },
            next: None,
        },
        kind: SessionKind::Refresh {
            ring_pk_hex: ring_pk,
        },
        pss_interval: ring.pss_interval,
        policy_id: ring.policy_id,
        ring_id,
        report_signature: None,
    };
    prepare.config_digest = transport::config_digest(&prepare).map_err(DkgError::Serialization)?;
    prepare.report_signature = Some(sign_control_message(
        &state,
        prepare.ceremony_id,
        prepare.attempt_id,
        "prepare",
        prepare.config_digest,
    )?);
    coordinate_prepared(state, routes, prepare)
        .await
        .map(|(ceremony_id, attempt_id)| RefreshStartOutcome::Started(ceremony_id, attempt_id))
}

/// Trigger a due PSS refresh. Any current-committee member may call this, but
/// only the deterministic canonical leader coordinates the attempt. Repeated
/// forwarded starts retry that same leader and coalesce through its local
/// ceremony-start lock.
pub(crate) async fn start_refresh<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    ring_id: String,
    ring_pk: String,
) -> Result<RefreshStartOutcome>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let ring = read_ring_for_route(&*state.bulletin, &ring_id, routes.version)
        .await
        .map_err(DkgError::ProtocolError)?;
    if !ring.peer_node_keys.contains(&state.node_key) {
        return Err(DkgError::Unauthorized(
            "only a current-committee member may trigger PSS refresh".into(),
        ));
    }
    let canonical_leader = transport::canonical_leader(&ring.peer_node_keys)
        .ok_or(DkgError::InvalidParticipantCount(0))?
        .to_string();
    if canonical_leader == state.node_key {
        return coordinate_refresh(state, routes, ring_id, ring_pk).await;
    }

    let resolved = resolve_node_routes(&state.bulletin, std::slice::from_ref(&canonical_leader))
        .await
        .map_err(DkgError::Unauthorized)?;
    let leader_route = resolved
        .iter()
        .find_map(|route| (route.node_key == canonical_leader).then_some(route.peer_id.clone()))
        .ok_or_else(|| {
            DkgError::InvalidState("canonical refresh leader route is missing".into())
        })?;
    let bundle = RingShareBundle::load_by_ring_key(&state.local_storage, &ring_pk)
        .map_err(|error| DkgError::Storage(error.to_string()))?;
    let ceremony = CeremonyId(derive_refresh_session_id(
        &ring_pk,
        &ring.peer_node_keys,
        ring.threshold,
        &bundle.public_polynomial,
    )?);
    let assignments = canonical_node_id_assignments_from_node_keys(&ring.peer_node_keys)
        .map_err(DkgError::InvalidInput)?;
    let leader_participant = assignments
        .get(&canonical_leader)
        .copied()
        .map(ParticipantRef::current)
        .ok_or_else(|| DkgError::InvalidState("refresh leader assignment is missing".into()))?;
    crate::metrics::record_dkg_transport_event("control", "refresh_start_forwarded");
    let forwarding_deadline =
        Instant::now() + DKG_PREPARATION_TIMEOUT + DKG_FORWARDED_START_RESPONSE_GRACE;
    let response = retry_preparation_control_classified(
        &state,
        routes,
        &leader_route,
        DkgControlMessage::StartRefresh {
            ring_id: ring_id.clone(),
            expected_ring_pk: ring_pk.clone(),
            requester_node_key: state.node_key.clone(),
        },
        forwarding_deadline,
    )
    .await;
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            if error.is_unreachable() {
                spawn_pss_offline_observations(
                    state.clone(),
                    routes,
                    PssOfflineObservationSeed::direct(
                        ceremony,
                        SessionKind::Refresh {
                            ring_pk_hex: ring_pk,
                        },
                        ring_id,
                        routes.version,
                        PssOfflineStage::StartForward,
                        [(leader_participant, canonical_leader, leader_route)],
                    ),
                );
            }
            return Err(error.into_error());
        }
    };
    match response {
        DkgControlMessage::RefreshStartAccepted {
            ceremony_id,
            attempt_id,
        } if ceremony_id == ceremony => Ok(RefreshStartOutcome::Forwarded(ceremony_id, attempt_id)),
        DkgControlMessage::RefreshNotDue => Ok(RefreshStartOutcome::NotDue),
        other => Err(DkgError::ProtocolError(format!(
            "canonical refresh leader returned unexpected start response: {other:?}"
        ))),
    }
}

pub(super) async fn coordinate_fresh<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    ring_id: String,
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
        .ok_or(DkgError::InvalidParticipantCount(0))?
        .to_string();
    if leader != state.node_key {
        return Err(DkgError::Unauthorized(
            "StartFresh must be handled by the canonical leader".into(),
        ));
    }
    let session_id = derive_fresh_dkg_session_id(&ring_id)?;
    let _start_guard = lock_ceremony_start(&state, CeremonyId(session_id)).await;
    if let Some(attempt_id) = state.dkg_session_state.transport_attempt(&session_id).await {
        return Ok((CeremonyId(session_id), attempt_id));
    }
    let ceremony_id = CeremonyId(session_id);
    let attempt_id = AttemptId::random();
    let committee = transport::ceremony_committee_digest(&ring.peer_node_keys, None);
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
        committees: CeremonyConfig {
            current: CommitteeConfig {
                node_keys: ring.peer_node_keys.clone(),
                peer_routes: peer_ids.clone(),
                node_id_assignments: assignments,
                threshold: ring.threshold,
            },
            next: None,
        },
        kind: SessionKind::Fresh,
        pss_interval: ring.pss_interval,
        policy_id: ring.policy_id.clone(),
        ring_id,
        report_signature: None,
    };
    prepare.config_digest = transport::config_digest(&prepare).map_err(DkgError::Serialization)?;
    prepare.report_signature = Some(sign_control_message(
        &state,
        prepare.ceremony_id,
        prepare.attempt_id,
        "prepare",
        prepare.config_digest,
    )?);

    coordinate_prepared(state, routes, prepare).await
}
