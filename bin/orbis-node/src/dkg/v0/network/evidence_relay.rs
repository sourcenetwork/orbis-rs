use super::*;

pub(crate) async fn send_reshare_share_ack<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    receiver_node_id: u32,
    dealer_id: u32,
    selector_peer: &str,
) -> std::result::Result<(), PeerDeliveryFailure>
where
    D: CoordinatorDkg,
{
    coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |_| ())
        .await
        .map_err(|error| PeerDeliveryFailure {
            error: crate::dkg::v0::coordinator::attempt_state_error(attempt, error),
            unreachable: false,
            reachable: false,
        })?;
    let ceremony_id = attempt.ceremony_id;
    let attempt_id = attempt.attempt_id;
    let receiver = ParticipantRef::next(receiver_node_id);
    let dealer = ParticipantRef::current(dealer_id);
    let idempotency_key = transport::derive_control_message_id(
        ceremony_id,
        attempt_id,
        "reshare-share-ack",
        receiver,
        ParticipantRef::next(1),
        &dealer,
    )
    .map_err(DkgError::Serialization)
    .map_err(|error| PeerDeliveryFailure {
        error,
        unreachable: false,
        reachable: false,
    })?;
    let response = control_request_with_timeout_classified(
        &coord.app_state,
        coord.routes,
        selector_peer,
        DkgControlMessage::ReshareShareAck {
            ceremony_id,
            attempt_id,
            idempotency_key,
            receiver,
            dealer,
        },
        PEER_RESPONSE_TIMEOUT,
    )
    .await
    .map_err(|failure| {
        let unreachable = failure.is_unreachable();
        let reachable = failure.proves_reachable();
        PeerDeliveryFailure {
            unreachable,
            reachable,
            error: failure.into_error(),
        }
    })?;
    match response {
        DkgControlMessage::ReshareShareAcked {
            ceremony_id: got_ceremony,
            attempt_id: got_attempt,
            idempotency_key: got_key,
        } if got_ceremony == ceremony_id
            && got_attempt == attempt_id
            && got_key == idempotency_key =>
        {
            Ok(())
        }
        response => Err(PeerDeliveryFailure {
            error: DkgError::ProtocolError(format!(
                "selector returned invalid reshare acknowledgement response: {response:?}"
            )),
            unreachable: false,
            reachable: true,
        }),
    }
}

pub(crate) async fn relay_invalid_share_evidence<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    evidence: SignedDkgShare,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    relay_private_evidence(
        coord,
        attempt,
        ParticipantRef::next(evidence.statement.to_node_id),
        |ceremony_id, attempt_id, key| DkgControlMessage::RelayInvalidShareEvidence {
            ceremony_id,
            attempt_id,
            idempotency_key: key,
            evidence: evidence.clone(),
        },
        "invalid-share-evidence",
        &evidence,
    )
    .await
}

pub(crate) async fn relay_invalid_commitment_evidence<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    commitment_a: SignedDkgCommitment,
    commitment_b: SignedDkgCommitment,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let next_node_id = coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |session| {
            session
                .reshare
                .params
                .as_ref()
                .and_then(|params| params.new_node_id)
        })
        .await
        .map_err(|error| crate::dkg::v0::coordinator::attempt_state_error(attempt, error))?
        .ok_or_else(|| {
            DkgError::Unauthorized("evidence relay requires next-committee role".into())
        })?;
    let payload = (commitment_a.clone(), commitment_b.clone());
    relay_private_evidence(
        coord,
        attempt,
        ParticipantRef::next(next_node_id),
        |ceremony_id, attempt_id, key| DkgControlMessage::RelayInvalidCommitmentEvidence {
            ceremony_id,
            attempt_id,
            idempotency_key: key,
            commitment_a: commitment_a.clone(),
            commitment_b: commitment_b.clone(),
        },
        "invalid-commitment-evidence",
        &payload,
    )
    .await
}

pub(crate) async fn relay_public_origin_fault_evidence<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    fault_kind: DkgPublicOriginFaultKind,
    contribution_a: SignedPayload,
    contribution_b: Option<SignedPayload>,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let next_node_id = coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |session| {
            session
                .reshare
                .params
                .as_ref()
                .and_then(|params| params.new_node_id)
        })
        .await
        .map_err(|error| crate::dkg::v0::coordinator::attempt_state_error(attempt, error))?
        .ok_or_else(|| {
            DkgError::Unauthorized(
                "public-origin evidence relay requires next-committee role".into(),
            )
        })?;
    let payload = (fault_kind, contribution_a.clone(), contribution_b.clone());
    relay_private_evidence(
        coord,
        attempt,
        ParticipantRef::next(next_node_id),
        |ceremony_id, attempt_id, key| DkgControlMessage::RelayPublicOriginFaultEvidence {
            ceremony_id,
            attempt_id,
            idempotency_key: key,
            fault_kind,
            contribution_a: contribution_a.clone(),
            contribution_b: contribution_b.clone(),
        },
        "public-origin-fault-evidence",
        &payload,
    )
    .await
}

pub(crate) async fn relay_leader_equivocation_evidence<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    delivery_id_a: [u8; 16],
    delivery_a: SignedPayload,
    delivery_id_b: [u8; 16],
    delivery_b: SignedPayload,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let next_node_id = coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |session| {
            session
                .reshare
                .params
                .as_ref()
                .and_then(|params| params.new_node_id)
        })
        .await
        .map_err(|error| crate::dkg::v0::coordinator::attempt_state_error(attempt, error))?
        .ok_or_else(|| {
            DkgError::Unauthorized(
                "leader-equivocation evidence relay requires next-committee role".into(),
            )
        })?;
    let payload = (
        delivery_id_a,
        delivery_a.clone(),
        delivery_id_b,
        delivery_b.clone(),
    );
    relay_private_evidence(
        coord,
        attempt,
        ParticipantRef::next(next_node_id),
        |ceremony_id, attempt_id, key| DkgControlMessage::RelayLeaderEquivocationEvidence {
            ceremony_id,
            attempt_id,
            idempotency_key: key,
            delivery_id_a,
            delivery_a: delivery_a.clone(),
            delivery_id_b,
            delivery_b: delivery_b.clone(),
        },
        "leader-equivocation-evidence",
        &payload,
    )
    .await
}

/// Same shape as `relay_leader_equivocation_evidence` — see
/// `DkgControlMessage::RelayLeaderBatchMismatchEvidence`.
pub(crate) async fn relay_leader_batch_mismatch_evidence<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    delivery_id_a: [u8; 16],
    delivery_a: SignedPayload,
    delivery_id_b: [u8; 16],
    delivery_b: SignedPayload,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let next_node_id = coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |session| {
            session
                .reshare
                .params
                .as_ref()
                .and_then(|params| params.new_node_id)
        })
        .await
        .map_err(|error| crate::dkg::v0::coordinator::attempt_state_error(attempt, error))?
        .ok_or_else(|| {
            DkgError::Unauthorized(
                "leader batch-mismatch evidence relay requires next-committee role".into(),
            )
        })?;
    let payload = (
        delivery_id_a,
        delivery_a.clone(),
        delivery_id_b,
        delivery_b.clone(),
    );
    relay_private_evidence(
        coord,
        attempt,
        ParticipantRef::next(next_node_id),
        |ceremony_id, attempt_id, key| DkgControlMessage::RelayLeaderBatchMismatchEvidence {
            ceremony_id,
            attempt_id,
            idempotency_key: key,
            delivery_id_a,
            delivery_a: delivery_a.clone(),
            delivery_id_b,
            delivery_b: delivery_b.clone(),
        },
        "leader-batch-mismatch-evidence",
        &payload,
    )
    .await
}

/// Same shape as `relay_control_message_fault_evidence`, minus the second
/// artifact — see `DkgControlMessage::RelayLeaderPublicFaultEvidence`.
pub(crate) async fn relay_leader_public_fault_evidence<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    fault_kind: DkgLeaderPublicFaultKind,
    delivery_id: [u8; 16],
    delivery: SignedPayload,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let next_node_id = coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |session| {
            session
                .reshare
                .params
                .as_ref()
                .and_then(|params| params.new_node_id)
        })
        .await
        .map_err(|error| crate::dkg::v0::coordinator::attempt_state_error(attempt, error))?
        .ok_or_else(|| {
            DkgError::Unauthorized(
                "leader public-fault evidence relay requires next-committee role".into(),
            )
        })?;
    let payload = (fault_kind, delivery_id, delivery.clone());
    relay_private_evidence(
        coord,
        attempt,
        ParticipantRef::next(next_node_id),
        |ceremony_id, attempt_id, key| DkgControlMessage::RelayLeaderPublicFaultEvidence {
            ceremony_id,
            attempt_id,
            idempotency_key: key,
            fault_kind,
            delivery_id,
            delivery: delivery.clone(),
        },
        "leader-public-fault-evidence",
        &payload,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_control_message_fault_evidence<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    accused_node_key: String,
    message_kind: String,
    fault_kind: DkgControlMessageFaultKind,
    artifact_a: ControlMessageArtifact,
    artifact_b: Option<ControlMessageArtifact>,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let next_node_id = coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |session| {
            session
                .reshare
                .params
                .as_ref()
                .and_then(|params| params.new_node_id)
        })
        .await
        .map_err(|error| crate::dkg::v0::coordinator::attempt_state_error(attempt, error))?
        .ok_or_else(|| {
            DkgError::Unauthorized(
                "control-message fault evidence relay requires next-committee role".into(),
            )
        })?;
    let payload = (
        accused_node_key.clone(),
        message_kind.clone(),
        fault_kind,
        artifact_a.clone(),
        artifact_b.clone(),
    );
    relay_private_evidence(
        coord,
        attempt,
        ParticipantRef::next(next_node_id),
        |ceremony_id, attempt_id, key| DkgControlMessage::RelayControlMessageFaultEvidence {
            ceremony_id,
            attempt_id,
            idempotency_key: key,
            accused_node_key: accused_node_key.clone(),
            message_kind: message_kind.to_string(),
            fault_kind,
            artifact_a: artifact_a.clone(),
            artifact_b: artifact_b.clone(),
        },
        "control-message-fault-evidence",
        &payload,
    )
    .await
}

pub(super) async fn relay_private_evidence<D, T, F>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    origin: ParticipantRef,
    make_request: F,
    message_kind: &str,
    payload: &T,
) -> Result<()>
where
    D: CoordinatorDkg,
    T: serde::Serialize,
    F: Fn(CeremonyId, AttemptId, MessageId) -> DkgControlMessage,
{
    let attempt_id = attempt.attempt_id;
    let current_routes = coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |session| {
            session.routing.node_id_to_peer_id.clone()
        })
        .await
        .map_err(|error| crate::dkg::v0::coordinator::attempt_state_error(attempt, error))?;
    let ceremony_id = attempt.ceremony_id;
    let mut requests = FuturesUnordered::new();
    for (node_id, peer) in current_routes {
        let recipient = ParticipantRef::current(node_id);
        let key = transport::derive_control_message_id(
            ceremony_id,
            attempt_id,
            message_kind,
            origin,
            recipient,
            payload,
        )
        .map_err(DkgError::Serialization)?;
        let request = make_request(ceremony_id, attempt_id, key);
        requests.push(async move {
            matches!(
                control_request_with_timeout(
                    &coord.app_state,
                    coord.routes,
                    &peer,
                    request,
                    PEER_RESPONSE_TIMEOUT,
                )
                .await,
                Ok(DkgControlMessage::EvidenceAccepted {
                    ceremony_id: got_ceremony,
                    attempt_id: got_attempt,
                    idempotency_key,
                }) if got_ceremony == ceremony_id
                    && got_attempt == attempt_id
                    && idempotency_key == key
            )
        });
    }
    while let Some(accepted) = requests.next().await {
        if accepted {
            return Ok(());
        }
    }
    Err(DkgError::NetworkCommunication(
        "private evidence was not accepted by any current-committee member".into(),
    ))
}

/// Relay terminal transport-liveness candidates from a pure pending-new
/// reshare participant to current-committee report signers. One authenticated
/// acceptance is sufficient because the receiving signer drives the existing
/// threshold-report workflow.
pub(crate) async fn relay_pss_offline_candidates<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    stage: PssOfflineStage,
    mut accused: Vec<ParticipantRef>,
    committees: &CeremonyConfig,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    accused.sort_unstable();
    accused.dedup();
    if accused.is_empty() || accused.len() > MAX_DKG_COMMITTEE_SIZE {
        return Err(DkgError::InvalidInput(
            "offline-candidate relay size is outside the committee bound".into(),
        ));
    }
    if committees.current.node_keys.contains(&state.node_key)
        || !committees
            .next
            .as_ref()
            .is_some_and(|next| next.node_keys.contains(&state.node_key))
    {
        return Err(DkgError::Unauthorized(
            "offline-candidate relay requires a pure pending-new reshare member".into(),
        ));
    }
    if accused
        .iter()
        .any(|participant| committees.route(*participant).is_none())
    {
        return Err(DkgError::InvalidInput(
            "offline-candidate relay names a participant outside the ceremony".into(),
        ));
    }

    let sender = state.network.local_peer_id();
    let idempotency_key = transport::derive_offline_candidates_id(
        ceremony_id,
        attempt_id,
        sender.as_bytes(),
        stage,
        &accused,
    )
    .map_err(DkgError::Serialization)?;
    let accused_routes: BTreeSet<_> = accused
        .iter()
        .filter_map(|participant| committees.route(*participant))
        .map(|route| extract_node_part(route).to_lowercase())
        .collect();
    let mut requests = FuturesUnordered::new();
    for peer in &committees.current.peer_routes {
        if is_self_peer_id(&state.network, peer)
            || accused_routes.contains(&extract_node_part(peer).to_lowercase())
        {
            continue;
        }
        let state = state.clone();
        let peer = peer.clone();
        let accused = accused.clone();
        requests.push(async move {
            matches!(
                control_request_with_timeout(
                    &state,
                    routes,
                    &peer,
                    DkgControlMessage::RelayOfflineCandidates {
                        ceremony_id,
                        attempt_id,
                        idempotency_key,
                        stage,
                        accused,
                    },
                    PEER_RESPONSE_TIMEOUT,
                )
                .await,
                Ok(DkgControlMessage::OfflineCandidatesAccepted {
                    ceremony_id: got_ceremony,
                    attempt_id: got_attempt,
                    idempotency_key: got_key,
                }) if got_ceremony == ceremony_id
                    && got_attempt == attempt_id
                    && got_key == idempotency_key
            )
        });
    }
    while let Some(accepted) = requests.next().await {
        if accepted {
            return Ok(());
        }
    }
    Err(DkgError::NetworkCommunication(
        "offline candidates were not accepted by any current-committee member".into(),
    ))
}
