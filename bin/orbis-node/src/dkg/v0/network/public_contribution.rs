use super::*;

pub(super) async fn verify_signed_contribution<D>(
    state: &Arc<AppState<D>>,
    signed: &SignedPayload,
) -> Result<DkgPublicContribution>
where
    D: CoordinatorDkg,
{
    let pubsub = state.network.pubsub().ok_or_else(|| {
        DkgError::InvalidState("network backend does not provide authenticated pub-sub".into())
    })?;
    let verified = pubsub
        .verify(PUBLIC_CONTRIBUTION_SIGNING_DOMAIN, signed)
        .await
        .map_err(|error| DkgError::Unauthorized(error.to_string()))?;
    let contribution: DkgPublicContribution =
        transport::decode(&verified.data, MAX_CONTROL_MESSAGE_BYTES)
            .map_err(DkgError::Deserialization)?;
    contribution
        .validate_message_id()
        .map_err(DkgError::Unauthorized)?;
    let info = state
        .dkg_session_state
        .transport_info(&contribution.ceremony_id.0)
        .await
        .ok_or_else(|| DkgError::SessionNotFound(contribution.ceremony_id.0.to_string()))?;
    if info.1 != contribution.attempt_id || info.2 != contribution.committee_digest {
        return Err(DkgError::Unauthorized(
            "stale or foreign public contribution".into(),
        ));
    }
    let expected_ring_id = state
        .dkg_session_state
        .ring_id_for_session(&contribution.ceremony_id.0)
        .await
        .ok_or_else(|| DkgError::InvalidState("session ring ID is missing".into()))?;
    if contribution.ring_id != expected_ring_id {
        return Err(DkgError::Unauthorized(
            "public contribution ring ID does not match the active session".into(),
        ));
    }
    let expected_peer = state
        .dkg_session_state
        .peer_id_for_participant(&contribution.ceremony_id.0, contribution.origin)
        .await
        .ok_or_else(|| {
            DkgError::Unauthorized("public contribution origin is not in committee".into())
        })?;
    if !peer_matches_route(&verified.origin, &expected_peer) {
        return Err(DkgError::Unauthorized(
            "public contribution endpoint identity does not match Vera NodeInfo".into(),
        ));
    }
    let (kind, active_dealers) = state
        .dkg_session_state
        .with_state(&contribution.ceremony_id.0, |session| {
            (
                session.kind.clone(),
                session.transport.active_dealers.clone(),
            )
        })
        .await
        .ok_or_else(|| DkgError::SessionNotFound(contribution.ceremony_id.0.to_string()))?;
    let phase = contribution.payload.phase();
    let allowed = match kind {
        SessionKind::Fresh => {
            contribution.origin.scope == CommitteeScope::Current
                && matches!(
                    phase,
                    PublicPhase::CommitmentHashes | PublicPhase::Commitments
                )
        }
        SessionKind::Refresh { .. } => {
            contribution.origin.scope == CommitteeScope::Current
                && matches!(
                    phase,
                    PublicPhase::Commitments
                        | PublicPhase::CommitmentAudit
                        | PublicPhase::RefreshHealthCheck
                )
        }
        SessionKind::Reshare { .. } => match phase {
            PublicPhase::Commitments => active_dealers.contains(&contribution.origin),
            PublicPhase::CommitmentAudit => contribution.origin.scope == CommitteeScope::Next,
            PublicPhase::ReshareParticipantSet => contribution.origin == ParticipantRef::next(1),
            PublicPhase::CommitmentHashes | PublicPhase::RefreshHealthCheck => false,
        },
    };
    if !allowed {
        return Err(DkgError::Unauthorized(
            "public contribution origin is not permitted for this ceremony phase".into(),
        ));
    }
    Ok(contribution)
}

pub(super) async fn record_public_contribution_at_leader<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    signed: SignedPayload,
    contribution: &DkgPublicContribution,
) -> Result<bool>
where
    D: CoordinatorDkg,
{
    let outcome = state
        .dkg_session_state
        .record_public_contribution(
            &contribution.ceremony_id.0,
            contribution.attempt_id,
            contribution.payload.phase(),
            contribution.origin,
            signed,
        )
        .await;
    match outcome {
        PublicContributionRecordOutcome::Recorded => {
            crate::metrics::record_dkg_transport_event("public", "contribution");
            Ok(true)
        }
        PublicContributionRecordOutcome::DuplicateSame => Ok(false),
        PublicContributionRecordOutcome::ConflictingDuplicate {
            retained,
            conflicting,
        } => {
            let reason = format!(
                "origin {:?} equivocated in public phase {:?}",
                contribution.origin,
                contribution.payload.phase()
            );
            tracing::error!(
                session_id = contribution.ceremony_id.0,
                attempt_id = %hex::encode(contribution.attempt_id.0),
                phase = ?contribution.payload.phase(),
                origin = ?contribution.origin,
                message_id = %hex::encode(contribution.message_id.0),
                "leader aborting DKG attempt after signed origin equivocation"
            );
            crate::metrics::record_dkg_transport_event("public", "protocol_violation_abort");
            let attempt = AttemptKey::new(contribution.ceremony_id, contribution.attempt_id);
            let evidence = PublicCommitmentEquivocation {
                origin: contribution.origin,
                retained: retained.clone(),
                conflicting: conflicting.clone(),
            };
            report_public_commitment_equivocation_best_effort(
                state,
                routes,
                attempt,
                (contribution.payload.phase() == PublicPhase::Commitments).then_some(&evidence),
            )
            .await;
            let origin_fault = PublicOriginFaultEvidence {
                fault_kind: DkgPublicOriginFaultKind::OriginEquivocation,
                contribution_a: retained,
                contribution_b: Some(conflicting),
            };
            report_public_origin_fault_best_effort(
                state,
                routes,
                attempt,
                (contribution.payload.phase() != PublicPhase::Commitments).then_some(&origin_fault),
            )
            .await;
            let participant_routes = state
                .dkg_session_state
                .transport_participant_routes(&contribution.ceremony_id.0)
                .await
                .unwrap_or_default();
            state
                .dkg_session_state
                .abort_transport_attempt(attempt, TopicTaskDisposition::Abort)
                .await;
            broadcast_attempt_abort(
                state,
                routes,
                participant_routes,
                contribution.ceremony_id,
                contribution.attempt_id,
                reason.clone(),
            )
            .await;
            Err(DkgError::ProtocolError(reason))
        }
        PublicContributionRecordOutcome::StaleAttempt => Err(DkgError::ProtocolError(
            "public contribution targets a stale attempt".into(),
        )),
        PublicContributionRecordOutcome::MissingSession => Err(DkgError::SessionNotFound(
            contribution.ceremony_id.0.to_string(),
        )),
    }
}

#[cfg(test)]
pub(crate) async fn record_public_contribution_at_leader_for_test<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    signed: SignedPayload,
    contribution: &DkgPublicContribution,
) -> Result<bool>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    record_public_contribution_at_leader(state, routes, signed, contribution).await
}

pub(super) async fn record_public_contribution<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    signed: SignedPayload,
    contribution: &DkgPublicContribution,
) -> Result<bool>
where
    D: CoordinatorDkg,
{
    let outcome = state
        .dkg_session_state
        .record_public_contribution(
            &contribution.ceremony_id.0,
            contribution.attempt_id,
            contribution.payload.phase(),
            contribution.origin,
            signed.clone(),
        )
        .await;
    match outcome {
        PublicContributionRecordOutcome::DuplicateSame => return Ok(false),
        PublicContributionRecordOutcome::Recorded => {}
        PublicContributionRecordOutcome::StaleAttempt => {
            return Err(DkgError::ProtocolError(
                "public contribution targets a stale attempt".into(),
            ))
        }
        PublicContributionRecordOutcome::ConflictingDuplicate {
            retained,
            conflicting,
        } => {
            tracing::error!(
                session_id = contribution.ceremony_id.0,
                attempt_id = %hex::encode(contribution.attempt_id.0),
                phase = ?contribution.payload.phase(),
                origin = ?contribution.origin,
                message_id = %hex::encode(contribution.message_id.0),
                "aborting DKG attempt after signed origin equivocation"
            );
            crate::metrics::record_dkg_transport_event("public", "protocol_violation_abort");
            let attempt = AttemptKey::new(contribution.ceremony_id, contribution.attempt_id);
            let evidence = PublicCommitmentEquivocation {
                origin: contribution.origin,
                retained: retained.clone(),
                conflicting: conflicting.clone(),
            };
            report_public_commitment_equivocation_best_effort(
                state,
                routes,
                attempt,
                (contribution.payload.phase() == PublicPhase::Commitments).then_some(&evidence),
            )
            .await;
            let origin_fault = PublicOriginFaultEvidence {
                fault_kind: DkgPublicOriginFaultKind::OriginEquivocation,
                contribution_a: retained,
                contribution_b: Some(conflicting),
            };
            report_public_origin_fault_best_effort(
                state,
                routes,
                attempt,
                (contribution.payload.phase() != PublicPhase::Commitments).then_some(&origin_fault),
            )
            .await;
            state
                .dkg_session_state
                .abort_transport_attempt(attempt, TopicTaskDisposition::Abort)
                .await;
            return Err(DkgError::ProtocolError(
                "conflicting duplicate public contribution".into(),
            ));
        }
        PublicContributionRecordOutcome::MissingSession => {
            return Err(DkgError::SessionNotFound(
                contribution.ceremony_id.0.to_string(),
            ))
        }
    }
    crate::metrics::record_dkg_transport_event("public", "contribution");
    Ok(true)
}

/// Validate the contribution's protocol payload without retaining it, mutating
/// cryptographic state, or advancing a phase. Proven invalid Refresh commitments
/// may enqueue best-effort reporting evidence before the caller aborts the attempt.
pub(super) async fn preflight_public_contribution<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    contribution: &DkgPublicContribution,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let attempt = AttemptKey::new(contribution.ceremony_id, contribution.attempt_id);
    let local_is_origin = state
        .dkg_session_state
        .with_attempt_state(attempt, |session| session.transport.committees.clone())
        .await
        .map_err(|error| crate::dkg::v0::coordinator::attempt_state_error(attempt, error))?
        .and_then(|committees| {
            committees
                .node_key(contribution.origin)
                .map(|node_key| node_key == state.node_key)
        })
        .unwrap_or(false);
    if contribution.origin.scope == CommitteeScope::Current && local_is_origin {
        return Ok(());
    }
    let coordinator = DkgCoordinator::with_routes(state.clone(), routes);
    match &contribution.payload {
        DkgPublicPayload::CommitmentHash { commitment_hash } => {
            preflight_commitment_hash_message(
                &coordinator,
                attempt,
                contribution.origin.node_id,
                *commitment_hash,
            )
            .await
        }
        DkgPublicPayload::Commitment {
            commitment,
            report_evidence,
        } => prepare_commitment_message(
            &coordinator,
            attempt,
            contribution.origin.node_id,
            commitment,
            report_evidence.as_deref(),
            None,
        )
        .await
        .map(|_| ()),
        DkgPublicPayload::CommitmentAudit { .. } => {
            preflight_commitment_audit_message(&coordinator, attempt).await
        }
        DkgPublicPayload::RefreshHealthCheckResult {
            statement,
            signature,
        } => {
            preflight_result(
                &coordinator,
                attempt,
                contribution.origin.node_id,
                statement,
                signature.as_deref(),
            )
            .await
        }
        DkgPublicPayload::ReshareParticipantSet { selected_dealers } => {
            if selected_dealers
                .iter()
                .any(|dealer| dealer.scope != CommitteeScope::Current)
            {
                return Err(DkgError::Unauthorized(
                    "ReshareParticipantSet dealers must use current-committee scope".into(),
                ));
            }
            let selected_dealer_ids = selected_dealers
                .iter()
                .map(|dealer| dealer.node_id)
                .collect::<Vec<_>>();
            preflight_reshare_participant_set(
                &coordinator,
                attempt,
                contribution.origin.node_id,
                &selected_dealer_ids,
            )
            .await
        }
    }
}

/// Exact retransmissions have already crossed the preflight barrier. Conflicts
/// are intentionally left to the atomic record operation, which classifies
/// origin equivocation without applying either value.
pub(super) async fn preflight_public_contribution_if_new<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    signed: &SignedPayload,
    contribution: &DkgPublicContribution,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let attempt = AttemptKey::new(contribution.ceremony_id, contribution.attempt_id);
    let existing = state
        .dkg_session_state
        .with_attempt_state(attempt, |session| {
            session
                .transport
                .public_contributions
                .get(&contribution.payload.phase())
                .and_then(|items| items.get(&contribution.origin))
                .cloned()
        })
        .await
        .map_err(|error| crate::dkg::v0::coordinator::attempt_state_error(attempt, error))?;
    if existing.is_some() {
        // Both identical retransmissions and signed conflicts are handled by
        // the following atomic record operation. Neither should be applied as
        // a new contribution during preflight.
        return Ok(());
    }
    let ids = BTreeMap::from([(contribution.origin, contribution.message_id)]);
    let root = transport::phase_root(
        contribution.ceremony_id,
        contribution.attempt_id,
        contribution.payload.phase(),
        &ids,
    );
    let single = DkgPublicMessage::Chunk {
        ceremony_id: contribution.ceremony_id,
        attempt_id: contribution.attempt_id,
        phase: contribution.payload.phase(),
        phase_root: root,
        index: 0,
        contributions: vec![signed.clone()],
        // Sizing probe only — this instance is never broadcast, just measured
        // below to enforce `MAX_PUBLIC_CHUNK_BYTES` before accepting the
        // contribution.
        signed_at: now_unix_secs()?,
    };
    let encoded_len = transport::encode(&single)
        .map_err(DkgError::Serialization)?
        .len();
    if encoded_len > transport::MAX_PUBLIC_CHUNK_BYTES {
        return Err(DkgError::InvalidInput(format!(
            "signed public contribution requires a {encoded_len}-byte Gossip chunk, exceeding the {}-byte limit",
            transport::MAX_PUBLIC_CHUNK_BYTES
        )));
    }
    preflight_public_contribution(state, routes, contribution).await
}

pub(super) fn attributable_public_preflight_error(error: &DkgError) -> bool {
    matches!(
        error,
        DkgError::Unauthorized(_)
            | DkgError::Deserialization(_)
            | DkgError::Crypto(_)
            | DkgError::InvalidInput(_)
            | DkgError::CommitmentVerificationFailed(_)
    )
}

pub(super) async fn dispatch_public_contribution<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    signed: SignedPayload,
    contribution: DkgPublicContribution,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let attempt = AttemptKey::new(contribution.ceremony_id, contribution.attempt_id);
    let session_id = attempt.session_id();
    let message_id = contribution.message_id;
    loop {
        match state
            .dkg_session_state
            .claim_transport_message(attempt, message_id)
            .await
        {
            MessageProcessingClaim::Claimed => break,
            MessageProcessingClaim::AlreadyProcessed => return Ok(()),
            MessageProcessingClaim::AlreadyProcessing => {
                sleep(Duration::from_millis(10)).await;
            }
            MessageProcessingClaim::MissingSession => {
                return Err(DkgError::SessionNotFound(session_id.to_string()));
            }
            MessageProcessingClaim::StaleAttempt => return Ok(()),
        }
    }

    let result =
        dispatch_public_contribution_once(state.clone(), routes, signed, contribution).await;
    state
        .dkg_session_state
        .finish_transport_message(attempt, message_id, result.is_ok())
        .await;
    result
}

pub(super) async fn dispatch_public_contribution_once<D>(
    state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    _signed: SignedPayload,
    contribution: DkgPublicContribution,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let attempt = AttemptKey::new(contribution.ceremony_id, contribution.attempt_id);
    let local_is_origin = state
        .dkg_session_state
        .with_attempt_state(attempt, |session| session.transport.committees.clone())
        .await
        .map_err(|error| crate::dkg::v0::coordinator::attempt_state_error(attempt, error))?
        .and_then(|committees| {
            committees
                .node_key(contribution.origin)
                .map(|node_key| node_key == state.node_key)
        })
        .unwrap_or(false);
    if contribution.origin.scope == CommitteeScope::Current && local_is_origin {
        return Ok(());
    }
    let coordinator = DkgCoordinator::with_routes(state, routes);
    match contribution.payload {
        DkgPublicPayload::CommitmentHash { commitment_hash } => {
            Box::pin(handle_commitment_hash_message(
                &coordinator,
                attempt,
                contribution.origin.node_id,
                commitment_hash,
            ))
            .await?
        }
        DkgPublicPayload::Commitment {
            commitment,
            report_evidence,
        } => {
            Box::pin(handle_commitment_message(
                &coordinator,
                attempt,
                contribution.origin.node_id,
                commitment,
                report_evidence.map(|boxed| *boxed),
            ))
            .await?
        }
        DkgPublicPayload::CommitmentAudit { revealed } => {
            Box::pin(handle_commitment_audit_message(
                &coordinator,
                attempt,
                revealed,
            ))
            .await?
        }
        DkgPublicPayload::RefreshHealthCheckResult {
            statement,
            signature,
        } => {
            Box::pin(handle_result(
                &coordinator,
                attempt,
                contribution.origin.node_id,
                statement,
                signature,
            ))
            .await?
        }
        DkgPublicPayload::ReshareParticipantSet { selected_dealers } => {
            if contribution.origin != ParticipantRef::next(1) {
                return Err(DkgError::Unauthorized(
                    "reshare participant set must originate from next-committee selector 1".into(),
                ));
            }
            let selected = selected_dealers
                .into_iter()
                .map(|dealer| dealer.node_id)
                .collect();
            Box::pin(handle_reshare_participant_set(
                &coordinator,
                attempt,
                contribution.origin.node_id,
                selected,
            ))
            .await?;
        }
    }
    Ok(())
}

pub(crate) fn contribution_ids(
    items: &BTreeMap<ParticipantRef, SignedPayload>,
) -> BTreeMap<ParticipantRef, transport::MessageId> {
    items
        .iter()
        .filter_map(|(origin, signed)| {
            transport::decode::<DkgPublicContribution>(&signed.data, MAX_CONTROL_MESSAGE_BYTES)
                .ok()
                .map(|contribution| (*origin, contribution.message_id))
        })
        .collect()
}
