use super::*;

/// Re-authenticate a transport-level Commitment conflict and, when the two
/// nested dealer statements prove PSS equivocation, hand it to the existing
/// direct-or-relay reporting pipeline. `Ok(false)` is an intentionally
/// non-reportable conflict (Fresh DKG, missing evidence, or a pair that does
/// not satisfy the equivocation refutation).
pub(super) async fn queue_public_commitment_equivocation<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    attempt: AttemptKey,
    evidence: &PublicCommitmentEquivocation,
) -> Result<bool>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let retained = verify_signed_contribution(state, &evidence.retained).await?;
    let conflicting = verify_signed_contribution(state, &evidence.conflicting).await?;
    if retained.ceremony_id != attempt.ceremony_id
        || retained.attempt_id != attempt.attempt_id
        || conflicting.ceremony_id != attempt.ceremony_id
        || conflicting.attempt_id != attempt.attempt_id
        || retained.origin != evidence.origin
        || conflicting.origin != evidence.origin
    {
        return Err(DkgError::Unauthorized(
            "public commitment equivocation evidence does not match the active attempt or origin"
                .into(),
        ));
    }
    let (
        DkgPublicPayload::Commitment {
            commitment: retained_bytes,
            report_evidence: Some(retained_evidence),
        },
        DkgPublicPayload::Commitment {
            commitment: conflicting_bytes,
            report_evidence: Some(conflicting_evidence),
        },
    ) = (retained.payload, conflicting.payload)
    else {
        return Ok(false);
    };

    let coord = DkgCoordinator::<D>::with_routes(state.clone(), routes);
    let Some(retained_evidence) = verify_commitment_evidence(
        &coord,
        attempt,
        evidence.origin.node_id,
        &retained_bytes,
        Some(*retained_evidence),
    )
    .await?
    else {
        return Ok(false);
    };
    let Some(conflicting_evidence) = verify_commitment_evidence(
        &coord,
        attempt,
        evidence.origin.node_id,
        &conflicting_bytes,
        Some(*conflicting_evidence),
    )
    .await?
    else {
        return Ok(false);
    };
    if !commitments_prove_equivocation(&retained_evidence, &conflicting_evidence) {
        return Ok(false);
    }

    crate::metrics::record_dkg_transport_event("public", "equivocation_candidate");
    queue_or_relay_equivocation(&coord, attempt, retained_evidence, conflicting_evidence).await?;
    crate::metrics::record_dkg_transport_event("public", "equivocation_report_queued");
    Ok(true)
}

#[cfg(test)]
pub(crate) async fn queue_public_commitment_equivocation_for_test<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    attempt: AttemptKey,
    origin: ParticipantRef,
    retained: SignedPayload,
    conflicting: SignedPayload,
) -> Result<bool>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    queue_public_commitment_equivocation(
        state,
        routes,
        attempt,
        &PublicCommitmentEquivocation {
            origin,
            retained,
            conflicting,
        },
    )
    .await
}

pub(super) async fn report_public_commitment_equivocation_best_effort<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    attempt: AttemptKey,
    evidence: Option<&PublicCommitmentEquivocation>,
) where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let Some(evidence) = evidence else {
        return;
    };
    if let Err(error) = queue_public_commitment_equivocation(state, routes, attempt, evidence).await
    {
        crate::metrics::record_dkg_transport_event("public", "equivocation_report_failed");
        tracing::warn!(
            session_id = attempt.session_id(),
            attempt_id = %hex::encode(attempt.attempt_id.0),
            origin = ?evidence.origin,
            error = %error,
            "failed to queue or relay authenticated public commitment equivocation"
        );
    }
}

pub(super) async fn report_public_origin_fault_best_effort<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    attempt: AttemptKey,
    evidence: Option<&PublicOriginFaultEvidence>,
) where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let Some(evidence) = evidence else {
        return;
    };
    crate::metrics::record_dkg_transport_event("public", "origin_fault_candidate");
    let coordinator = DkgCoordinator::with_routes(state.clone(), routes);
    match queue_or_relay_public_origin_fault(
        &coordinator,
        attempt,
        evidence.fault_kind,
        evidence.contribution_a.clone(),
        evidence.contribution_b.clone(),
    )
    .await
    {
        Ok(()) => {
            crate::metrics::record_dkg_transport_event("public", "origin_fault_report_queued")
        }
        Err(error) => {
            crate::metrics::record_dkg_transport_event("public", "origin_fault_report_failed");
            tracing::warn!(
                session_id = attempt.session_id(),
                attempt_id = %hex::encode(attempt.attempt_id.0),
                error = %error,
                "failed to queue or relay authenticated public-origin fault"
            );
        }
    }
}

pub(super) async fn report_leader_equivocation_best_effort<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    attempt: AttemptKey,
    evidence: Option<&LeaderDeliveryEquivocation>,
) where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let Some(evidence) = evidence else {
        return;
    };
    crate::metrics::record_dkg_transport_event("public", "leader_equivocation_candidate");
    let coordinator = DkgCoordinator::with_routes(state.clone(), routes);
    let retained = SignedPayload {
        origin: evidence.retained.origin.clone(),
        signature: evidence.retained.signature.clone(),
        data: evidence.retained.data.clone(),
    };
    let conflicting = SignedPayload {
        origin: evidence.conflicting.origin.clone(),
        signature: evidence.conflicting.signature.clone(),
        data: evidence.conflicting.data.clone(),
    };
    match queue_or_relay_leader_equivocation(
        &coordinator,
        attempt,
        evidence.retained.delivery_id,
        retained,
        evidence.conflicting.delivery_id,
        conflicting,
    )
    .await
    {
        Ok(()) => crate::metrics::record_dkg_transport_event(
            "public",
            "leader_equivocation_report_queued",
        ),
        Err(error) => {
            crate::metrics::record_dkg_transport_event(
                "public",
                "leader_equivocation_report_failed",
            );
            tracing::warn!(
                session_id = attempt.session_id(),
                attempt_id = %hex::encode(attempt.attempt_id.0),
                error = %error,
                "failed to queue or relay authenticated leader-equivocation evidence"
            );
        }
    }
}

pub(super) async fn report_leader_public_fault_best_effort<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    attempt: AttemptKey,
    evidence: Option<&LeaderPublicFaultEvidence>,
) where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let Some(evidence) = evidence else {
        return;
    };
    crate::metrics::record_dkg_transport_event("public", "leader_public_fault_candidate");
    let coordinator = DkgCoordinator::with_routes(state.clone(), routes);
    let delivery = SignedPayload {
        origin: evidence.delivery.origin.clone(),
        signature: evidence.delivery.signature.clone(),
        data: evidence.delivery.data.clone(),
    };
    match queue_or_relay_leader_public_fault(
        &coordinator,
        attempt,
        evidence.fault_kind,
        evidence.delivery.delivery_id,
        delivery,
    )
    .await
    {
        Ok(()) => crate::metrics::record_dkg_transport_event(
            "public",
            "leader_public_fault_report_queued",
        ),
        Err(error) => {
            crate::metrics::record_dkg_transport_event(
                "public",
                "leader_public_fault_report_failed",
            );
            tracing::warn!(
                session_id = attempt.session_id(),
                attempt_id = %hex::encode(attempt.attempt_id.0),
                error = %error,
                "failed to queue authenticated leader public-fault evidence"
            );
        }
    }
}

pub(super) async fn report_leader_batch_mismatch_best_effort<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    attempt: AttemptKey,
    evidence: Option<&LeaderDeliveryEquivocation>,
) where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let Some(evidence) = evidence else {
        return;
    };
    crate::metrics::record_dkg_transport_event("public", "leader_batch_mismatch_candidate");
    let coordinator = DkgCoordinator::with_routes(state.clone(), routes);
    let retained = SignedPayload {
        origin: evidence.retained.origin.clone(),
        signature: evidence.retained.signature.clone(),
        data: evidence.retained.data.clone(),
    };
    let conflicting = SignedPayload {
        origin: evidence.conflicting.origin.clone(),
        signature: evidence.conflicting.signature.clone(),
        data: evidence.conflicting.data.clone(),
    };
    match queue_or_relay_leader_batch_mismatch(
        &coordinator,
        attempt,
        evidence.retained.delivery_id,
        retained,
        evidence.conflicting.delivery_id,
        conflicting,
    )
    .await
    {
        Ok(()) => crate::metrics::record_dkg_transport_event(
            "public",
            "leader_batch_mismatch_report_queued",
        ),
        Err(error) => {
            crate::metrics::record_dkg_transport_event(
                "public",
                "leader_batch_mismatch_report_failed",
            );
            tracing::warn!(
                session_id = attempt.session_id(),
                attempt_id = %hex::encode(attempt.attempt_id.0),
                error = %error,
                "failed to queue authenticated leader batch-mismatch evidence"
            );
        }
    }
}

/// A leader-signed `PublicPhaseResponse` that's independently provable as
/// invalid on its own (currently just `oversized_repair_page` — see
/// `DkgControlMessageFaultKind`). Unlike the Gossip-delivery leader-fault
/// kinds, the accused here is always exactly `prepare.leader_node_key` (the
/// canonical leader that served the direct-QUIC repair connection), so the
/// caller supplies it directly rather than this function re-deriving it.
pub(super) async fn report_oversized_repair_page_best_effort<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    attempt: AttemptKey,
    accused_node_key: &str,
    evidence: Option<&ControlMessageArtifact>,
) where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let Some(evidence) = evidence else {
        return;
    };
    crate::metrics::record_dkg_transport_event("public", "oversized_repair_page_candidate");
    let coordinator = DkgCoordinator::with_routes(state.clone(), routes);
    match queue_or_relay_control_message_fault(
        &coordinator,
        attempt,
        accused_node_key.to_string(),
        "public_phase_response".to_string(),
        DkgControlMessageFaultKind::OversizedRepairPage,
        evidence.clone(),
        None,
    )
    .await
    {
        Ok(()) => crate::metrics::record_dkg_transport_event(
            "public",
            "oversized_repair_page_report_queued",
        ),
        Err(error) => {
            crate::metrics::record_dkg_transport_event(
                "public",
                "oversized_repair_page_report_failed",
            );
            tracing::warn!(
                session_id = attempt.session_id(),
                attempt_id = %hex::encode(attempt.attempt_id.0),
                error = %error,
                "failed to queue authenticated oversized repair-page evidence"
            );
        }
    }
}

/// Records a follower's signed control-plane acknowledgement
/// (`Prepared`/`Activated`/`Begun`) and reports `AckEquivocation` if the
/// same follower already signed a *different* digest for the identical
/// (ceremony, attempt, message_kind) request. Best-effort throughout: a
/// missing/invalid signature, or a failure to record/report, never blocks
/// the caller's own accept/reject handling of the response — this function
/// only ever adds attribution on top of behavior that already happens.
#[allow(clippy::too_many_arguments)]
pub(super) async fn record_control_ack_best_effort<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: &PrepareSession,
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    message_kind: &'static str,
    digest: [u8; 32],
    peer: &str,
    report_signature: Option<ControlSignature>,
) where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let Some(signature) = report_signature else {
        return;
    };
    let Some(participant) = participant_for_transport_peer(&prepare.committees, peer) else {
        return;
    };
    let Some(follower_node_key) = prepare.committees.node_key(participant) else {
        return;
    };
    let follower_node_key = follower_node_key.to_string();
    if verify_control_signature(
        ceremony_id,
        attempt_id,
        message_kind,
        digest,
        &follower_node_key,
        &signature,
    )
    .is_err()
    {
        return;
    }

    let attempt = AttemptKey::new(ceremony_id, attempt_id);
    let Some((existing_digest, existing_signature)) = state
        .dkg_session_state
        .record_control_ack(
            attempt,
            follower_node_key.clone(),
            message_kind,
            digest,
            &signature,
        )
        .await
    else {
        return;
    };

    crate::metrics::record_dkg_transport_event("control", "ack_equivocation_candidate");
    let coordinator = DkgCoordinator::with_routes(state.clone(), routes);
    let artifact_a = ControlMessageArtifact {
        signed_at: existing_signature.signed_at,
        signature: existing_signature.signature,
        data: existing_digest.to_vec(),
    };
    let artifact_b = ControlMessageArtifact {
        signed_at: signature.signed_at,
        signature: signature.signature,
        data: digest.to_vec(),
    };
    match queue_or_relay_control_message_fault(
        &coordinator,
        attempt,
        follower_node_key,
        message_kind.to_string(),
        DkgControlMessageFaultKind::AckEquivocation,
        artifact_a,
        Some(artifact_b),
    )
    .await
    {
        Ok(()) => {
            crate::metrics::record_dkg_transport_event("control", "ack_equivocation_report_queued")
        }
        Err(error) => {
            crate::metrics::record_dkg_transport_event("control", "ack_equivocation_report_failed");
            tracing::warn!(
                session_id = ceremony_id.0,
                attempt_id = %hex::encode(attempt_id.0),
                message_kind,
                %error,
                "failed to queue or relay authenticated control-ack equivocation"
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn record_control_ack_best_effort_for_test<D>(
    state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: &PrepareSession,
    ceremony_id: CeremonyId,
    attempt_id: AttemptId,
    message_kind: &'static str,
    digest: [u8; 32],
    peer: &str,
    report_signature: Option<ControlSignature>,
) where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    record_control_ack_best_effort(
        state,
        routes,
        prepare,
        ceremony_id,
        attempt_id,
        message_kind,
        digest,
        peer,
        report_signature,
    )
    .await
}
