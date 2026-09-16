use super::*;

/// Package a single leader-signed manifest that is independently provable
/// as invalid on its own (no conflicting counterpart needed) into a report.
/// Unlike `queue_leader_equivocation_report`, the accused's guilt doesn't
/// depend on a second delivery — `registry.rs`'s validator re-runs
/// `PhaseManifest::validate` against an independently-derived expected
/// origin set, so this only ever succeeds for phases where that set is
/// chain-derivable (not Reshare's `Commitments` phase — see
/// `expected_leader_manifest_shape`).
async fn queue_leader_public_fault_report<D>(
    app_state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    attempt: AttemptKey,
    fault_kind: DkgLeaderPublicFaultKind,
    delivery_id: [u8; 16],
    delivery: network::SignedPayload,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let coordinator = DkgCoordinator::with_routes(app_state.clone(), routes);
    let binding = evidence_binding(&coordinator, attempt)
        .await?
        .ok_or_else(|| {
            DkgError::Unauthorized("Fresh DKG leader public fault is not reportable".to_string())
        })?;
    let canonical_leader = transport::canonical_leader(&binding.receiver_node_keys)
        .ok_or_else(|| {
            DkgError::InvalidState(
                "leader public-fault evidence has an empty committee".to_string(),
            )
        })?
        .to_string();
    let decoded: transport::DkgPublicMessage =
        transport::decode(&delivery.data, transport::MAX_PUBLIC_ORIGIN_EVIDENCE_BYTES)
            .map_err(DkgError::Deserialization)?;
    let (ceremony_id, attempt_id, phase) =
        leader_delivery_attempt_and_phase(&decoded).ok_or_else(|| {
            DkgError::InvalidInput("leader delivery is not a manifest or chunk".to_string())
        })?;
    if ceremony_id != attempt.ceremony_id || attempt_id != attempt.attempt_id {
        return Err(DkgError::Unauthorized(
            "leader public-fault evidence does not target the active attempt".to_string(),
        ));
    }
    // See `queue_leader_equivocation_report`'s matching comment: anchor to
    // when the leader actually broadcast this delivery, not
    // report-construction time.
    let signed_at = leader_delivery_signed_at(&decoded).ok_or_else(|| {
        DkgError::InvalidInput("leader delivery is not a manifest or chunk".to_string())
    })?;
    let accused_committee_scope = if binding.origin_protocol == "pss_reshare" {
        CommitteeScope::PendingNew
    } else {
        CommitteeScope::Current
    };
    let accused_info = read_node_info(&app_state, &canonical_leader).await?;
    let statement = DkgLeaderPublicFaultStatement {
        domain: DKG_LEADER_PUBLIC_FAULT_DOMAIN.to_string(),
        chain_id: binding.chain_id,
        ring_id: binding.ring_id.clone(),
        ring_pk: binding.ring_pk,
        ring_state_sha256: binding.ring_state_sha256,
        protocol_version: binding.protocol_version,
        request_id: binding.request_id,
        signed_at,
        responder_node_key: canonical_leader.clone(),
        origin_protocol: binding.origin_protocol,
        accused_committee_scope,
        signing_committee_scope: CommitteeScope::Current,
        attempt_id: attempt.attempt_id.0,
        phase: phase.as_metric_label().to_string(),
        fault_kind,
        delivery_id,
        delivery: EndpointSignedContribution {
            origin: delivery.origin,
            signature: delivery.signature,
            data: delivery.data,
        },
    };
    let observation = InvalidCryptoResponseObservation {
        ring_id: binding.ring_id,
        accused_node_key: canonical_leader,
        accused_peer_id: accused_info.peer_id,
        observed_at: statement.signed_at.saturating_sub(CHAIN_BLOCK_GRACE_SECS),
        inline_document: None,
        evidence: InvalidCryptoResponse::DkgLeaderPublicFault {
            statement: Box::new(statement),
        },
    };
    queue_report::<D, SignImpl>(
        app_state,
        routes,
        ReportObservation::InvalidCryptoResponse(Box::new(observation)),
    )
    .await
    .map_err(|error| DkgError::Generic(error.to_string()))?;
    Ok(())
}

/// Relays via the same mechanism as `dkg_leader_equivocation`/
/// `dkg_leader_batch_mismatch` (`relay_private_evidence`, non-blocking
/// spawn — see RPT-13) for a pure pending-new reshare receiver that alone
/// detects a Reshare-phase fault (Reshare's `Commitments` phase itself is
/// still excluded — see `expected_leader_manifest_shape` — but
/// `CommitmentAudit`/`ReshareParticipantSet` are covered).
pub async fn queue_or_relay_leader_public_fault<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    fault_kind: DkgLeaderPublicFaultKind,
    delivery_id: [u8; 16],
    delivery: network::SignedPayload,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    if local_node_is_current_route_member(coord, attempt).await? {
        queue_leader_public_fault_report(
            coord.app_state.clone(),
            coord.routes,
            attempt,
            fault_kind,
            delivery_id,
            delivery,
        )
        .await
    } else {
        let origin_protocol = evidence_binding(coord, attempt)
            .await?
            .ok_or_else(|| {
                DkgError::Unauthorized(
                    "Fresh DKG leader public fault is not reportable".to_string(),
                )
            })?
            .origin_protocol;
        if origin_protocol != "pss_reshare" {
            return Err(DkgError::Unauthorized(
                "local node is not in the report signing committee".to_string(),
            ));
        }
        let app_state = coord.app_state.clone();
        let routes = coord.routes;
        spawn_evidence_relay(
            attempt.session_id(),
            "dkg_leader_public_fault",
            async move {
                let coordinator = DkgCoordinator::with_routes(app_state, routes);
                crate::dkg::v0::network::relay_leader_public_fault_evidence(
                    &coordinator,
                    attempt,
                    fault_kind,
                    delivery_id,
                    delivery,
                )
                .await
            },
        );
        Ok(())
    }
}

pub async fn handle_leader_public_fault_evidence_relay<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    fault_kind: DkgLeaderPublicFaultKind,
    delivery_id: [u8; 16],
    delivery: network::SignedPayload,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    verify_relay_is_current_signer(coord, attempt).await?;
    let binding = evidence_binding(coord, attempt).await?.ok_or_else(|| {
        DkgError::Unauthorized("Fresh DKG leader public fault is not reportable".to_string())
    })?;
    if binding.origin_protocol != "pss_reshare" {
        return Err(DkgError::Unauthorized(
            "leader public-fault evidence relay is only valid for Reshare".to_string(),
        ));
    }
    queue_leader_public_fault_report(
        coord.app_state.clone(),
        coord.routes,
        attempt,
        fault_kind,
        delivery_id,
        delivery,
    )
    .await
}
