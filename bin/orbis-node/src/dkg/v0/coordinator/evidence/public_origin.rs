use super::*;

pub async fn queue_or_relay_public_origin_fault<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    fault_kind: DkgPublicOriginFaultKind,
    contribution_a: network::SignedPayload,
    contribution_b: Option<network::SignedPayload>,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    if local_node_is_current_route_member(coord, attempt).await? {
        queue_public_origin_fault_report(
            coord.app_state.clone(),
            coord.routes,
            attempt,
            fault_kind,
            contribution_a,
            contribution_b,
        )
        .await
    } else {
        let origin_protocol = evidence_binding(coord, attempt)
            .await?
            .ok_or_else(|| {
                DkgError::Unauthorized(
                    "Fresh DKG public-origin faults are not reportable".to_string(),
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
            "dkg_public_origin_fault",
            async move {
                let coordinator = DkgCoordinator::with_routes(app_state, routes);
                relay_public_origin_fault_evidence(
                    &coordinator,
                    attempt,
                    fault_kind,
                    contribution_a,
                    contribution_b,
                )
                .await
            },
        );
        Ok(())
    }
}

pub async fn handle_public_origin_fault_evidence_relay<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    fault_kind: DkgPublicOriginFaultKind,
    contribution_a: network::SignedPayload,
    contribution_b: Option<network::SignedPayload>,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    verify_relay_is_current_signer(coord, attempt).await?;
    let binding = evidence_binding(coord, attempt).await?.ok_or_else(|| {
        DkgError::Unauthorized("Fresh DKG public-origin faults are not reportable".to_string())
    })?;
    if binding.origin_protocol != "pss_reshare" {
        return Err(DkgError::Unauthorized(
            "public-origin fault relay is only valid for Reshare".to_string(),
        ));
    }
    queue_public_origin_fault_report(
        coord.app_state.clone(),
        coord.routes,
        attempt,
        fault_kind,
        contribution_a,
        contribution_b,
    )
    .await
}

async fn queue_public_origin_fault_report<D>(
    app_state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    attempt: AttemptKey,
    fault_kind: DkgPublicOriginFaultKind,
    contribution_a: network::SignedPayload,
    contribution_b: Option<network::SignedPayload>,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let coordinator = DkgCoordinator::with_routes(app_state.clone(), routes);
    let binding = evidence_binding(&coordinator, attempt)
        .await?
        .ok_or_else(|| {
            DkgError::Unauthorized("Fresh DKG public-origin faults are not reportable".to_string())
        })?;
    let decoded: DkgPublicContribution = transport::decode(
        &contribution_a.data,
        transport::MAX_PUBLIC_ORIGIN_EVIDENCE_BYTES,
    )
    .map_err(DkgError::Deserialization)?;
    if decoded.ceremony_id != attempt.ceremony_id || decoded.attempt_id != attempt.attempt_id {
        return Err(DkgError::Unauthorized(
            "public-origin evidence does not target the active attempt".to_string(),
        ));
    }
    let evidence_signed_at = match fault_kind {
        DkgPublicOriginFaultKind::InvalidPayload => decoded.signed_at,
        DkgPublicOriginFaultKind::OriginEquivocation => {
            let contribution_b = contribution_b.as_ref().ok_or_else(|| {
                DkgError::InvalidInput(
                    "public-origin equivocation evidence requires two contributions".to_string(),
                )
            })?;
            let decoded_b: DkgPublicContribution = transport::decode(
                &contribution_b.data,
                transport::MAX_PUBLIC_ORIGIN_EVIDENCE_BYTES,
            )
            .map_err(DkgError::Deserialization)?;
            decoded.signed_at.max(decoded_b.signed_at)
        }
    };
    let (accused_committee_scope, node_keys) = match decoded.origin.scope {
        transport::CommitteeScope::Current => (CommitteeScope::Current, &binding.current_node_keys),
        transport::CommitteeScope::Next => {
            (CommitteeScope::PendingNew, &binding.receiver_node_keys)
        }
    };
    let accused_node_key = node_key_for_canonical_node_id(decoded.origin.node_id, node_keys)
        .ok_or_else(|| {
            DkgError::Unauthorized(
                "public-origin evidence participant is not in the bound committee".to_string(),
            )
        })?;
    let accused_info = read_node_info(&app_state, &accused_node_key).await?;
    let statement = DkgPublicOriginFaultStatement {
        domain: DKG_PUBLIC_ORIGIN_FAULT_DOMAIN.to_string(),
        chain_id: binding.chain_id,
        ring_id: binding.ring_id.clone(),
        ring_pk: binding.ring_pk,
        ring_state_sha256: binding.ring_state_sha256,
        protocol_version: binding.protocol_version,
        request_id: binding.request_id,
        signed_at: evidence_signed_at,
        responder_node_key: accused_node_key.clone(),
        origin_protocol: binding.origin_protocol,
        accused_committee_scope,
        signing_committee_scope: CommitteeScope::Current,
        attempt_id: attempt.attempt_id.0,
        phase: decoded.payload.phase().as_metric_label().to_string(),
        fault_kind,
        contribution_a: EndpointSignedContribution {
            origin: contribution_a.origin,
            signature: contribution_a.signature,
            data: contribution_a.data,
        },
        contribution_b: contribution_b.map(|contribution| EndpointSignedContribution {
            origin: contribution.origin,
            signature: contribution.signature,
            data: contribution.data,
        }),
    };
    let observation = InvalidCryptoResponseObservation {
        ring_id: binding.ring_id,
        accused_node_key,
        accused_peer_id: accused_info.peer_id,
        observed_at: statement.signed_at.saturating_sub(CHAIN_BLOCK_GRACE_SECS),
        inline_document: None,
        evidence: InvalidCryptoResponse::DkgPublicOriginFault {
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
