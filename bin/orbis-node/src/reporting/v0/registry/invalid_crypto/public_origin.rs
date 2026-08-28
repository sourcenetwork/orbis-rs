use super::*;

impl InvalidCryptoResponseHandler {
    pub(super) async fn validate_dkg_public_origin_fault(
        &self,
        envelope: &ReportEnvelope,
        context: &ReportValidationContext,
        ring: &RingPayload,
        statement: &DkgPublicOriginFaultStatement,
    ) -> Result<()> {
        validate_invalid_crypto_statement_prologue(
            envelope,
            context,
            InvalidCryptoStatementPrologue {
                label: "DKG public-origin fault".to_string(),
                domain: statement.domain.clone(),
                expected_domain: DKG_PUBLIC_ORIGIN_FAULT_DOMAIN.to_string(),
                chain_id: statement.chain_id.clone(),
                ring_id: statement.ring_id.clone(),
                ring_pk: statement.ring_pk.clone(),
                ring_state_sha256: statement.ring_state_sha256.clone(),
                request_id: statement.request_id.clone(),
                signed_at: statement.signed_at,
                responder_node_key: statement.responder_node_key.clone(),
                check_anchor: true,
            },
        )?;
        if !is_valid_invalid_crypto_dkg_origin(&statement.origin_protocol) {
            return Err(ReportingError::InvalidReport(format!(
                "unsupported DKG public-origin protocol {}",
                statement.origin_protocol
            )));
        }
        if statement.signing_committee_scope != CommitteeScope::Current {
            return Err(ReportingError::Unauthorized(
                "DKG public-origin reports must use the current signing committee".to_string(),
            ));
        }
        if statement.origin_protocol == "pss_refresh"
            && statement.accused_committee_scope != CommitteeScope::Current
        {
            return Err(ReportingError::Unauthorized(
                "Refresh public-origin reports require a current-committee accused".to_string(),
            ));
        }
        let effective_version =
            validate_report_route_version_at_observed_at(envelope, ring, context.routes.version)?;
        if statement.protocol_version != effective_version {
            return Err(ReportingError::Unauthorized(format!(
                "DKG public-origin protocol version {} does not match effective ring version {}",
                statement.protocol_version, effective_version
            )));
        }

        let signing_committee = validate_ring_and_membership_for_scopes(
            envelope,
            ring,
            statement.accused_committee_scope,
            CommitteeScope::Current,
            "DKG public-origin fault",
        )?;
        validate_node_routes(envelope, context, ring).await?;
        validate_local_signer(
            envelope,
            context,
            &signing_committee,
            "DKG public-origin fault",
        )?;

        let contribution_a = verify_public_origin_endpoint_envelope(
            envelope,
            context,
            ring,
            statement,
            &statement.contribution_a,
        )
        .await?;
        match statement.fault_kind {
            DkgPublicOriginFaultKind::InvalidPayload => {
                if statement.contribution_b.is_some() {
                    return Err(ReportingError::InvalidReport(
                        "invalid-payload public-origin evidence must contain one contribution"
                            .to_string(),
                    ));
                }
                if contribution_a.signed_at != statement.signed_at {
                    return Err(ReportingError::Unauthorized(
                        "invalid-payload report timestamp does not match its contribution"
                            .to_string(),
                    ));
                }
                if !public_origin_payload_proves_failure(
                    envelope,
                    context,
                    ring,
                    statement,
                    &contribution_a,
                )
                .await?
                {
                    return Err(ReportingError::Unauthorized(
                        "public contribution does not prove the claimed payload fault".to_string(),
                    ));
                }
            }
            DkgPublicOriginFaultKind::OriginEquivocation => {
                let contribution_b_envelope =
                    statement.contribution_b.as_ref().ok_or_else(|| {
                        ReportingError::InvalidReport(
                            "origin-equivocation evidence requires two contributions".to_string(),
                        )
                    })?;
                let contribution_b = verify_public_origin_endpoint_envelope(
                    envelope,
                    context,
                    ring,
                    statement,
                    contribution_b_envelope,
                )
                .await?;
                if contribution_a.signed_at.max(contribution_b.signed_at) != statement.signed_at {
                    return Err(ReportingError::Unauthorized(
                        "origin-equivocation report timestamp is not the later contribution time"
                            .to_string(),
                    ));
                }
                if contribution_a.payload.phase() == DkgPublicPhase::Commitments
                    || !public_origin_role_allowed(
                        &statement.origin_protocol,
                        contribution_a.origin,
                        contribution_a.payload.phase(),
                    )
                    || contribution_a.ceremony_id != contribution_b.ceremony_id
                    || contribution_a.attempt_id != contribution_b.attempt_id
                    || contribution_a.origin != contribution_b.origin
                    || contribution_a.payload.phase() != contribution_b.payload.phase()
                    || contribution_a.payload == contribution_b.payload
                {
                    return Err(ReportingError::Unauthorized(
                        "public contributions do not prove non-Commitment origin equivocation"
                            .to_string(),
                    ));
                }
            }
        }
        Ok(())
    }
}

pub(crate) async fn verify_public_origin_endpoint_envelope(
    envelope: &ReportEnvelope,
    context: &ReportValidationContext,
    ring: &RingPayload,
    statement: &DkgPublicOriginFaultStatement,
    evidence: &EndpointSignedContribution,
) -> Result<DkgPublicContribution> {
    if evidence.origin.len() != 32 || evidence.signature.len() != 64 || evidence.data.is_empty() {
        return Err(ReportingError::InvalidReport(
            "DKG public-origin endpoint envelope has invalid field lengths".to_string(),
        ));
    }
    let pubsub = context.network.pubsub().ok_or_else(|| {
        ReportingError::InvalidReport(
            "network backend does not support endpoint-authenticated public evidence".to_string(),
        )
    })?;
    let signed = network::SignedPayload {
        origin: evidence.origin.clone(),
        signature: evidence.signature.clone(),
        data: evidence.data.clone(),
    };
    let authenticated = pubsub
        .verify(PUBLIC_CONTRIBUTION_SIGNING_DOMAIN, &signed)
        .await
        .map_err(|error| {
            ReportingError::Unauthorized(format!(
                "invalid DKG public-origin endpoint signature: {error}"
            ))
        })?;
    let accused_endpoint = extract_node_part(&envelope.accused_peer_id).to_lowercase();
    if hex::encode(authenticated.origin.as_bytes()) != accused_endpoint {
        return Err(ReportingError::Unauthorized(
            "public contribution endpoint does not match the accused peer ID".to_string(),
        ));
    }
    let contribution: DkgPublicContribution = transport::decode(
        &authenticated.data,
        transport::MAX_PUBLIC_ORIGIN_EVIDENCE_BYTES,
    )
    .map_err(ReportingError::InvalidReport)?;
    contribution
        .validate_message_id()
        .map_err(ReportingError::Unauthorized)?;
    let ceremony_id = statement.request_id.parse::<u128>().map_err(|_| {
        ReportingError::InvalidReport(
            "DKG public-origin request_id is not a ceremony ID".to_string(),
        )
    })?;
    let expected_scope = match statement.accused_committee_scope {
        CommitteeScope::Current => transport::CommitteeScope::Current,
        CommitteeScope::PendingNew => transport::CommitteeScope::Next,
    };
    let accused_committee = committee_for_scope(ring, statement.accused_committee_scope)?;
    let expected_node_id = determine_session_node_id(
        &envelope.accused_node_key,
        &accused_committee.peer_node_keys,
    )
    .ok_or_else(|| {
        ReportingError::Unauthorized(
            "accused node is not in the public-origin node-id map".to_string(),
        )
    })?;
    if !public_origin_protocol_allows_phase(
        &statement.origin_protocol,
        contribution.payload.phase(),
    ) {
        return Err(ReportingError::Unauthorized(
            "public contribution phase is not valid for the claimed PSS protocol".to_string(),
        ));
    }
    if contribution.ceremony_id.0 != ceremony_id
        || contribution.attempt_id.0 != statement.attempt_id
        || contribution.ring_id != statement.ring_id
        || contribution.origin.scope != expected_scope
        || contribution.origin.node_id != expected_node_id
        || contribution.payload.phase().as_metric_label() != statement.phase
    {
        return Err(ReportingError::Unauthorized(
            "public contribution does not match the normalized fault statement".to_string(),
        ));
    }
    Ok(contribution)
}

pub(crate) async fn public_origin_payload_proves_failure(
    envelope: &ReportEnvelope,
    context: &ReportValidationContext,
    ring: &RingPayload,
    statement: &DkgPublicOriginFaultStatement,
    contribution: &DkgPublicContribution,
) -> Result<bool> {
    if !public_origin_role_allowed(
        &statement.origin_protocol,
        contribution.origin,
        contribution.payload.phase(),
    ) {
        return Ok(true);
    }
    match &contribution.payload {
        DkgPublicPayload::Commitment {
            commitment,
            report_evidence,
        } => {
            let expected_coefficients = match statement.origin_protocol.as_str() {
                "pss_refresh" => ring.threshold as usize,
                "pss_reshare" => {
                    ring.new_threshold
                        .map(|value| value as usize)
                        .ok_or_else(|| {
                            ReportingError::Unauthorized(
                                "Reshare public-origin evidence requires a pending threshold"
                                    .to_string(),
                            )
                        })?
                }
                _ => return Ok(false),
            };
            let decoded = deserialize_wire_commitment(commitment);
            if commitment.is_empty()
                || !commitment.len().is_multiple_of(GROUP_POINT_SIZE)
                || commitment.len() / GROUP_POINT_SIZE != expected_coefficients
                || decoded.is_err()
            {
                return Ok(true);
            }

            let Some(report_evidence) = report_evidence else {
                return Ok(true);
            };
            let expected_node_id = contribution.origin.node_id;
            let nested_is_valid = validate_equivocation_commitment_shape(
                envelope,
                context,
                &report_evidence.statement,
                &report_evidence.signature,
                false,
            )
            .is_ok()
                && report_evidence.statement.request_id == statement.request_id
                && report_evidence.statement.signed_at <= contribution.signed_at
                && report_evidence.statement.from_node_id == expected_node_id
                && report_evidence.statement.commitment == *commitment
                && report_evidence.statement.origin_protocol == statement.origin_protocol
                && report_evidence.statement.accused_committee_scope
                    == statement.accused_committee_scope
                && report_evidence.statement.signing_committee_scope == CommitteeScope::Current
                && verify_node_message(
                    &envelope.accused_node_key,
                    &report_evidence.statement.canonical_bytes(),
                    &report_evidence.signature,
                )
                .is_ok();
            if !nested_is_valid {
                return Ok(true);
            }

            // A validly signed non-identity Refresh commitment belongs to the
            // stronger RPT-03 evidence kind and must not earn a second demerit
            // through the generic public-origin path.
            if statement.origin_protocol == "pss_refresh"
                && decoded.is_ok_and(|commitment| !commitment.constant_term_is_identity())
            {
                return Ok(false);
            }
            Ok(false)
        }
        DkgPublicPayload::ReshareParticipantSet { selected_dealers } => {
            if statement.origin_protocol != "pss_reshare"
                || statement.accused_committee_scope != CommitteeScope::PendingNew
                || contribution.origin != ParticipantRef::next(1)
            {
                return Ok(false);
            }
            let mut canonical = selected_dealers.clone();
            canonical.sort();
            canonical.dedup();
            Ok(selected_dealers.len() != ring.threshold as usize
                || canonical.len() != selected_dealers.len()
                || selected_dealers.iter().any(|dealer| {
                    dealer.scope != transport::CommitteeScope::Current
                        || dealer.node_id == 0
                        || dealer.node_id as usize > ring.peer_node_keys.len()
                }))
        }
        DkgPublicPayload::RefreshHealthCheckResult {
            statement: health,
            signature,
        } => {
            if statement.origin_protocol != "pss_refresh"
                || health.domain != REFRESH_HEALTH_CHECK_DOMAIN
                || health.session_id != contribution.ceremony_id.0
                || health.ring_pk != ring.ring_pk
                || health.threshold != ring.threshold
                || health.total_participants as usize != ring.peer_node_keys.len()
                || health.peer_node_keys_sha256
                    != refresh_health_check_peer_node_keys_sha256(&ring.peer_node_keys)
            {
                return Ok(true);
            }
            let Some(signature) = signature else {
                return Ok(false);
            };
            let message = match refresh_health_check_message(health) {
                Ok(message) => message,
                Err(_) => return Ok(true),
            };
            let signature_bytes = match hex::decode(signature) {
                Ok(bytes) => bytes,
                Err(_) => return Ok(true),
            };
            let signature = match SignaturePoint::from_bytes(&signature_bytes) {
                Ok(signature) => signature,
                Err(_) => return Ok(true),
            };
            let ring_pk_bytes = hex::decode(&ring.ring_pk)
                .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;
            let ring_pk = GroupAffine::from_bytes(&ring_pk_bytes)
                .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;
            Ok(SignImpl::new()
                .verify(&ring_pk, &message, &signature)
                .is_err())
        }
        DkgPublicPayload::CommitmentHash { .. } | DkgPublicPayload::CommitmentAudit { .. } => {
            Ok(false)
        }
    }
}

pub(crate) fn public_origin_role_allowed(
    origin_protocol: &str,
    origin: ParticipantRef,
    phase: DkgPublicPhase,
) -> bool {
    match (origin_protocol, phase) {
        ("pss_refresh", DkgPublicPhase::Commitments | DkgPublicPhase::CommitmentAudit) => {
            origin.scope == transport::CommitteeScope::Current
        }
        ("pss_refresh", DkgPublicPhase::RefreshHealthCheck) => origin == ParticipantRef::current(1),
        ("pss_reshare", DkgPublicPhase::Commitments) => {
            origin.scope == transport::CommitteeScope::Current
        }
        ("pss_reshare", DkgPublicPhase::CommitmentAudit) => {
            origin.scope == transport::CommitteeScope::Next
        }
        ("pss_reshare", DkgPublicPhase::ReshareParticipantSet) => origin == ParticipantRef::next(1),
        _ => false,
    }
}
