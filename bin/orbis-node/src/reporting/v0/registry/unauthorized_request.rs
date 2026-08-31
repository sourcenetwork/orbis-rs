use super::*;

pub(super) struct UnauthorizedRequestHandler;

#[async_trait]
impl ReportHandler for UnauthorizedRequestHandler {
    fn report_type(&self) -> &'static str {
        UNAUTHORIZED_REQUEST_REPORT_TYPE
    }

    fn in_flight_key(&self, observation: &ReportObservation) -> Result<InFlightReportKey> {
        let observation = Self::observation(observation)?;
        Ok(InFlightReportKey {
            report_type: self.report_type(),
            ring_id: observation.ring_id.clone(),
            subject_key: format!(
                "{}:{}",
                observation.accused_node_key, observation.payload.statement.request_id
            ),
        })
    }

    async fn prepare(
        &self,
        observation: ReportObservation,
        context: &ReportPreparationContext,
    ) -> Result<PreparedReport> {
        let ReportObservation::UnauthorizedRequest(observation) = observation else {
            return Err(ReportingError::InvalidReport(
                "unauthorized_request handler received the wrong observation type".to_string(),
            ));
        };

        // The relayer is always a current-committee member, so the current committee signs.
        let (ring, ring_config) =
            build_signing_ring_config(&observation.ring_id, CommitteeScope::Current, context)
                .await?;

        let envelope = self.build_envelope(
            &observation,
            &ring,
            &context.reporter_node_key,
            context.bulletin.chain_id(),
        );

        Ok(PreparedReport {
            signing_options: self.signing_options(&envelope),
            envelope,
            ring_config,
            inline_document: observation.inline_document,
        })
    }

    async fn validate(
        &self,
        envelope: &ReportEnvelope,
        context: &ReportValidationContext,
    ) -> Result<()> {
        let payload = UnauthorizedRequestPayload::from_canonical_bytes(&envelope.payload)?;
        let statement = &payload.statement;

        validate_relay_request_statement_shape(envelope, context, statement)?;

        let ring_post = context
            .bulletin
            .read(envelope.ring_id.clone(), BulletinKind::Ring)
            .await
            .map_err(|error| ReportingError::Bulletin(error.to_string()))?;
        let ring = RingPayload::try_from(ring_post)
            .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;

        let effective_version =
            validate_report_route_version_at_observed_at(envelope, &ring, context.routes.version)?;
        if statement.protocol_version != effective_version {
            return Err(ReportingError::Unauthorized(format!(
                "relay request protocol version {} does not match effective ring version {}",
                statement.protocol_version, effective_version
            )));
        }

        let signing_committee = validate_ring_and_membership_for_scopes(
            envelope,
            &ring,
            statement.accused_committee_scope,
            statement.signing_committee_scope,
            "unauthorized-request",
        )?;
        validate_node_routes(envelope, context, &ring).await?;
        validate_local_signer(
            envelope,
            context,
            &signing_committee,
            "unauthorized-request",
        )?;

        let accused_committee = committee_for_scope(&ring, statement.accused_committee_scope)?;
        let expected_from_node_id = determine_session_node_id(
            &envelope.accused_node_key,
            &accused_committee.peer_node_keys,
        )
        .ok_or_else(|| {
            ReportingError::Unauthorized(
                "relayer is not in the accused committee node-id map".to_string(),
            )
        })?;
        if statement.from_node_id != expected_from_node_id {
            return Err(ReportingError::Unauthorized(format!(
                "relay request from_node_id {} does not match relayer node_id {}",
                statement.from_node_id, expected_from_node_id
            )));
        }

        // The relayer must actually have signed the request it forwarded.
        verify_node_message(
            &envelope.accused_node_key,
            &statement.canonical_bytes(),
            &payload.relay_signature,
        )
        .map_err(|error| {
            ReportingError::Unauthorized(format!("invalid relay request signature: {}", error))
        })?;

        require_relayed_request_unauthorized(context, statement, &payload.checked_at_anchor).await
    }
}

impl UnauthorizedRequestHandler {
    pub(super) fn observation(
        observation: &ReportObservation,
    ) -> Result<&UnauthorizedRequestObservation> {
        match observation {
            ReportObservation::UnauthorizedRequest(observation) => Ok(observation),
            _ => Err(ReportingError::InvalidReport(
                "unauthorized_request handler received the wrong observation type".to_string(),
            )),
        }
    }

    pub(super) fn build_envelope(
        &self,
        observation: &UnauthorizedRequestObservation,
        ring: &RingPayload,
        reporter_node_key: &str,
        chain_id: String,
    ) -> ReportEnvelope {
        ReportEnvelope {
            domain: REPORT_DOMAIN.to_string(),
            report_type: self.report_type().to_string(),
            chain_id,
            ring_id: observation.ring_id.clone(),
            ring_pk: ring.ring_pk.clone(),
            ring_state_sha256: ring_state_sha256(ring),
            reporter_node_key: reporter_node_key.to_string(),
            accused_node_key: observation.accused_node_key.clone(),
            accused_peer_id: observation.accused_peer_id.clone(),
            observed_at: observation.observed_at,
            expires_at: observation.observed_at.saturating_add(REPORT_TTL_SECS),
            payload: observation.payload.canonical_bytes(),
            session_id: observation.payload.statement.request_id.clone(),
        }
    }

    pub(super) fn signing_options(&self, envelope: &ReportEnvelope) -> SigningOptions {
        let mut excluded_node_keys = HashSet::new();
        excluded_node_keys.insert(envelope.accused_node_key.clone());
        SigningOptions { excluded_node_keys }
    }
}

pub(super) fn validate_relay_request_statement_shape(
    envelope: &ReportEnvelope,
    context: &ReportValidationContext,
    statement: &RelayRequestStatement,
) -> Result<()> {
    validate_invalid_crypto_statement_prologue(
        envelope,
        context,
        InvalidCryptoStatementPrologue {
            label: "relay request".to_string(),
            domain: statement.domain.clone(),
            expected_domain: RELAY_REQUEST_DOMAIN.to_string(),
            chain_id: statement.chain_id.clone(),
            ring_id: statement.ring_id.clone(),
            ring_pk: statement.ring_pk.clone(),
            ring_state_sha256: statement.ring_state_sha256.clone(),
            request_id: statement.request_id.clone(),
            signed_at: statement.signed_at,
            responder_node_key: statement.relayer_node_key.clone(),
            check_anchor: true,
        },
    )?;
    if statement.origin_protocol != "pre" && statement.origin_protocol != "sign" {
        return Err(ReportingError::InvalidReport(format!(
            "unsupported relay request origin protocol {}",
            statement.origin_protocol
        )));
    }
    if statement.accused_committee_scope != CommitteeScope::Current
        || statement.signing_committee_scope != CommitteeScope::Current
    {
        return Err(ReportingError::Unauthorized(
            "relay request reports must use current accused and signing scopes".to_string(),
        ));
    }
    if statement.from_node_id == 0 {
        return Err(ReportingError::InvalidReport(
            "relay request from_node_id must be non-zero".to_string(),
        ));
    }
    if statement.actor_id.trim().is_empty() {
        return Err(ReportingError::InvalidReport(
            "relay request actor_id cannot be empty".to_string(),
        ));
    }
    if statement.object_id.trim().is_empty() {
        return Err(ReportingError::InvalidReport(
            "relay request object_id cannot be empty".to_string(),
        ));
    }
    if statement.valid_window_start.is_some() != statement.valid_window_end.is_some() {
        return Err(ReportingError::InvalidReport(
            "relay request valid_window bounds must both be present or both absent".to_string(),
        ));
    }
    // The relayer must have forwarded promptly after the caller signed. Both values are signed, so
    // this drift check is reproducible by every co-signer regardless of report propagation delay.
    if statement.signed_at.abs_diff(statement.user_signed_at) > RELAY_CHECK_MAX_DRIFT_SECS {
        return Err(ReportingError::InvalidReport(format!(
            "relay request signed_at {} drifts from caller signed_at {} by more than {}s",
            statement.signed_at, statement.user_signed_at, RELAY_CHECK_MAX_DRIFT_SECS
        )));
    }
    Ok(())
}

/// The refutation for an `unauthorized_request` report: re-run the ACP check for the relayed request
/// as of the acceptor's captured `checked_at_anchor` (an opaque `Authz` point-in-history token). If
/// the actor **is** authorized at that anchor the relayer forwarded a legitimate request → reject
/// the report; only an unauthorized verdict confirms it. `anchor_time(anchor) ≈ signed_at` binds the
/// anchor to the relay moment, so it reflects the policy state when the relayer checked — protecting
/// an honest relayer from a revocation that lands right after it forwards, with no assumption about
/// what the anchor encodes.
pub(super) async fn require_relayed_request_unauthorized(
    context: &ReportValidationContext,
    statement: &RelayRequestStatement,
    checked_at_anchor: &str,
) -> Result<()> {
    let anchor_time = context
        .authz
        .anchor_time(checked_at_anchor)
        .await
        .map_err(|error| ReportingError::Bulletin(error.to_string()))?;
    if anchor_time.abs_diff(statement.signed_at) > RELAY_CHECK_MAX_DRIFT_SECS {
        return Err(ReportingError::InvalidReport(format!(
            "relay request anchor time {} drifts from signed_at {} by more than {}s",
            anchor_time, statement.signed_at, RELAY_CHECK_MAX_DRIFT_SECS
        )));
    }

    let valid_window = match (statement.valid_window_start, statement.valid_window_end) {
        (Some(start), Some(end)) => Some(ValidWindow { start, end }),
        (None, None) => None,
        _ => {
            return Err(ReportingError::InvalidReport(
                "relay request valid_window bounds must both be present or both absent".to_string(),
            ))
        }
    };

    let access_request = match statement.origin_protocol.as_str() {
        "pre" => {
            let (policy_id, resource, permission, tier, timestamp) = if statement.document_inline {
                let evidence = require_inline_document_evidence(
                    context,
                    &statement.ring_id,
                    &statement.object_id,
                    statement.timestamp,
                )?;
                (
                    evidence.policy_id.clone(),
                    evidence.resource.clone(),
                    evidence.permission.clone(),
                    evidence.tier.clone(),
                    statement.timestamp,
                )
            } else {
                reject_unexpected_inline_document_evidence(context)?;
                let document_post = context
                    .bulletin
                    .read(statement.object_id.clone(), BulletinKind::Document)
                    .await
                    .map_err(|error| ReportingError::Bulletin(error.to_string()))?;
                let document = DocumentPayload::try_from(document_post)
                    .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;
                (
                    document.policy_id,
                    document.resource,
                    document.permission,
                    document.tier,
                    document.timestamp,
                )
            };
            AccessCheckRequest::new(
                policy_id,
                resource,
                statement.object_id.clone(),
                permission,
                tier,
                timestamp,
                valid_window,
            )
        }
        "sign" => {
            let derivation_post = context
                .bulletin
                .read(statement.object_id.clone(), BulletinKind::KeyDerivation)
                .await
                .map_err(|error| ReportingError::Bulletin(error.to_string()))?;
            let derivation: KeyDerivation = serde_json::from_slice(&derivation_post.payload)
                .map_err(|error| {
                    ReportingError::InvalidReport(format!(
                        "failed to parse key derivation: {}",
                        error
                    ))
                })?;
            AccessCheckRequest::new(
                derivation.policy_id,
                derivation.resource,
                statement.object_id.clone(),
                derivation.permission,
                None,
                statement.timestamp,
                valid_window,
            )
        }
        other => {
            return Err(ReportingError::InvalidReport(format!(
                "unsupported relay request origin protocol {}",
                other
            )))
        }
    };

    let request_bytes = access_request
        .to_bytes()
        .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;
    let authorized = context
        .authz
        .check_at(request_bytes, &statement.actor_id, checked_at_anchor)
        .await
        .map_err(|error| ReportingError::Bulletin(error.to_string()))?;
    if authorized {
        return Err(ReportingError::Unauthorized(
            "relayed request was authorized at the captured anchor".to_string(),
        ));
    }
    Ok(())
}
