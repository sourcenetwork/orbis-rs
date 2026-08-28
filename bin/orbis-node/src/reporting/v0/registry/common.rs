use super::*;

#[derive(Debug, Clone)]
pub(super) struct CommitteeView {
    pub(super) peer_node_keys: Vec<String>,
    pub(super) threshold: u32,
}

pub(super) async fn build_signing_ring_config(
    ring_id: &str,
    signing_committee_scope: CommitteeScope,
    context: &ReportPreparationContext,
) -> Result<(RingPayload, RingConfig)> {
    let ring_post = context
        .bulletin
        .read(ring_id.to_string(), BulletinKind::Ring)
        .await
        .map_err(|error| ReportingError::Bulletin(error.to_string()))?;
    let ring = RingPayload::try_from(ring_post)
        .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;

    let signing_committee = committee_for_scope(&ring, signing_committee_scope)?;
    let node_routes = resolve_node_routes(&context.bulletin, &signing_committee.peer_node_keys)
        .await
        .map_err(ReportingError::InvalidReport)?;
    let peer_ids = peer_ids_from_routes(&node_routes);
    let ring_pk_bytes = hex::decode(&ring.ring_pk)
        .map_err(|error| ReportingError::Serialization(error.to_string()))?;
    let poly_state = RingPolyState::load_from_ring_pk_hex(&context.local_storage, &ring.ring_pk)
        .map_err(ReportingError::InvalidReport)?;
    let ring_config = RingConfig {
        ring_id: ring_id.to_string(),
        ring_pk_bytes,
        peer_ids,
        peer_node_keys: signing_committee.peer_node_keys,
        threshold: signing_committee.threshold as usize,
        total_participants: node_routes.len(),
        public_polynomial_hex: poly_state.public_polynomial,
    };

    Ok((ring, ring_config))
}

pub(super) fn validate_ring_and_membership(
    envelope: &ReportEnvelope,
    payload: &NodeOffline,
    ring: &RingPayload,
) -> Result<CommitteeView> {
    validate_ring_and_membership_for_scopes(
        envelope,
        ring,
        payload.accused_committee_scope,
        payload.signing_committee_scope,
        "offline",
    )
}

pub(super) fn report_effective_version_at_observed_at(
    envelope: &ReportEnvelope,
    ring: &RingPayload,
) -> Result<u64> {
    ring.upgrade_info
        .effective_version(envelope.observed_at)
        .map_err(|error| ReportingError::InvalidReport(error.to_string()))
}

pub(super) fn validate_report_route_version_at_observed_at(
    envelope: &ReportEnvelope,
    ring: &RingPayload,
    route_version: u64,
) -> Result<u64> {
    let effective_version = report_effective_version_at_observed_at(envelope, ring)?;
    if effective_version != route_version {
        return Err(ReportingError::Unauthorized(format!(
            "report protocol version {} is not effective for ring {}",
            route_version, envelope.ring_id
        )));
    }
    Ok(effective_version)
}

pub(super) fn validate_ring_and_membership_for_scopes(
    envelope: &ReportEnvelope,
    ring: &RingPayload,
    accused_committee_scope: CommitteeScope,
    signing_committee_scope: CommitteeScope,
    report_label: &str,
) -> Result<CommitteeView> {
    if ring.ring_pk.is_empty() {
        return Err(ReportingError::Unauthorized(format!(
            "{report_label} reports require a finalized ring"
        )));
    }
    if ring.ring_pk != envelope.ring_pk {
        return Err(ReportingError::Unauthorized(
            "report ring public key is stale".to_string(),
        ));
    }
    if ring_state_sha256(ring) != envelope.ring_state_sha256 {
        return Err(ReportingError::Unauthorized(
            "report ring-state digest is stale".to_string(),
        ));
    }
    let accused_committee = committee_for_scope(ring, accused_committee_scope)?;
    let signing_committee = committee_for_scope(ring, signing_committee_scope)?;
    if signing_committee.threshold < 2 {
        return Err(ReportingError::Unauthorized(format!(
            "{report_label} reporting requires ring threshold >= 2"
        )));
    }
    if signing_committee.threshold as usize > signing_committee.peer_node_keys.len() {
        return Err(ReportingError::Unauthorized(format!(
            "{report_label} reporting threshold exceeds signing committee size"
        )));
    }
    if signing_committee
        .peer_node_keys
        .iter()
        .any(|member| member == &envelope.accused_node_key)
        && signing_committee.threshold as usize
            > signing_committee.peer_node_keys.len().saturating_sub(1)
    {
        return Err(ReportingError::Unauthorized(
            "ring threshold cannot be met while excluding the accused node".to_string(),
        ));
    }
    if !signing_committee
        .peer_node_keys
        .iter()
        .any(|member| member == &envelope.reporter_node_key)
    {
        return Err(ReportingError::Unauthorized(format!(
            "reporter node {} is not in the signing committee",
            envelope.reporter_node_key
        )));
    }
    if !accused_committee
        .peer_node_keys
        .iter()
        .any(|member| member == &envelope.accused_node_key)
    {
        return Err(ReportingError::Unauthorized(format!(
            "accused node {} is not in the accused committee",
            envelope.accused_node_key
        )));
    }
    Ok(signing_committee)
}

pub(super) fn committee_for_scope(
    ring: &RingPayload,
    scope: CommitteeScope,
) -> Result<CommitteeView> {
    match scope {
        CommitteeScope::Current => Ok(CommitteeView {
            peer_node_keys: ring.peer_node_keys.clone(),
            threshold: ring.threshold,
        }),
        CommitteeScope::PendingNew => {
            if ring.new_peer_node_keys.is_none() && ring.new_threshold.is_none() {
                return Err(ReportingError::Unauthorized(
                    "pending-new committee scope requires a pending reshare".to_string(),
                ));
            }
            Ok(CommitteeView {
                peer_node_keys: ring
                    .new_peer_node_keys
                    .clone()
                    .unwrap_or_else(|| ring.peer_node_keys.clone()),
                threshold: ring.new_threshold.unwrap_or(ring.threshold),
            })
        }
    }
}

pub(super) async fn validate_node_routes(
    envelope: &ReportEnvelope,
    context: &ReportValidationContext,
    _ring: &RingPayload,
) -> Result<()> {
    let accused_info = read_node_info(&context.bulletin, &envelope.accused_node_key).await?;
    if accused_info.peer_id != envelope.accused_peer_id {
        return Err(ReportingError::Unauthorized(
            "accused peer ID no longer matches NodeInfo".to_string(),
        ));
    }

    let reporter_info = read_node_info(&context.bulletin, &envelope.reporter_node_key).await?;
    let reporter_peer_hex = context
        .requester_peer_id
        .as_ref()
        .map(|requester| hex::encode(requester.as_bytes()))
        .unwrap_or_else(|| hex::encode(context.network.local_peer_id().as_bytes()));
    if extract_node_part(&reporter_info.peer_id) != reporter_peer_hex {
        return Err(ReportingError::Unauthorized(
            "report coordinator peer does not match reporter NodeInfo".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn validate_local_signer(
    envelope: &ReportEnvelope,
    context: &ReportValidationContext,
    signing_committee: &CommitteeView,
    report_label: &str,
) -> Result<()> {
    if context.local_node_key == envelope.accused_node_key {
        return Err(ReportingError::Unauthorized(format!(
            "the accused node cannot sign its own {report_label} report"
        )));
    }
    if !signing_committee
        .peer_node_keys
        .iter()
        .any(|node_key| node_key == &context.local_node_key)
    {
        return Err(ReportingError::Unauthorized(format!(
            "local signer is not in the {report_label} report ring"
        )));
    }
    Ok(())
}

pub(super) struct InvalidCryptoStatementPrologue {
    pub(super) label: String,
    pub(super) domain: String,
    pub(super) expected_domain: String,
    pub(super) chain_id: String,
    pub(super) ring_id: String,
    pub(super) ring_pk: String,
    pub(super) ring_state_sha256: String,
    pub(super) request_id: String,
    pub(super) signed_at: u64,
    pub(super) responder_node_key: String,
    /// Whether `signed_at` must anchor the envelope's `observed_at`. True for the statement
    /// whose timestamp anchors the report; false for a second statement (e.g. the other
    /// commitment in an equivocation report) that only needs ring/session binding.
    pub(super) check_anchor: bool,
}

pub(super) fn validate_invalid_crypto_statement_prologue(
    envelope: &ReportEnvelope,
    context: &ReportValidationContext,
    statement: InvalidCryptoStatementPrologue,
) -> Result<()> {
    let label = statement.label.as_str();
    if statement.domain != statement.expected_domain {
        return Err(ReportingError::InvalidReport(format!(
            "unexpected {label} domain {}",
            statement.domain
        )));
    }
    if statement.chain_id != envelope.chain_id || envelope.chain_id != context.bulletin.chain_id() {
        return Err(ReportingError::Unauthorized(format!(
            "{label} chain ID does not match report chain ID"
        )));
    }
    if statement.ring_id != envelope.ring_id
        || statement.ring_pk != envelope.ring_pk
        || statement.ring_state_sha256 != envelope.ring_state_sha256
    {
        return Err(ReportingError::Unauthorized(format!(
            "{label} ring binding does not match report envelope"
        )));
    }
    if statement.request_id != envelope.session_id {
        return Err(ReportingError::Unauthorized(format!(
            "{label} request_id does not match report session_id"
        )));
    }
    if statement.check_anchor {
        validate_evidence_anchor(statement.signed_at, envelope.observed_at)?;
    }
    if statement.responder_node_key != envelope.accused_node_key {
        return Err(ReportingError::Unauthorized(format!(
            "{label} responder does not match accused node"
        )));
    }
    Ok(())
}

/// Pin the envelope to the evidence: `observed_at == signed_at - grace`.
/// The envelope's fixed `observed_at + REPORT_TTL_SECS` expiry then doubles as
/// the evidence expiry, so the shared shape checks (`observed_at <= now`,
/// `now <= expires_at`) bound how long one signed bad response stays
/// reportable — without this, it could be re-wrapped in fresh envelopes and
/// re-reported indefinitely once the chain prunes its dedupe records.
pub(super) fn validate_evidence_anchor(signed_at: u64, observed_at: u64) -> Result<()> {
    if signed_at < CHAIN_BLOCK_GRACE_SECS || observed_at != signed_at - CHAIN_BLOCK_GRACE_SECS {
        return Err(ReportingError::Unauthorized(
            "report envelope is not anchored to the evidence timestamp".to_string(),
        ));
    }
    Ok(())
}

/// Fetch the out-of-band inline-document evidence for a PRE report whose statement has
/// `document_inline` set, and re-bind it to `object_id`. The evidence is supplied by whoever
/// assembled the report (never signed by the accused — only `object_id` is), so a validator must
/// confirm it hashes to the signed `object_id` before trusting any field of it. Errors if no
/// evidence reached this validator or if it does not match.
pub(super) fn require_inline_document_evidence<'a>(
    context: &'a ReportValidationContext,
    ring_id: &str,
    object_id: &str,
    timestamp: Option<u64>,
) -> Result<&'a ReportedDocumentEvidence> {
    let evidence = context.inline_document.as_ref().ok_or_else(|| {
        ReportingError::InvalidReport(
            "statement marks the request inline but no inline document evidence was provided"
                .to_string(),
        )
    })?;
    let expected_object_id = generate_document_id(
        ring_id,
        &evidence.document,
        &evidence.proof,
        &evidence.policy_id,
        &evidence.resource,
        &evidence.permission,
        evidence.tier.as_deref(),
        timestamp,
    );
    if expected_object_id != object_id {
        return Err(ReportingError::InvalidReport(
            "inline document evidence does not match object_id".to_string(),
        ));
    }
    Ok(evidence)
}

/// A non-inline PRE report must not carry inline-document evidence: its presence means the report
/// was assembled inconsistently, or is an attempt to smuggle ACP inputs past the bulletin
/// re-fetch.
pub(super) fn reject_unexpected_inline_document_evidence(
    context: &ReportValidationContext,
) -> Result<()> {
    if context.inline_document.is_some() {
        return Err(ReportingError::InvalidReport(
            "statement does not mark the request inline but inline document evidence was provided"
                .to_string(),
        ));
    }
    Ok(())
}

pub(super) async fn read_node_info(
    bulletin: &Arc<dyn Bulletin + Send + Sync>,
    node_key: &str,
) -> Result<NodeInfo> {
    let post = bulletin
        .read(node_key.to_string(), BulletinKind::NodeInfo)
        .await
        .map_err(|error| ReportingError::Bulletin(error.to_string()))?;
    NodeInfo::try_from(post).map_err(|error| ReportingError::InvalidReport(error.to_string()))
}
