use super::*;

impl InvalidCryptoResponseHandler {
    pub(super) async fn validate_dkg_share_evidence(
        &self,
        envelope: &ReportEnvelope,
        context: &ReportValidationContext,
        ring: &RingPayload,
        statement: &DkgShareStatement,
        response_signature: &[u8],
    ) -> Result<()> {
        validate_dkg_share_statement_shape(envelope, statement, response_signature, context)?;

        let effective_version =
            validate_report_route_version_at_observed_at(envelope, ring, context.routes.version)?;
        if statement.protocol_version != effective_version {
            return Err(ReportingError::Unauthorized(format!(
                "DKG share protocol version {} does not match effective ring version {}",
                statement.protocol_version, effective_version
            )));
        }

        let signing_committee = validate_ring_and_membership_for_scopes(
            envelope,
            ring,
            statement.accused_committee_scope,
            statement.signing_committee_scope,
            "DKG invalid-share",
        )?;
        validate_node_routes(envelope, context, ring).await?;
        validate_local_signer(envelope, context, &signing_committee, "DKG invalid-share")?;

        let accused_committee = committee_for_scope(ring, statement.accused_committee_scope)?;
        let expected_from_node_id = determine_session_node_id(
            &envelope.accused_node_key,
            &accused_committee.peer_node_keys,
        )
        .ok_or_else(|| {
            ReportingError::Unauthorized(
                "accused node is not in the DKG share node-id map".to_string(),
            )
        })?;
        if statement.from_node_id != expected_from_node_id {
            return Err(ReportingError::Unauthorized(format!(
                "DKG share from_node_id {} does not match accused node_id {}",
                statement.from_node_id, expected_from_node_id
            )));
        }

        let receiver_committee = if statement.origin_protocol == "pss_reshare" {
            committee_for_scope(ring, CommitteeScope::PendingNew)?
        } else {
            committee_for_scope(ring, CommitteeScope::Current)?
        };
        let expected_receiver_node_key = receiver_committee
            .peer_node_keys
            .get(statement.to_node_id.saturating_sub(1) as usize)
            .ok_or_else(|| {
                ReportingError::Unauthorized(format!(
                    "DKG share to_node_id {} is outside the receiver committee",
                    statement.to_node_id
                ))
            })?;
        if &statement.receiver_node_key != expected_receiver_node_key {
            return Err(ReportingError::Unauthorized(
                "DKG share receiver node key does not match to_node_id".to_string(),
            ));
        }

        verify_node_message(
            &envelope.accused_node_key,
            &statement.commitment_statement.canonical_bytes(),
            &statement.commitment_signature,
        )
        .map_err(|error| {
            ReportingError::Unauthorized(format!("invalid DKG commitment signature: {}", error))
        })?;

        verify_node_message(
            &envelope.accused_node_key,
            &statement.canonical_bytes(),
            response_signature,
        )
        .map_err(|error| {
            ReportingError::Unauthorized(format!("invalid DKG share signature: {}", error))
        })?;

        require_dkg_share_verification_failure(statement)
    }

    pub(super) async fn validate_dkg_equivocation_evidence(
        &self,
        envelope: &ReportEnvelope,
        context: &ReportValidationContext,
        ring: &RingPayload,
        commitment_a: &SignedDkgCommitment,
        commitment_b: &SignedDkgCommitment,
    ) -> Result<()> {
        // Neither commitment individually anchors the envelope: the report is
        // anchored to whichever of the two has the LATER signed_at (matching
        // `dkg_public_origin_fault`'s OriginEquivocation case), since
        // equivocation is only provable once the second, conflicting
        // commitment arrives — that can legitimately be well after the first
        // within a long-running attempt, and anchoring to the earlier one
        // would let the report's TTL close before the fault was detectable.
        validate_equivocation_commitment_shape(
            envelope,
            context,
            &commitment_a.statement,
            &commitment_a.signature,
            false,
        )?;
        validate_equivocation_commitment_shape(
            envelope,
            context,
            &commitment_b.statement,
            &commitment_b.signature,
            false,
        )?;
        validate_evidence_anchor(
            commitment_a
                .statement
                .signed_at
                .max(commitment_b.statement.signed_at),
            envelope.observed_at,
        )?;

        let effective_version =
            validate_report_route_version_at_observed_at(envelope, ring, context.routes.version)?;
        if commitment_a.statement.protocol_version != effective_version
            || commitment_b.statement.protocol_version != effective_version
        {
            return Err(ReportingError::Unauthorized(format!(
                "DKG equivocation protocol version does not match effective ring version {}",
                effective_version
            )));
        }

        let signing_committee = validate_ring_and_membership_for_scopes(
            envelope,
            ring,
            CommitteeScope::Current,
            CommitteeScope::Current,
            "DKG equivocation",
        )?;
        validate_node_routes(envelope, context, ring).await?;
        validate_local_signer(envelope, context, &signing_committee, "DKG equivocation")?;

        let accused_committee = committee_for_scope(ring, CommitteeScope::Current)?;
        let expected_from_node_id = determine_session_node_id(
            &envelope.accused_node_key,
            &accused_committee.peer_node_keys,
        )
        .ok_or_else(|| {
            ReportingError::Unauthorized(
                "accused node is not in the DKG equivocation node-id map".to_string(),
            )
        })?;
        if commitment_a.statement.from_node_id != expected_from_node_id
            || commitment_b.statement.from_node_id != expected_from_node_id
        {
            return Err(ReportingError::Unauthorized(format!(
                "DKG equivocation from_node_id does not match accused node_id {}",
                expected_from_node_id
            )));
        }

        verify_node_message(
            &envelope.accused_node_key,
            &commitment_a.statement.canonical_bytes(),
            &commitment_a.signature,
        )
        .map_err(|error| {
            ReportingError::Unauthorized(format!(
                "invalid DKG equivocation commitment_a signature: {}",
                error
            ))
        })?;
        verify_node_message(
            &envelope.accused_node_key,
            &commitment_b.statement.canonical_bytes(),
            &commitment_b.signature,
        )
        .map_err(|error| {
            ReportingError::Unauthorized(format!(
                "invalid DKG equivocation commitment_b signature: {}",
                error
            ))
        })?;

        // The refutation: equivocation requires the same attempt and per-attempt nonce
        // with different bytes. A cross-attempt pair is not equivocation even if a dealer
        // reuses its nonce.
        if !commitment_a
            .statement
            .proves_equivocation_with(&commitment_b.statement)
        {
            return Err(ReportingError::Unauthorized(
                "reported commitments are not equivocation".to_string(),
            ));
        }

        Ok(())
    }

    pub(super) async fn validate_dkg_invalid_refresh_commitment_evidence(
        &self,
        envelope: &ReportEnvelope,
        context: &ReportValidationContext,
        ring: &RingPayload,
        statement: &DkgCommitmentStatement,
        response_signature: &[u8],
    ) -> Result<()> {
        validate_refresh_commitment_statement_shape(
            envelope,
            statement,
            response_signature,
            context,
        )?;

        let effective_version =
            validate_report_route_version_at_observed_at(envelope, ring, context.routes.version)?;
        if statement.protocol_version != effective_version {
            return Err(ReportingError::Unauthorized(format!(
                "DKG refresh commitment protocol version {} does not match effective ring version {}",
                statement.protocol_version, effective_version
            )));
        }

        let signing_committee = validate_ring_and_membership_for_scopes(
            envelope,
            ring,
            statement.accused_committee_scope,
            statement.signing_committee_scope,
            "DKG invalid-refresh-commitment",
        )?;
        validate_node_routes(envelope, context, ring).await?;
        validate_local_signer(
            envelope,
            context,
            &signing_committee,
            "DKG invalid-refresh-commitment",
        )?;

        let accused_committee = committee_for_scope(ring, statement.accused_committee_scope)?;
        let expected_from_node_id = determine_session_node_id(
            &envelope.accused_node_key,
            &accused_committee.peer_node_keys,
        )
        .ok_or_else(|| {
            ReportingError::Unauthorized(
                "accused node is not in the DKG refresh commitment node-id map".to_string(),
            )
        })?;
        if statement.from_node_id != expected_from_node_id {
            return Err(ReportingError::Unauthorized(format!(
                "DKG refresh commitment from_node_id {} does not match accused node_id {}",
                statement.from_node_id, expected_from_node_id
            )));
        }

        verify_node_message(
            &envelope.accused_node_key,
            &statement.canonical_bytes(),
            response_signature,
        )
        .map_err(|error| {
            ReportingError::Unauthorized(format!(
                "invalid DKG refresh commitment signature: {}",
                error
            ))
        })?;

        require_refresh_commitment_is_invalid(statement)
    }
}

pub(crate) fn validate_dkg_share_statement_shape(
    envelope: &ReportEnvelope,
    statement: &DkgShareStatement,
    response_signature: &[u8],
    context: &ReportValidationContext,
) -> Result<()> {
    validate_invalid_crypto_statement_prologue(
        envelope,
        context,
        InvalidCryptoStatementPrologue {
            label: "DKG share".to_string(),
            domain: statement.domain.clone(),
            expected_domain: DKG_SHARE_DOMAIN.to_string(),
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
            "unsupported DKG share origin protocol {}",
            statement.origin_protocol
        )));
    }
    if statement.accused_committee_scope != CommitteeScope::Current
        || statement.signing_committee_scope != CommitteeScope::Current
    {
        return Err(ReportingError::Unauthorized(
            "DKG share reports must use current accused and signing scopes".to_string(),
        ));
    }
    if statement.from_node_id == 0 || statement.to_node_id == 0 {
        return Err(ReportingError::InvalidReport(
            "DKG share node IDs must be non-zero".to_string(),
        ));
    }
    if statement.receiver_node_key.trim().is_empty() {
        return Err(ReportingError::InvalidReport(
            "DKG share receiver_node_key cannot be empty".to_string(),
        ));
    }
    if statement.crypto_backend != DkgImpl::name() {
        return Err(ReportingError::Unauthorized(format!(
            "DKG share crypto backend {} does not match local backend {}",
            statement.crypto_backend,
            DkgImpl::name()
        )));
    }
    if statement.share_value.is_empty() {
        return Err(ReportingError::InvalidReport(
            "DKG share value cannot be empty".to_string(),
        ));
    }
    if statement.commitment_signature.is_empty() {
        return Err(ReportingError::InvalidReport(
            "DKG commitment signature cannot be empty".to_string(),
        ));
    }
    if response_signature.is_empty() {
        return Err(ReportingError::InvalidReport(
            "DKG share signature cannot be empty".to_string(),
        ));
    }
    validate_dkg_commitment_statement_shape(statement)
}

pub(crate) fn validate_dkg_commitment_statement_shape(statement: &DkgShareStatement) -> Result<()> {
    let commitment = &statement.commitment_statement;
    if commitment.domain != DKG_COMMITMENT_DOMAIN {
        return Err(ReportingError::InvalidReport(format!(
            "unexpected DKG commitment domain {}",
            commitment.domain
        )));
    }
    if commitment.chain_id != statement.chain_id
        || commitment.ring_id != statement.ring_id
        || commitment.ring_pk != statement.ring_pk
        || commitment.ring_state_sha256 != statement.ring_state_sha256
        || commitment.protocol_version != statement.protocol_version
        || commitment.request_id != statement.request_id
        || commitment.responder_node_key != statement.responder_node_key
        || commitment.origin_protocol != statement.origin_protocol
        || commitment.accused_committee_scope != statement.accused_committee_scope
        || commitment.signing_committee_scope != statement.signing_committee_scope
        || commitment.from_node_id != statement.from_node_id
        || commitment.crypto_backend != statement.crypto_backend
    {
        return Err(ReportingError::Unauthorized(
            "DKG commitment binding does not match DKG share statement".to_string(),
        ));
    }
    if commitment.signed_at > statement.signed_at {
        return Err(ReportingError::Unauthorized(
            "DKG commitment was signed after the DKG share".to_string(),
        ));
    }
    if commitment.commitment.is_empty() {
        return Err(ReportingError::InvalidReport(
            "DKG commitment cannot be empty".to_string(),
        ));
    }
    if !commitment.commitment.len().is_multiple_of(GROUP_POINT_SIZE) {
        return Err(ReportingError::InvalidReport(format!(
            "DKG commitment length {} is not a multiple of {}",
            commitment.commitment.len(),
            GROUP_POINT_SIZE
        )));
    }
    Ok(())
}

pub(crate) fn validate_refresh_commitment_statement_shape(
    envelope: &ReportEnvelope,
    statement: &DkgCommitmentStatement,
    response_signature: &[u8],
    context: &ReportValidationContext,
) -> Result<()> {
    validate_invalid_crypto_statement_prologue(
        envelope,
        context,
        InvalidCryptoStatementPrologue {
            label: "DKG refresh commitment".to_string(),
            domain: statement.domain.clone(),
            expected_domain: DKG_COMMITMENT_DOMAIN.to_string(),
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
    // This report kind is refresh-ONLY: a reshare commitment legitimately has a
    // non-identity constant term, so it must never be reportable as an invalid refresh.
    if statement.origin_protocol != "pss_refresh" {
        return Err(ReportingError::InvalidReport(format!(
            "DKG invalid-refresh-commitment report requires pss_refresh origin, got {}",
            statement.origin_protocol
        )));
    }
    if statement.accused_committee_scope != CommitteeScope::Current
        || statement.signing_committee_scope != CommitteeScope::Current
    {
        return Err(ReportingError::Unauthorized(
            "DKG refresh commitment reports must use current accused and signing scopes"
                .to_string(),
        ));
    }
    if statement.from_node_id == 0 {
        return Err(ReportingError::InvalidReport(
            "DKG refresh commitment from_node_id must be non-zero".to_string(),
        ));
    }
    if statement.crypto_backend != DkgImpl::name() {
        return Err(ReportingError::Unauthorized(format!(
            "DKG refresh commitment crypto backend {} does not match local backend {}",
            statement.crypto_backend,
            DkgImpl::name()
        )));
    }
    if statement.commitment.is_empty() {
        return Err(ReportingError::InvalidReport(
            "DKG refresh commitment cannot be empty".to_string(),
        ));
    }
    if !statement.commitment.len().is_multiple_of(GROUP_POINT_SIZE) {
        return Err(ReportingError::InvalidReport(format!(
            "DKG refresh commitment length {} is not a multiple of {}",
            statement.commitment.len(),
            GROUP_POINT_SIZE
        )));
    }
    if response_signature.is_empty() {
        return Err(ReportingError::InvalidReport(
            "DKG refresh commitment signature cannot be empty".to_string(),
        ));
    }
    Ok(())
}

/// The refutation for an invalid-refresh-commitment report: a valid refresh delta
/// commitment has an identity constant term, so if it decodes and the constant term IS
/// identity the commitment is fine → reject the report. A commitment that cannot be
/// decoded is itself an attributable fault (mirrors `require_dkg_share_verification_failure`).
pub(crate) fn require_refresh_commitment_is_invalid(
    statement: &DkgCommitmentStatement,
) -> Result<()> {
    let Ok(commitment) = deserialize_wire_commitment(&statement.commitment) else {
        return Ok(());
    };
    if commitment.constant_term_is_identity() {
        return Err(ReportingError::Unauthorized(
            "reported refresh commitment has a valid identity constant term".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn require_dkg_share_verification_failure(statement: &DkgShareStatement) -> Result<()> {
    // The nested commitment and share value are the responder's own signed crypto
    // output. A responder that signs a statement whose commitment or share value
    // cannot be decoded returned an unusable share, which is itself an attributable
    // verification failure — confirm the report on a decode error rather than
    // rejecting it.
    let Ok(commitment) = deserialize_wire_commitment(&statement.commitment_statement.commitment)
    else {
        return Ok(());
    };
    let Ok(share_value) = ScalarField::from_bytes(&statement.share_value) else {
        return Ok(());
    };

    if commitment.verify_share(statement.to_node_id, &share_value) {
        return Err(ReportingError::Unauthorized(
            "reported DKG share verifies successfully".to_string(),
        ));
    }
    Ok(())
}
