use super::*;

impl InvalidCryptoResponseHandler {
    pub(super) async fn validate_pre_evidence(
        &self,
        envelope: &ReportEnvelope,
        context: &ReportValidationContext,
        ring: &RingPayload,
        statement: &crate::reporting::v0::types::PreReencryptResponseStatement,
        response_signature: &[u8],
    ) -> Result<()> {
        validate_pre_reencrypt_response_statement_shape(
            envelope,
            statement,
            response_signature,
            context,
        )?;
        let effective_version =
            validate_report_route_version_at_observed_at(envelope, ring, context.routes.version)?;
        if statement.protocol_version != effective_version {
            return Err(ReportingError::Unauthorized(format!(
                "PRE response protocol version {} does not match effective ring version {}",
                statement.protocol_version, effective_version
            )));
        }

        let signing_committee = validate_ring_and_membership_for_scopes(
            envelope,
            ring,
            CommitteeScope::Current,
            CommitteeScope::Current,
            "PRE invalid-proof",
        )?;
        validate_node_routes(envelope, context, ring).await?;
        validate_local_signer(envelope, context, &signing_committee, "PRE invalid-proof")?;

        let expected_node_id =
            determine_session_node_id(&envelope.accused_node_key, &ring.peer_node_keys)
                .ok_or_else(|| {
                    ReportingError::Unauthorized(
                        "accused node is not in the current ring node-id map".to_string(),
                    )
                })?;
        if statement.from_node_id != expected_node_id {
            return Err(ReportingError::Unauthorized(format!(
                "PRE response from_node_id {} does not match accused node_id {}",
                statement.from_node_id, expected_node_id
            )));
        }

        verify_node_message(
            &envelope.accused_node_key,
            &statement.canonical_bytes(),
            response_signature,
        )
        .map_err(|error| {
            ReportingError::Unauthorized(format!("invalid PRE response signature: {}", error))
        })?;

        require_pre_proof_verification_failure(statement, context).await
    }

    pub(super) async fn validate_sign_evidence(
        &self,
        envelope: &ReportEnvelope,
        context: &ReportValidationContext,
        ring: &RingPayload,
        statement: &SignResponseStatement,
        response_signature: &[u8],
    ) -> Result<()> {
        validate_sign_response_statement_shape(envelope, statement, response_signature, context)?;

        let effective_version =
            validate_report_route_version_at_observed_at(envelope, ring, context.routes.version)?;
        if statement.protocol_version != effective_version {
            return Err(ReportingError::Unauthorized(format!(
                "Sign response protocol version {} does not match effective ring version {}",
                statement.protocol_version, effective_version
            )));
        }

        let signing_committee = validate_ring_and_membership_for_scopes(
            envelope,
            ring,
            statement.accused_committee_scope,
            statement.signing_committee_scope,
            "Sign invalid-response",
        )?;
        validate_node_routes(envelope, context, ring).await?;
        validate_local_signer(
            envelope,
            context,
            &signing_committee,
            "Sign invalid-response",
        )?;

        let accused_committee = committee_for_scope(ring, statement.accused_committee_scope)?;
        let expected_node_id = determine_session_node_id(
            &envelope.accused_node_key,
            &accused_committee.peer_node_keys,
        )
        .ok_or_else(|| {
            ReportingError::Unauthorized(
                "accused node is not in the Sign response node-id map".to_string(),
            )
        })?;
        if statement.from_node_id != expected_node_id {
            return Err(ReportingError::Unauthorized(format!(
                "Sign response from_node_id {} does not match accused node_id {}",
                statement.from_node_id, expected_node_id
            )));
        }

        verify_node_message(
            &envelope.accused_node_key,
            &statement.canonical_bytes(),
            response_signature,
        )
        .map_err(|error| {
            ReportingError::Unauthorized(format!("invalid Sign response signature: {}", error))
        })?;

        require_sign_share_verification_failure(statement, context)
    }
}

pub(crate) fn validate_pre_reencrypt_response_statement_shape(
    envelope: &ReportEnvelope,
    statement: &PreReencryptResponseStatement,
    response_signature: &[u8],
    context: &ReportValidationContext,
) -> Result<()> {
    validate_invalid_crypto_statement_prologue(
        envelope,
        context,
        InvalidCryptoStatementPrologue {
            label: "PRE response".to_string(),
            domain: statement.domain.clone(),
            expected_domain: PRE_REENCRYPT_RESPONSE_DOMAIN.to_string(),
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
    if !is_valid_invalid_crypto_pre_origin(&statement.origin_protocol) {
        return Err(ReportingError::InvalidReport(format!(
            "unsupported PRE response origin protocol {}",
            statement.origin_protocol
        )));
    }
    if statement.object_id.trim().is_empty() {
        return Err(ReportingError::InvalidReport(
            "PRE response object_id cannot be empty".to_string(),
        ));
    }
    if statement.crypto_backend != PreImpl::name() {
        return Err(ReportingError::Unauthorized(format!(
            "PRE response crypto backend {} does not match local backend {}",
            statement.crypto_backend,
            PreImpl::name()
        )));
    }
    if response_signature.is_empty() {
        return Err(ReportingError::InvalidReport(
            "PRE response signature cannot be empty".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_sign_response_statement_shape(
    envelope: &ReportEnvelope,
    statement: &SignResponseStatement,
    response_signature: &[u8],
    context: &ReportValidationContext,
) -> Result<()> {
    validate_invalid_crypto_statement_prologue(
        envelope,
        context,
        InvalidCryptoStatementPrologue {
            label: "Sign response".to_string(),
            domain: statement.domain.clone(),
            expected_domain: SIGN_RESPONSE_DOMAIN.to_string(),
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
    if !is_valid_invalid_crypto_sign_origin(&statement.origin_protocol) {
        return Err(ReportingError::InvalidReport(format!(
            "unsupported Sign response origin protocol {}",
            statement.origin_protocol
        )));
    }
    if statement.crypto_backend != SignImpl::name() {
        return Err(ReportingError::Unauthorized(format!(
            "Sign response crypto backend {} does not match local backend {}",
            statement.crypto_backend,
            SignImpl::name()
        )));
    }
    if statement.message.is_empty() {
        return Err(ReportingError::InvalidReport(
            "Sign response message cannot be empty".to_string(),
        ));
    }
    if statement.sig_share.is_empty() {
        return Err(ReportingError::InvalidReport(
            "Sign response sig_share cannot be empty".to_string(),
        ));
    }
    if response_signature.is_empty() {
        return Err(ReportingError::InvalidReport(
            "Sign response signature cannot be empty".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn require_sign_share_verification_failure(
    statement: &SignResponseStatement,
    context: &ReportValidationContext,
) -> Result<()> {
    let poly_state =
        RingPolyState::load_from_ring_pk_hex(&context.local_storage, &statement.ring_pk)
            .map_err(ReportingError::InvalidReport)?;
    let pub_poly_bytes = hex::decode(&poly_state.public_polynomial)
        .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;
    let pub_poly = PubPolyImpl::from_bytes(&pub_poly_bytes).map_err(|error| {
        ReportingError::InvalidReport(format!("failed to deserialize public polynomial: {error}"))
    })?;
    // The sig_share is the responder's own signed crypto output. A responder that
    // signs a statement whose sig_share cannot be decoded returned an unusable
    // response, which is itself an attributable verification failure — confirm the
    // report on a decode error rather than rejecting it. (pub_poly above and
    // signing_commitments below are round/infrastructure inputs, so a decode error
    // there stays InvalidReport.)
    let Ok(sig_share_v) = SigShareInner::from_bytes(&statement.sig_share) else {
        return Ok(());
    };
    let sig_share = PubShare {
        i: statement.from_node_id,
        v: sig_share_v,
    };
    let signing_commitments = deserialize_commitments::<SignImpl>(&statement.signing_commitments)
        .map_err(|error| {
        ReportingError::InvalidReport(format!("failed to deserialize Sign commitments: {error}"))
    })?;
    let signer = SignImpl::new();
    match signer.verify_share(
        &statement.message,
        &pub_poly,
        &sig_share,
        &signing_commitments,
        statement.derivation.as_deref(),
        statement.metadata.as_deref(),
    ) {
        Ok(()) => Err(ReportingError::Unauthorized(
            "reported Sign share verifies successfully".to_string(),
        )),
        Err(_) => Ok(()),
    }
}

pub(crate) async fn require_pre_proof_verification_failure(
    statement: &crate::reporting::v0::types::PreReencryptResponseStatement,
    context: &ReportValidationContext,
) -> Result<()> {
    let secret = if statement.document_inline {
        let evidence = require_inline_document_evidence(
            context,
            &statement.ring_id,
            &statement.object_id,
            statement.timestamp,
        )?;
        deserialize_secret(&evidence.document)
            .map_err(|error| ReportingError::InvalidReport(error.to_string()))?
    } else {
        reject_unexpected_inline_document_evidence(context)?;
        let document_post = context
            .bulletin
            .read(statement.object_id.clone(), BulletinKind::Document)
            .await
            .map_err(|error| ReportingError::Bulletin(error.to_string()))?;
        let document = DocumentPayload::try_from(document_post)
            .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;
        if document.ring_id != statement.ring_id {
            return Err(ReportingError::Unauthorized(
                "PRE response object is not bound to the report ring".to_string(),
            ));
        }
        deserialize_secret(&document.document)
            .map_err(|error| ReportingError::InvalidReport(error.to_string()))?
    };
    let rdr_pk = GroupAffine::from_bytes(&statement.rdr_pk).map_err(|error| {
        ReportingError::InvalidReport(format!("failed to deserialize reader public key: {error}"))
    })?;
    let enc_cmt = GroupAffine::from_bytes(&secret.enc_cmt).map_err(|error| {
        ReportingError::InvalidReport(format!(
            "failed to deserialize encrypted commitment: {error}"
        ))
    })?;
    // The share, challenge, and proof are the responder's own signed crypto
    // output. A responder that signs a statement whose share/challenge/proof
    // cannot be decoded returned an unusable response, which is itself an
    // attributable verification failure — confirm the report on a decode error
    // rather than rejecting it. (rdr_pk, enc_cmt, and pub_poly above are
    // request/infrastructure inputs, so a decode error there stays InvalidReport.)
    let Ok(share) = GroupAffine::from_bytes(&statement.share) else {
        return Ok(());
    };
    let Ok(challenge) = ScalarField::from_bytes(&statement.challenge) else {
        return Ok(());
    };
    let Ok(proof) = ScalarField::from_bytes(&statement.proof) else {
        return Ok(());
    };
    let poly_state =
        RingPolyState::load_from_ring_pk_hex(&context.local_storage, &statement.ring_pk)
            .map_err(ReportingError::InvalidReport)?;
    let pub_poly_bytes = hex::decode(&poly_state.public_polynomial)
        .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;
    let pub_poly = PubPolyImpl::from_bytes(&pub_poly_bytes).map_err(|error| {
        ReportingError::InvalidReport(format!("failed to deserialize public polynomial: {error}"))
    })?;
    let reply = ReencryptReply {
        share: PubShare {
            i: statement.from_node_id,
            v: share,
        },
        challenge,
        proof,
    };

    match PreImpl::new().verify(
        &rdr_pk,
        &pub_poly,
        &enc_cmt,
        &reply,
        statement.derivation.as_deref(),
    ) {
        Ok(()) => Err(ReportingError::Unauthorized(
            "reported PRE proof verifies successfully".to_string(),
        )),
        Err(_) => Ok(()),
    }
}
