//! PET per-share DLEQ proof evidence — mirrors `pre_sign.rs`'s PRE half
//! almost exactly, with two differences: there is no "recently retired
//! generation" candidate-polynomial list (PET has no refresh/reshare yet,
//! so only the current public polynomial is ever checked against), and the
//! resolved document supplies a `PetTag` (via `pet_tag`/`pet_tag_proof`)
//! rather than a `Secret`/`enc_cmt`.

use super::*;

impl InvalidCryptoResponseHandler {
    pub(super) async fn validate_pet_evidence(
        &self,
        envelope: &ReportEnvelope,
        context: &ReportValidationContext,
        ring: &RingPayload,
        statement: &PetCheckResponseStatement,
        response_signature: &[u8],
    ) -> Result<()> {
        validate_pet_check_response_statement_shape(
            envelope,
            statement,
            response_signature,
            context,
        )?;
        let effective_version =
            validate_report_route_version_at_observed_at(envelope, ring, context.routes.version)?;
        if statement.protocol_version != effective_version {
            return Err(ReportingError::Unauthorized(format!(
                "PET response protocol version {} does not match effective ring version {}",
                statement.protocol_version, effective_version
            )));
        }

        let signing_committee = validate_ring_and_membership_for_scopes(
            envelope,
            ring,
            CommitteeScope::Current,
            CommitteeScope::Current,
            "PET invalid-proof",
        )?;
        validate_node_routes(envelope, context, ring).await?;
        validate_local_signer(envelope, context, &signing_committee, "PET invalid-proof")?;

        let expected_node_id =
            determine_session_node_id(&envelope.accused_node_key, &ring.peer_node_keys)
                .ok_or_else(|| {
                    ReportingError::Unauthorized(
                        "accused node is not in the current ring node-id map".to_string(),
                    )
                })?;
        if statement.from_node_id != expected_node_id {
            return Err(ReportingError::Unauthorized(format!(
                "PET response from_node_id {} does not match accused node_id {}",
                statement.from_node_id, expected_node_id
            )));
        }

        verify_node_message(
            &envelope.accused_node_key,
            &statement.canonical_bytes(),
            response_signature,
        )
        .map_err(|error| {
            ReportingError::Unauthorized(format!("invalid PET response signature: {}", error))
        })?;

        require_pet_proof_verification_failure(statement, context).await
    }
}

pub(crate) fn validate_pet_check_response_statement_shape(
    envelope: &ReportEnvelope,
    statement: &PetCheckResponseStatement,
    response_signature: &[u8],
    context: &ReportValidationContext,
) -> Result<()> {
    validate_invalid_crypto_statement_prologue(
        envelope,
        context,
        InvalidCryptoStatementPrologue {
            label: "PET response".to_string(),
            domain: statement.domain.clone(),
            expected_domain: PET_CHECK_RESPONSE_DOMAIN.to_string(),
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
    if !is_valid_invalid_crypto_pet_origin(&statement.origin_protocol) {
        return Err(ReportingError::InvalidReport(format!(
            "unsupported PET response origin protocol {}",
            statement.origin_protocol
        )));
    }
    if statement.object_id.trim().is_empty() {
        return Err(ReportingError::InvalidReport(
            "PET response object_id cannot be empty".to_string(),
        ));
    }
    if statement.crypto_backend != PetImpl::name() {
        return Err(ReportingError::Unauthorized(format!(
            "PET response crypto backend {} does not match local backend {}",
            statement.crypto_backend,
            PetImpl::name()
        )));
    }
    if response_signature.is_empty() {
        return Err(ReportingError::InvalidReport(
            "PET response signature cannot be empty".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn is_valid_invalid_crypto_pet_origin(origin_protocol: &str) -> bool {
    origin_protocol == "pet"
}

/// Resolve the `PetTag` this contribution was checked against — from the
/// out-of-band inline evidence when the underlying PRE request was inline,
/// or by reading the document from the bulletin otherwise. Mirrors
/// `require_pre_proof_verification_failure`'s document resolution exactly,
/// except it extracts a tag instead of a `Secret`.
async fn resolve_pet_tag(
    statement: &PetCheckResponseStatement,
    context: &ReportValidationContext,
) -> Result<PetTag> {
    let (pet_tag, pet_tag_proof) = if statement.document_inline {
        let evidence = require_inline_document_evidence(
            context,
            &statement.ring_id,
            &statement.object_id,
            statement.timestamp,
        )?;
        (evidence.pet_tag.clone(), evidence.pet_tag_proof.clone())
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
                "PET response object is not bound to the report ring".to_string(),
            ));
        }
        (document.pet_tag, document.pet_tag_proof)
    };
    let pet_tag = pet_tag.ok_or_else(|| {
        ReportingError::InvalidReport("document has no pet_tag but ring requires PET".to_string())
    })?;
    let _pet_tag_proof = pet_tag_proof.ok_or_else(|| {
        ReportingError::InvalidReport(
            "document has no pet_tag_proof but ring requires PET".to_string(),
        )
    })?;
    PetTag::try_from(pet_tag)
        .map_err(|error| ReportingError::InvalidReport(format!("malformed PET tag: {error}")))
}

pub(crate) async fn require_pet_proof_verification_failure(
    statement: &PetCheckResponseStatement,
    context: &ReportValidationContext,
) -> Result<()> {
    let tag = resolve_pet_tag(statement, context).await?;

    // The partial, challenge, and proof are the responder's own signed
    // crypto output. A responder that signs a statement whose values cannot
    // be decoded returned an unusable response, which is itself an
    // attributable verification failure — confirm the report on a decode
    // error rather than rejecting it. (The public polynomial below is
    // infrastructure input, not something either party to the report
    // controls, so a decode error there stays a hard `InvalidReport`.)
    let Ok(partial) = GroupAffine::from_bytes(&statement.partial) else {
        return Ok(());
    };
    let Ok(challenge) = ScalarField::from_bytes(&statement.challenge) else {
        return Ok(());
    };
    let Ok(proof) = ScalarField::from_bytes(&statement.proof) else {
        return Ok(());
    };

    // PET has no refresh/reshare yet, so there is exactly one generation to
    // check against — no `candidate_public_polynomials`-style history list
    // needed (unlike PRE/Sign).
    let bundle = RingShareBundle::load_by_ring_key(&context.local_storage, &statement.ring_id)
        .map_err(ReportingError::InvalidReport)?;
    let pub_poly_bytes = hex::decode(&bundle.public_polynomial)
        .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;
    let pub_poly = PubPolyImpl::from_bytes(&pub_poly_bytes)
        .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;

    let reply = PetCheckReply {
        partial: PubShare {
            i: statement.from_node_id,
            v: partial,
        },
        challenge,
        proof,
    };

    if PetImpl::verify_partial_pet_check(&pub_poly, &tag, &reply).is_ok() {
        return Err(ReportingError::Unauthorized(
            "reported PET check share verifies successfully under the current ring polynomial"
                .to_string(),
        ));
    }
    Ok(())
}
