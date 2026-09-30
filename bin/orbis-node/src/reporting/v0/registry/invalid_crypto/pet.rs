//! PET blind-equality-test evidence validation (audit finding #2's
//! replacement for the old single-round per-share DLEQ evidence — a genuine
//! `Z·R` decryption proof would not verify against that old shape, and must
//! not be coerced into it).
//!
//! Unlike every other evidence kind in this module, the accused's own signed
//! statement binds only an opaque `context_digest`/`certificate_digest`, not
//! individually-reconstructable fields — see
//! `reporting::v0::types::pet_blind`'s module doc comment. The matching
//! `PetBlindContext` a validator needs to independently recompute that
//! digest and resolve the tag/target from primary sources (the bulletin)
//! does **not** travel inside the evidence itself (it carries the audit
//! target's object id, which must never be posted on chain) — it arrives
//! out-of-band via `ReportValidationContext::pet_blind_context`, fetched
//! with `require_pet_blind_context`, exactly like `ReportedDocumentEvidence`
//! travels via `inline_document`.

use super::*;
use crypto::r#trait::PubPoly;

impl InvalidCryptoResponseHandler {
    pub(super) async fn validate_pet_blind_reveal_evidence(
        &self,
        envelope: &ReportEnvelope,
        context: &ReportValidationContext,
        ring: &RingPayload,
        blind_context: &PetBlindContext,
        statement: &PetBlindRevealStatement,
        response_signature: &[u8],
    ) -> Result<()> {
        if statement.domain != PET_BLIND_REVEAL_RESPONSE_DOMAIN {
            return Err(ReportingError::InvalidReport(format!(
                "unexpected PET blind-reveal domain {}",
                statement.domain
            )));
        }
        validate_pet_blind_prologue(
            envelope,
            context,
            ring,
            blind_context,
            &statement.context_digest,
            statement.signed_at,
        )?;

        let expected_node_id =
            determine_session_node_id(&envelope.accused_node_key, &ring.peer_node_keys)
                .ok_or_else(|| {
                    ReportingError::Unauthorized(
                        "accused node is not in the current ring node-id map".to_string(),
                    )
                })?;
        if statement.from_node_id != expected_node_id {
            return Err(ReportingError::Unauthorized(format!(
                "PET blind-reveal response from_node_id {} does not match accused node_id {}",
                statement.from_node_id, expected_node_id
            )));
        }

        verify_node_message(
            &envelope.accused_node_key,
            &statement.canonical_bytes(),
            response_signature,
        )
        .map_err(|error| {
            ReportingError::Unauthorized(format!(
                "invalid PET blind-reveal response signature: {}",
                error
            ))
        })?;

        require_pet_blind_reveal_verification_failure(blind_context, statement, context).await
    }

    pub(super) async fn validate_pet_blind_decrypt_evidence(
        &self,
        envelope: &ReportEnvelope,
        context: &ReportValidationContext,
        ring: &RingPayload,
        blind_context: &PetBlindContext,
        statement: &PetBlindDecryptStatement,
        response_signature: &[u8],
    ) -> Result<()> {
        if statement.domain != PET_BLIND_DECRYPT_RESPONSE_DOMAIN {
            return Err(ReportingError::InvalidReport(format!(
                "unexpected PET blind-decrypt domain {}",
                statement.domain
            )));
        }
        validate_pet_blind_prologue(
            envelope,
            context,
            ring,
            blind_context,
            &statement.context_digest,
            statement.signed_at,
        )?;

        let expected_node_id =
            determine_session_node_id(&envelope.accused_node_key, &ring.peer_node_keys)
                .ok_or_else(|| {
                    ReportingError::Unauthorized(
                        "accused node is not in the current ring node-id map".to_string(),
                    )
                })?;
        if statement.from_node_id != expected_node_id {
            return Err(ReportingError::Unauthorized(format!(
                "PET blind-decrypt response from_node_id {} does not match accused node_id {}",
                statement.from_node_id, expected_node_id
            )));
        }

        verify_node_message(
            &envelope.accused_node_key,
            &statement.canonical_bytes(),
            response_signature,
        )
        .map_err(|error| {
            ReportingError::Unauthorized(format!(
                "invalid PET blind-decrypt response signature: {}",
                error
            ))
        })?;

        require_pet_blind_decrypt_verification_failure(blind_context, statement, context).await
    }
}

/// Bindings shared by both PET-blind evidence kinds: the accompanying
/// `PetBlindContext` must itself hash to the statement's claimed
/// `context_digest`, must bind the same chain/ring the envelope claims, must
/// name the *current* ring's own PET checking key (never a stale one), and
/// the statement's `signed_at` must anchor the envelope's `observed_at`.
fn validate_pet_blind_prologue(
    envelope: &ReportEnvelope,
    context: &ReportValidationContext,
    ring: &RingPayload,
    blind_context: &PetBlindContext,
    claimed_context_digest: &[u8; 32],
    signed_at: u64,
) -> Result<()> {
    if &blind_context.context_digest() != claimed_context_digest {
        return Err(ReportingError::InvalidReport(
            "PET blind evidence context does not hash to its own claimed context_digest"
                .to_string(),
        ));
    }
    if blind_context.chain_id != envelope.chain_id
        || envelope.chain_id != context.bulletin.chain_id()
    {
        return Err(ReportingError::Unauthorized(
            "PET blind evidence chain ID does not match report chain ID".to_string(),
        ));
    }
    if blind_context.ring_id != envelope.ring_id
        || blind_context.ring_pk != envelope.ring_pk
        || blind_context.ring_state_sha256 != envelope.ring_state_sha256
    {
        return Err(ReportingError::Unauthorized(
            "PET blind evidence ring binding does not match report envelope".to_string(),
        ));
    }
    if blind_context.attempt_id != envelope.session_id {
        return Err(ReportingError::Unauthorized(
            "PET blind evidence attempt_id does not match report session_id".to_string(),
        ));
    }
    if !ring.requires_pet {
        return Err(ReportingError::Unauthorized(
            "PET blind evidence reported against a ring that does not require PET".to_string(),
        ));
    }
    let current_pet_pk = ring.pet_pk.as_deref().ok_or_else(|| {
        ReportingError::Unauthorized(
            "ring requires PET but its checking key has not finalized".to_string(),
        )
    })?;
    if blind_context.pet_pk != current_pet_pk {
        return Err(ReportingError::Unauthorized(
            "PET blind evidence does not bind the ring's current checking key".to_string(),
        ));
    }
    if blind_context.crypto_backend != PetImpl::name() {
        return Err(ReportingError::Unauthorized(format!(
            "PET blind evidence crypto backend {} does not match local backend {}",
            blind_context.crypto_backend,
            PetImpl::name()
        )));
    }
    validate_evidence_anchor(signed_at, envelope.observed_at)
}

/// Resolve the `PetTag` and audit-target fingerprint `blind_context` was
/// checked against — from the out-of-band inline evidence when the
/// underlying PRE request was inline, or by reading the document from the
/// bulletin otherwise. Mirrors the old protocol's document resolution
/// exactly, except it is driven by `PetBlindContext`'s fields rather than a
/// `PetCheckResponseStatement`'s.
async fn resolve_pet_blind_tag_and_target(
    blind_context: &PetBlindContext,
    context: &ReportValidationContext,
) -> Result<(PetTag, GroupAffine)> {
    let (pet_tag, _pet_tag_proof) = if blind_context.document_inline {
        let evidence = require_inline_document_evidence(
            context,
            &blind_context.ring_id,
            &blind_context.object_id,
            blind_context.timestamp,
        )?;
        (evidence.pet_tag.clone(), evidence.pet_tag_proof.clone())
    } else {
        reject_unexpected_inline_document_evidence(context)?;
        let document_post = context
            .bulletin
            .read(blind_context.object_id.clone(), BulletinKind::Document)
            .await
            .map_err(|error| ReportingError::Bulletin(error.to_string()))?;
        let document = DocumentPayload::try_from(document_post)
            .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;
        if document.ring_id != blind_context.ring_id {
            return Err(ReportingError::Unauthorized(
                "PET blind evidence object is not bound to the report ring".to_string(),
            ));
        }
        (document.pet_tag, document.pet_tag_proof)
    };
    let pet_tag = pet_tag.ok_or_else(|| {
        ReportingError::InvalidReport("document has no pet_tag but ring requires PET".to_string())
    })?;
    let tag = PetTag::try_from(pet_tag)
        .map_err(|error| ReportingError::InvalidReport(format!("malformed PET tag: {error}")))?;
    let target_fingerprint =
        PetImpl::owner_fingerprint(blind_context.audit_target_object_id.as_bytes())
            .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;
    Ok((tag, target_fingerprint))
}

async fn require_pet_blind_reveal_verification_failure(
    blind_context: &PetBlindContext,
    statement: &PetBlindRevealStatement,
    context: &ReportValidationContext,
) -> Result<()> {
    let (tag, target_fingerprint) =
        resolve_pet_blind_tag_and_target(blind_context, context).await?;

    // The opening/proof fields are the responder's own signed crypto
    // output. A responder that signs a statement whose values cannot be
    // decoded returned an unusable response, which is itself an
    // attributable verification failure — confirm the report on a decode
    // error rather than rejecting it.
    let recomputed_commitment = pet_blind_commit_hash(
        &statement.attempt_id,
        &statement.context_digest,
        statement.from_node_id,
        &statement.commit_salt,
        &statement.blinded_r,
        &statement.blinded_diff,
    );
    if recomputed_commitment != statement.commitment.as_slice() {
        // Signed, but does not open its own claimed commitment.
        return Ok(());
    }

    let (Ok(blinded_r), Ok(blinded_diff), Ok(challenge), Ok(proof)) = (
        GroupAffine::from_bytes(&statement.blinded_r),
        GroupAffine::from_bytes(&statement.blinded_diff),
        ScalarField::from_bytes(&statement.challenge),
        ScalarField::from_bytes(&statement.proof),
    ) else {
        return Ok(());
    };
    let reply = crypto::r#trait::BlindingReply {
        blinded_r,
        blinded_diff,
        challenge,
        proof,
    };
    let commitment: [u8; 32] = statement.commitment.as_slice().try_into().map_err(|_| {
        ReportingError::InvalidReport("PET blind-reveal commitment is not 32 bytes".to_string())
    })?;
    let blind_transcript_digest = pet_blind_proof_transcript_digest(
        &statement.attempt_id,
        &statement.context_digest,
        &statement.selection_digest,
        statement.from_node_id,
        &commitment,
    );

    if PetImpl::verify_blinding_correctness(
        &tag,
        &target_fingerprint,
        &reply,
        &blind_transcript_digest,
    )
    .is_ok()
    {
        return Err(ReportingError::Unauthorized(
            "reported PET blind-reveal proof verifies successfully".to_string(),
        ));
    }
    Ok(())
}

pub(crate) async fn require_pet_blind_decrypt_verification_failure(
    blind_context: &PetBlindContext,
    statement: &PetBlindDecryptStatement,
    _context: &ReportValidationContext,
) -> Result<()> {
    // The share/challenge/proof/polynomial are the responder's own signed
    // crypto output; a decode failure on any of them is itself an
    // attributable verification failure — confirm the report rather than
    // rejecting it.
    let Ok(partial) = GroupAffine::from_bytes(&statement.partial) else {
        return Ok(());
    };
    let Ok(challenge) = ScalarField::from_bytes(&statement.challenge) else {
        return Ok(());
    };
    let Ok(proof) = ScalarField::from_bytes(&statement.proof) else {
        return Ok(());
    };
    let Ok(claimed_poly) = PubPolyImpl::from_bytes(&statement.public_polynomial) else {
        return Ok(());
    };

    // Authenticate the responder's own claimed polynomial against the
    // ring's known, generation-invariant `pet_pk` — every genuine
    // generation of this ring's PET key, whatever `RefreshPet`/`ResharePet`
    // it came from, evaluates to the same `pet_pk` at x=0. This lets a
    // verifier accept a genuine response from a generation it hasn't
    // personally caught up to yet (reshare-atomicity finding #3: a
    // candidate-list approach checking only the verifier's own
    // current/recently-retired polynomials has no way to recognize a
    // generation *ahead* of it), while still rejecting a fabricated claim:
    // forging a polynomial that authenticates here requires genuinely
    // holding a real share of this ring's actual `pet_sk`.
    let pet_pk_bytes = hex::decode(&blind_context.pet_pk)
        .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;
    let pet_pk = GroupAffine::from_bytes(&pet_pk_bytes)
        .map_err(|error| ReportingError::InvalidReport(error.to_string()))?;

    let reply = PetCheckReply {
        partial: PubShare {
            i: statement.from_node_id,
            v: partial,
        },
        challenge,
        proof,
    };
    // Reused unchanged, against this statement's own claimed `aggregate_r`
    // in place of the old protocol's bare `R` — `masked_fingerprint` is
    // never read by `verify_partial_pet_check`.
    let synthetic_tag = PetTag {
        ephemeral_point: statement.aggregate_r.clone(),
        masked_fingerprint: Vec::new(),
    };

    let verifies = claimed_poly.eval(0) == pet_pk
        && PetImpl::verify_partial_pet_check(&claimed_poly, &synthetic_tag, &reply).is_ok();
    if verifies {
        return Err(ReportingError::Unauthorized(
            "reported PET blind-decrypt share verifies successfully against its own claimed, \
             authenticated public polynomial"
                .to_string(),
        ));
    }
    Ok(())
}
