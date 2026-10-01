//! Shared verification logic for the PET blind equality test (audit finding
//! #2 — see `docs/plans/pet-blind-equality-test-design.md`).
//!
//! [`verify_pet_check_request`] independently verifies the underlying tag
//! itself (unchanged from the old single-round protocol — the tag-knowledge
//! proof and its transcript digest are unaffected by *how* the threshold
//! check that follows is run). It is shared by every one of the three
//! phases' handlers (`coordinator::handlers`) and the initiator's own local
//! contribution.
//!
//! [`build_and_verify_pet_blind_certificate`] is the single shared
//! certificate-validation routine used identically by the decrypt-phase
//! responder handler, the initiator's own certificate assembly, and PRE
//! admission's independent re-check — see the design doc's "Round 2 —
//! Reveal" section: "Validating this complete certificate is a shared
//! operation used by the initiator, every decryptor, PRE admission, and
//! relevant reporting verifiers."
//!
//! [`PetCoordinator::verify_pet_admission`] exists so a PRE peer can refuse
//! to release its reencryption share for a `requires_pet` ring unless it is
//! independently convinced a genuine blind equality test already passed (see
//! `pre::v0::coordinator::handlers::handle_reencrypt_request`). Unlike every
//! other function in this file, it does take the audit target as an input —
//! see this module's original design note (still accurate) on why that
//! committee-internal exposure is a deliberate, reviewed trade-off.

use super::PetCoordinator;
use crate::helpers::identity::{extract_node_part, node_key_for_id};
use crate::helpers::node_routes::resolve_node_routes;
use crate::helpers::protocol_version::read_ring_for_route;
use crate::pet::v0::attestation::{
    build_pet_blind_context, invalid_pet_blind_decrypt_observation,
    invalid_pet_blind_reveal_observation, PetBlindEvidence,
};
use crate::pet::v0::error::{PetError, Result};
use crate::pet::v0::messages::PetCheckContext;
use crate::reporting::v0::observation::InvalidCryptoResponseObservation;
use crate::reporting::v0::types::{
    pet_blind_commit_hash, pet_blind_proof_transcript_digest, pet_blind_selection_digest,
    PetBlindCertificate, PetBlindContext, PetBlindDecryptStatement, PetBlindRevealStatement,
    PetBlindSignedReveal, ReportedDocumentEvidence,
};
use crate::ring_state::RingShareBundle;
use authn::{resolve_jwt_did, BearerToken, PreClaims};
use authz::r#trait::Authz;
use authz::vera::{AccessCheckRequest, ValidWindow};
use bulletin::r#trait::Bulletin;
use common::blockchain::verify_node_message;
use crypto::context::CiphertextContext;
use crypto::r#trait::{
    BlindingReply, CryptoDeserialize, DistKeyShare, Dkg, EncryptionProof, Pet, PetCheckReply,
    PetTag, PubShare, Secret, TagKnowledgeProof, ThresholdSigner,
};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr};
use crypto::{SigShareInner, SignImpl, SignaturePoint};
use network::PeerId;
use std::collections::HashSet;
use std::sync::Arc;

/// Authorization gate for PET, additive to the cryptographic tag-match
/// below, not a replacement for it: a genuinely matching tag still proves
/// the tag is real; this proves the requester is allowed to invoke/learn
/// that fact at all. Mirrors `pre::v0::helpers::check_policy_access`'s exact
/// shape, checked against `audit_target_object_id` instead of the
/// document's own `object_id` — same resource type, same permission name,
/// same relation schema. This is what lets whoever holds `creator` on the
/// audit target delegate `reader` to other actors, exactly like decrypting
/// the document itself.
pub(crate) async fn check_pet_permission(
    authz: &(dyn Authz + Send + Sync),
    document: &bulletin::r#trait::DocumentPayload,
    audit_target_object_id: &str,
    actor_id: &str,
    valid_window: Option<ValidWindow>,
) -> Result<()> {
    let permission = AccessCheckRequest::new(
        document.policy_id.clone(),
        document.resource.clone(),
        audit_target_object_id.to_string(),
        document.permission.clone(),
        document.tier.clone(),
        document.timestamp,
        valid_window,
    )
    .to_bytes()
    .map_err(|e| PetError::Acp(format!("Error formatting PET access request: {}", e)))?;

    let is_authorized = authz
        .check(permission, actor_id)
        .await
        .map_err(|e| PetError::Acp(format!("Error in PET Authz request: {}", e)))?;

    if !is_authorized {
        return Err(PetError::Mismatch);
    }

    Ok(())
}

/// Independently authenticate and authorize a PET check request received
/// directly over the wire, for whichever phase is currently running. Unlike
/// the normal initiator's own entry point (which calls `check_pet_permission`
/// before doing anything) and unlike PRE admission (whose caller already
/// independently re-verified the same JWT before ever reaching it), every
/// phase's handler is reachable from a raw wire message with no other
/// upstream authentication at all. Without this, a direct peer request could
/// obtain a genuine contribution for any document/target without ever going
/// through the ACP-gated normal PRE entry point — see the PET audit fix
/// checklist, finding #3.
///
/// Re-verifies `ctx.token_string` the same way PRE's own responders
/// re-verify `PreRequestContext::token_string`, binds it to *this* request's
/// `object_id`/`salt`, derives the actor from it, and then runs the exact
/// same `check_pet_permission` gate the normal initiator already runs.
/// Returns the derived `actor_id` — needed by every caller to build this
/// attempt's canonical `PetBlindContext`.
pub(crate) async fn verify_pet_audit_authorization(
    authz: &(dyn Authz + Send + Sync),
    ctx: &PetCheckContext,
    trusted_auth_relay_dids: Option<&[String]>,
    current_time: u64,
) -> Result<String> {
    let token: BearerToken<PreClaims> = resolve_jwt_did(
        &ctx.token_string,
        current_time,
        crate::constants::MAX_TOKEN_LIFETIME_SECS,
        crate::constants::MAX_JWT_BYTES,
        crate::constants::JWT_CLOCK_SKEW_LEEWAY_SECS,
    )
    .map_err(|e| PetError::InvalidInput(format!("JWT validation failed: {}", e)))?;

    if token.claims.object_id != ctx.object_id {
        return Err(PetError::InvalidInput(format!(
            "Token object_id '{}' does not match request object_id '{}'",
            token.claims.object_id, ctx.object_id
        )));
    }
    if token.claims.salt != ctx.salt {
        return Err(PetError::InvalidInput(
            "Token salt does not match request salt".to_string(),
        ));
    }

    let actor_id = crate::helpers::auth::request_actor(&token, trusted_auth_relay_dids)
        .map_err(PetError::InvalidInput)?;

    check_pet_permission(
        authz,
        &ctx.document,
        &ctx.audit_target_object_id,
        &actor_id,
        ctx.valid_window.clone(),
    )
    .await?;

    Ok(actor_id)
}

/// Resolve the authenticated transport sender's ring-committee node key —
/// `from_node_id`/any request field is a claim to validate, never proof of
/// coordinator identity (see the design doc's "Protocol: three rounds"
/// section). Used to bind `PetBlindContext::coordinator_node_key` from a
/// live connection's own peer id, exactly as `resolve_node_routes` already
/// lets the initiator resolve the reverse direction.
pub(crate) async fn resolve_coordinator_node_key(
    bulletin: &Arc<dyn Bulletin + Send + Sync>,
    peer_id: &PeerId,
    ring_payload: &bulletin::r#trait::RingPayload,
) -> Result<String> {
    let routes = resolve_node_routes(bulletin, &ring_payload.peer_node_keys)
        .await
        .map_err(PetError::ProtocolError)?;
    let peer_hex = hex::encode(peer_id.as_bytes());
    routes
        .into_iter()
        .find(|route| extract_node_part(&route.peer_id).eq_ignore_ascii_case(&peer_hex))
        .map(|route| route.node_key)
        .ok_or_else(|| {
            PetError::InvalidInput(
                "requesting peer is not a member of the ring committee".to_string(),
            )
        })
}

fn deserialize_secret(document_json: &str) -> Result<Secret> {
    serde_json::from_str(document_json)
        .map_err(|e| PetError::Deserialization(format!("Failed to deserialize secret: {}", e)))
}

fn build_ciphertext_context(
    ring_pk_hex: &str,
    document: &bulletin::r#trait::DocumentPayload,
    salt: Option<&str>,
    pet_pk_hex: Option<&str>,
) -> Result<CiphertextContext> {
    let ring_pk = hex::decode(ring_pk_hex)
        .map_err(|e| PetError::InvalidInput(format!("Invalid ring_pk hex encoding: {}", e)))?;
    // Shared with `pre::v0::helpers::build_ciphertext_context`, mirroring how
    // `check_document_id_binding` is already reused across both modules —
    // see finding #5 in the PET audit fix checklist.
    let pet_tag = crate::pre::v0::helpers::build_pet_tag_binding(document, pet_pk_hex)
        .map_err(|e| PetError::InvalidInput(format!("PET tag binding: {e}")))?;
    Ok(CiphertextContext {
        ring_pk,
        policy_id: document.policy_id.clone(),
        resource: document.resource.clone(),
        permission: document.permission.clone(),
        tier: document.tier.clone(),
        timestamp: document.timestamp,
        salt: salt.map(str::to_string),
        pet_tag,
    })
}

/// The outcome of checking one committee member's contribution against a
/// signed statement, distinguishing *why* it failed rather than leaving
/// callers to infer that from an error's variant or message text — the two
/// live per-phase verifiers (`verify_reveal_response`/`verify_decrypt_response`)
/// need this distinction to decide `Rejected` vs `InvalidProof`, and a
/// string-matched proxy for it is exactly the kind of check a future,
/// unrelated wording change could silently break.
enum ContributionCheckOutcome<T> {
    Verified(T),
    /// Never reached the point of being this node's own authenticated,
    /// signed claim — an unresolvable identity, a bad signature, or content
    /// that could equally be a coordinator/list-binding problem rather than
    /// this responder's fault. Never independently reportable.
    NotAttributable(PetError),
    /// Signed by this node (its signature over these exact bytes verified),
    /// but the content itself is cryptographically invalid — genuinely
    /// reportable misconduct.
    Invalid(PetError),
}

impl<T> ContributionCheckOutcome<T> {
    fn into_result(self) -> Result<T> {
        match self {
            Self::Verified(value) => Ok(value),
            Self::NotAttributable(error) | Self::Invalid(error) => Err(error),
        }
    }
}

/// `C_i`'s opening plus its blinding-correctness proof, verified against
/// `tag`/`target_fingerprint`, for one selected participant. Shared by
/// [`build_and_verify_pet_blind_certificate`] and the live reveal-phase
/// collector (`verify_reveal_response`) — both need the exact same checks
/// (signature, opening, proof), differing only in how a failure is reported.
fn verify_one_reveal<P>(
    statement: &PetBlindRevealStatement,
    response_signature: &[u8],
    ring_payload: &bulletin::r#trait::RingPayload,
    tag: &PetTag,
    target_fingerprint: &P::PublicKey,
    expected_commitment: [u8; 32],
    selection_digest: [u8; 32],
) -> ContributionCheckOutcome<(G1Affine, G1Affine)>
where
    P: Pet<ShareValue = Fr, PublicKey = G1Affine>,
{
    use ContributionCheckOutcome::{Invalid, NotAttributable, Verified};

    let Some(node_key) = node_key_for_id(statement.from_node_id, &ring_payload.peer_node_keys)
    else {
        return NotAttributable(PetError::Crypto(format!(
            "reveal from_node_id {} is not in the ring committee",
            statement.from_node_id
        )));
    };
    if node_key != statement.responder_node_key {
        return NotAttributable(PetError::Crypto(format!(
            "reveal responder_node_key does not match the resolved committee identity for node {}",
            statement.from_node_id
        )));
    }
    if let Err(e) = verify_node_message(&node_key, &statement.canonical_bytes(), response_signature)
    {
        return NotAttributable(PetError::Crypto(format!(
            "invalid reveal signature from node {}: {e}",
            statement.from_node_id
        )));
    }
    // Everything from here on is this node's own authenticated, signed
    // claim — any failure below is genuinely attributable to it.
    if statement.commitment.as_slice() != expected_commitment {
        return NotAttributable(PetError::Crypto(format!(
            "reveal commitment for node {} does not match the selected list",
            statement.from_node_id
        )));
    }
    if statement.selection_digest != selection_digest {
        return NotAttributable(PetError::Crypto(format!(
            "reveal selection_digest for node {} does not match the selected list",
            statement.from_node_id
        )));
    }
    let recomputed_commitment = pet_blind_commit_hash(
        &statement.attempt_id,
        &statement.context_digest,
        statement.from_node_id,
        &statement.commit_salt,
        &statement.blinded_r,
        &statement.blinded_diff,
    );
    if recomputed_commitment != expected_commitment {
        return Invalid(PetError::Crypto(format!(
            "reveal from node {} does not open its own commitment",
            statement.from_node_id
        )));
    }

    let (Ok(blinded_r), Ok(blinded_diff), Ok(challenge), Ok(proof)) = (
        G1Affine::from_bytes(&statement.blinded_r),
        G1Affine::from_bytes(&statement.blinded_diff),
        Fr::from_bytes(&statement.challenge),
        Fr::from_bytes(&statement.proof),
    ) else {
        return Invalid(PetError::Deserialization(format!(
            "failed to decode reveal fields from node {}",
            statement.from_node_id
        )));
    };
    let reply = BlindingReply {
        blinded_r,
        blinded_diff,
        challenge,
        proof,
    };
    let blind_transcript_digest = pet_blind_proof_transcript_digest(
        &statement.attempt_id,
        &statement.context_digest,
        &selection_digest,
        statement.from_node_id,
        &expected_commitment,
    );
    if let Err(e) =
        P::verify_blinding_correctness(tag, target_fingerprint, &reply, &blind_transcript_digest)
    {
        return Invalid(PetError::Crypto(format!(
            "blinding-correctness proof failed for node {}: {e}",
            statement.from_node_id
        )));
    }

    Verified((blinded_r, blinded_diff))
}

/// The single shared certificate-validation routine — see this module's doc
/// comment for the four call sites that must all use exactly this function.
/// Validates the selected list's shape, every selected node's signature,
/// commitment opening, and blinding-correctness proof, then returns the
/// reconstructed aggregate points `(Z·R, Z·(T-Y))`. Rejects a zero aggregate
/// `Z·R` — the one check that cannot be expressed per-reply, only over the
/// complete, verified set (see `Pet::verify_blinding_correctness`'s own doc
/// comment on this exact division of responsibility).
pub(crate) fn build_and_verify_pet_blind_certificate<D, P>(
    certificate: &PetBlindCertificate,
    ring_payload: &bulletin::r#trait::RingPayload,
    tag: &PetTag,
    target_fingerprint: &P::PublicKey,
) -> Result<(G1Affine, G1Affine)>
where
    D: Dkg<PublicKey = G1Affine>,
    P: Pet<ShareValue = Fr, PublicKey = G1Affine>,
{
    let threshold = ring_payload.threshold as usize;
    if certificate.all_commitments.len() != threshold {
        return Err(PetError::Crypto(format!(
            "certificate selected list has {} entries, ring threshold is {}",
            certificate.all_commitments.len(),
            threshold
        )));
    }
    if certificate.reveals.len() != threshold {
        return Err(PetError::Crypto(format!(
            "certificate has {} reveals, ring threshold is {}",
            certificate.reveals.len(),
            threshold
        )));
    }

    let mut expected_commitments: Vec<(u32, [u8; 32])> = Vec::with_capacity(threshold);
    let mut seen_commitment_ids = HashSet::new();
    for (node_id, bytes) in &certificate.all_commitments {
        if !seen_commitment_ids.insert(*node_id) {
            return Err(PetError::Crypto(format!(
                "duplicate node id {node_id} in certificate selected list"
            )));
        }
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            PetError::Deserialization("certificate commitment is not 32 bytes".to_string())
        })?;
        expected_commitments.push((*node_id, arr));
    }
    let selection_digest = pet_blind_selection_digest(
        &certificate.attempt_id,
        &certificate.context_digest,
        &expected_commitments,
    );

    let mut aggregate_r: Option<G1Affine> = None;
    let mut aggregate_diff: Option<G1Affine> = None;
    let mut seen_reveal_ids = HashSet::new();

    for signed_reveal in &certificate.reveals {
        let statement = &signed_reveal.statement;
        if statement.attempt_id != certificate.attempt_id {
            return Err(PetError::Crypto(
                "reveal attempt_id does not match the certificate".to_string(),
            ));
        }
        if statement.context_digest != certificate.context_digest {
            return Err(PetError::Crypto(
                "reveal context_digest does not match the certificate".to_string(),
            ));
        }
        if !seen_reveal_ids.insert(statement.from_node_id) {
            return Err(PetError::Crypto(format!(
                "duplicate reveal for node {}",
                statement.from_node_id
            )));
        }
        let expected_commitment = expected_commitments
            .iter()
            .find(|(id, _)| *id == statement.from_node_id)
            .map(|(_, bytes)| *bytes)
            .ok_or_else(|| {
                PetError::Crypto(format!(
                    "reveal from node {} is not present in the selected list",
                    statement.from_node_id
                ))
            })?;

        let (blinded_r, blinded_diff) = verify_one_reveal::<P>(
            statement,
            &signed_reveal.response_signature,
            ring_payload,
            tag,
            target_fingerprint,
            expected_commitment,
            selection_digest,
        )
        .into_result()?;

        aggregate_r = Some(match aggregate_r {
            Some(acc) => crypto::helpers::add_points(&acc, &blinded_r)
                .map_err(|e| PetError::Crypto(e.to_string()))?,
            None => blinded_r,
        });
        aggregate_diff = Some(match aggregate_diff {
            Some(acc) => crypto::helpers::add_points(&acc, &blinded_diff)
                .map_err(|e| PetError::Crypto(e.to_string()))?,
            None => blinded_diff,
        });
    }

    let aggregate_r =
        aggregate_r.ok_or_else(|| PetError::Crypto("certificate has no reveals".to_string()))?;
    let aggregate_diff =
        aggregate_diff.ok_or_else(|| PetError::Crypto("certificate has no reveals".to_string()))?;

    if D::public_key_is_identity(&aggregate_r) {
        return Err(PetError::Crypto(
            "certificate's aggregate ephemeral point is the identity — a corrupted or colluding \
             blinding set"
                .to_string(),
        ));
    }

    Ok((aggregate_r, aggregate_diff))
}

/// One decrypt-phase share, verified against the certificate's own
/// reconstructed aggregate points. Shared by the live decrypt-phase
/// collector and PRE admission — both need the exact same checks.
fn verify_one_decrypt<P>(
    statement: &PetBlindDecryptStatement,
    response_signature: &[u8],
    ring_payload: &bulletin::r#trait::RingPayload,
    pub_poly: &P::PubPoly,
    expected_context_digest: [u8; 32],
    expected_certificate_digest: [u8; 32],
    expected_attempt_id: &str,
    expected_aggregate_r: &[u8],
    expected_aggregate_diff: &[u8],
) -> ContributionCheckOutcome<PubShare<G1Affine>>
where
    P: Pet<ShareValue = Fr, PublicKey = G1Affine>,
{
    use ContributionCheckOutcome::{Invalid, NotAttributable, Verified};

    if statement.attempt_id != expected_attempt_id {
        return NotAttributable(PetError::Crypto(
            "decrypt statement attempt_id does not match the certificate".to_string(),
        ));
    }
    if statement.context_digest != expected_context_digest {
        return NotAttributable(PetError::Crypto(
            "decrypt statement context_digest does not match this attempt".to_string(),
        ));
    }
    if statement.certificate_digest != expected_certificate_digest {
        return NotAttributable(PetError::Crypto(
            "decrypt statement certificate_digest does not match the certificate".to_string(),
        ));
    }
    if statement.aggregate_r != expected_aggregate_r
        || statement.aggregate_diff != expected_aggregate_diff
    {
        return NotAttributable(PetError::Crypto(
            "decrypt statement aggregate points do not match the certificate's own reconstruction"
                .to_string(),
        ));
    }
    let Some(node_key) = node_key_for_id(statement.from_node_id, &ring_payload.peer_node_keys)
    else {
        return NotAttributable(PetError::Crypto(format!(
            "decrypt from_node_id {} is not in the ring committee",
            statement.from_node_id
        )));
    };
    if node_key != statement.responder_node_key {
        return NotAttributable(PetError::Crypto(format!(
            "decrypt responder_node_key does not match the resolved committee identity for node {}",
            statement.from_node_id
        )));
    }
    if let Err(e) = verify_node_message(&node_key, &statement.canonical_bytes(), response_signature)
    {
        return NotAttributable(PetError::Crypto(format!(
            "invalid decrypt signature from node {}: {e}",
            statement.from_node_id
        )));
    }
    // Everything from here on is this node's own authenticated, signed
    // claim — any failure below is genuinely attributable to it.
    let (Ok(partial), Ok(challenge), Ok(proof)) = (
        G1Affine::from_bytes(&statement.partial),
        Fr::from_bytes(&statement.challenge),
        Fr::from_bytes(&statement.proof),
    ) else {
        return Invalid(PetError::Deserialization(format!(
            "failed to decode decrypt fields from node {}",
            statement.from_node_id
        )));
    };
    let reply = PetCheckReply {
        partial: PubShare {
            i: statement.from_node_id,
            v: partial,
        },
        challenge,
        proof,
    };
    let synthetic_tag = PetTag {
        ephemeral_point: expected_aggregate_r.to_vec(),
        masked_fingerprint: Vec::new(),
    };
    if let Err(e) = P::verify_partial_pet_check(pub_poly, &synthetic_tag, &reply) {
        return Invalid(PetError::Crypto(format!(
            "decrypt share from node {} failed its per-share proof verification: {e}",
            statement.from_node_id
        )));
    }

    Verified(PubShare {
        i: statement.from_node_id,
        v: partial,
    })
}

impl<D, P> PetCoordinator<D, P>
where
    D: Dkg<ShareValue = Fr, PublicKey = G1Affine> + Clone + Send + Sync + 'static,
    P: Pet<ShareValue = Fr, PublicKey = G1Affine, PubPoly = D::PubPoly>,
    SignImpl: ThresholdSigner<
            ShareValue = Fr,
            PublicKey = G1Affine,
            DistKeyShare = DistKeyShare<Fr>,
            PubPoly = D::PubPoly,
            Signature = SignaturePoint,
            SigShare = PubShare<SigShareInner>,
        > + Send
        + Sync
        + 'static,
{
    /// Independently verify a PET-check request end to end — resolves the
    /// live ring, rebuilds the tag-knowledge-proof transcript digest from
    /// primary sources, and verifies the proof. Never trusts anything the
    /// initiator merely asserts: every value used here is either read live
    /// from the bulletin or bound into the proof itself. Unchanged from the
    /// old single-round protocol — this only validates the underlying tag,
    /// not how the threshold check around it is run.
    pub(crate) async fn verify_pet_check_request(
        &self,
        ctx: &PetCheckContext,
    ) -> Result<(PetTag, String, [u8; 32], bulletin::r#trait::RingPayload)> {
        let ring_payload = read_ring_for_route(
            &*self.app_state.bulletin,
            &ctx.document.ring_id,
            self.routes.version,
        )
        .await
        .map_err(PetError::ProtocolError)?;

        if !ring_payload.requires_pet {
            return Err(PetError::ProtocolError(format!(
                "ring {} does not require a PET check",
                ctx.document.ring_id
            )));
        }

        // `ctx.document` and `ctx.object_id` are independent fields on the
        // wire — nothing upstream of this guarantees they actually describe
        // the same document. Without this check, a malicious initiator could
        // pair a genuine document A with a different document B's id.
        crate::pre::v0::helpers::check_document_id_binding(&ctx.object_id, &ctx.document).map_err(
            |e| PetError::InvalidInput(format!("document does not match object_id: {e}")),
        )?;

        let pet_pk_hex = ring_payload.pet_pk.clone().ok_or_else(|| {
            PetError::InvalidState(format!(
                "ring {} requires PET but its checking key has not finalized",
                ctx.document.ring_id
            ))
        })?;
        let pet_pk_bytes = hex::decode(&pet_pk_hex)
            .map_err(|e| PetError::InvalidInput(format!("Invalid pet_pk hex encoding: {}", e)))?;

        let tag_json = ctx.document.pet_tag.as_deref().ok_or_else(|| {
            PetError::InvalidInput("document has no pet_tag but ring requires PET".to_string())
        })?;
        let tag_proof_json = ctx.document.pet_tag_proof.as_deref().ok_or_else(|| {
            PetError::InvalidInput(
                "document has no pet_tag_proof but ring requires PET".to_string(),
            )
        })?;
        let tag = PetTag::try_from(tag_json.to_string())
            .map_err(|e| PetError::Deserialization(format!("Failed to deserialize tag: {}", e)))?;
        let tag_proof = TagKnowledgeProof::try_from(tag_proof_json.to_string()).map_err(|e| {
            PetError::Deserialization(format!("Failed to deserialize tag proof: {}", e))
        })?;

        let secret = deserialize_secret(&ctx.document.document)?;
        let payload_proof = EncryptionProof::try_from(ctx.document.proof.clone()).map_err(|e| {
            PetError::Deserialization(format!("Failed to deserialize proof: {}", e))
        })?;
        let ciphertext_context = build_ciphertext_context(
            &ring_payload.ring_pk,
            &ctx.document,
            ctx.salt.as_deref(),
            Some(&pet_pk_hex),
        )?;

        let digest = crypto::pet_context::tag_proof_digest(
            &tag.ephemeral_point,
            &tag.masked_fingerprint,
            &pet_pk_bytes,
            &ctx.document.ring_id,
            &ciphertext_context,
            &secret,
            &payload_proof,
        );
        P::verify_tag_knowledge(&tag, &tag_proof, &digest).map_err(|e| {
            PetError::Crypto(format!("Tag-knowledge proof verification failed: {}", e))
        })?;

        Ok((tag, pet_pk_hex, digest, ring_payload))
    }

    /// The PRE-release gate: verify that a genuine blind equality test
    /// passed for `document`/`salt`, using `evidence` (the certificate plus
    /// its threshold decrypt responses) as portable, signature-backed
    /// evidence rather than re-running the three-round fan-out itself.
    /// Called by every PRE committee member before it will release a
    /// reencryption share for a `requires_pet` ring.
    ///
    /// `evidence.coordinator_node_key` is an unauthenticated claim at the
    /// wire level, but self-correcting: it feeds into the independently
    /// recomputed `context_digest` this function checks against the
    /// certificate, and every reveal inside the certificate was itself
    /// signed by a committee member who resolved the *real* coordinator
    /// identity from its own live connection — a wrong claim here simply
    /// fails that comparison.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn verify_pet_admission(
        &self,
        document: &bulletin::r#trait::DocumentPayload,
        salt: Option<&str>,
        object_id: &str,
        document_evidence: Option<ReportedDocumentEvidence>,
        audit_target_object_id: &str,
        actor_id: &str,
        valid_window: Option<ValidWindow>,
        ring_payload: &bulletin::r#trait::RingPayload,
        evidence: &PetBlindEvidence,
    ) -> Result<()> {
        let document_inline = document_evidence.is_some();
        // Authorization gate first — an unauthorized caller learns nothing
        // about whether the tag itself would have matched.
        check_pet_permission(
            &*self.app_state.authz,
            document,
            audit_target_object_id,
            actor_id,
            valid_window.clone(),
        )
        .await?;

        let ctx = PetCheckContext {
            document: document.clone(),
            salt: salt.map(str::to_string),
            object_id: object_id.to_string(),
            document_inline,
            // Unused on this path — see `handle_check_request`'s original
            // note (still accurate): this function already performed its
            // own, equivalent authorization above.
            token_string: String::new(),
            audit_target_object_id: audit_target_object_id.to_string(),
            valid_window,
        };
        let (tag, pet_pk_hex, _digest, _) = self.verify_pet_check_request(&ctx).await?;

        let blind_context = build_pet_blind_context(
            self.app_state.bulletin.chain_id(),
            ring_payload,
            &pet_pk_hex,
            self.routes.version,
            P::name(),
            &ctx,
            actor_id.to_string(),
            evidence.coordinator_node_key.clone(),
            evidence.certificate.attempt_id.clone(),
        );
        let context_digest = blind_context.context_digest();
        if context_digest != evidence.certificate.context_digest {
            return Err(PetError::Mismatch);
        }

        let target_fingerprint = P::owner_fingerprint(audit_target_object_id.as_bytes())
            .map_err(|e| PetError::Crypto(format!("Failed to compute owner fingerprint: {}", e)))?;

        let (aggregate_r, aggregate_diff) = build_and_verify_pet_blind_certificate::<D, P>(
            &evidence.certificate,
            ring_payload,
            &tag,
            &target_fingerprint,
        )
        .map_err(|_| PetError::Mismatch)?;

        let threshold = ring_payload.threshold as usize;
        let n = ring_payload.peer_node_keys.len();
        if evidence.decrypt_responses.len() < threshold {
            return Err(PetError::InsufficientShares {
                got: evidence.decrypt_responses.len(),
                need: threshold,
            });
        }

        let bundle =
            RingShareBundle::load_by_pet_ring_key(&self.app_state.local_storage, &document.ring_id)
                .map_err(|e| {
                    PetError::Storage(format!("Failed to load PET share bundle: {}", e))
                })?;
        let pub_poly_bytes = hex::decode(&bundle.public_polynomial).map_err(|e| {
            PetError::Deserialization(format!("Failed to decode PET public polynomial hex: {}", e))
        })?;
        let pub_poly = <D::PubPoly>::from_bytes(&pub_poly_bytes).map_err(|e| {
            PetError::Deserialization(format!(
                "Failed to deserialize PET public polynomial: {}",
                e
            ))
        })?;

        let aggregate_r_bytes = crypto::r#trait::CryptoSerialize::to_bytes(&aggregate_r)
            .map_err(|e| PetError::Serialization(e.to_string()))?;
        let aggregate_diff_bytes = crypto::r#trait::CryptoSerialize::to_bytes(&aggregate_diff)
            .map_err(|e| PetError::Serialization(e.to_string()))?;
        let certificate_digest = evidence.certificate.certificate_digest();

        let mut shares = Vec::with_capacity(threshold);
        let mut seen_indices = HashSet::new();
        for signed_decrypt in evidence.decrypt_responses.iter().take(threshold) {
            let share = verify_one_decrypt::<P>(
                &signed_decrypt.statement,
                &signed_decrypt.response_signature,
                ring_payload,
                &pub_poly,
                context_digest,
                certificate_digest,
                &evidence.certificate.attempt_id,
                &aggregate_r_bytes,
                &aggregate_diff_bytes,
            )
            .into_result()
            .map_err(|_| PetError::Mismatch)?;
            if !seen_indices.insert(share.i) {
                return Err(PetError::Mismatch);
            }
            shares.push(share);
        }

        let combined = P::combine_pet_check_shares(&shares, threshold, n).map_err(|e| {
            PetError::Crypto(format!("Failed to combine PET decrypt shares: {}", e))
        })?;
        let combined_bytes = crypto::r#trait::CryptoSerialize::to_bytes(&combined)
            .map_err(|e| PetError::Serialization(e.to_string()))?;

        if combined_bytes != aggregate_diff_bytes {
            return Err(PetError::Mismatch);
        }
        Ok(())
    }
}

/// Outcome of verifying one live `CommitResponse` during the initiator's
/// round-1 collection loop. Commit responses carry no signature (they are
/// transport-authenticated only, per the design doc's Round 1 section: a
/// hiding commitment has nothing yet worth attributing misconduct over), so
/// there is no reportable failure mode here — only accept or reject.
pub(crate) enum PetCommitResponseVerification {
    Verified { node_id: u32, commitment: [u8; 32] },
    Rejected,
}

/// Verify one live `PetMessage::CommitResponse` and decide whether it can be
/// accepted into `seen_node_ids`. Mirrors the old protocol's
/// `verify_check_response`'s acceptance ordering: peek, resolve identity,
/// check the response's own recomputed context digest, only then consume
/// the participant's slot.
pub(crate) fn verify_commit_response(
    response: crate::pet::v0::messages::PetMessage,
    ring_payload: &bulletin::r#trait::RingPayload,
    expected_context_digest: [u8; 32],
    seen_node_ids: &mut HashSet<u32>,
) -> PetCommitResponseVerification {
    let crate::pet::v0::messages::PetMessage::CommitResponse {
        from_node_id,
        context_digest,
        commitment,
        ..
    } = response
    else {
        return PetCommitResponseVerification::Rejected;
    };
    if seen_node_ids.contains(&from_node_id) {
        return PetCommitResponseVerification::Rejected;
    }
    if node_key_for_id(from_node_id, &ring_payload.peer_node_keys).is_none() {
        return PetCommitResponseVerification::Rejected;
    }
    if context_digest != expected_context_digest {
        return PetCommitResponseVerification::Rejected;
    }
    let Ok(commitment): std::result::Result<[u8; 32], _> = commitment.try_into() else {
        return PetCommitResponseVerification::Rejected;
    };
    if !seen_node_ids.insert(from_node_id) {
        return PetCommitResponseVerification::Rejected;
    }
    PetCommitResponseVerification::Verified {
        node_id: from_node_id,
        commitment,
    }
}

pub(crate) enum PetRevealResponseVerification {
    Verified(Box<PetBlindSignedReveal>),
    InvalidProof(Box<InvalidCryptoResponseObservation>),
    Rejected,
}

/// Verify one live `PetMessage::RevealResponse` against the exact selected
/// list fixed after round 1. `all_commitments` must already be the
/// canonical, sorted selected list; `selection_digest` is its digest.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_reveal_response<P>(
    response: crate::pet::v0::messages::PetMessage,
    ring_id: &str,
    ring_payload: &bulletin::r#trait::RingPayload,
    accused_peer_id: &str,
    tag: &PetTag,
    target_fingerprint: &P::PublicKey,
    all_commitments: &[(u32, [u8; 32])],
    selection_digest: [u8; 32],
    blind_context: &PetBlindContext,
    document_evidence: &Option<ReportedDocumentEvidence>,
    seen_node_ids: &mut HashSet<u32>,
) -> PetRevealResponseVerification
where
    P: Pet<ShareValue = Fr, PublicKey = G1Affine>,
{
    let crate::pet::v0::messages::PetMessage::RevealResponse {
        attempt_id,
        context_digest,
        selection_digest: response_selection_digest,
        from_node_id,
        commitment,
        blinded_r,
        blinded_diff,
        commit_salt,
        challenge,
        proof,
        signed_at,
        response_signature,
        ..
    } = response
    else {
        return PetRevealResponseVerification::Rejected;
    };
    if seen_node_ids.contains(&from_node_id) {
        return PetRevealResponseVerification::Rejected;
    }
    let Some(node_key) = node_key_for_id(from_node_id, &ring_payload.peer_node_keys) else {
        return PetRevealResponseVerification::Rejected;
    };
    if response_selection_digest != selection_digest {
        return PetRevealResponseVerification::Rejected;
    }
    let Some(&(_, expected_commitment)) =
        all_commitments.iter().find(|(id, _)| *id == from_node_id)
    else {
        return PetRevealResponseVerification::Rejected;
    };

    let statement = PetBlindRevealStatement {
        domain: crate::reporting::v0::types::PET_BLIND_REVEAL_RESPONSE_DOMAIN.to_string(),
        chain_id: blind_context.chain_id.clone(),
        ring_id: blind_context.ring_id.clone(),
        ring_pk: blind_context.ring_pk.clone(),
        ring_state_sha256: blind_context.ring_state_sha256.clone(),
        protocol_version: blind_context.protocol_version,
        attempt_id,
        context_digest,
        selection_digest,
        responder_node_key: node_key.clone(),
        from_node_id,
        commitment,
        blinded_r,
        blinded_diff,
        commit_salt,
        challenge,
        proof,
        signed_at,
    };

    match verify_one_reveal::<P>(
        &statement,
        &response_signature,
        ring_payload,
        tag,
        target_fingerprint,
        expected_commitment,
        selection_digest,
    ) {
        ContributionCheckOutcome::Verified(_) => {
            if !seen_node_ids.insert(from_node_id) {
                return PetRevealResponseVerification::Rejected;
            }
            PetRevealResponseVerification::Verified(Box::new(PetBlindSignedReveal {
                statement,
                response_signature,
            }))
        }
        ContributionCheckOutcome::Invalid(_) => {
            let observation = invalid_pet_blind_reveal_observation(
                ring_id.to_string(),
                node_key,
                accused_peer_id.to_string(),
                blind_context.clone(),
                statement,
                response_signature,
                document_evidence.clone(),
            );
            PetRevealResponseVerification::InvalidProof(Box::new(observation))
        }
        ContributionCheckOutcome::NotAttributable(_) => PetRevealResponseVerification::Rejected,
    }
}

pub(crate) enum PetDecryptResponseVerification {
    Verified(
        Box<crate::reporting::v0::types::PetBlindSignedDecrypt>,
        PubShare<G1Affine>,
    ),
    InvalidProof(Box<InvalidCryptoResponseObservation>),
    Rejected,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_decrypt_response<P>(
    response: crate::pet::v0::messages::PetMessage,
    ring_id: &str,
    ring_payload: &bulletin::r#trait::RingPayload,
    accused_peer_id: &str,
    pub_poly: &P::PubPoly,
    expected_context_digest: [u8; 32],
    expected_certificate_digest: [u8; 32],
    expected_attempt_id: &str,
    expected_aggregate_r: &[u8],
    expected_aggregate_diff: &[u8],
    blind_context: &PetBlindContext,
    document_evidence: &Option<ReportedDocumentEvidence>,
    seen_node_ids: &mut HashSet<u32>,
) -> PetDecryptResponseVerification
where
    P: Pet<ShareValue = Fr, PublicKey = G1Affine>,
{
    let crate::pet::v0::messages::PetMessage::DecryptResponse {
        attempt_id,
        context_digest,
        certificate_digest,
        from_node_id,
        aggregate_r,
        aggregate_diff,
        partial,
        challenge,
        proof,
        signed_at,
        public_polynomial,
        response_signature,
        ..
    } = response
    else {
        return PetDecryptResponseVerification::Rejected;
    };
    if seen_node_ids.contains(&from_node_id) {
        return PetDecryptResponseVerification::Rejected;
    }
    let Some(node_key) = node_key_for_id(from_node_id, &ring_payload.peer_node_keys) else {
        return PetDecryptResponseVerification::Rejected;
    };
    let statement = PetBlindDecryptStatement {
        domain: crate::reporting::v0::types::PET_BLIND_DECRYPT_RESPONSE_DOMAIN.to_string(),
        chain_id: blind_context.chain_id.clone(),
        ring_id: blind_context.ring_id.clone(),
        ring_pk: blind_context.ring_pk.clone(),
        ring_state_sha256: blind_context.ring_state_sha256.clone(),
        protocol_version: blind_context.protocol_version,
        attempt_id,
        context_digest,
        certificate_digest,
        responder_node_key: node_key.clone(),
        from_node_id,
        aggregate_r,
        aggregate_diff,
        partial,
        challenge,
        proof,
        signed_at,
        public_polynomial,
    };
    if verify_node_message(&node_key, &statement.canonical_bytes(), &response_signature).is_err() {
        return PetDecryptResponseVerification::Rejected;
    }

    match verify_one_decrypt::<P>(
        &statement,
        &response_signature,
        ring_payload,
        pub_poly,
        expected_context_digest,
        expected_certificate_digest,
        expected_attempt_id,
        expected_aggregate_r,
        expected_aggregate_diff,
    ) {
        ContributionCheckOutcome::Verified(share) => {
            if !seen_node_ids.insert(from_node_id) {
                return PetDecryptResponseVerification::Rejected;
            }
            let signed_decrypt = crate::reporting::v0::types::PetBlindSignedDecrypt {
                statement,
                response_signature,
            };
            PetDecryptResponseVerification::Verified(Box::new(signed_decrypt), share)
        }
        ContributionCheckOutcome::Invalid(_) => {
            let observation = invalid_pet_blind_decrypt_observation(
                ring_id.to_string(),
                node_key,
                accused_peer_id.to_string(),
                blind_context.clone(),
                statement,
                response_signature,
                document_evidence.clone(),
            );
            PetDecryptResponseVerification::InvalidProof(Box::new(observation))
        }
        ContributionCheckOutcome::NotAttributable(_) => PetDecryptResponseVerification::Rejected,
    }
}

/// Regression coverage for [`build_and_verify_pet_blind_certificate`] — the
/// single shared certificate-validation routine every other layer (the
/// initiator, every decryptor, PRE admission) relies on. Reuses the old
/// single-round protocol's exact fixture-building pattern (a degree-0
/// "identical shares" polynomial, so a genuinely DLEQ-verifiable
/// contribution needs no real DKG ceremony) — see `crypto::PetImpl`'s own
/// generic suite for the underlying `prove_blinding_correctness`/
/// `verify_blinding_correctness` coverage; this module's job is the
/// certificate-shape checks built *around* that primitive.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::test_helpers::{
        cleanup_db, create_test_app_state_with_bulletin, test_db_path, TestKeyPair,
    };
    use crate::pet::v0::messages::{CommitRequest, PetMessage};
    use crate::reporting::v0::types::{
        pet_blind_selection_digest, PetBlindCertificate, PetBlindSignedDecrypt,
        PetBlindSignedReveal, PET_BLIND_DECRYPT_RESPONSE_DOMAIN, PET_BLIND_REVEAL_RESPONSE_DOMAIN,
    };
    use authz::dummy::DummyAuthZ;
    use bulletin::dummy::DummyBulletin;
    use bulletin::r#trait::{DocumentPayload, NodeInfo, RingPayload};
    use common::blockchain::{sign_node_message_with_hex_key, ChainConfig, TxSigner};
    use crypto::r#trait::{CryptoSerialize, PriShare};
    use crypto::{DkgImpl, PetImpl};
    use network::PeerId;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use zeroize::Zeroizing;

    fn current_unix_time() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_secs()
    }

    const RING_ID: &str = "pet-blind-test-ring";
    const AUDIT_TARGET: &str = "pet-blind-cert-test-target";

    struct TestSigner {
        secret_hex: String,
        pubkey_hex: String,
    }

    fn gen_signer() -> TestSigner {
        let mut key = [0u8; 32];
        loop {
            getrandom::getrandom(&mut key).expect("generate test signing key");
            if TxSigner::new(&key, ChainConfig::local()).is_ok() {
                break;
            }
        }
        let secret_hex = hex::encode(key);
        let pubkey_hex = TxSigner::from_hex_key(&secret_hex, ChainConfig::local())
            .expect("construct test signer")
            .public_key_hex();
        TestSigner {
            secret_hex,
            pubkey_hex,
        }
    }

    /// A ring plus a genuinely tag-knowledge-verifiable document/tag, whose
    /// checking-key secret (`pet_sk`) is shared identically by every
    /// committee member (a degree-0 polynomial, mirroring the old
    /// single-round protocol's own fixture trick) — this is what lets
    /// `decrypt_share` below compute genuine, individually-DLEQ-verifiable
    /// decrypt shares without a real DKG ceremony.
    struct TagFixture {
        ring_payload: RingPayload,
        document: DocumentPayload,
        tag: PetTag,
        signers: Vec<TestSigner>,
        pet_sk: Fr,
    }

    /// The fixture's document is genuinely bound to its own `object_id` —
    /// `verify_pet_check_request` enforces this (finding #7), so callers
    /// must derive `object_id` from the actual fixture document.
    fn object_id_for(fixture: &TagFixture) -> String {
        common::blockchain::orbis::generate_document_id(
            &fixture.document.ring_id,
            &fixture.document.document,
            &fixture.document.proof,
            &fixture.document.policy_id,
            &fixture.document.resource,
            &fixture.document.permission,
            fixture.document.tier.as_deref(),
            fixture.document.timestamp,
            fixture.document.pet_tag.as_deref(),
            fixture.document.pet_tag_proof.as_deref(),
        )
        .expect("compute object_id for fixture document")
    }

    /// Builds a ring/document/tag whose tag genuinely matches `target` — a
    /// certificate's own validity never depends on this (blinding is
    /// target-independent arithmetic; only the final decrypt-phase equality
    /// check is target-sensitive), but `verify_pet_check_request` and the
    /// admission/handler tests below need a real, tag-knowledge-verifiable
    /// document to get past that gate before exercising the check under
    /// test.
    fn build_fixture(committee_size: usize, threshold: u32, target: &str) -> TagFixture {
        let mut signers: Vec<TestSigner> = (0..committee_size).map(|_| gen_signer()).collect();
        signers.sort_by(|a, b| a.pubkey_hex.cmp(&b.pubkey_hex));
        let peer_node_keys: Vec<String> = signers.iter().map(|s| s.pubkey_hex.clone()).collect();

        let (pet_sk, pet_pk) =
            crypto::helpers::generate_keypair().expect("generate pet checking keypair");
        let ring_payload = RingPayload {
            upgrade_info: Default::default(),
            ring_pk: "aa".repeat(32),
            new_peer_node_keys: None,
            new_threshold: None,
            peer_node_keys,
            threshold,
            pss_interval: 60,
            block_number_nonce: 0,
            policy_id: Some("test-policy".to_string()),
            trusted_auth_relay_dids: None,
            reporting: Default::default(),
            requires_pet: true,
            pet_pk: Some(hex::encode(
                CryptoSerialize::to_bytes(&pet_pk).expect("serialize pet_pk"),
            )),
        };

        let (r_tag, r_point) =
            crypto::helpers::generate_keypair().expect("generate ephemeral tag keypair");
        let combined = crypto::helpers::mul_point(&r_point, &pet_sk).expect("compute pet_sk*R");
        let target_fingerprint =
            PetImpl::owner_fingerprint(target.as_bytes()).expect("compute F(target)");
        let masked = crypto::helpers::add_points(&target_fingerprint, &combined)
            .expect("combine fingerprint and blinding");
        let tag = PetTag {
            ephemeral_point: CryptoSerialize::to_bytes(&r_point).expect("serialize R"),
            masked_fingerprint: CryptoSerialize::to_bytes(&masked).expect("serialize T"),
        };

        let secret = Secret {
            enc_cmt: vec![1, 2, 3],
            encrypted_data: vec![4, 5, 6],
            nonce: vec![7, 8, 9],
        };
        let payload_proof = EncryptionProof {
            challenge: vec![10, 11],
            response: vec![12, 13],
        };
        let mut document = DocumentPayload {
            ring_id: RING_ID.to_string(),
            document: serde_json::to_string(&secret).expect("serialize secret"),
            proof: String::try_from(EncryptionProof {
                challenge: payload_proof.challenge.clone(),
                response: payload_proof.response.clone(),
            })
            .expect("serialize payload proof"),
            policy_id: "test-policy".to_string(),
            resource: "test-resource".to_string(),
            permission: "read".to_string(),
            tier: None,
            timestamp: None,
            pet_tag: None,
            pet_tag_proof: None,
        };

        // Required noncircular construction order (PET audit fix checklist,
        // finding #5): the tag must be on the document *before* the context
        // it's bound into is built.
        let pet_pk_hex = ring_payload.pet_pk.clone().expect("pet_pk");
        let pet_pk_bytes = hex::decode(&pet_pk_hex).expect("decode pet_pk hex");
        document.pet_tag = Some(String::try_from(tag.clone()).expect("serialize tag"));
        let ciphertext_context =
            build_ciphertext_context(&ring_payload.ring_pk, &document, None, Some(&pet_pk_hex))
                .expect("build ciphertext context");
        let digest = crypto::pet_context::tag_proof_digest(
            &tag.ephemeral_point,
            &tag.masked_fingerprint,
            &pet_pk_bytes,
            &document.ring_id,
            &ciphertext_context,
            &secret,
            &payload_proof,
        );
        let tag_proof =
            PetImpl::prove_tag_knowledge(&r_tag, &tag, &digest).expect("prove tag knowledge");
        document.pet_tag_proof = Some(String::try_from(tag_proof).expect("serialize tag proof"));

        TagFixture {
            ring_payload,
            document,
            tag,
            signers,
            pet_sk,
        }
    }

    fn fixture_pub_poly(fixture: &TagFixture) -> crypto::PubPolyImpl {
        let pet_pk_bytes = hex::decode(fixture.ring_payload.pet_pk.as_ref().expect("pet_pk"))
            .expect("decode pet_pk hex");
        let pet_pk = G1Affine::from_bytes(&pet_pk_bytes).expect("decode pet_pk point");
        crypto::PubPolyImpl {
            commits: vec![pet_pk],
        }
    }

    /// A throwaway context sufficient for the pure `verify_reveal_response`/
    /// `verify_decrypt_response` tests below, which only pass it through to
    /// build an `InvalidProof` observation on failure — never independently
    /// validated by those functions themselves.
    fn throwaway_blind_context() -> PetBlindContext {
        PetBlindContext {
            chain_id: "test-chain".to_string(),
            protocol_version: 0,
            crypto_backend: PetImpl::name(),
            ring_id: RING_ID.to_string(),
            ring_pk: "aa".repeat(32),
            ring_state_sha256: "bb".repeat(32),
            pet_pk: "cc".repeat(32),
            object_id: "test-object".to_string(),
            salt: None,
            timestamp: None,
            document_inline: false,
            audit_target_object_id: AUDIT_TARGET.to_string(),
            actor_id: "test-actor".to_string(),
            valid_window_start: None,
            valid_window_end: None,
            coordinator_node_key: "test-coordinator".to_string(),
            attempt_id: "attempt-1".to_string(),
        }
    }

    /// This node's round-1 output plus everything round 2 needs to open it —
    /// `z_i` stays around so the test can build the real, selection-bound
    /// proof once `all_commitments` is fixed, exactly like
    /// `pending_blind::PendingBlinding` does in production.
    struct Contribution {
        node_id: u32,
        z_i: Fr,
        commit_salt: [u8; 32],
        commitment: [u8; 32],
    }

    fn commit(
        tag: &PetTag,
        target_fingerprint: &G1Affine,
        attempt_id: &str,
        context_digest: [u8; 32],
        node_id: u32,
    ) -> Contribution {
        let (z_i, _unused) = crypto::helpers::generate_keypair().expect("sample blinding scalar");
        let preliminary =
            PetImpl::prove_blinding_correctness(&z_i, tag, target_fingerprint, &[0u8; 32])
                .expect("compute blinding points");
        let blinded_r_bytes =
            CryptoSerialize::to_bytes(&preliminary.blinded_r).expect("serialize blinded_r");
        let blinded_diff_bytes =
            CryptoSerialize::to_bytes(&preliminary.blinded_diff).expect("serialize blinded_diff");
        let commit_salt: [u8; 32] = rand::random();
        let commitment = pet_blind_commit_hash(
            attempt_id,
            &context_digest,
            node_id,
            &commit_salt,
            &blinded_r_bytes,
            &blinded_diff_bytes,
        );
        Contribution {
            node_id,
            z_i,
            commit_salt,
            commitment,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn reveal(
        tag: &PetTag,
        target_fingerprint: &G1Affine,
        attempt_id: &str,
        context_digest: [u8; 32],
        all_commitments: &[(u32, [u8; 32])],
        contribution: &Contribution,
        signer: &TestSigner,
    ) -> PetBlindSignedReveal {
        let selection_digest =
            pet_blind_selection_digest(attempt_id, &context_digest, all_commitments);
        let blind_transcript_digest = pet_blind_proof_transcript_digest(
            attempt_id,
            &context_digest,
            &selection_digest,
            contribution.node_id,
            &contribution.commitment,
        );
        let real_reply = PetImpl::prove_blinding_correctness(
            &contribution.z_i,
            tag,
            target_fingerprint,
            &blind_transcript_digest,
        )
        .expect("compute blinding-correctness proof");
        let statement = PetBlindRevealStatement {
            domain: PET_BLIND_REVEAL_RESPONSE_DOMAIN.to_string(),
            chain_id: "test-chain".to_string(),
            ring_id: RING_ID.to_string(),
            ring_pk: "aa".repeat(32),
            ring_state_sha256: "bb".repeat(32),
            protocol_version: 0,
            attempt_id: attempt_id.to_string(),
            context_digest,
            selection_digest,
            responder_node_key: signer.pubkey_hex.clone(),
            from_node_id: contribution.node_id,
            commitment: contribution.commitment.to_vec(),
            blinded_r: CryptoSerialize::to_bytes(&real_reply.blinded_r)
                .expect("serialize blinded_r"),
            blinded_diff: CryptoSerialize::to_bytes(&real_reply.blinded_diff)
                .expect("serialize blinded_diff"),
            commit_salt: contribution.commit_salt,
            challenge: CryptoSerialize::to_bytes(&real_reply.challenge)
                .expect("serialize challenge"),
            proof: CryptoSerialize::to_bytes(&real_reply.proof).expect("serialize proof"),
            signed_at: 1_700_000_000,
        };
        let response_signature =
            sign_node_message_with_hex_key(&signer.secret_hex, &statement.canonical_bytes())
                .expect("sign reveal");
        PetBlindSignedReveal {
            statement,
            response_signature,
        }
    }

    fn reveal_statement_to_message(
        statement: PetBlindRevealStatement,
        response_signature: Vec<u8>,
    ) -> PetMessage {
        PetMessage::RevealResponse {
            request_id: "reveal-attempt-1".to_string(),
            attempt_id: statement.attempt_id,
            context_digest: statement.context_digest,
            selection_digest: statement.selection_digest,
            from_node_id: statement.from_node_id,
            commitment: statement.commitment,
            blinded_r: statement.blinded_r,
            blinded_diff: statement.blinded_diff,
            commit_salt: statement.commit_salt,
            challenge: statement.challenge,
            proof: statement.proof,
            signed_at: statement.signed_at,
            response_signature,
        }
    }

    fn genuine_reveal_message(
        fixture: &TagFixture,
        target_fingerprint: &G1Affine,
        attempt_id: &str,
        context_digest: [u8; 32],
        all_commitments: &[(u32, [u8; 32])],
        contribution: &Contribution,
    ) -> PetMessage {
        let signer = &fixture.signers[(contribution.node_id - 1) as usize];
        let signed = reveal(
            &fixture.tag,
            target_fingerprint,
            attempt_id,
            context_digest,
            all_commitments,
            contribution,
            signer,
        );
        reveal_statement_to_message(signed.statement, signed.response_signature)
    }

    /// A reveal claiming `contribution.node_id`'s slot with an invalid
    /// signature — exactly what a malicious responder sends to try to
    /// preempt an honest participant's id without ever having a real key.
    fn spoofed_reveal_message(
        fixture: &TagFixture,
        target_fingerprint: &G1Affine,
        attempt_id: &str,
        context_digest: [u8; 32],
        all_commitments: &[(u32, [u8; 32])],
        contribution: &Contribution,
    ) -> PetMessage {
        let mut message = genuine_reveal_message(
            fixture,
            target_fingerprint,
            attempt_id,
            context_digest,
            all_commitments,
            contribution,
        );
        if let PetMessage::RevealResponse {
            response_signature, ..
        } = &mut message
        {
            response_signature[0] ^= 0x01;
        }
        message
    }

    /// A reveal genuinely signed by `contribution.node_id`'s real key,
    /// opening its real commitment (`blinded_r`/`blinded_diff`/`commit_salt`
    /// all genuine), but with a caller-supplied `challenge`/`proof` —
    /// authenticated and self-consistent with its own commitment, but
    /// cryptographically wrong (decodable garbage) or undecodable
    /// (malformed), depending what the caller passes. Distinguishing these
    /// two matters: finding #9 in the old protocol was exactly a malformed
    /// response dodging attribution that a decodable-but-wrong one didn't.
    #[allow(clippy::too_many_arguments)]
    fn reveal_with_bad_proof(
        fixture: &TagFixture,
        target_fingerprint: &G1Affine,
        attempt_id: &str,
        context_digest: [u8; 32],
        all_commitments: &[(u32, [u8; 32])],
        contribution: &Contribution,
        challenge: Vec<u8>,
        proof: Vec<u8>,
    ) -> PetMessage {
        let signer = &fixture.signers[(contribution.node_id - 1) as usize];
        let selection_digest =
            pet_blind_selection_digest(attempt_id, &context_digest, all_commitments);
        let points = PetImpl::prove_blinding_correctness(
            &contribution.z_i,
            &fixture.tag,
            target_fingerprint,
            &[0u8; 32],
        )
        .expect("recompute genuine blinded points");
        let statement = PetBlindRevealStatement {
            domain: PET_BLIND_REVEAL_RESPONSE_DOMAIN.to_string(),
            chain_id: "test-chain".to_string(),
            ring_id: RING_ID.to_string(),
            ring_pk: "aa".repeat(32),
            ring_state_sha256: "bb".repeat(32),
            protocol_version: 0,
            attempt_id: attempt_id.to_string(),
            context_digest,
            selection_digest,
            responder_node_key: signer.pubkey_hex.clone(),
            from_node_id: contribution.node_id,
            commitment: contribution.commitment.to_vec(),
            blinded_r: CryptoSerialize::to_bytes(&points.blinded_r).expect("serialize blinded_r"),
            blinded_diff: CryptoSerialize::to_bytes(&points.blinded_diff)
                .expect("serialize blinded_diff"),
            commit_salt: contribution.commit_salt,
            challenge,
            proof,
            signed_at: 1_700_000_000,
        };
        let response_signature =
            sign_node_message_with_hex_key(&signer.secret_hex, &statement.canonical_bytes())
                .expect("sign reveal with bad proof");
        reveal_statement_to_message(statement, response_signature)
    }

    fn decrypt_statement_to_message(
        statement: PetBlindDecryptStatement,
        response_signature: Vec<u8>,
    ) -> PetMessage {
        PetMessage::DecryptResponse {
            request_id: "decrypt-attempt-1".to_string(),
            attempt_id: statement.attempt_id,
            context_digest: statement.context_digest,
            certificate_digest: statement.certificate_digest,
            from_node_id: statement.from_node_id,
            aggregate_r: statement.aggregate_r,
            aggregate_diff: statement.aggregate_diff,
            partial: statement.partial,
            challenge: statement.challenge,
            proof: statement.proof,
            signed_at: statement.signed_at,
            public_polynomial: statement.public_polynomial,
            response_signature,
        }
    }

    /// A genuine decrypt share from committee member `node_id` against
    /// `certificate`'s reconstructed aggregate points — computed from the
    /// fixture's real (shared) `pet_sk`, reusing the existing per-share DLEQ
    /// (`Pet::partial_pet_check`) unchanged, against `aggregate_r` in place
    /// of the old protocol's bare `R`.
    fn decrypt_share(
        fixture: &TagFixture,
        certificate: &PetBlindCertificate,
        aggregate_r: &G1Affine,
        aggregate_diff: &G1Affine,
        node_id: u32,
    ) -> PetBlindSignedDecrypt {
        let aggregate_r_bytes =
            CryptoSerialize::to_bytes(aggregate_r).expect("serialize aggregate_r");
        let aggregate_diff_bytes =
            CryptoSerialize::to_bytes(aggregate_diff).expect("serialize aggregate_diff");
        let synthetic_tag = PetTag {
            ephemeral_point: aggregate_r_bytes.clone(),
            masked_fingerprint: Vec::new(),
        };
        let reply = PetImpl::partial_pet_check(&fixture.pet_sk, node_id, &synthetic_tag)
            .expect("compute genuine decrypt share");
        let signer = &fixture.signers[(node_id - 1) as usize];
        let statement = PetBlindDecryptStatement {
            domain: PET_BLIND_DECRYPT_RESPONSE_DOMAIN.to_string(),
            chain_id: "test-chain".to_string(),
            ring_id: RING_ID.to_string(),
            ring_pk: "aa".repeat(32),
            ring_state_sha256: "bb".repeat(32),
            protocol_version: 0,
            attempt_id: certificate.attempt_id.clone(),
            context_digest: certificate.context_digest,
            certificate_digest: certificate.certificate_digest(),
            responder_node_key: signer.pubkey_hex.clone(),
            from_node_id: node_id,
            aggregate_r: aggregate_r_bytes,
            aggregate_diff: aggregate_diff_bytes,
            partial: CryptoSerialize::to_bytes(&reply.partial.v).expect("serialize partial"),
            challenge: CryptoSerialize::to_bytes(&reply.challenge).expect("serialize challenge"),
            proof: CryptoSerialize::to_bytes(&reply.proof).expect("serialize proof"),
            signed_at: 1_700_000_000,
            // Unused by the live-round verification these fixtures exercise
            // (`verify_one_decrypt` takes its own authoritative `pub_poly`
            // parameter) — only report verification reads this field.
            public_polynomial: vec![0xaa, 0xbb],
        };
        let response_signature =
            sign_node_message_with_hex_key(&signer.secret_hex, &statement.canonical_bytes())
                .expect("sign decrypt share");
        PetBlindSignedDecrypt {
            statement,
            response_signature,
        }
    }

    /// Genuinely signed by `node_id`, opening cleanly against
    /// `certificate`'s real aggregate points, but with undecodable
    /// `partial`/`challenge`/`proof` bytes.
    fn malformed_decrypt_share(
        fixture: &TagFixture,
        certificate: &PetBlindCertificate,
        aggregate_r: &G1Affine,
        aggregate_diff: &G1Affine,
        node_id: u32,
    ) -> PetBlindSignedDecrypt {
        let aggregate_r_bytes =
            CryptoSerialize::to_bytes(aggregate_r).expect("serialize aggregate_r");
        let aggregate_diff_bytes =
            CryptoSerialize::to_bytes(aggregate_diff).expect("serialize aggregate_diff");
        let signer = &fixture.signers[(node_id - 1) as usize];
        let statement = PetBlindDecryptStatement {
            domain: PET_BLIND_DECRYPT_RESPONSE_DOMAIN.to_string(),
            chain_id: "test-chain".to_string(),
            ring_id: RING_ID.to_string(),
            ring_pk: "aa".repeat(32),
            ring_state_sha256: "bb".repeat(32),
            protocol_version: 0,
            attempt_id: certificate.attempt_id.clone(),
            context_digest: certificate.context_digest,
            certificate_digest: certificate.certificate_digest(),
            responder_node_key: signer.pubkey_hex.clone(),
            from_node_id: node_id,
            aggregate_r: aggregate_r_bytes,
            aggregate_diff: aggregate_diff_bytes,
            partial: vec![0xff, 0xff, 0xff],
            challenge: vec![0xff, 0xff, 0xff],
            proof: vec![0xff, 0xff, 0xff],
            signed_at: 1_700_000_000,
            public_polynomial: vec![0xaa, 0xbb],
        };
        let response_signature =
            sign_node_message_with_hex_key(&signer.secret_hex, &statement.canonical_bytes())
                .expect("sign malformed decrypt share");
        PetBlindSignedDecrypt {
            statement,
            response_signature,
        }
    }

    /// Builds a certificate for exactly `node_ids` (sorted, canonical order)
    /// against `attempt_id`/`context_digest` — the caller picks these last
    /// two explicitly (rather than a fixed placeholder) whenever the result
    /// must match an externally, independently recomputed digest, as
    /// `verify_pet_admission`'s own tests need.
    fn build_certificate_for(
        fixture: &TagFixture,
        target_fingerprint: &G1Affine,
        attempt_id: &str,
        context_digest: [u8; 32],
        node_ids: &[u32],
    ) -> PetBlindCertificate {
        let contributions: Vec<Contribution> = node_ids
            .iter()
            .map(|&id| {
                commit(
                    &fixture.tag,
                    target_fingerprint,
                    attempt_id,
                    context_digest,
                    id,
                )
            })
            .collect();
        let all_commitments: Vec<(u32, [u8; 32])> = contributions
            .iter()
            .map(|c| (c.node_id, c.commitment))
            .collect();
        let reveals: Vec<PetBlindSignedReveal> = contributions
            .iter()
            .map(|c| {
                let signer = &fixture.signers[(c.node_id - 1) as usize];
                reveal(
                    &fixture.tag,
                    target_fingerprint,
                    attempt_id,
                    context_digest,
                    &all_commitments,
                    c,
                    signer,
                )
            })
            .collect();
        PetBlindCertificate {
            attempt_id: attempt_id.to_string(),
            context_digest,
            all_commitments: all_commitments
                .iter()
                .map(|(id, bytes)| (*id, bytes.to_vec()))
                .collect(),
            reveals,
        }
    }

    /// Builds a genuine, fully valid 2-of-3 certificate with a fixed
    /// placeholder attempt_id/context_digest — the shared base every
    /// certificate-only rejection test below tampers with exactly one
    /// thing. Certificate-level checks don't depend on the digest matching
    /// any external context (that binding is `verify_pet_admission`'s job,
    /// tested separately below), so a fixed placeholder is fine here.
    fn build_valid_certificate(
        fixture: &TagFixture,
        target_fingerprint: &G1Affine,
    ) -> PetBlindCertificate {
        build_certificate_for(fixture, target_fingerprint, "attempt-1", [7u8; 32], &[1, 2])
    }

    /// A deterministic 64-hex-char peer id for committee member `index` —
    /// registered as that signer's `NodeInfo` below so
    /// `resolve_coordinator_node_key` (every handler's first line of
    /// defense against a spoofed coordinator identity) can resolve it.
    fn peer_id_hex_for(index: usize) -> String {
        hex::encode([(index as u8) + 1; 32])
    }

    async fn test_coordinator(
        db_name: &str,
        ring_payload: &RingPayload,
    ) -> PetCoordinator<DkgImpl, PetImpl> {
        let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("dummy bulletin"));
        dummy_bulletin
            .set_ring(RING_ID.to_string(), ring_payload.clone())
            .expect("seed ring");
        // Every phase's handler independently resolves the authenticated
        // transport sender's ring identity (never trusting a claimed
        // `from_node_id`) — register a resolvable NodeInfo for each
        // committee member so that resolution can succeed in tests that
        // need it.
        for (i, node_key) in ring_payload.peer_node_keys.iter().enumerate() {
            dummy_bulletin
                .set_node_info(
                    node_key.clone(),
                    NodeInfo {
                        peer_id: peer_id_hex_for(i),
                        controller_key: "controller".to_string(),
                        whitelisted_policy_ids: vec![],
                        whitelisted_ring_ids: vec![],
                    },
                )
                .expect("seed node info");
        }
        let app_state = create_test_app_state_with_bulletin(true, dummy_bulletin, db_name).await;

        // `verify_pet_admission`/every handler loads this ring's PET
        // checking-key bundle to get a public polynomial to verify
        // per-share DLEQ proofs against. Every fixture's "threshold
        // sharing" is the degree-0 "identical shares" trick
        // (`TagFixture::pet_sk`), so a single-commit polynomial pinned to
        // the ring's own `pet_pk` is exactly the matching public
        // commitment. `share_bytes` carries the same `pet_sk` as every
        // other "share" for the same reason, at index 1 — matching
        // `peer_id_hex_for(0)`/`signers[0]`, so this node can act as
        // committee member 1 in handler tests.
        let pet_pk_bytes = hex::decode(ring_payload.pet_pk.as_ref().expect("ring_payload.pet_pk"))
            .expect("decode pet_pk hex");
        let pet_pk = G1Affine::from_bytes(&pet_pk_bytes).expect("decode pet_pk point");
        let pub_poly = crypto::PubPolyImpl {
            commits: vec![pet_pk],
        };
        let placeholder_share = PriShare {
            i: 1,
            v: Fr::from(1u64),
        };
        let bundle = RingShareBundle {
            share_bytes: Zeroizing::new(
                CryptoSerialize::to_bytes(&placeholder_share).expect("serialize placeholder share"),
            ),
            public_polynomial: hex::encode(
                CryptoSerialize::to_bytes(&pub_poly).expect("serialize pub_poly"),
            ),
            last_pss: 0,
        };
        bundle
            .save_by_pet_ring_key(&app_state.local_storage, RING_ID)
            .expect("seed PET bundle");

        PetCoordinator::<DkgImpl, PetImpl>::with_routes(Arc::new(app_state), &::network::V0)
    }

    // ========================================================================
    // Audit finding #7: `document` and `object_id` are independent fields on
    // `PetCheckContext`'s wire — nothing upstream of `verify_pet_check_request`
    // guarantees a live PET request's initiator supplied a genuinely matching
    // pair. Unchanged from the old single-round protocol.
    // ========================================================================

    #[tokio::test]
    #[serial_test::serial]
    async fn verify_pet_check_request_rejects_a_document_object_id_mismatch() {
        let db_name = "pet_check_request_rejects_document_object_id_mismatch";
        let fixture_a = build_fixture(3, 2, AUDIT_TARGET);
        let fixture_b = build_fixture(3, 2, AUDIT_TARGET);
        let coordinator = test_coordinator(db_name, &fixture_a.ring_payload).await;

        let ctx = PetCheckContext {
            document: fixture_a.document.clone(),
            salt: None,
            object_id: object_id_for(&fixture_b),
            document_inline: false,
            token_string: String::new(),
            audit_target_object_id: String::new(),
            valid_window: None,
        };

        let result = coordinator.verify_pet_check_request(&ctx).await;
        assert!(
            matches!(result, Err(PetError::InvalidInput(_))),
            "document = A paired with object_id = id(B) must be rejected before any proof is \
             computed or signed, got {:?}",
            result
        );
        cleanup_db(&test_db_path(db_name));
    }

    // ========================================================================
    // Finding #3 (PET audit fix checklist): every phase's handler is the one
    // entry point reachable from a raw wire message with no other upstream
    // authentication. `verify_pet_audit_authorization` closes that gap; it
    // needs only an `Authz` impl, so most of these tests call it directly.
    // ========================================================================

    fn audit_authz_fixture() -> (TestKeyPair, DocumentPayload, String) {
        let signer = TestKeyPair::new();
        let document = DocumentPayload {
            ring_id: "audit-authz-ring".to_string(),
            document: String::new(),
            proof: String::new(),
            policy_id: "test-policy".to_string(),
            resource: "test-resource".to_string(),
            permission: "read".to_string(),
            tier: None,
            timestamp: None,
            pet_tag: None,
            pet_tag_proof: None,
        };
        (signer, document, "audit-authz-object".to_string())
    }

    // ========================================================================
    // `check_pet_permission` itself — the ACP gate `verify_pet_audit_authorization`
    // (and the normal initiator path) both rely on. Flagged twice before as a real
    // gap: `DummyAuthZ` is permissive by construction, so every test above and below
    // that uses it can only ever exercise the *accept* path — none of them prove this
    // gate actually rejects a denied actor. `DenyingAuthZ` (authz::dummy) closes that.
    // ========================================================================

    #[tokio::test]
    async fn check_pet_permission_rejects_a_denied_actor() {
        let (_signer, document, _object_id) = audit_authz_fixture();
        let authz = authz::dummy::DenyingAuthZ;

        let result = check_pet_permission(&authz, &document, "any-target", "any-actor", None).await;

        assert!(
            matches!(result, Err(PetError::Mismatch)),
            "a denied ACP decision must reject the PET permission gate: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn check_pet_permission_accepts_an_authorized_actor() {
        let (_signer, document, _object_id) = audit_authz_fixture();
        let authz = DummyAuthZ;

        let result = check_pet_permission(&authz, &document, "any-target", "any-actor", None).await;

        assert!(
            result.is_ok(),
            "an authorized ACP decision must pass the PET permission gate: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn verify_pet_audit_authorization_rejects_a_garbage_token() {
        let (_signer, document, object_id) = audit_authz_fixture();
        let ctx = PetCheckContext {
            document,
            salt: None,
            object_id,
            document_inline: false,
            token_string: "not-a-jwt".to_string(),
            audit_target_object_id: "any-target".to_string(),
            valid_window: None,
        };
        let authz = DummyAuthZ;
        let result = verify_pet_audit_authorization(&authz, &ctx, None, current_unix_time()).await;
        assert!(
            matches!(result, Err(PetError::InvalidInput(_))),
            "a garbage token must be rejected: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn verify_pet_audit_authorization_rejects_a_token_for_a_different_object_id() {
        let (signer, document, object_id) = audit_authz_fixture();
        let token = signer
            .create_pre_jwt(b"unused".to_vec(), "a-different-object-id", None, None)
            .expect("sign token");
        let ctx = PetCheckContext {
            document,
            salt: None,
            object_id,
            document_inline: false,
            token_string: token,
            audit_target_object_id: "any-target".to_string(),
            valid_window: None,
        };
        let authz = DummyAuthZ;
        let result = verify_pet_audit_authorization(&authz, &ctx, None, current_unix_time()).await;
        assert!(
            matches!(result, Err(PetError::InvalidInput(_))),
            "a token authorizing a different object_id must be rejected: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn verify_pet_audit_authorization_rejects_a_token_for_a_different_salt() {
        let (signer, document, object_id) = audit_authz_fixture();
        let token = signer
            .create_pre_jwt(
                b"unused".to_vec(),
                &object_id,
                None,
                Some("original-salt".to_string()),
            )
            .expect("sign token");
        let ctx = PetCheckContext {
            document,
            salt: Some("different-salt".to_string()),
            object_id,
            document_inline: false,
            token_string: token,
            audit_target_object_id: "any-target".to_string(),
            valid_window: None,
        };
        let authz = DummyAuthZ;
        let result = verify_pet_audit_authorization(&authz, &ctx, None, current_unix_time()).await;
        assert!(
            matches!(result, Err(PetError::InvalidInput(_))),
            "a token authorizing a different salt must be rejected: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn verify_pet_audit_authorization_accepts_a_genuinely_matching_token() {
        let (signer, document, object_id) = audit_authz_fixture();
        let token = signer
            .create_pre_jwt(b"unused".to_vec(), &object_id, None, None)
            .expect("sign token");
        let ctx = PetCheckContext {
            document,
            salt: None,
            object_id,
            document_inline: false,
            token_string: token,
            audit_target_object_id: "any-target".to_string(),
            valid_window: None,
        };
        let authz = DummyAuthZ;
        let result = verify_pet_audit_authorization(&authz, &ctx, None, current_unix_time()).await;
        assert!(
            result.is_ok(),
            "a genuinely matching, valid token must be accepted: {:?}",
            result
        );
    }

    /// End-to-end wiring check (not just the standalone function): a raw
    /// `CommitRequest` with no valid audit authorization must be rejected by
    /// the real `handle_message`/`handle_commit_request` path, before this
    /// node's secret share is ever touched. `verify_pet_audit_authorization`
    /// runs before `resolve_coordinator_node_key`, so an arbitrary peer id
    /// (not registered anywhere) is fine here.
    #[tokio::test]
    #[serial_test::serial]
    async fn handle_commit_request_rejects_a_request_with_no_valid_audit_authorization() {
        let db_name = "pet_handle_commit_request_rejects_unauthorized_audit";
        let fixture = build_fixture(3, 2, AUDIT_TARGET);
        let coordinator = test_coordinator(db_name, &fixture.ring_payload).await;
        let peer_id = PeerId::new(vec![0u8; 32]);

        let request = CommitRequest {
            request_id: "commit-attempt-1".to_string(),
            attempt_id: "attempt-1".to_string(),
            from_node_id: 1,
            context: PetCheckContext {
                document: fixture.document.clone(),
                salt: None,
                object_id: object_id_for(&fixture),
                document_inline: false,
                token_string: "not-a-jwt".to_string(),
                audit_target_object_id: AUDIT_TARGET.to_string(),
                valid_window: None,
            },
        };

        let result = coordinator
            .handle_message(PetMessage::CommitRequest(Box::new(request)), &peer_id)
            .await;

        assert!(
            matches!(result, Err(PetError::InvalidInput(_))),
            "a CommitRequest with no valid audit authorization must be rejected: {:?}",
            result
        );
        cleanup_db(&test_db_path(db_name));
    }

    /// Confirms the rejection above isn't vacuous against a gate that
    /// rejects every `CommitRequest`: a valid, correctly-bound audit token,
    /// from a peer id that genuinely resolves to a ring committee member,
    /// must still be accepted end-to-end.
    #[tokio::test]
    #[serial_test::serial]
    async fn handle_commit_request_accepts_a_request_with_valid_audit_authorization() {
        let db_name = "pet_handle_commit_request_accepts_valid_audit_authorization";
        let fixture = build_fixture(3, 2, AUDIT_TARGET);
        let coordinator = test_coordinator(db_name, &fixture.ring_payload).await;
        // Committee member 1 (`signers[0]`/`peer_id_hex_for(0)`) plays the
        // coordinator here — this node's own stored share is also index 1
        // (see `test_coordinator`), so it can answer as itself.
        let peer_id = PeerId::new(hex::decode(peer_id_hex_for(0)).expect("decode test peer id"));

        let object_id = object_id_for(&fixture);
        let token = TestKeyPair::new()
            .create_pre_jwt(b"unused".to_vec(), &object_id, None, None)
            .expect("sign token");
        let request = CommitRequest {
            request_id: "commit-attempt-1".to_string(),
            attempt_id: "attempt-1".to_string(),
            from_node_id: 1,
            context: PetCheckContext {
                document: fixture.document.clone(),
                salt: None,
                object_id,
                document_inline: false,
                token_string: token,
                audit_target_object_id: AUDIT_TARGET.to_string(),
                valid_window: None,
            },
        };

        let result = coordinator
            .handle_message(PetMessage::CommitRequest(Box::new(request)), &peer_id)
            .await;

        assert!(
            matches!(result, Ok(Some(PetMessage::CommitResponse { .. }))),
            "a CommitRequest with a valid, correctly-bound audit token from a resolvable \
             coordinator must be accepted: {:?}",
            result
        );
        cleanup_db(&test_db_path(db_name));
    }

    // ========================================================================
    // `verify_pet_admission` — the PRE-release gate. Every rejection below
    // isolates one specific defect in an otherwise-genuine `PetBlindEvidence`
    // bundle; the final test confirms genuine evidence is admitted, so the
    // rejections above aren't vacuous against a gate that rejects everything.
    // ========================================================================

    const ADMISSION_ACTOR: &str = "test-actor";
    const ADMISSION_COORDINATOR: &str = "admission-coordinator";
    const ADMISSION_ATTEMPT: &str = "admission-attempt-1";

    fn admission_ctx(fixture: &TagFixture) -> PetCheckContext {
        PetCheckContext {
            document: fixture.document.clone(),
            salt: None,
            object_id: object_id_for(fixture),
            document_inline: false,
            token_string: String::new(),
            audit_target_object_id: AUDIT_TARGET.to_string(),
            valid_window: None,
        }
    }

    /// Independently recomputes exactly what `verify_pet_admission` itself
    /// will compute for `context_digest`, so the test's own evidence can be
    /// built to genuinely match it — mirrors how a real PRE peer's evidence
    /// only ever admits because its signers independently derived the same
    /// digest, never because the digest was merely copied.
    fn admission_context_digest(
        coordinator: &PetCoordinator<DkgImpl, PetImpl>,
        fixture: &TagFixture,
    ) -> [u8; 32] {
        let ctx = admission_ctx(fixture);
        let blind_context = build_pet_blind_context(
            coordinator.app_state.bulletin.chain_id(),
            &fixture.ring_payload,
            fixture.ring_payload.pet_pk.as_ref().expect("pet_pk"),
            coordinator.routes.version,
            PetImpl::name(),
            &ctx,
            ADMISSION_ACTOR.to_string(),
            ADMISSION_COORDINATOR.to_string(),
            ADMISSION_ATTEMPT.to_string(),
        );
        blind_context.context_digest()
    }

    fn build_admission_evidence(
        fixture: &TagFixture,
        target_fingerprint: &G1Affine,
        context_digest: [u8; 32],
        reveal_node_ids: &[u32],
        decrypt_node_ids: &[u32],
    ) -> PetBlindEvidence {
        let certificate = build_certificate_for(
            fixture,
            target_fingerprint,
            ADMISSION_ATTEMPT,
            context_digest,
            reveal_node_ids,
        );
        let (aggregate_r, aggregate_diff) =
            build_and_verify_pet_blind_certificate::<DkgImpl, PetImpl>(
                &certificate,
                &fixture.ring_payload,
                &fixture.tag,
                target_fingerprint,
            )
            .expect("certificate must be genuinely valid in this fixture");
        let decrypt_responses = decrypt_node_ids
            .iter()
            .map(|&id| decrypt_share(fixture, &certificate, &aggregate_r, &aggregate_diff, id))
            .collect();
        PetBlindEvidence {
            certificate,
            decrypt_responses,
            coordinator_node_key: ADMISSION_COORDINATOR.to_string(),
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn verify_pet_admission_rejects_missing_decrypt_responses() {
        let db_name = "pet_admission_rejects_missing_decrypt_responses";
        let fixture = build_fixture(3, 2, AUDIT_TARGET);
        let coordinator = test_coordinator(db_name, &fixture.ring_payload).await;
        let context_digest = admission_context_digest(&coordinator, &fixture);
        let target_fingerprint =
            PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
        let evidence =
            build_admission_evidence(&fixture, &target_fingerprint, context_digest, &[1, 2], &[]);

        let result = coordinator
            .verify_pet_admission(
                &fixture.document,
                None,
                &object_id_for(&fixture),
                None,
                AUDIT_TARGET,
                ADMISSION_ACTOR,
                None,
                &fixture.ring_payload,
                &evidence,
            )
            .await;

        assert!(
            matches!(
                result,
                Err(PetError::InsufficientShares { got: 0, need: 2 })
            ),
            "expected InsufficientShares, got {:?}",
            result
        );
        cleanup_db(&test_db_path(db_name));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn verify_pet_admission_rejects_insufficient_decrypt_responses() {
        let db_name = "pet_admission_rejects_insufficient_decrypt_responses";
        let fixture = build_fixture(3, 2, AUDIT_TARGET);
        let coordinator = test_coordinator(db_name, &fixture.ring_payload).await;
        let context_digest = admission_context_digest(&coordinator, &fixture);
        let target_fingerprint =
            PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
        let evidence =
            build_admission_evidence(&fixture, &target_fingerprint, context_digest, &[1, 2], &[1]);

        let result = coordinator
            .verify_pet_admission(
                &fixture.document,
                None,
                &object_id_for(&fixture),
                None,
                AUDIT_TARGET,
                ADMISSION_ACTOR,
                None,
                &fixture.ring_payload,
                &evidence,
            )
            .await;

        assert!(
            matches!(
                result,
                Err(PetError::InsufficientShares { got: 1, need: 2 })
            ),
            "expected InsufficientShares, got {:?}",
            result
        );
        cleanup_db(&test_db_path(db_name));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn verify_pet_admission_rejects_duplicate_decrypt_indices() {
        let db_name = "pet_admission_rejects_duplicate_decrypt_indices";
        let fixture = build_fixture(3, 2, AUDIT_TARGET);
        let coordinator = test_coordinator(db_name, &fixture.ring_payload).await;
        let context_digest = admission_context_digest(&coordinator, &fixture);
        let target_fingerprint =
            PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
        // Two independently-genuine decrypt shares for the *same* slot
        // (byte-identical rebuilds) — isolates the duplicate-index check.
        let evidence = build_admission_evidence(
            &fixture,
            &target_fingerprint,
            context_digest,
            &[1, 2],
            &[1, 1],
        );

        let result = coordinator
            .verify_pet_admission(
                &fixture.document,
                None,
                &object_id_for(&fixture),
                None,
                AUDIT_TARGET,
                ADMISSION_ACTOR,
                None,
                &fixture.ring_payload,
                &evidence,
            )
            .await;

        assert!(
            matches!(result, Err(PetError::Mismatch)),
            "expected a duplicate-index rejection, got {:?}",
            result
        );
        cleanup_db(&test_db_path(db_name));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn verify_pet_admission_rejects_a_forged_decrypt_signature() {
        let db_name = "pet_admission_rejects_a_forged_decrypt_signature";
        let fixture = build_fixture(3, 2, AUDIT_TARGET);
        let coordinator = test_coordinator(db_name, &fixture.ring_payload).await;
        let context_digest = admission_context_digest(&coordinator, &fixture);
        let target_fingerprint =
            PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
        let mut evidence = build_admission_evidence(
            &fixture,
            &target_fingerprint,
            context_digest,
            &[1, 2],
            &[1, 2],
        );
        evidence.decrypt_responses[1].response_signature[0] ^= 0x01;

        let result = coordinator
            .verify_pet_admission(
                &fixture.document,
                None,
                &object_id_for(&fixture),
                None,
                AUDIT_TARGET,
                ADMISSION_ACTOR,
                None,
                &fixture.ring_payload,
                &evidence,
            )
            .await;

        assert!(
            matches!(result, Err(PetError::Mismatch)),
            "expected a signature-verification rejection, got {:?}",
            result
        );
        cleanup_db(&test_db_path(db_name));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn verify_pet_admission_rejects_a_malformed_decrypt_share() {
        let db_name = "pet_admission_rejects_a_malformed_decrypt_share";
        let fixture = build_fixture(3, 2, AUDIT_TARGET);
        let coordinator = test_coordinator(db_name, &fixture.ring_payload).await;
        let context_digest = admission_context_digest(&coordinator, &fixture);
        let target_fingerprint =
            PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
        let certificate = build_certificate_for(
            &fixture,
            &target_fingerprint,
            ADMISSION_ATTEMPT,
            context_digest,
            &[1, 2],
        );
        let (aggregate_r, aggregate_diff) =
            build_and_verify_pet_blind_certificate::<DkgImpl, PetImpl>(
                &certificate,
                &fixture.ring_payload,
                &fixture.tag,
                &target_fingerprint,
            )
            .expect("certificate must be genuinely valid in this fixture");
        let genuine = decrypt_share(&fixture, &certificate, &aggregate_r, &aggregate_diff, 1);
        let malformed =
            malformed_decrypt_share(&fixture, &certificate, &aggregate_r, &aggregate_diff, 2);
        let evidence = PetBlindEvidence {
            certificate,
            decrypt_responses: vec![genuine, malformed],
            coordinator_node_key: ADMISSION_COORDINATOR.to_string(),
        };

        let result = coordinator
            .verify_pet_admission(
                &fixture.document,
                None,
                &object_id_for(&fixture),
                None,
                AUDIT_TARGET,
                ADMISSION_ACTOR,
                None,
                &fixture.ring_payload,
                &evidence,
            )
            .await;

        assert!(
            matches!(result, Err(PetError::Mismatch)),
            "expected a malformed-share rejection, got {:?}",
            result
        );
        cleanup_db(&test_db_path(db_name));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn verify_pet_admission_rejects_a_tampered_certificate() {
        let db_name = "pet_admission_rejects_a_tampered_certificate";
        let fixture = build_fixture(3, 2, AUDIT_TARGET);
        let coordinator = test_coordinator(db_name, &fixture.ring_payload).await;
        let context_digest = admission_context_digest(&coordinator, &fixture);
        let target_fingerprint =
            PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
        let mut evidence = build_admission_evidence(
            &fixture,
            &target_fingerprint,
            context_digest,
            &[1, 2],
            &[1, 2],
        );
        let last = evidence.certificate.reveals.len() - 1;
        evidence.certificate.reveals[last].statement.blinded_r[0] ^= 0xFF;

        let result = coordinator
            .verify_pet_admission(
                &fixture.document,
                None,
                &object_id_for(&fixture),
                None,
                AUDIT_TARGET,
                ADMISSION_ACTOR,
                None,
                &fixture.ring_payload,
                &evidence,
            )
            .await;

        assert!(
            matches!(result, Err(PetError::Mismatch)),
            "admission must independently re-detect a tampered certificate, not just trust it, \
             got {:?}",
            result
        );
        cleanup_db(&test_db_path(db_name));
    }

    /// Confirms the rejections above aren't vacuous against a gate that
    /// rejects everything: genuinely signed, correctly combining evidence
    /// for a tag that really does match the audited owner must be admitted.
    #[tokio::test]
    #[serial_test::serial]
    async fn verify_pet_admission_accepts_genuine_evidence() {
        let db_name = "pet_admission_accepts_genuine_evidence";
        let fixture = build_fixture(3, 2, AUDIT_TARGET);
        let coordinator = test_coordinator(db_name, &fixture.ring_payload).await;
        let context_digest = admission_context_digest(&coordinator, &fixture);
        let target_fingerprint =
            PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
        let evidence = build_admission_evidence(
            &fixture,
            &target_fingerprint,
            context_digest,
            &[1, 2],
            &[1, 2],
        );

        let result = coordinator
            .verify_pet_admission(
                &fixture.document,
                None,
                &object_id_for(&fixture),
                None,
                AUDIT_TARGET,
                ADMISSION_ACTOR,
                None,
                &fixture.ring_payload,
                &evidence,
            )
            .await;

        assert!(
            result.is_ok(),
            "expected genuine evidence to be admitted: {:?}",
            result
        );
        cleanup_db(&test_db_path(db_name));
    }

    // ========================================================================
    // `verify_reveal_response`'s acceptance ordering must never let a
    // rejected or invalid response consume a participant's slot — mirrors
    // the old single-round protocol's `verify_check_response` coverage,
    // applied to the new, novel reveal phase. Pure functions (no
    // `AppState`/local storage/network), so these tests call them directly.
    // ========================================================================

    #[test]
    fn spoofed_reveal_does_not_block_the_honest_participants_later_valid_response() {
        let fixture = build_fixture(3, 2, AUDIT_TARGET);
        let target_fingerprint =
            PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
        let attempt_id = "attempt-1";
        let context_digest = [7u8; 32];
        let c1 = commit(
            &fixture.tag,
            &target_fingerprint,
            attempt_id,
            context_digest,
            1,
        );
        let c2 = commit(
            &fixture.tag,
            &target_fingerprint,
            attempt_id,
            context_digest,
            2,
        );
        let all_commitments = vec![(1, c1.commitment), (2, c2.commitment)];
        let selection_digest =
            pet_blind_selection_digest(attempt_id, &context_digest, &all_commitments);
        let blind_context = throwaway_blind_context();
        let mut seen_node_ids = HashSet::new();

        let spoofed = spoofed_reveal_message(
            &fixture,
            &target_fingerprint,
            attempt_id,
            context_digest,
            &all_commitments,
            &c1,
        );
        let spoofed_result = verify_reveal_response::<PetImpl>(
            spoofed,
            &fixture.document.ring_id,
            &fixture.ring_payload,
            "accused-peer",
            &fixture.tag,
            &target_fingerprint,
            &all_commitments,
            selection_digest,
            &blind_context,
            &None,
            &mut seen_node_ids,
        );
        assert!(
            matches!(spoofed_result, PetRevealResponseVerification::Rejected),
            "a spoofed reveal must be rejected"
        );
        assert!(
            !seen_node_ids.contains(&1),
            "a rejected reveal must not consume the claimed participant's slot"
        );

        let genuine = genuine_reveal_message(
            &fixture,
            &target_fingerprint,
            attempt_id,
            context_digest,
            &all_commitments,
            &c1,
        );
        let genuine_result = verify_reveal_response::<PetImpl>(
            genuine,
            &fixture.document.ring_id,
            &fixture.ring_payload,
            "accused-peer",
            &fixture.tag,
            &target_fingerprint,
            &all_commitments,
            selection_digest,
            &blind_context,
            &None,
            &mut seen_node_ids,
        );
        assert!(
            matches!(genuine_result, PetRevealResponseVerification::Verified(_)),
            "node 1's real, later reveal must still be accepted"
        );
    }

    #[test]
    fn invalid_proof_reveal_does_not_consume_the_slot_for_a_subsequent_valid_contribution() {
        let fixture = build_fixture(3, 2, AUDIT_TARGET);
        let target_fingerprint =
            PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
        let attempt_id = "attempt-1";
        let context_digest = [7u8; 32];
        let c1 = commit(
            &fixture.tag,
            &target_fingerprint,
            attempt_id,
            context_digest,
            1,
        );
        let c2 = commit(
            &fixture.tag,
            &target_fingerprint,
            attempt_id,
            context_digest,
            2,
        );
        let all_commitments = vec![(1, c1.commitment), (2, c2.commitment)];
        let selection_digest =
            pet_blind_selection_digest(attempt_id, &context_digest, &all_commitments);
        let blind_context = throwaway_blind_context();
        let mut seen_node_ids = HashSet::new();

        let bad = reveal_with_bad_proof(
            &fixture,
            &target_fingerprint,
            attempt_id,
            context_digest,
            &all_commitments,
            &c1,
            CryptoSerialize::to_bytes(&Fr::from(7u64)).expect("serialize challenge"),
            CryptoSerialize::to_bytes(&Fr::from(9u64)).expect("serialize proof"),
        );
        let bad_result = verify_reveal_response::<PetImpl>(
            bad,
            &fixture.document.ring_id,
            &fixture.ring_payload,
            "accused-peer",
            &fixture.tag,
            &target_fingerprint,
            &all_commitments,
            selection_digest,
            &blind_context,
            &None,
            &mut seen_node_ids,
        );
        assert!(
            matches!(bad_result, PetRevealResponseVerification::InvalidProof(_)),
            "an authenticated but cryptographically invalid reveal must be reported, not just \
             dropped: {:?}",
            match bad_result {
                PetRevealResponseVerification::InvalidProof(_) => "InvalidProof",
                PetRevealResponseVerification::Rejected => "Rejected",
                PetRevealResponseVerification::Verified(_) => "Verified",
            }
        );
        assert!(
            !seen_node_ids.contains(&1),
            "an invalid-proof reveal must not consume the participant's slot"
        );

        let genuine = genuine_reveal_message(
            &fixture,
            &target_fingerprint,
            attempt_id,
            context_digest,
            &all_commitments,
            &c1,
        );
        let genuine_result = verify_reveal_response::<PetImpl>(
            genuine,
            &fixture.document.ring_id,
            &fixture.ring_payload,
            "accused-peer",
            &fixture.tag,
            &target_fingerprint,
            &all_commitments,
            selection_digest,
            &blind_context,
            &None,
            &mut seen_node_ids,
        );
        assert!(
            matches!(genuine_result, PetRevealResponseVerification::Verified(_)),
            "node 1's real contribution must still be accepted after its own earlier invalid \
             attempt"
        );
    }

    #[test]
    fn malformed_reveal_is_reported_and_does_not_consume_the_slot() {
        let fixture = build_fixture(3, 2, AUDIT_TARGET);
        let target_fingerprint =
            PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
        let attempt_id = "attempt-1";
        let context_digest = [7u8; 32];
        let c1 = commit(
            &fixture.tag,
            &target_fingerprint,
            attempt_id,
            context_digest,
            1,
        );
        let c2 = commit(
            &fixture.tag,
            &target_fingerprint,
            attempt_id,
            context_digest,
            2,
        );
        let all_commitments = vec![(1, c1.commitment), (2, c2.commitment)];
        let selection_digest =
            pet_blind_selection_digest(attempt_id, &context_digest, &all_commitments);
        let blind_context = throwaway_blind_context();
        let mut seen_node_ids = HashSet::new();

        let bad = reveal_with_bad_proof(
            &fixture,
            &target_fingerprint,
            attempt_id,
            context_digest,
            &all_commitments,
            &c1,
            vec![0xff, 0xff, 0xff],
            vec![0xff, 0xff, 0xff],
        );
        let bad_result = verify_reveal_response::<PetImpl>(
            bad,
            &fixture.document.ring_id,
            &fixture.ring_payload,
            "accused-peer",
            &fixture.tag,
            &target_fingerprint,
            &all_commitments,
            selection_digest,
            &blind_context,
            &None,
            &mut seen_node_ids,
        );
        assert!(
            matches!(bad_result, PetRevealResponseVerification::InvalidProof(_)),
            "an authenticated but undecodable reveal must be reported, not just dropped \
             (finding #9)"
        );
        assert!(
            !seen_node_ids.contains(&1),
            "a malformed reveal must not consume the participant's slot"
        );

        let genuine = genuine_reveal_message(
            &fixture,
            &target_fingerprint,
            attempt_id,
            context_digest,
            &all_commitments,
            &c1,
        );
        let genuine_result = verify_reveal_response::<PetImpl>(
            genuine,
            &fixture.document.ring_id,
            &fixture.ring_payload,
            "accused-peer",
            &fixture.tag,
            &target_fingerprint,
            &all_commitments,
            selection_digest,
            &blind_context,
            &None,
            &mut seen_node_ids,
        );
        assert!(
            matches!(genuine_result, PetRevealResponseVerification::Verified(_)),
            "node 1's real contribution must still be accepted after its own earlier malformed \
             attempt"
        );
    }

    #[test]
    fn duplicate_valid_reveals_count_only_once() {
        let fixture = build_fixture(3, 2, AUDIT_TARGET);
        let target_fingerprint =
            PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
        let attempt_id = "attempt-1";
        let context_digest = [7u8; 32];
        let c1 = commit(
            &fixture.tag,
            &target_fingerprint,
            attempt_id,
            context_digest,
            1,
        );
        let c2 = commit(
            &fixture.tag,
            &target_fingerprint,
            attempt_id,
            context_digest,
            2,
        );
        let all_commitments = vec![(1, c1.commitment), (2, c2.commitment)];
        let selection_digest =
            pet_blind_selection_digest(attempt_id, &context_digest, &all_commitments);
        let blind_context = throwaway_blind_context();
        let mut seen_node_ids = HashSet::new();

        let first = verify_reveal_response::<PetImpl>(
            genuine_reveal_message(
                &fixture,
                &target_fingerprint,
                attempt_id,
                context_digest,
                &all_commitments,
                &c1,
            ),
            &fixture.document.ring_id,
            &fixture.ring_payload,
            "accused-peer",
            &fixture.tag,
            &target_fingerprint,
            &all_commitments,
            selection_digest,
            &blind_context,
            &None,
            &mut seen_node_ids,
        );
        assert!(matches!(first, PetRevealResponseVerification::Verified(_)));

        let second = verify_reveal_response::<PetImpl>(
            genuine_reveal_message(
                &fixture,
                &target_fingerprint,
                attempt_id,
                context_digest,
                &all_commitments,
                &c1,
            ),
            &fixture.document.ring_id,
            &fixture.ring_payload,
            "accused-peer",
            &fixture.tag,
            &target_fingerprint,
            &all_commitments,
            selection_digest,
            &blind_context,
            &None,
            &mut seen_node_ids,
        );
        assert!(
            matches!(second, PetRevealResponseVerification::Rejected),
            "a second valid reveal for an already-accepted id must count only once"
        );
    }

    #[test]
    fn three_of_five_reveal_collection_succeeds_despite_earlier_spoofing_and_invalid_proof_attempts(
    ) {
        let fixture = build_fixture(5, 3, AUDIT_TARGET);
        let target_fingerprint =
            PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
        let attempt_id = "attempt-1";
        let context_digest = [7u8; 32];
        let contributions: Vec<Contribution> = (1..=3)
            .map(|id| {
                commit(
                    &fixture.tag,
                    &target_fingerprint,
                    attempt_id,
                    context_digest,
                    id,
                )
            })
            .collect();
        let all_commitments: Vec<(u32, [u8; 32])> = contributions
            .iter()
            .map(|c| (c.node_id, c.commitment))
            .collect();
        let selection_digest =
            pet_blind_selection_digest(attempt_id, &context_digest, &all_commitments);
        let blind_context = throwaway_blind_context();
        let mut seen_node_ids = HashSet::new();
        let mut verified = Vec::new();

        let messages = vec![
            spoofed_reveal_message(
                &fixture,
                &target_fingerprint,
                attempt_id,
                context_digest,
                &all_commitments,
                &contributions[0],
            ),
            reveal_with_bad_proof(
                &fixture,
                &target_fingerprint,
                attempt_id,
                context_digest,
                &all_commitments,
                &contributions[1],
                CryptoSerialize::to_bytes(&Fr::from(7u64)).expect("serialize challenge"),
                CryptoSerialize::to_bytes(&Fr::from(9u64)).expect("serialize proof"),
            ),
            genuine_reveal_message(
                &fixture,
                &target_fingerprint,
                attempt_id,
                context_digest,
                &all_commitments,
                &contributions[0],
            ),
            genuine_reveal_message(
                &fixture,
                &target_fingerprint,
                attempt_id,
                context_digest,
                &all_commitments,
                &contributions[1],
            ),
            genuine_reveal_message(
                &fixture,
                &target_fingerprint,
                attempt_id,
                context_digest,
                &all_commitments,
                &contributions[2],
            ),
        ];
        for message in messages {
            if let PetRevealResponseVerification::Verified(signed) = verify_reveal_response::<PetImpl>(
                message,
                &fixture.document.ring_id,
                &fixture.ring_payload,
                "accused-peer",
                &fixture.tag,
                &target_fingerprint,
                &all_commitments,
                selection_digest,
                &blind_context,
                &None,
                &mut seen_node_ids,
            ) {
                verified.push(signed);
            }
        }

        assert_eq!(
            seen_node_ids,
            std::collections::HashSet::from([1, 2, 3]),
            "the three genuine reveals must all be accepted despite the earlier spoofing and \
             invalid-proof attempts on nodes 1 and 2"
        );
        assert_eq!(verified.len(), 3, "threshold must be reached");
    }

    // ========================================================================
    // `verify_decrypt_response`'s acceptance ordering — reuses the old
    // single-round protocol's per-share DLEQ machinery unchanged, now
    // against a certificate's aggregate points, so coverage here is lighter
    // than reveal's (which is genuinely new): one ordering test, one
    // multi-node collection test.
    // ========================================================================

    #[test]
    fn spoofed_decrypt_does_not_block_the_honest_participants_later_valid_response() {
        let fixture = build_fixture(3, 2, AUDIT_TARGET);
        let target_fingerprint =
            PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
        let certificate = build_valid_certificate(&fixture, &target_fingerprint);
        let (aggregate_r, aggregate_diff) =
            build_and_verify_pet_blind_certificate::<DkgImpl, PetImpl>(
                &certificate,
                &fixture.ring_payload,
                &fixture.tag,
                &target_fingerprint,
            )
            .expect("valid certificate");
        let pub_poly = fixture_pub_poly(&fixture);
        let blind_context = throwaway_blind_context();
        let mut seen_node_ids = HashSet::new();
        let aggregate_r_bytes =
            CryptoSerialize::to_bytes(&aggregate_r).expect("serialize aggregate_r");
        let aggregate_diff_bytes =
            CryptoSerialize::to_bytes(&aggregate_diff).expect("serialize aggregate_diff");

        let genuine_share = decrypt_share(&fixture, &certificate, &aggregate_r, &aggregate_diff, 1);
        let mut spoofed_message = decrypt_statement_to_message(
            genuine_share.statement.clone(),
            genuine_share.response_signature.clone(),
        );
        if let PetMessage::DecryptResponse {
            response_signature, ..
        } = &mut spoofed_message
        {
            response_signature[0] ^= 0x01;
        }
        let spoofed_result = verify_decrypt_response::<PetImpl>(
            spoofed_message,
            &fixture.document.ring_id,
            &fixture.ring_payload,
            "accused-peer",
            &pub_poly,
            certificate.context_digest,
            certificate.certificate_digest(),
            &certificate.attempt_id,
            &aggregate_r_bytes,
            &aggregate_diff_bytes,
            &blind_context,
            &None,
            &mut seen_node_ids,
        );
        assert!(
            matches!(spoofed_result, PetDecryptResponseVerification::Rejected),
            "a spoofed decrypt share must be rejected"
        );
        assert!(!seen_node_ids.contains(&1));

        let genuine_message =
            decrypt_statement_to_message(genuine_share.statement, genuine_share.response_signature);
        let genuine_result = verify_decrypt_response::<PetImpl>(
            genuine_message,
            &fixture.document.ring_id,
            &fixture.ring_payload,
            "accused-peer",
            &pub_poly,
            certificate.context_digest,
            certificate.certificate_digest(),
            &certificate.attempt_id,
            &aggregate_r_bytes,
            &aggregate_diff_bytes,
            &blind_context,
            &None,
            &mut seen_node_ids,
        );
        assert!(
            matches!(genuine_result, PetDecryptResponseVerification::Verified(..)),
            "node 1's real decrypt share must still be accepted"
        );
    }

    #[test]
    fn three_of_five_decrypt_collection_succeeds_despite_earlier_spoofing() {
        let fixture = build_fixture(5, 3, AUDIT_TARGET);
        let target_fingerprint =
            PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
        let certificate = build_certificate_for(
            &fixture,
            &target_fingerprint,
            "attempt-1",
            [7u8; 32],
            &[1, 2, 3],
        );
        let (aggregate_r, aggregate_diff) =
            build_and_verify_pet_blind_certificate::<DkgImpl, PetImpl>(
                &certificate,
                &fixture.ring_payload,
                &fixture.tag,
                &target_fingerprint,
            )
            .expect("valid certificate");
        let pub_poly = fixture_pub_poly(&fixture);
        let blind_context = throwaway_blind_context();
        let mut seen_node_ids = HashSet::new();
        let mut verified = Vec::new();
        let aggregate_r_bytes =
            CryptoSerialize::to_bytes(&aggregate_r).expect("serialize aggregate_r");
        let aggregate_diff_bytes =
            CryptoSerialize::to_bytes(&aggregate_diff).expect("serialize aggregate_diff");

        let spoofed_share = decrypt_share(&fixture, &certificate, &aggregate_r, &aggregate_diff, 1);
        let mut spoofed_message = decrypt_statement_to_message(
            spoofed_share.statement.clone(),
            spoofed_share.response_signature.clone(),
        );
        if let PetMessage::DecryptResponse {
            response_signature, ..
        } = &mut spoofed_message
        {
            response_signature[0] ^= 0x01;
        }

        let share_2 = decrypt_share(&fixture, &certificate, &aggregate_r, &aggregate_diff, 2);
        let share_3 = decrypt_share(&fixture, &certificate, &aggregate_r, &aggregate_diff, 3);
        let messages = vec![
            spoofed_message,
            decrypt_statement_to_message(spoofed_share.statement, spoofed_share.response_signature),
            decrypt_statement_to_message(share_2.statement, share_2.response_signature),
            decrypt_statement_to_message(share_3.statement, share_3.response_signature),
        ];
        for message in messages {
            if let PetDecryptResponseVerification::Verified(_, share) =
                verify_decrypt_response::<PetImpl>(
                    message,
                    &fixture.document.ring_id,
                    &fixture.ring_payload,
                    "accused-peer",
                    &pub_poly,
                    certificate.context_digest,
                    certificate.certificate_digest(),
                    &certificate.attempt_id,
                    &aggregate_r_bytes,
                    &aggregate_diff_bytes,
                    &blind_context,
                    &None,
                    &mut seen_node_ids,
                )
            {
                verified.push(share);
            }
        }

        assert_eq!(
            seen_node_ids,
            std::collections::HashSet::from([1, 2, 3]),
            "the three genuine decrypt shares must all be accepted despite the earlier spoofing \
             attempt on node 1"
        );
        assert_eq!(verified.len(), 3, "threshold must be reached");
    }

    #[test]
    fn certificate_validates_and_recovers_a_nonidentity_aggregate() {
        let fixture = build_fixture(3, 2, AUDIT_TARGET);
        let target_fingerprint =
            PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
        let certificate = build_valid_certificate(&fixture, &target_fingerprint);

        let (aggregate_r, _aggregate_diff) =
            build_and_verify_pet_blind_certificate::<DkgImpl, PetImpl>(
                &certificate,
                &fixture.ring_payload,
                &fixture.tag,
                &target_fingerprint,
            )
            .expect("a genuinely valid certificate must verify");
        assert!(
            !DkgImpl::public_key_is_identity(&aggregate_r),
            "the aggregate ephemeral point must never be the identity"
        );
    }

    #[test]
    fn certificate_rejects_a_tampered_blinded_r() {
        let fixture = build_fixture(3, 2, AUDIT_TARGET);
        let target_fingerprint =
            PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
        let mut certificate = build_valid_certificate(&fixture, &target_fingerprint);
        let last = certificate.reveals.len() - 1;
        certificate.reveals[last].statement.blinded_r[0] ^= 0xFF;

        let result = build_and_verify_pet_blind_certificate::<DkgImpl, PetImpl>(
            &certificate,
            &fixture.ring_payload,
            &fixture.tag,
            &target_fingerprint,
        );
        assert!(
            result.is_err(),
            "a tampered blinded_r must fail its commitment opening or its proof"
        );
    }

    #[test]
    fn certificate_rejects_a_non_opening_reveal() {
        let fixture = build_fixture(3, 2, AUDIT_TARGET);
        let target_fingerprint =
            PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
        let mut certificate = build_valid_certificate(&fixture, &target_fingerprint);
        let last = certificate.reveals.len() - 1;
        certificate.reveals[last].statement.commit_salt[0] ^= 0xFF;

        let result = build_and_verify_pet_blind_certificate::<DkgImpl, PetImpl>(
            &certificate,
            &fixture.ring_payload,
            &fixture.tag,
            &target_fingerprint,
        );
        assert!(
            result.is_err(),
            "a reveal with the wrong commit_salt must not open its claimed commitment"
        );
    }

    #[test]
    fn certificate_rejects_a_duplicate_node_id() {
        let fixture = build_fixture(3, 2, AUDIT_TARGET);
        let target_fingerprint =
            PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
        let mut certificate = build_valid_certificate(&fixture, &target_fingerprint);
        let duplicate = certificate.reveals[0].clone();
        certificate.reveals[1] = duplicate;

        let result = build_and_verify_pet_blind_certificate::<DkgImpl, PetImpl>(
            &certificate,
            &fixture.ring_payload,
            &fixture.tag,
            &target_fingerprint,
        );
        assert!(
            result.is_err(),
            "two reveals claiming the same node id must be rejected"
        );
    }

    #[test]
    fn certificate_rejects_a_short_reveal_list() {
        let fixture = build_fixture(3, 2, AUDIT_TARGET);
        let target_fingerprint =
            PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
        let mut certificate = build_valid_certificate(&fixture, &target_fingerprint);
        certificate.reveals.pop();

        let result = build_and_verify_pet_blind_certificate::<DkgImpl, PetImpl>(
            &certificate,
            &fixture.ring_payload,
            &fixture.tag,
            &target_fingerprint,
        );
        assert!(
            result.is_err(),
            "fewer reveals than the ring's threshold must be rejected, never silently accepted"
        );
    }

    #[test]
    fn certificate_rejects_wrong_target_fingerprint() {
        let fixture = build_fixture(3, 2, AUDIT_TARGET);
        let target_fingerprint =
            PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
        let certificate = build_valid_certificate(&fixture, &target_fingerprint);
        let other_fingerprint =
            PetImpl::owner_fingerprint(b"someone-else").expect("compute F(other)");

        let result = build_and_verify_pet_blind_certificate::<DkgImpl, PetImpl>(
            &certificate,
            &fixture.ring_payload,
            &fixture.tag,
            &other_fingerprint,
        );
        assert!(
            result.is_err(),
            "a certificate built against one target must not verify against a different one"
        );
    }
}
