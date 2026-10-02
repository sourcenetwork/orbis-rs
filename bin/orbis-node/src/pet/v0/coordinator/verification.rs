//! Shared verification logic for the PET blind equality test — the
//! multi-round blinded check protocol that replaced PET's original
//! single-round check, which leaked information about the plaintext
//! fingerprint across repeated checks.
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
///
/// `expected_node_id` is the caller's own transport-level authentication of
/// who actually sent this response (e.g. the committee member it addressed
/// this specific request to) — the message body's own `from_node_id` field
/// is otherwise just an unauthenticated self-report, since Commit responses
/// carry no signature. Without this check, any committee member could claim
/// a different, honest member's slot in its own response and cause that
/// honest member's genuine (later) response to be rejected as a duplicate.
pub(crate) fn verify_commit_response(
    response: crate::pet::v0::messages::PetMessage,
    ring_payload: &bulletin::r#trait::RingPayload,
    expected_context_digest: [u8; 32],
    expected_node_id: u32,
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
    if from_node_id != expected_node_id {
        return PetCommitResponseVerification::Rejected;
    }
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
mod tests;
