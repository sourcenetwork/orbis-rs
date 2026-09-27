//! Shared verification logic used by the initiator's own local
//! contribution, every incoming `PetCheckRequest` handler, and every PRE
//! peer gating its own reencryption-share release — the same
//! `verify_pet_check_request` code path runs identically in all three
//! places, so there is exactly one place that decides "is this tag
//! genuinely Bankd's, for this exact document."
//!
//! `verify_pet_check_request` deliberately does *not* resolve or need the
//! audit target: computing a threshold contribution (`share_i * R`) reveals
//! nothing about which owner it will ultimately be checked against, and
//! nothing about whether the check will pass — that comparison happens
//! exactly once, by the initiator, after combining every contribution (see
//! `initiator.rs`). Responders only need to confirm the request is for a
//! real, Bankd-issued tag before touching their secret share with it: an
//! unverified `R` could otherwise be used to probe the checking key.
//!
//! [`PetCoordinator::verify_pet_admission`] is different: it exists so a PRE
//! peer can refuse to release its reencryption share for a `requires_pet`
//! ring unless it is independently convinced a genuine threshold PET check
//! already passed (see `pre::v0::coordinator::handlers::handle_reencrypt_request`).
//! That independent verification is only meaningful if the verifier knows
//! what it is verifying, so — unlike every other function in this file —
//! it does take the audit target as an input, and every ring committee
//! member that could release a share for a PET-gated document now learns
//! it. This is a deliberate, reviewed trade-off: the alternative (a
//! target-blind proof of correct match) would need a ZK circuit, well out
//! of scope here. The exposure stays committee-internal, the same trust
//! boundary as `actor_id`/`object_id`, which peers already see in
//! `PreRequestContext` today.
//!
//! `audit_target_object_id` is the plaintext owner identity itself — the
//! exact value `Pet::owner_fingerprint` is computed over — not a handle
//! that gets resolved to some other identity via ACP. There is deliberately
//! no such resolution step: a caller can name any object it likes, but
//! that alone gets it nowhere without both [`check_pet_permission`] (real
//! ACP permission on that exact object) and a tag that genuinely encodes
//! that exact identity (unforgeable without knowing Bankd's tag secret).

use super::PetCoordinator;
use crate::helpers::identity::node_key_for_id;
use crate::helpers::protocol_version::read_ring_for_route;
use crate::pet::v0::attestation::{
    invalid_pet_response_observation, PetCheckStatementContext, PetShareAttestation,
};
use crate::pet::v0::error::{PetError, Result};
use crate::pet::v0::messages::PetCheckContext;
use crate::reporting::v0::observation::ReportObservation;
use crate::reporting::v0::queue_report;
use crate::reporting::v0::types::{
    ring_state_sha256, PetCheckResponseStatement, ReportedDocumentEvidence,
};
use crate::ring_state::RingShareBundle;
use authn::{resolve_jwt_did, BearerToken, PreClaims};
use authz::r#trait::Authz;
use authz::vera::{AccessCheckRequest, ValidWindow};
use bulletin::r#trait::{BulletinKind, NodeInfo};
use common::blockchain::verify_node_message;
use crypto::context::CiphertextContext;
use crypto::r#trait::{
    CryptoDeserialize, DistKeyShare, Dkg, EncryptionProof, Pet, PetCheckReply, PetTag, PubShare,
    Secret, TagKnowledgeProof, ThresholdSigner,
};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr};
use crypto::{SigShareInner, SignImpl, SignaturePoint};
use std::collections::HashSet;

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
/// directly over the wire — closes the gap `handle_check_request` alone has:
/// unlike the normal initiator's own entry point (`initiate_pet_check`,
/// which calls `check_pet_permission` before doing anything), and unlike
/// `verify_pet_admission` (whose caller already independently re-verified
/// the same JWT before ever reaching it), `handle_check_request` is
/// reachable from a raw wire message with no other upstream authentication
/// at all. Without this, a direct peer request could obtain a genuine
/// contribution (and, combined with every other peer's, an equality oracle)
/// for any document/target without ever going through the ACP-gated normal
/// PRE entry point — see the PET audit fix checklist, finding #3.
///
/// Re-verifies `ctx.token_string` the same way PRE's own responders
/// re-verify `PreRequestContext::token_string`, binds it to *this* request's
/// `object_id`/`salt` (so a token authorizing one document/round can't be
/// replayed against a different one), derives the actor from it, and then
/// runs the exact same `check_pet_permission` gate the normal initiator
/// already runs.
pub(crate) async fn verify_pet_audit_authorization(
    authz: &(dyn Authz + Send + Sync),
    ctx: &PetCheckContext,
    trusted_auth_relay_dids: Option<&[String]>,
    current_time: u64,
) -> Result<()> {
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
    .await
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
    /// from the bulletin or bound into the proof itself.
    ///
    /// Returns the verified tag, the ring's resolved `pet_pk` hex (so
    /// callers that also need it — e.g. to sanity-check their local share —
    /// don't have to re-read the ring a second time), the transcript digest
    /// the proof was checked against, and the live-resolved `ring_payload`
    /// itself (so a caller that doesn't already have one to hand — like
    /// `handlers::handle_check_request` — doesn't need a second bulletin
    /// read just to build its signed statement's `ring_pk`/`ring_state_sha256`).
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
        // wire, supplied directly by the initiator over PET's own P2P round
        // — unlike PRE's own request handling, nothing upstream of this
        // guarantees they actually describe the same document. Without this
        // check, a malicious initiator could pair a genuine document A with
        // a different document B's id; this node would compute and sign a
        // genuinely correct proof for A while the resulting statement claims
        // B's id, which a report validator (loading B by that signed id)
        // could later use to falsely accuse this honest node.
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

    /// The PRE-release gate: verify that a genuine threshold PET check
    /// passed for `document`/`salt`, using `attestations` as portable,
    /// signature-backed evidence rather than re-running the threshold
    /// fan-out itself. Called by every PRE committee member before it will
    /// release a reencryption share for a `requires_pet` ring — see this
    /// file's module doc comment for the target-visibility trade-off this
    /// implies.
    ///
    /// `ring_payload` is passed in rather than re-read here because the
    /// caller (`handle_reencrypt_request`) already resolved it from the
    /// bulletin as the authoritative source for its own ACP check — reusing
    /// it does not weaken independence, since it is `pre`'s own read, never
    /// anything asserted by the initiator.
    /// Best-effort: resolve `node_key`'s peer id via the bulletin and queue
    /// an invalid-crypto report for it. Shared by `verify_pet_admission`'s
    /// two attributable-failure branches — an authenticated attestation that
    /// fails to decode (finding #9), and one that decodes but fails its DLEQ
    /// proof — which differ only in which check failed, not in how the
    /// report is built or queued. No live connection to the accused node
    /// exists here (this validates forwarded evidence, not a peer response),
    /// so `accused_peer_id` is resolved via the bulletin, the same way
    /// `queue_unauthorized_request_report` does for the same reason.
    async fn queue_pet_admission_report(
        &self,
        ring_id: &str,
        node_key: &str,
        statement: PetCheckResponseStatement,
        response_signature: Vec<u8>,
        document_evidence: Option<ReportedDocumentEvidence>,
        from_node_id: u32,
    ) {
        let Ok(node_info_post) = self
            .app_state
            .bulletin
            .read(node_key.to_string(), BulletinKind::NodeInfo)
            .await
        else {
            return;
        };
        let Ok(node_info) = NodeInfo::try_from(node_info_post) else {
            return;
        };
        let observation = invalid_pet_response_observation(
            ring_id.to_string(),
            node_key.to_string(),
            node_info.peer_id,
            statement,
            response_signature,
            document_evidence,
        );
        let _ = queue_report::<D, SignImpl>(
            self.app_state.clone(),
            self.routes,
            ReportObservation::InvalidCryptoResponse(Box::new(observation)),
        )
        .await
        .inspect_err(|error| {
            tracing::warn!(
                from_node_id,
                %error,
                "Failed to queue PET invalid-proof report observation"
            );
        });
    }

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
        attestations: &[PetShareAttestation],
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
            // Unused on this path: `verify_pet_check_request` never reads
            // `token_string`/`audit_target_object_id`/`valid_window` itself
            // (only `handle_check_request` re-verifies those, for the raw
            // wire-message entry point — see finding #3 in the PET audit fix
            // checklist). This function already performed its own,
            // equivalent authorization above using the real
            // `actor_id`/`audit_target_object_id`/`valid_window`, so a
            // placeholder here is correct, not a gap.
            token_string: String::new(),
            audit_target_object_id: audit_target_object_id.to_string(),
            valid_window,
        };
        let (tag, _pet_pk_hex, _digest, _) = self.verify_pet_check_request(&ctx).await?;

        let threshold = ring_payload.threshold as usize;
        let n = ring_payload.peer_node_keys.len();
        if attestations.len() < threshold {
            return Err(PetError::InsufficientShares {
                got: attestations.len(),
                need: threshold,
            });
        }

        // Per-share verification needs the checking key's own public
        // polynomial, not the main ring key's — this node already has one
        // locally, since it's about to release its own reencryption share
        // for this same main-ring committee (see `initiator.rs`'s identical
        // comment for why that implies PET-committee membership too).
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

        let statement_ctx = PetCheckStatementContext {
            chain_id: self.app_state.bulletin.chain_id(),
            ring_id: document.ring_id.clone(),
            ring_pk: ring_payload.ring_pk.clone(),
            ring_state_sha256: ring_state_sha256(ring_payload),
            protocol_version: self.routes.version,
            object_id: object_id.to_string(),
            salt: salt.map(str::to_string),
            crypto_backend: P::name(),
            timestamp: document.timestamp,
            document_inline,
        };

        let mut shares = Vec::with_capacity(threshold);
        let mut seen_indices = HashSet::new();
        for attestation in attestations.iter().take(threshold) {
            // Required order — mirrors `initiator.rs`'s live collection loop
            // exactly, for the same reason (see that file's comment):
            // resolve identity, verify signature, decode, verify the DLEQ
            // proof, and only then record the index as seen. This function
            // validates a fixed, already-selected list with hard-fail
            // semantics (any problem aborts the whole admission check via
            // `?`), so the ordering here is about not misattributing a
            // rejection to an unauthenticated claimed identity, not about
            // resilience to a live, streaming attack.
            let node_key = node_key_for_id(attestation.from_node_id, &ring_payload.peer_node_keys)
                .ok_or_else(|| {
                    PetError::Crypto(format!(
                        "PET attestation from_node_id {} is not in the ring committee",
                        attestation.from_node_id
                    ))
                })?;
            let statement = statement_ctx.statement_for(
                node_key.clone(),
                attestation.request_id.clone(),
                attestation.signed_at,
                attestation.from_node_id,
                attestation.partial.clone(),
                attestation.challenge.clone(),
                attestation.proof.clone(),
            );
            verify_node_message(
                &node_key,
                &statement.canonical_bytes(),
                &attestation.signature,
            )
            .map_err(|e| {
                PetError::Crypto(format!(
                    "invalid PET attestation signature from node {}: {}",
                    attestation.from_node_id, e
                ))
            })?;
            let (Ok(partial), Ok(challenge), Ok(proof)) = (
                G1Affine::from_bytes(&attestation.partial),
                Fr::from_bytes(&attestation.challenge),
                Fr::from_bytes(&attestation.proof),
            ) else {
                // Authenticated (its signature just verified above) but
                // undecodable — same attributability as a decodable-but-
                // cryptographically-invalid response below (finding #9): a
                // malicious node can't dodge reporting just by signing
                // garbage bytes instead of a well-formed wrong proof.
                self.queue_pet_admission_report(
                    &document.ring_id,
                    &node_key,
                    statement,
                    attestation.signature.clone(),
                    document_evidence.clone(),
                    attestation.from_node_id,
                )
                .await;
                return Err(PetError::Deserialization(format!(
                    "failed to deserialize PET attestation from node {}",
                    attestation.from_node_id
                )));
            };
            let reply = PetCheckReply {
                partial: PubShare {
                    i: attestation.from_node_id,
                    v: partial,
                },
                challenge,
                proof,
            };
            if let Err(error) = P::verify_partial_pet_check(&pub_poly, &tag, &reply) {
                // Authenticated (its signature just verified) but
                // cryptographically invalid — attributable and reportable,
                // unlike a signature failure above.
                self.queue_pet_admission_report(
                    &document.ring_id,
                    &node_key,
                    statement,
                    attestation.signature.clone(),
                    document_evidence.clone(),
                    attestation.from_node_id,
                )
                .await;
                return Err(PetError::Crypto(format!(
                    "PET attestation from node {} failed its per-share proof verification: {}",
                    attestation.from_node_id, error
                )));
            }
            if !seen_indices.insert(attestation.from_node_id) {
                return Err(PetError::Crypto(format!(
                    "duplicate PET attestation index {}",
                    attestation.from_node_id
                )));
            }
            shares.push(PubShare {
                i: attestation.from_node_id,
                v: partial,
            });
        }

        let combined = P::combine_pet_check_shares(&shares, threshold, n)
            .map_err(|e| PetError::Crypto(format!("Failed to combine PET check shares: {}", e)))?;

        // `audit_target_object_id` *is* the plaintext owner identity — the
        // same value `F()` is computed over — not a handle to resolve via
        // ACP. `check_pet_permission` above already confirmed the requester
        // is allowed to test this exact object; a wrong guess here fails
        // the match below regardless, so no separate identity lookup adds
        // any protection.
        let target_fingerprint = P::owner_fingerprint(audit_target_object_id.as_bytes())
            .map_err(|e| PetError::Crypto(format!("Failed to compute owner fingerprint: {}", e)))?;

        P::verify_pet_match(&tag, &combined, &target_fingerprint).map_err(|_| PetError::Mismatch)
    }

    /// Verify one live `PetCheckResponse` and decide whether it can be
    /// accepted into `seen_node_ids` — shared by `initiator.rs`'s collection
    /// loop, extracted (mirroring `pre::v0::coordinator::verification::verify_peer_response`)
    /// so the acceptance ordering (audit finding #6's fix) is directly unit
    /// testable without a live network. Required acceptance order,
    /// enforced by early-returning `Rejected`/`InvalidProof` at every step
    /// before the one line that mutates `seen_node_ids`:
    ///
    /// 1. Fast-path peek only (`seen_node_ids.contains`) — never a mutating
    ///    insert at this point.
    /// 2. Resolve the claimed id against the authoritative committee.
    /// 3. Verify the signature over the reconstructed statement — a
    ///    signature failure is never attributed to the claimed id, since the
    ///    sender was never authenticated as that node.
    /// 4. Decode the contribution and proof.
    /// 5. Verify the DLEQ proof against this participant's authoritative
    ///    public share — authenticated but invalid is reportable
    ///    (`InvalidProof`), unlike an earlier rejection.
    /// 6. Only now consume the participant's slot (`seen_node_ids.insert`).
    /// 7. Accept.
    ///
    /// A rejected or invalid-proof response never touches `seen_node_ids`,
    /// so a spoofed or cryptographically bad response claiming an honest
    /// participant's id can never block that participant's later genuine
    /// response from being accepted.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn verify_check_response(
        response: crate::pet::v0::messages::PetMessage,
        peer_id: &str,
        ring_payload: &bulletin::r#trait::RingPayload,
        ring_id: &str,
        pub_poly: &P::PubPoly,
        tag: &PetTag,
        statement_ctx: &PetCheckStatementContext,
        request_id: &str,
        document_evidence: &Option<ReportedDocumentEvidence>,
        seen_node_ids: &mut HashSet<u32>,
    ) -> PetCheckResponseVerification {
        let crate::pet::v0::messages::PetMessage::CheckResponse {
            from_node_id,
            partial,
            challenge,
            proof,
            signed_at,
            signature,
            ..
        } = response
        else {
            return PetCheckResponseVerification::Rejected;
        };

        // 1. Fast-path only — a cheap peek, never a mutating insert.
        if seen_node_ids.contains(&from_node_id) {
            return PetCheckResponseVerification::Rejected;
        }
        // 2. Resolve the claimed id against the authoritative committee.
        let Some(node_key) = node_key_for_id(from_node_id, &ring_payload.peer_node_keys) else {
            tracing::warn!(
                peer = %peer_id,
                from_node_id,
                "PET Coordinator: dropping check share from an out-of-range node id"
            );
            return PetCheckResponseVerification::Rejected;
        };
        // 3. Verify the signature over the reconstructed statement.
        let statement = statement_ctx.statement_for(
            node_key.clone(),
            request_id.to_string(),
            signed_at,
            from_node_id,
            partial.clone(),
            challenge.clone(),
            proof.clone(),
        );
        if let Err(error) = verify_node_message(&node_key, &statement.canonical_bytes(), &signature)
        {
            tracing::warn!(
                peer = %peer_id,
                from_node_id,
                %error,
                "PET Coordinator: dropping check share with an invalid signature"
            );
            return PetCheckResponseVerification::Rejected;
        }
        // 4. Decode the contribution and proof.
        let (Ok(parsed_partial), Ok(parsed_challenge), Ok(parsed_proof)) = (
            G1Affine::from_bytes(&partial),
            Fr::from_bytes(&challenge),
            Fr::from_bytes(&proof),
        ) else {
            tracing::warn!(
                peer = %peer_id,
                from_node_id,
                "PET Coordinator: dropping authenticated but malformed check share"
            );
            // Authenticated (its signature just verified above) but
            // undecodable — same attributability as a decodable-but-
            // cryptographically-invalid response below (finding #9): a
            // malicious responder can't dodge reporting just by signing
            // garbage bytes instead of a well-formed wrong proof.
            let observation = invalid_pet_response_observation(
                ring_id.to_string(),
                node_key,
                peer_id.to_string(),
                statement,
                signature,
                document_evidence.clone(),
            );
            return PetCheckResponseVerification::InvalidProof(Box::new(observation));
        };
        // 5. Verify the DLEQ proof against this participant's authoritative
        //    public share.
        let reply = PetCheckReply {
            partial: PubShare {
                i: from_node_id,
                v: parsed_partial,
            },
            challenge: parsed_challenge,
            proof: parsed_proof,
        };
        if let Err(error) = P::verify_partial_pet_check(pub_poly, tag, &reply) {
            tracing::warn!(
                peer = %peer_id,
                from_node_id,
                %error,
                "PET Coordinator: dropping authenticated but cryptographically invalid check share"
            );
            let observation = invalid_pet_response_observation(
                ring_id.to_string(),
                node_key,
                peer_id.to_string(),
                statement,
                signature,
                document_evidence.clone(),
            );
            return PetCheckResponseVerification::InvalidProof(Box::new(observation));
        }
        // 6. Only now consume the participant's slot.
        if !seen_node_ids.insert(from_node_id) {
            return PetCheckResponseVerification::Rejected;
        }
        // 7. Accept.
        PetCheckResponseVerification::Verified(
            PubShare {
                i: from_node_id,
                v: parsed_partial,
            },
            Box::new(PetShareAttestation {
                request_id: request_id.to_string(),
                from_node_id,
                partial,
                challenge,
                proof,
                signed_at,
                signature,
            }),
        )
    }
}

pub(crate) enum PetCheckResponseVerification {
    Verified(PubShare<G1Affine>, Box<PetShareAttestation>),
    InvalidProof(Box<crate::reporting::v0::observation::InvalidCryptoResponseObservation>),
    Rejected,
}

/// Regression coverage for the peer-side PET admission gate: proves that
/// `verify_pet_admission` — the check `pre::v0::coordinator::handlers::handle_reencrypt_request`
/// runs before releasing a reencryption share on a `requires_pet` ring — actually
/// rejects a request that skips or forges the threshold check, not just that the
/// happy path still works. Without this gate, nothing on the PRE peer side ever
/// consulted `requires_pet` at all: a compromised or simply modified initiator
/// could skip `initiate_pet_check` entirely and still collect valid reencryption
/// shares from every honest peer.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::test_helpers::{
        cleanup_db, create_test_app_state_with_bulletin, test_db_path, TestKeyPair,
    };
    use crate::pet::v0::messages::{PetCheckRequest, PetMessage};
    use authz::dummy::DummyAuthZ;
    use bulletin::dummy::DummyBulletin;
    use bulletin::r#trait::{DocumentPayload, RingPayload};
    use common::blockchain::{sign_node_message_with_hex_key, ChainConfig, TxSigner};
    use crypto::r#trait::{CryptoSerialize, PriShare};
    use crypto::{DkgImpl, PetImpl};
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use zeroize::Zeroizing;

    fn current_unix_time() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_secs()
    }

    const RING_ID: &str = "pet-admission-test-ring";
    const AUDIT_TARGET: &str = "pet-admission-audit-target";
    const TEST_REQUEST_ID: &str = "pet-admission-test-request";

    /// The fixture's document genuinely bound to its own `object_id` —
    /// `verify_pet_check_request` now enforces this (finding #7's fix), so a
    /// placeholder constant no longer works: every test must derive its
    /// `object_id` from its own fixture's actual document.
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

    /// A throwaway node-identity signing keypair, generated the same way
    /// `create_test_app_state_with_bulletin` mints a real node's signing
    /// key — `verify_node_message` only accepts a real secp256k1 key it can
    /// parse, not an arbitrary string.
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

    /// Everything needed to hand `verify_pet_admission` a genuinely-valid
    /// tag-knowledge proof, so every rejection below happens at the
    /// attestation layer under test, not because the tag itself was rejected.
    struct FixtureBase {
        ring_payload: RingPayload,
        document: DocumentPayload,
        secret: Secret,
        payload_proof: EncryptionProof,
        signers: Vec<TestSigner>,
        r_tag: Fr,
        r_point: G1Affine,
        /// The ring's PET checking-key secret. Every committee member is
        /// given this *same* scalar as its "share" — a degree-0 polynomial,
        /// so any subset's Lagrange combination recovers it exactly — mirrors
        /// `crypto`'s own `identical_shares` test helper. This lets
        /// `valid_attestation` compute genuine, individually-DLEQ-verifiable
        /// contributions rather than random points.
        pet_sk: Fr,
    }

    struct TagFixture {
        ring_payload: RingPayload,
        document: DocumentPayload,
        signers: Vec<TestSigner>,
        pet_sk: Fr,
    }

    /// Builds everything except the tag's `masked_fingerprint` (callers supply
    /// that, since rejection tests use garbage bytes — never checked by
    /// `verify_tag_knowledge`, only the Schnorr proof over `ephemeral_point`
    /// is — while the one happy-path test needs a real `F(owner) + pet_sk*R`).
    fn build_base(committee_size: usize, threshold: u32) -> FixtureBase {
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

        let secret = Secret {
            enc_cmt: vec![1, 2, 3],
            encrypted_data: vec![4, 5, 6],
            nonce: vec![7, 8, 9],
        };
        let payload_proof = EncryptionProof {
            challenge: vec![10, 11],
            response: vec![12, 13],
        };
        let document = DocumentPayload {
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

        FixtureBase {
            ring_payload,
            document,
            secret,
            payload_proof,
            signers,
            r_tag,
            r_point,
            pet_sk,
        }
    }

    /// Completes a [`FixtureBase`] into a genuinely tag-knowledge-verifiable
    /// [`TagFixture`], given the `masked_fingerprint` bytes the caller wants.
    fn finalize_fixture(mut base: FixtureBase, masked_fingerprint: Vec<u8>) -> TagFixture {
        let ephemeral_point =
            CryptoSerialize::to_bytes(&base.r_point).expect("serialize ephemeral point");
        let tag = PetTag {
            ephemeral_point,
            masked_fingerprint,
        };
        let pet_pk_hex = base.ring_payload.pet_pk.clone().unwrap();
        let pet_pk_bytes = hex::decode(&pet_pk_hex).expect("decode pet_pk hex");
        // Required noncircular construction order (PET audit fix checklist,
        // finding #5): the tag must be on the document *before* the context
        // it's bound into is built, since `build_ciphertext_context` reads
        // `document.pet_tag` to reconstruct the binding — mirrors the real
        // order `cli_tool::generate_pet_tag`/`prepare_secret` now enforce.
        base.document.pet_tag = Some(String::try_from(tag.clone()).expect("serialize tag"));
        let ciphertext_context = build_ciphertext_context(
            &base.ring_payload.ring_pk,
            &base.document,
            None,
            Some(&pet_pk_hex),
        )
        .expect("build ciphertext context");
        let digest = crypto::pet_context::tag_proof_digest(
            &tag.ephemeral_point,
            &tag.masked_fingerprint,
            &pet_pk_bytes,
            &base.document.ring_id,
            &ciphertext_context,
            &base.secret,
            &base.payload_proof,
        );
        let tag_proof =
            PetImpl::prove_tag_knowledge(&base.r_tag, &tag, &digest).expect("prove tag knowledge");

        base.document.pet_tag_proof =
            Some(String::try_from(tag_proof).expect("serialize tag proof"));

        TagFixture {
            ring_payload: base.ring_payload,
            document: base.document,
            signers: base.signers,
            pet_sk: base.pet_sk,
        }
    }

    /// A garbage-`masked_fingerprint` fixture — sufficient for every test
    /// below that expects rejection to happen at the attestation layer, never
    /// reaching `combine_pet_check_shares`/`verify_pet_match`.
    fn build_fixture(committee_size: usize, threshold: u32) -> TagFixture {
        let base = build_base(committee_size, threshold);
        finalize_fixture(base, vec![9, 9, 9])
    }

    /// A fixture whose tag genuinely matches `target` — needed only by the
    /// one happy-path test, which must reach `verify_pet_match` and have it
    /// succeed.
    fn build_fixture_with_real_target(
        committee_size: usize,
        threshold: u32,
        target: &str,
    ) -> TagFixture {
        let base = build_base(committee_size, threshold);
        let combined =
            crypto::helpers::mul_point(&base.r_point, &base.pet_sk).expect("compute pet_sk*R");
        let target_fingerprint =
            PetImpl::owner_fingerprint(target.as_bytes()).expect("compute F(target)");
        let masked = crypto::helpers::add_points(&target_fingerprint, &combined)
            .expect("combine fingerprint and blinding");
        let masked_bytes =
            CryptoSerialize::to_bytes(&masked).expect("serialize masked fingerprint");
        finalize_fixture(base, masked_bytes)
    }

    /// A correctly-signed, genuinely DLEQ-valid attestation from committee
    /// member `node_id` (1-based, matching `signers[node_id - 1]`'s sorted
    /// position) — computed from the fixture's real (shared) `pet_sk`, so
    /// every rejection test below isolates the one specific defect it
    /// introduces rather than failing at an earlier, unrelated proof check.
    /// Matches `DummyBulletin::chain_id()` (`"vera-localnet"`) and
    /// `::network::V0.version` exactly, so a statement built here verifies
    /// identically whether reconstructed by `verify_pet_admission` (which
    /// reads them from a real, if dummy, `AppState`) or by
    /// `verify_check_response` (a pure function, given these fixed test
    /// values directly — no coordinator needed).
    fn test_statement_ctx(fixture: &TagFixture) -> PetCheckStatementContext {
        PetCheckStatementContext {
            chain_id: "vera-localnet".to_string(),
            ring_id: fixture.document.ring_id.clone(),
            ring_pk: fixture.ring_payload.ring_pk.clone(),
            ring_state_sha256: ring_state_sha256(&fixture.ring_payload),
            protocol_version: ::network::V0.version,
            object_id: object_id_for(fixture),
            salt: None,
            crypto_backend: PetImpl::name(),
            timestamp: fixture.document.timestamp,
            document_inline: false,
        }
    }

    fn valid_attestation(fixture: &TagFixture, node_id: u32) -> PetShareAttestation {
        let tag = PetTag::try_from(fixture.document.pet_tag.clone().expect("fixture has a tag"))
            .expect("parse fixture tag");
        let reply = PetImpl::partial_pet_check(&fixture.pet_sk, node_id, &tag)
            .expect("compute genuine partial");
        let partial_bytes = CryptoSerialize::to_bytes(&reply.partial.v).expect("serialize partial");
        let challenge_bytes =
            CryptoSerialize::to_bytes(&reply.challenge).expect("serialize challenge");
        let proof_bytes = CryptoSerialize::to_bytes(&reply.proof).expect("serialize proof");
        let signed_at = 1_700_000_000u64;
        let statement_ctx = test_statement_ctx(fixture);
        let signer = &fixture.signers[(node_id - 1) as usize];
        let statement = statement_ctx.statement_for(
            signer.pubkey_hex.clone(),
            TEST_REQUEST_ID.to_string(),
            signed_at,
            node_id,
            partial_bytes.clone(),
            challenge_bytes.clone(),
            proof_bytes.clone(),
        );
        let signature =
            sign_node_message_with_hex_key(&signer.secret_hex, &statement.canonical_bytes())
                .expect("sign attestation");
        PetShareAttestation {
            request_id: TEST_REQUEST_ID.to_string(),
            from_node_id: node_id,
            partial: partial_bytes,
            challenge: challenge_bytes,
            proof: proof_bytes,
            signed_at,
            signature,
        }
    }

    async fn test_coordinator(
        db_name: &str,
        ring_payload: &RingPayload,
    ) -> PetCoordinator<DkgImpl, PetImpl> {
        let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("dummy bulletin"));
        dummy_bulletin
            .set_ring(RING_ID.to_string(), ring_payload.clone())
            .expect("seed ring");
        let app_state = create_test_app_state_with_bulletin(true, dummy_bulletin, db_name).await;

        // `verify_pet_admission` loads this ring's PET checking-key bundle to
        // get a public polynomial to verify per-share DLEQ proofs against.
        // Every fixture's "threshold sharing" is the degree-0 "identical
        // shares" trick (see `FixtureBase::pet_sk`), so a single-commit
        // polynomial pinned to the ring's own `pet_pk` is exactly the
        // matching public commitment. `share_bytes` itself is never read by
        // `verify_pet_admission`, so a throwaway placeholder is fine there.
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
    // pair, unlike PRE's own request handling (which always resolves both
    // together via `resolve_document_and_ring_payloads`).
    // ========================================================================

    #[tokio::test]
    #[serial_test::serial]
    async fn verify_pet_check_request_rejects_a_document_object_id_mismatch() {
        let db_name = "pet_check_request_rejects_document_object_id_mismatch";
        // Same ring, two different documents (distinct random tags/proofs) —
        // `fixture_a.document`, `fixture_b`'s id: exactly finding #7's attack
        // shape, a malicious coordinator pairing a genuine document with a
        // different document's claimed identity.
        let fixture_a = build_fixture(3, 2);
        let fixture_b = build_fixture(3, 2);
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

    #[tokio::test]
    #[serial_test::serial]
    async fn verify_pet_admission_rejects_missing_attestations() {
        let db_name = "pet_admission_rejects_missing_attestations";
        let fixture = build_fixture(3, 2);
        let coordinator = test_coordinator(db_name, &fixture.ring_payload).await;

        let result = coordinator
            .verify_pet_admission(
                &fixture.document,
                None,
                &object_id_for(&fixture),
                None,
                AUDIT_TARGET,
                "test-actor",
                None,
                &fixture.ring_payload,
                &[],
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
    async fn verify_pet_admission_rejects_insufficient_attestations() {
        let db_name = "pet_admission_rejects_insufficient_attestations";
        let fixture = build_fixture(3, 2);
        let coordinator = test_coordinator(db_name, &fixture.ring_payload).await;

        let attestations = vec![valid_attestation(&fixture, 1)];
        let result = coordinator
            .verify_pet_admission(
                &fixture.document,
                None,
                &object_id_for(&fixture),
                None,
                AUDIT_TARGET,
                "test-actor",
                None,
                &fixture.ring_payload,
                &attestations,
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
    async fn verify_pet_admission_rejects_duplicate_attestation_indices() {
        let db_name = "pet_admission_rejects_duplicate_indices";
        let fixture = build_fixture(3, 2);
        let coordinator = test_coordinator(db_name, &fixture.ring_payload).await;

        let first = valid_attestation(&fixture, 1);
        // A second, independently "genuine" contribution for the *same*
        // slot — signature and DLEQ proof both pass (it's a byte-identical
        // rebuild), so this isolates the duplicate-index check specifically.
        let second = valid_attestation(&fixture, 1);
        let result = coordinator
            .verify_pet_admission(
                &fixture.document,
                None,
                &object_id_for(&fixture),
                None,
                AUDIT_TARGET,
                "test-actor",
                None,
                &fixture.ring_payload,
                &[first, second],
            )
            .await;

        assert!(
            matches!(result, Err(PetError::Crypto(_))),
            "expected a duplicate-index rejection, got {:?}",
            result
        );
        cleanup_db(&test_db_path(db_name));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn verify_pet_admission_rejects_out_of_range_node_id() {
        let db_name = "pet_admission_rejects_out_of_range_node_id";
        let fixture = build_fixture(3, 2);
        let coordinator = test_coordinator(db_name, &fixture.ring_payload).await;

        let mut out_of_range = valid_attestation(&fixture, 1);
        out_of_range.from_node_id = 99; // outside the 3-member committee
        let attestations = vec![out_of_range, valid_attestation(&fixture, 2)];
        let result = coordinator
            .verify_pet_admission(
                &fixture.document,
                None,
                &object_id_for(&fixture),
                None,
                AUDIT_TARGET,
                "test-actor",
                None,
                &fixture.ring_payload,
                &attestations,
            )
            .await;

        assert!(
            matches!(result, Err(PetError::Crypto(_))),
            "expected an out-of-range node id rejection, got {:?}",
            result
        );
        cleanup_db(&test_db_path(db_name));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn verify_pet_admission_rejects_forged_signature() {
        let db_name = "pet_admission_rejects_forged_signature";
        let fixture = build_fixture(3, 2);
        let coordinator = test_coordinator(db_name, &fixture.ring_payload).await;

        let genuine = valid_attestation(&fixture, 1);
        let mut forged = valid_attestation(&fixture, 2);
        // Node 2's real signature, but for a *different* partial than the one
        // actually being submitted under its name — exactly what a
        // compromised/absent initiator would have to fabricate to bypass PET
        // without ever contacting node 2 for a genuine contribution.
        let (_sk, other_point) =
            crypto::helpers::generate_keypair().expect("generate mismatched partial");
        forged.partial = CryptoSerialize::to_bytes(&other_point).expect("serialize partial");

        let result = coordinator
            .verify_pet_admission(
                &fixture.document,
                None,
                &object_id_for(&fixture),
                None,
                AUDIT_TARGET,
                "test-actor",
                None,
                &fixture.ring_payload,
                &[genuine, forged],
            )
            .await;

        assert!(
            matches!(result, Err(PetError::Crypto(_))),
            "expected a signature-verification rejection, got {:?}",
            result
        );
        cleanup_db(&test_db_path(db_name));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn verify_pet_admission_rejects_and_reports_a_malformed_attestation() {
        let db_name = "pet_admission_rejects_and_reports_malformed_attestation";
        let fixture = build_fixture(3, 2);
        let coordinator = test_coordinator(db_name, &fixture.ring_payload).await;

        let genuine = valid_attestation(&fixture, 1);
        // Node 2's real signature, over genuinely undecodable
        // partial/challenge/proof bytes — distinct from a forged-signature
        // or a decodable-but-wrong DLEQ proof (finding #9): before the fix
        // this fell through to a bare deserialization error with no report
        // ever queued for node 2. `verify_pet_admission` now attempts to
        // queue an invalid-crypto report for it before returning that same
        // error (best-effort — this test only asserts the outward
        // rejection, since queueing itself is fire-and-forget and never
        // gates the admission decision).
        let mut malformed = valid_attestation(&fixture, 2);
        malformed.partial = vec![0xff, 0xff, 0xff];
        let statement_ctx = test_statement_ctx(&fixture);
        let signer = &fixture.signers[1];
        let statement = statement_ctx.statement_for(
            signer.pubkey_hex.clone(),
            TEST_REQUEST_ID.to_string(),
            malformed.signed_at,
            2,
            malformed.partial.clone(),
            malformed.challenge.clone(),
            malformed.proof.clone(),
        );
        malformed.signature =
            sign_node_message_with_hex_key(&signer.secret_hex, &statement.canonical_bytes())
                .expect("sign malformed attestation");

        let result = coordinator
            .verify_pet_admission(
                &fixture.document,
                None,
                &object_id_for(&fixture),
                None,
                AUDIT_TARGET,
                "test-actor",
                None,
                &fixture.ring_payload,
                &[genuine, malformed],
            )
            .await;

        assert!(
            matches!(result, Err(PetError::Deserialization(_))),
            "expected a deserialization rejection, got {:?}",
            result
        );
        cleanup_db(&test_db_path(db_name));
    }

    /// Confirms the rejections above aren't vacuous against a gate that
    /// rejects everything: `threshold`-many genuinely signed, correctly
    /// combining attestations for a tag that really does match the audited
    /// owner must be admitted.
    #[tokio::test]
    #[serial_test::serial]
    async fn verify_pet_admission_accepts_genuine_attestations() {
        let db_name = "pet_admission_accepts_genuine_attestations";
        let committee_size = 3;
        let threshold = 2;
        let fixture = build_fixture_with_real_target(committee_size, threshold, AUDIT_TARGET);
        let coordinator = test_coordinator(db_name, &fixture.ring_payload).await;

        let attestations: Vec<PetShareAttestation> = (1..=threshold)
            .map(|node_id| valid_attestation(&fixture, node_id))
            .collect();

        let result = coordinator
            .verify_pet_admission(
                &fixture.document,
                None,
                &object_id_for(&fixture),
                None,
                AUDIT_TARGET,
                "test-actor",
                None,
                &fixture.ring_payload,
                &attestations,
            )
            .await;

        assert!(
            result.is_ok(),
            "expected genuine attestations to be admitted: {:?}",
            result
        );
        cleanup_db(&test_db_path(db_name));
    }

    // ========================================================================
    // `verify_check_response`'s acceptance ordering must
    // never let a rejected or invalid response consume a participant's slot.
    // `verify_check_response` is a pure function (no `AppState`/local
    // storage/network), so these tests call it directly — no coordinator,
    // no tokio runtime, no on-disk db.
    // ========================================================================

    fn fixture_tag(fixture: &TagFixture) -> PetTag {
        PetTag::try_from(fixture.document.pet_tag.clone().expect("fixture has a tag"))
            .expect("parse fixture tag")
    }

    fn fixture_pub_poly(fixture: &TagFixture) -> crypto::PubPolyImpl {
        let pet_pk_bytes = hex::decode(fixture.ring_payload.pet_pk.as_ref().expect("pet_pk"))
            .expect("decode pet_pk hex");
        let pet_pk = G1Affine::from_bytes(&pet_pk_bytes).expect("decode pet_pk point");
        crypto::PubPolyImpl {
            commits: vec![pet_pk],
        }
    }

    fn attestation_to_check_response(
        attestation: PetShareAttestation,
    ) -> crate::pet::v0::messages::PetMessage {
        crate::pet::v0::messages::PetMessage::CheckResponse {
            request_id: attestation.request_id,
            from_node_id: attestation.from_node_id,
            partial: attestation.partial,
            challenge: attestation.challenge,
            proof: attestation.proof,
            signed_at: attestation.signed_at,
            signature: attestation.signature,
        }
    }

    /// A response claiming `node_id`'s slot with an invalid signature —
    /// exactly what a malicious responder sends to try to preempt an honest
    /// participant's id without ever having a real key or share for it.
    fn spoofed_response(
        fixture: &TagFixture,
        node_id: u32,
    ) -> crate::pet::v0::messages::PetMessage {
        let mut response = attestation_to_check_response(valid_attestation(fixture, node_id));
        if let crate::pet::v0::messages::PetMessage::CheckResponse { signature, .. } = &mut response
        {
            signature[0] ^= 0x01;
        }
        response
    }

    /// A response genuinely signed by `node_id`'s real key, but over a
    /// partial/challenge/proof that was never computed via
    /// `Pet::partial_pet_check` — authenticated, but cryptographically
    /// invalid. Mirrors the shape a compromised (but key-holding) committee
    /// member, or a bug, would produce.
    fn invalid_proof_response(
        fixture: &TagFixture,
        node_id: u32,
    ) -> crate::pet::v0::messages::PetMessage {
        let (_sk, garbage_point) =
            crypto::helpers::generate_keypair().expect("generate garbage partial");
        let partial_bytes = CryptoSerialize::to_bytes(&garbage_point).expect("serialize partial");
        let challenge_bytes =
            CryptoSerialize::to_bytes(&Fr::from(7u64)).expect("serialize challenge");
        let proof_bytes = CryptoSerialize::to_bytes(&Fr::from(9u64)).expect("serialize proof");
        let signed_at = 1_700_000_000u64;
        let statement_ctx = test_statement_ctx(fixture);
        let signer = &fixture.signers[(node_id - 1) as usize];
        let statement = statement_ctx.statement_for(
            signer.pubkey_hex.clone(),
            TEST_REQUEST_ID.to_string(),
            signed_at,
            node_id,
            partial_bytes.clone(),
            challenge_bytes.clone(),
            proof_bytes.clone(),
        );
        let signature =
            sign_node_message_with_hex_key(&signer.secret_hex, &statement.canonical_bytes())
                .expect("sign attestation");
        crate::pet::v0::messages::PetMessage::CheckResponse {
            request_id: TEST_REQUEST_ID.to_string(),
            from_node_id: node_id,
            partial: partial_bytes,
            challenge: challenge_bytes,
            proof: proof_bytes,
            signed_at,
            signature,
        }
    }

    /// A response genuinely signed by `node_id`'s real key, but whose
    /// `partial`/`challenge`/`proof` bytes are not valid encodings of a
    /// group element/scalar at all — distinct from `invalid_proof_response`
    /// (which decodes fine but fails the DLEQ check). Finding #9: before the
    /// fix, this case fell through to a bare `Rejected`/deserialization
    /// error with no report ever queued, letting a malicious responder
    /// dodge reporting just by signing garbage instead of a well-formed
    /// wrong proof.
    fn malformed_response(
        fixture: &TagFixture,
        node_id: u32,
    ) -> crate::pet::v0::messages::PetMessage {
        let partial_bytes = vec![0xffu8; 3];
        let challenge_bytes = vec![0xffu8; 3];
        let proof_bytes = vec![0xffu8; 3];
        let signed_at = 1_700_000_000u64;
        let statement_ctx = test_statement_ctx(fixture);
        let signer = &fixture.signers[(node_id - 1) as usize];
        let statement = statement_ctx.statement_for(
            signer.pubkey_hex.clone(),
            TEST_REQUEST_ID.to_string(),
            signed_at,
            node_id,
            partial_bytes.clone(),
            challenge_bytes.clone(),
            proof_bytes.clone(),
        );
        let signature =
            sign_node_message_with_hex_key(&signer.secret_hex, &statement.canonical_bytes())
                .expect("sign malformed attestation");
        crate::pet::v0::messages::PetMessage::CheckResponse {
            request_id: TEST_REQUEST_ID.to_string(),
            from_node_id: node_id,
            partial: partial_bytes,
            challenge: challenge_bytes,
            proof: proof_bytes,
            signed_at,
            signature,
        }
    }

    #[test]
    fn spoofed_response_does_not_block_the_honest_participants_later_valid_response() {
        let fixture = build_fixture(3, 2);
        let pub_poly = fixture_pub_poly(&fixture);
        let tag = fixture_tag(&fixture);
        let statement_ctx = test_statement_ctx(&fixture);
        let mut seen_node_ids = HashSet::new();

        let spoofed = spoofed_response(&fixture, 1);
        let spoofed_result = PetCoordinator::<DkgImpl, PetImpl>::verify_check_response(
            spoofed,
            "peer-attacker",
            &fixture.ring_payload,
            &fixture.document.ring_id,
            &pub_poly,
            &tag,
            &statement_ctx,
            TEST_REQUEST_ID,
            &None,
            &mut seen_node_ids,
        );
        assert!(
            matches!(spoofed_result, PetCheckResponseVerification::Rejected),
            "a spoofed response must be rejected"
        );
        assert!(
            !seen_node_ids.contains(&1),
            "a rejected response must not consume the claimed participant's slot"
        );

        let genuine = attestation_to_check_response(valid_attestation(&fixture, 1));
        let genuine_result = PetCoordinator::<DkgImpl, PetImpl>::verify_check_response(
            genuine,
            "peer-1",
            &fixture.ring_payload,
            &fixture.document.ring_id,
            &pub_poly,
            &tag,
            &statement_ctx,
            TEST_REQUEST_ID,
            &None,
            &mut seen_node_ids,
        );
        assert!(
            matches!(genuine_result, PetCheckResponseVerification::Verified(..)),
            "node 1's real, later response must still be accepted"
        );
    }

    #[test]
    fn invalid_proof_response_does_not_consume_the_slot_for_a_subsequent_valid_contribution() {
        let fixture = build_fixture(3, 2);
        let pub_poly = fixture_pub_poly(&fixture);
        let tag = fixture_tag(&fixture);
        let statement_ctx = test_statement_ctx(&fixture);
        let mut seen_node_ids = HashSet::new();

        let bad = invalid_proof_response(&fixture, 1);
        let bad_result = PetCoordinator::<DkgImpl, PetImpl>::verify_check_response(
            bad,
            "peer-1",
            &fixture.ring_payload,
            &fixture.document.ring_id,
            &pub_poly,
            &tag,
            &statement_ctx,
            TEST_REQUEST_ID,
            &None,
            &mut seen_node_ids,
        );
        assert!(
            matches!(bad_result, PetCheckResponseVerification::InvalidProof(_)),
            "an authenticated but cryptographically invalid response must be reported, not silently dropped"
        );
        assert!(
            !seen_node_ids.contains(&1),
            "an invalid-proof response must not consume the participant's slot"
        );

        let genuine = attestation_to_check_response(valid_attestation(&fixture, 1));
        let genuine_result = PetCoordinator::<DkgImpl, PetImpl>::verify_check_response(
            genuine,
            "peer-1",
            &fixture.ring_payload,
            &fixture.document.ring_id,
            &pub_poly,
            &tag,
            &statement_ctx,
            TEST_REQUEST_ID,
            &None,
            &mut seen_node_ids,
        );
        assert!(
            matches!(genuine_result, PetCheckResponseVerification::Verified(..)),
            "node 1's real contribution must still be accepted after its own earlier invalid attempt"
        );
    }

    #[test]
    fn malformed_response_is_reported_and_does_not_consume_the_slot() {
        let fixture = build_fixture(3, 2);
        let pub_poly = fixture_pub_poly(&fixture);
        let tag = fixture_tag(&fixture);
        let statement_ctx = test_statement_ctx(&fixture);
        let mut seen_node_ids = HashSet::new();

        let bad = malformed_response(&fixture, 1);
        let bad_result = PetCoordinator::<DkgImpl, PetImpl>::verify_check_response(
            bad,
            "peer-1",
            &fixture.ring_payload,
            &fixture.document.ring_id,
            &pub_poly,
            &tag,
            &statement_ctx,
            TEST_REQUEST_ID,
            &None,
            &mut seen_node_ids,
        );
        assert!(
            matches!(bad_result, PetCheckResponseVerification::InvalidProof(_)),
            "an authenticated but undecodable response must be reported, not just dropped (finding #9)"
        );
        assert!(
            !seen_node_ids.contains(&1),
            "a malformed response must not consume the participant's slot"
        );

        let genuine = attestation_to_check_response(valid_attestation(&fixture, 1));
        let genuine_result = PetCoordinator::<DkgImpl, PetImpl>::verify_check_response(
            genuine,
            "peer-1",
            &fixture.ring_payload,
            &fixture.document.ring_id,
            &pub_poly,
            &tag,
            &statement_ctx,
            TEST_REQUEST_ID,
            &None,
            &mut seen_node_ids,
        );
        assert!(
            matches!(genuine_result, PetCheckResponseVerification::Verified(..)),
            "node 1's real contribution must still be accepted after its own earlier malformed attempt"
        );
    }

    #[test]
    fn duplicate_valid_contributions_count_only_once() {
        let fixture = build_fixture(3, 2);
        let pub_poly = fixture_pub_poly(&fixture);
        let tag = fixture_tag(&fixture);
        let statement_ctx = test_statement_ctx(&fixture);
        let mut seen_node_ids = HashSet::new();

        let first = PetCoordinator::<DkgImpl, PetImpl>::verify_check_response(
            attestation_to_check_response(valid_attestation(&fixture, 1)),
            "peer-1",
            &fixture.ring_payload,
            &fixture.document.ring_id,
            &pub_poly,
            &tag,
            &statement_ctx,
            TEST_REQUEST_ID,
            &None,
            &mut seen_node_ids,
        );
        assert!(matches!(first, PetCheckResponseVerification::Verified(..)));

        let second = PetCoordinator::<DkgImpl, PetImpl>::verify_check_response(
            attestation_to_check_response(valid_attestation(&fixture, 1)),
            "peer-1-retry",
            &fixture.ring_payload,
            &fixture.document.ring_id,
            &pub_poly,
            &tag,
            &statement_ctx,
            TEST_REQUEST_ID,
            &None,
            &mut seen_node_ids,
        );
        assert!(
            matches!(second, PetCheckResponseVerification::Rejected),
            "a second valid contribution for an already-accepted id must count only once"
        );
    }

    #[test]
    fn three_of_five_collection_succeeds_despite_earlier_spoofing_and_invalid_proof_attempts() {
        let fixture = build_fixture(5, 3);
        let pub_poly = fixture_pub_poly(&fixture);
        let tag = fixture_tag(&fixture);
        let statement_ctx = test_statement_ctx(&fixture);
        let mut seen_node_ids = HashSet::new();
        let mut shares = Vec::new();

        let responses = vec![
            spoofed_response(&fixture, 1),
            invalid_proof_response(&fixture, 2),
            attestation_to_check_response(valid_attestation(&fixture, 1)),
            attestation_to_check_response(valid_attestation(&fixture, 2)),
            attestation_to_check_response(valid_attestation(&fixture, 3)),
        ];
        for response in responses {
            if let PetCheckResponseVerification::Verified(share, _) =
                PetCoordinator::<DkgImpl, PetImpl>::verify_check_response(
                    response,
                    "peer",
                    &fixture.ring_payload,
                    &fixture.document.ring_id,
                    &pub_poly,
                    &tag,
                    &statement_ctx,
                    TEST_REQUEST_ID,
                    &None,
                    &mut seen_node_ids,
                )
            {
                shares.push(share);
            }
        }

        assert_eq!(
            seen_node_ids,
            std::collections::HashSet::from([1, 2, 3]),
            "the three genuine contributions must all be accepted despite the earlier spoofing \
             and invalid-proof attempts on nodes 1 and 2"
        );
        assert_eq!(shares.len(), 3, "threshold must be reached");
    }

    // ========================================================================
    // Finding #3 (PET audit fix checklist): `handle_check_request` is the
    // one entry point reachable from a raw wire message with no other
    // upstream authentication. `verify_pet_audit_authorization` closes that
    // gap; it needs only an `Authz` impl (no coordinator/bulletin/local
    // storage), so most of these tests call it directly.
    // ========================================================================

    /// A throwaway document + object_id sufficient for
    /// `verify_pet_audit_authorization`, which never reads
    /// `document.document`/`.proof`/`.pet_tag*` — only the policy fields
    /// `check_pet_permission` needs.
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

    /// Confirms the rejections above aren't vacuous: a genuinely matching,
    /// valid token must still be accepted (and, with `DummyAuthZ` always
    /// authorizing, reach `Ok(())`).
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
    /// `CheckRequest` with no valid audit authorization must be rejected by
    /// the real `handle_message`/`handle_check_request` path, before this
    /// node's secret share is ever touched.
    #[tokio::test]
    #[serial_test::serial]
    async fn handle_check_request_rejects_a_request_with_no_valid_audit_authorization() {
        let db_name = "pet_handle_check_request_rejects_unauthorized_audit";
        let fixture = build_fixture(3, 2);
        let coordinator = test_coordinator(db_name, &fixture.ring_payload).await;

        let request = PetCheckRequest {
            request_id: TEST_REQUEST_ID.to_string(),
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
            .handle_message(PetMessage::CheckRequest(Box::new(request)))
            .await;

        assert!(
            matches!(result, Err(PetError::InvalidInput(_))),
            "a CheckRequest with no valid audit authorization must be rejected: {:?}",
            result
        );
        cleanup_db(&test_db_path(db_name));
    }

    /// Confirms the rejection above isn't vacuous against a gate that
    /// rejects every `CheckRequest`: a valid, correctly-bound audit token
    /// must still be accepted end-to-end.
    #[tokio::test]
    #[serial_test::serial]
    async fn handle_check_request_accepts_a_request_with_valid_audit_authorization() {
        let db_name = "pet_handle_check_request_accepts_valid_audit_authorization";
        let fixture = build_fixture(3, 2);
        let coordinator = test_coordinator(db_name, &fixture.ring_payload).await;

        let object_id = object_id_for(&fixture);
        let token = TestKeyPair::new()
            .create_pre_jwt(b"unused".to_vec(), &object_id, None, None)
            .expect("sign token");
        let request = PetCheckRequest {
            request_id: TEST_REQUEST_ID.to_string(),
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
            .handle_message(PetMessage::CheckRequest(Box::new(request)))
            .await;

        assert!(
            matches!(result, Ok(Some(PetMessage::CheckResponse { .. }))),
            "a CheckRequest with a valid, correctly-bound audit token must be accepted: {:?}",
            result
        );
        cleanup_db(&test_db_path(db_name));
    }
}
