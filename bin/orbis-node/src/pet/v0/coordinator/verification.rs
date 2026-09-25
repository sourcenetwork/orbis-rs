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
//! it does resolve the audit target, and every ring committee member that
//! could release a share for a PET-gated document now learns it. This is a
//! deliberate, reviewed trade-off: the alternative (a target-blind proof of
//! correct ACP resolution and match) would need a ZK circuit over ACP's
//! live relational query, well out of scope here. The exposure stays
//! committee-internal, the same trust boundary as `actor_id`/`object_id`,
//! which peers already see in `PreRequestContext` today.

use super::PetCoordinator;
use crate::helpers::identity::node_key_for_id;
use crate::helpers::protocol_version::read_ring_for_route;
use crate::pet::v0::attestation::{pet_share_signing_bytes, PetShareAttestation};
use crate::pet::v0::error::{PetError, Result};
use crate::pet::v0::messages::PetCheckContext;
use crypto::context::CiphertextContext;
use crypto::r#trait::{
    CryptoDeserialize, Dkg, EncryptionProof, Pet, PetTag, PubShare, Secret, TagKnowledgeProof,
};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr};
use std::collections::HashSet;

/// The ACP resource type and relation an audit-target object's real owner is
/// registered under. Bankd registers `Relationship { object: (PET_OWNER_RESOURCE,
/// <audit_target_object_id>), relation: PET_OWNER_RELATION, subject:
/// Actor(<owner_did>) }` once per owner; this is the contract external
/// callers follow. Used only by `initiator.rs`'s final target resolution —
/// see this module's own doc comment for why responders never need it.
pub(crate) const PET_OWNER_RESOURCE: &str = "owner";
pub(crate) const PET_OWNER_RELATION: &str = "owner";

fn deserialize_secret(document_json: &str) -> Result<Secret> {
    serde_json::from_str(document_json)
        .map_err(|e| PetError::Deserialization(format!("Failed to deserialize secret: {}", e)))
}

fn build_ciphertext_context(
    ring_pk_hex: &str,
    document: &bulletin::r#trait::DocumentPayload,
    salt: Option<&str>,
) -> Result<CiphertextContext> {
    let ring_pk = hex::decode(ring_pk_hex)
        .map_err(|e| PetError::InvalidInput(format!("Invalid ring_pk hex encoding: {}", e)))?;
    Ok(CiphertextContext {
        ring_pk,
        policy_id: document.policy_id.clone(),
        resource: document.resource.clone(),
        permission: document.permission.clone(),
        tier: document.tier.clone(),
        timestamp: document.timestamp,
        salt: salt.map(str::to_string),
    })
}

impl<D, P> PetCoordinator<D, P>
where
    D: Dkg<ShareValue = Fr, PublicKey = G1Affine> + Clone + Send + Sync + 'static,
    P: Pet<ShareValue = Fr, PublicKey = G1Affine>,
{
    /// Independently verify a PET-check request end to end — resolves the
    /// live ring, rebuilds the tag-knowledge-proof transcript digest from
    /// primary sources, and verifies the proof. Never trusts anything the
    /// initiator merely asserts: every value used here is either read live
    /// from the bulletin or bound into the proof itself.
    ///
    /// Returns the verified tag, the ring's resolved `pet_pk` hex (so
    /// callers that also need it — e.g. to sanity-check their local share —
    /// don't have to re-read the ring a second time), and the transcript
    /// digest the proof was checked against (reused as the binding context
    /// for `PetShareAttestation` signatures).
    pub(crate) async fn verify_pet_check_request(
        &self,
        ctx: &PetCheckContext,
    ) -> Result<(PetTag, String, [u8; 32])> {
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
        let pet_pk_hex = ring_payload.pet_pk.ok_or_else(|| {
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
        let ciphertext_context =
            build_ciphertext_context(&ring_payload.ring_pk, &ctx.document, ctx.salt.as_deref())?;

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

        Ok((tag, pet_pk_hex, digest))
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
    pub(crate) async fn verify_pet_admission(
        &self,
        document: &bulletin::r#trait::DocumentPayload,
        salt: Option<&str>,
        audit_target_object_id: &str,
        ring_payload: &bulletin::r#trait::RingPayload,
        attestations: &[PetShareAttestation],
    ) -> Result<()> {
        let ctx = PetCheckContext {
            document: document.clone(),
            salt: salt.map(str::to_string),
        };
        let (tag, _pet_pk_hex, digest) = self.verify_pet_check_request(&ctx).await?;

        let threshold = ring_payload.threshold as usize;
        let n = ring_payload.peer_node_keys.len();
        if attestations.len() < threshold {
            return Err(PetError::InsufficientShares {
                got: attestations.len(),
                need: threshold,
            });
        }

        let mut shares = Vec::with_capacity(threshold);
        let mut seen_indices = HashSet::new();
        for attestation in attestations.iter().take(threshold) {
            if !seen_indices.insert(attestation.from_node_id) {
                return Err(PetError::Crypto(format!(
                    "duplicate PET attestation index {}",
                    attestation.from_node_id
                )));
            }
            let node_key = node_key_for_id(attestation.from_node_id, &ring_payload.peer_node_keys)
                .ok_or_else(|| {
                    PetError::Crypto(format!(
                        "PET attestation from_node_id {} is not in the ring committee",
                        attestation.from_node_id
                    ))
                })?;
            let signing_bytes =
                pet_share_signing_bytes(&digest, attestation.from_node_id, &attestation.partial);
            common::blockchain::verify_node_message(
                &node_key,
                &signing_bytes,
                &attestation.signature,
            )
            .map_err(|e| {
                PetError::Crypto(format!(
                    "invalid PET attestation signature from node {}: {}",
                    attestation.from_node_id, e
                ))
            })?;
            let partial = G1Affine::from_bytes(&attestation.partial).map_err(|e| {
                PetError::Deserialization(format!(
                    "failed to deserialize PET attestation partial: {}",
                    e
                ))
            })?;
            shares.push(PubShare {
                i: attestation.from_node_id,
                v: partial,
            });
        }

        let combined = P::combine_pet_check_shares(&shares, threshold, n)
            .map_err(|e| PetError::Crypto(format!("Failed to combine PET check shares: {}", e)))?;

        let target_owner_id = self
            .app_state
            .authz
            .resolve_relation_subject(
                &document.policy_id,
                PET_OWNER_RESOURCE,
                audit_target_object_id,
                PET_OWNER_RELATION,
            )
            .await
            .map_err(|e| PetError::Acp(e.to_string()))?;
        let target_fingerprint = P::owner_fingerprint(target_owner_id.as_bytes())
            .map_err(|e| PetError::Crypto(format!("Failed to compute owner fingerprint: {}", e)))?;

        P::verify_pet_match(&tag, &combined, &target_fingerprint).map_err(|_| PetError::Mismatch)
    }
}
