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
use crate::pet::v0::attestation::{pet_share_signing_bytes, PetShareAttestation};
use crate::pet::v0::error::{PetError, Result};
use crate::pet::v0::messages::PetCheckContext;
use authz::r#trait::Authz;
use authz::vera::{AccessCheckRequest, ValidWindow};
use crypto::context::CiphertextContext;
use crypto::r#trait::{
    CryptoDeserialize, Dkg, EncryptionProof, Pet, PetTag, PubShare, Secret, TagKnowledgeProof,
};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr};
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
        actor_id: &str,
        valid_window: Option<ValidWindow>,
        ring_payload: &bulletin::r#trait::RingPayload,
        attestations: &[PetShareAttestation],
    ) -> Result<()> {
        // Authorization gate first — an unauthorized caller learns nothing
        // about whether the tag itself would have matched.
        check_pet_permission(
            &*self.app_state.authz,
            document,
            audit_target_object_id,
            actor_id,
            valid_window,
        )
        .await?;

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
        cleanup_db, create_test_app_state_with_bulletin, test_db_path,
    };
    use bulletin::dummy::DummyBulletin;
    use bulletin::r#trait::{DocumentPayload, RingPayload};
    use common::blockchain::{sign_node_message_with_hex_key, ChainConfig, TxSigner};
    use crypto::r#trait::CryptoSerialize;
    use crypto::{DkgImpl, PetImpl};
    use std::sync::Arc;

    const RING_ID: &str = "pet-admission-test-ring";
    const AUDIT_TARGET: &str = "pet-admission-audit-target";

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
    }

    struct TagFixture {
        ring_payload: RingPayload,
        document: DocumentPayload,
        digest: [u8; 32],
        signers: Vec<TestSigner>,
    }

    /// Builds everything except the tag's `masked_fingerprint` (callers supply
    /// that, since rejection tests use garbage bytes — never checked by
    /// `verify_tag_knowledge`, only the Schnorr proof over `ephemeral_point`
    /// is — while the one happy-path test needs a real `F(owner) + pet_sk*R`).
    fn build_base(committee_size: usize, threshold: u32, pet_pk: &G1Affine) -> FixtureBase {
        let mut signers: Vec<TestSigner> = (0..committee_size).map(|_| gen_signer()).collect();
        signers.sort_by(|a, b| a.pubkey_hex.cmp(&b.pubkey_hex));
        let peer_node_keys: Vec<String> = signers.iter().map(|s| s.pubkey_hex.clone()).collect();

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
                CryptoSerialize::to_bytes(pet_pk).expect("serialize pet_pk"),
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
        let pet_pk_bytes =
            hex::decode(base.ring_payload.pet_pk.as_ref().unwrap()).expect("decode pet_pk hex");
        let ciphertext_context =
            build_ciphertext_context(&base.ring_payload.ring_pk, &base.document, None)
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

        base.document.pet_tag = Some(String::try_from(tag).expect("serialize tag"));
        base.document.pet_tag_proof =
            Some(String::try_from(tag_proof).expect("serialize tag proof"));

        TagFixture {
            ring_payload: base.ring_payload,
            document: base.document,
            digest,
            signers: base.signers,
        }
    }

    /// A garbage-`masked_fingerprint` fixture — sufficient for every test
    /// below that expects rejection to happen at the attestation layer, never
    /// reaching `combine_pet_check_shares`/`verify_pet_match`.
    fn build_fixture(committee_size: usize, threshold: u32) -> TagFixture {
        let (_unused_sk, placeholder_pet_pk) =
            crypto::helpers::generate_keypair().expect("generate placeholder pet keypair");
        let base = build_base(committee_size, threshold, &placeholder_pet_pk);
        finalize_fixture(base, vec![9, 9, 9])
    }

    /// A correctly-signed attestation from committee member `node_id`
    /// (1-based, matching `signers[node_id - 1]`'s sorted position). The
    /// partial value doesn't correspond to a real threshold share — fine for
    /// every test here, since each one is rejected before
    /// `combine_pet_check_shares` is ever reached.
    fn valid_attestation(fixture: &TagFixture, node_id: u32) -> PetShareAttestation {
        let (_throwaway_sk, partial_point) =
            crypto::helpers::generate_keypair().expect("generate stand-in partial");
        let partial = CryptoSerialize::to_bytes(&partial_point).expect("serialize partial");
        let signing_bytes = pet_share_signing_bytes(&fixture.digest, node_id, &partial);
        let signer = &fixture.signers[(node_id - 1) as usize];
        let signature = sign_node_message_with_hex_key(&signer.secret_hex, &signing_bytes)
            .expect("sign attestation");
        PetShareAttestation {
            from_node_id: node_id,
            partial,
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
        PetCoordinator::<DkgImpl, PetImpl>::with_routes(Arc::new(app_state), &::network::V0)
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
        let mut second = valid_attestation(&fixture, 2);
        second.from_node_id = 1; // claims the same committee slot as `first`
        let result = coordinator
            .verify_pet_admission(
                &fixture.document,
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

    /// Confirms the rejections above aren't vacuous against a gate that
    /// rejects everything: `threshold`-many genuinely signed, correctly
    /// combining attestations for a tag that really does match the audited
    /// owner must be admitted. Gated to bls12-381 because constructing a real
    /// `masked_fingerprint = F(owner) + pet_sk*R` needs one curve-point
    /// addition with no backend-agnostic primitive exposed for it — see
    /// `Pet::verify_pet_match`'s own doc comment for the same operation.
    #[cfg(feature = "bls12-381")]
    #[tokio::test]
    #[serial_test::serial]
    async fn verify_pet_admission_accepts_genuine_attestations() {
        use ark_bls12_381::G1Projective;
        use ark_ec::CurveGroup;

        let db_name = "pet_admission_accepts_genuine_attestations";
        let committee_size = 3;
        let threshold = 2;
        let (pet_sk, pet_pk) =
            crypto::helpers::generate_keypair().expect("generate pet checking keypair");
        let base = build_base(committee_size, threshold, &pet_pk);

        // Simulate a threshold sharing of the PET checking key by giving every
        // committee member the *same* scalar as its "share" — a degree-0
        // polynomial, so Lagrange interpolation over any subset of points
        // recovers it exactly regardless of `threshold`. Same trick as
        // `crypto`'s own `identical_shares` test helper.
        let staging_tag = PetTag {
            ephemeral_point: CryptoSerialize::to_bytes(&base.r_point)
                .expect("serialize ephemeral point"),
            masked_fingerprint: Vec::new(),
        };
        let combined =
            PetImpl::partial_pet_check(&pet_sk, &staging_tag).expect("compute pet_sk * R");
        let target_fingerprint =
            PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(owner)");
        let masked =
            (G1Projective::from(target_fingerprint) + G1Projective::from(combined)).into_affine();
        let masked_bytes =
            CryptoSerialize::to_bytes(&masked).expect("serialize masked fingerprint");

        let fixture = finalize_fixture(base, masked_bytes);
        let coordinator = test_coordinator(db_name, &fixture.ring_payload).await;

        let partial_bytes = CryptoSerialize::to_bytes(&combined).expect("serialize partial");
        let attestations: Vec<PetShareAttestation> = (1..=threshold)
            .map(|node_id| {
                let signing_bytes =
                    pet_share_signing_bytes(&fixture.digest, node_id, &partial_bytes);
                let signer = &fixture.signers[(node_id - 1) as usize];
                let signature = sign_node_message_with_hex_key(&signer.secret_hex, &signing_bytes)
                    .expect("sign attestation");
                PetShareAttestation {
                    from_node_id: node_id,
                    partial: partial_bytes.clone(),
                    signature,
                }
            })
            .collect();

        let result = coordinator
            .verify_pet_admission(
                &fixture.document,
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
}
