//! Shared integration test: PET decrypt-phase misbehavior. Node3 signs an
//! invalid DLEQ proof after passing normal authorization, certificate and
//! atomic-bundle checks. Its stored key remains valid, so commit/reveal
//! still succeed; honest decrypt shares keep PRE available while the
//! signed bad response produces an actual on-chain report and demerit.
//!
//! Report detection is backend-neutral production code (same reasoning as
//! `report_offline_pre_sign.rs`), and the fault-injection RPC
//! (`UnsafeTestingService::set_pet_decrypt_fault`) is registered
//! identically on both backends — so this runs as one real test on both,
//! reusing `pet_dkg_scenario::run_dkg` (already shared since PR 5c) for
//! the paired-DKG setup.

use super::report_scenario::{try_wait_for_demerits, STANDARD_RING_POLICY_YAML};
use super::{pet_dkg_scenario, TestEnvironmentImpl};
use crypto::r#trait::EncryptionProof;
use proto::unsafe_testing::{
    unsafe_testing_service_client::UnsafeTestingServiceClient, GetLocalStorageRequest,
    LocalStorageAccessMode, LocalStorageKey, LocalStorageKeyType, SetPetDecryptFaultRequest,
};
use test_support::fixture::{
    AuthorizationTestDriver, FixtureId, NetworkTestDriver, NodeFixture, NodeRef, NodeRole,
    PolicyFixture, RingFixture, ScenarioFixture, TestEnvironment,
};
use tokio::time::Duration;

#[tokio::test]
#[serial_test::serial]
#[cfg_attr(
    feature = "integration-test-native",
    ignore = "native's PET-gated inline-PRE document-id scheme isn't ported \
              yet (Cosmos's generate_document_id vs. native's \
              ThresholdObject::Document::id() — not interchangeable); fix \
              when that porting work happens"
)]
// Everything after the `unimplemented!()` document-id stub is genuinely
// unreachable on native (the whole point of `#[ignore]`-gating it above)
// — the lints are correct but noisy for a deliberately-stubbed branch.
#[cfg_attr(
    feature = "integration-test-native",
    allow(unreachable_code, unused_variables, clippy::diverging_sub_expression)
)]
async fn test_pet_invalid_decrypt_share_triggers_on_chain_report() {
    println!("Starting PET invalid-decrypt-share reporting integration test...");

    let ring = FixtureId::new("ring");
    let ring_policy = FixtureId::new("ring-policy");
    let fixture = ScenarioFixture {
        nodes: (0..3)
            .map(|_| NodeFixture {
                id: FixtureId::new("node"),
                role: NodeRole::Running,
            })
            .collect(),
        policies: vec![PolicyFixture {
            id: ring_policy.clone(),
            definition: STANDARD_RING_POLICY_YAML.to_string(),
        }],
        rings: vec![RingFixture {
            id: ring.clone(),
            members: vec![
                NodeRef::Running(0),
                NodeRef::Running(1),
                NodeRef::Running(2),
            ],
            threshold: 2,
            pss_interval: Duration::from_secs(86_400),
            requires_pet: true,
            policy: ring_policy.clone(),
            reporting: Default::default(),
            upgrade: None,
        }],
        ..Default::default()
    };

    let environment = TestEnvironmentImpl::provision(fixture).await;
    let ring_id = environment.fixture().rings[&ring].id.clone();
    let members = environment.fixture().rings[&ring].members.clone();
    let node3_key = members[2].clone();
    let endpoint = environment.nodes()[0].grpc_endpoint.clone();
    let node3_endpoint = environment.nodes()[2].grpc_endpoint.clone();

    println!("Starting paired DKG for ring {}...", ring_id.0);
    let (keys, _local_state) = pet_dkg_scenario::run_dkg(&environment, &ring_id).await;
    println!(
        "PET-enabled ring finalized: ring_pk={}..., pet_pk={}...",
        &keys.main[..40.min(keys.main.len())],
        &keys.pet[..40.min(keys.pet.len())],
    );

    // ── ACP + a genuinely PET-tagged document (mirrors test_cli_calls_dkg_for_pet_ring) ──
    println!("Setting up ACP for PET-gated PRE (document creator/reader, shared with the audit target)...");
    const PET_AUDIT_POLICY_YAML: &str = r#"
name: pet audit policy
resources:
- name: document
  relations:
  - name: creator
    types:
    - actor
  - name: reader
    types:
    - actor
  permissions:
  - name: read
    expr: creator + reader
  - name: write
    expr: creator
"#;
    let pet_audit_policy_id = environment.create_policy(PET_AUDIT_POLICY_YAML).await;

    let document_resource = "document";
    let read_permission = "read";
    let test_jwt_did = cli_tool::reader_did_from_seed("test_jwt");

    let owner_seed = "pet-report-test-owner-seed".to_string();
    let audit_target_object_id = cli_tool::reader_did_from_seed(&owner_seed);
    environment
        .register_object(
            &pet_audit_policy_id,
            document_resource,
            &audit_target_object_id,
        )
        .await;
    environment
        .grant(
            &pet_audit_policy_id,
            document_resource,
            &audit_target_object_id,
            "reader",
            &test_jwt_did,
        )
        .await;

    println!("Preparing a genuinely PET-tagged document...");
    let secret_message = b"PET decrypt-share report test secret";
    let (generated_tag, tag_r_tag) = cli_tool::generate_pet_tag(&keys.pet, &audit_target_object_id)
        .expect("generate a genuine PET tag");
    let pet_tag_binding = crypto::context::PetTagBinding {
        ring_id: ring_id.0.clone(),
        pet_pk: hex::decode(&keys.pet).expect("decode pet_pk hex"),
        ephemeral_point: generated_tag.ephemeral_point.clone(),
        masked_fingerprint: generated_tag.masked_fingerprint.clone(),
    };
    let prepared = cli_tool::prepare_secret(
        secret_message,
        &keys.main,
        None,
        pet_audit_policy_id.0.clone(),
        document_resource.to_string(),
        read_permission.to_string(),
        None,
        None,
        None,
        Some(pet_tag_binding),
    )
    .expect("prepare_secret for the PET-gated document");
    let pet_tag = cli_tool::prove_pet_tag_knowledge(
        &prepared,
        &ring_id.0,
        &keys.pet,
        generated_tag,
        tag_r_tag,
    )
    .expect("prove genuine PET tag knowledge");

    let document_json = String::from_utf8(prepared.encrypted_document.clone())
        .expect("encrypted_document is valid UTF-8");
    let proof_json: String = EncryptionProof {
        challenge: prepared.challenge.clone(),
        response: prepared.response.clone(),
    }
    .try_into()
    .expect("serialize encryption proof");
    let tag_json: String = pet_tag.tag.clone().try_into().expect("serialize tag");
    let tag_proof_json: String = pet_tag
        .tag_proof
        .clone()
        .try_into()
        .expect("serialize tag proof");

    // `generate_document_id` is Cosmos's own content-addressed document-id
    // scheme (`common::blockchain::orbis`, gated on the `cosmos` feature —
    // confirmed unavailable to native builds); native's own PET scenarios
    // (`native_pet.rs`) use a completely different one
    // (`ThresholdObject::Document::id()`), and `do_pre_with_inline_document`'s
    // server-side id validation is bulletin-backend-specific, so these
    // aren't interchangeable. Not yet ported for native — see the
    // `#[cfg_attr(ignore)]` on this test.
    #[cfg(feature = "integration-test-cosmos")]
    let pet_object_id = common::blockchain::orbis::generate_document_id(
        &ring_id.0,
        &document_json,
        &proof_json,
        &pet_audit_policy_id.0,
        document_resource,
        read_permission,
        None,
        None,
        Some(&tag_json),
        Some(&tag_proof_json),
    )
    .expect("generate PET-gated document id");
    #[cfg(feature = "integration-test-native")]
    let pet_object_id: String = unimplemented!(
        "native PET-gated inline-PRE document-id scheme not yet ported from \
         native_pet.rs's ThresholdObject::Document::id()"
    );

    environment
        .register_object(&pet_audit_policy_id, document_resource, &pet_object_id)
        .await;
    environment
        .grant(
            &pet_audit_policy_id,
            document_resource,
            &pet_object_id,
            "reader",
            &test_jwt_did,
        )
        .await;

    let inline_document = proto::v0::pre::InlineDocument {
        ring_id: ring_id.0.clone(),
        encrypted_document: prepared.encrypted_document.clone(),
        enc_cmt: prepared.enc_cmt.clone(),
        policy_id: pet_audit_policy_id.0.clone(),
        resource: document_resource.to_string(),
        permission: read_permission.to_string(),
        challenge: prepared.challenge.clone(),
        response: prepared.response.clone(),
        tier: None,
        timestamp: None,
        pet_tag: Some(proto::v0::pre::PetTagAttachment {
            ephemeral_point: pet_tag.tag.ephemeral_point.clone(),
            masked_fingerprint: pet_tag.tag.masked_fingerprint.clone(),
            knowledge_proof_challenge: pet_tag.tag_proof.challenge.clone(),
            knowledge_proof_response: pet_tag.tag_proof.response.clone(),
        }),
    };

    let mut unsafe_client = UnsafeTestingServiceClient::connect(node3_endpoint)
        .await
        .expect("connect unsafe-testing client to node3");
    let storage_key = LocalStorageKey {
        key_type: LocalStorageKeyType::PetRingKey as i32,
        ring_key: ring_id.0.clone(),
    };
    let stored = unsafe_client
        .get_local_storage(GetLocalStorageRequest {
            key: Some(storage_key.clone()),
            access_mode: LocalStorageAccessMode::Encrypted as i32,
        })
        .await
        .expect("read node3 PET ring share bundle")
        .into_inner();
    assert!(stored.found, "node3 PET ring share bundle should exist");
    unsafe_client
        .set_pet_decrypt_fault(SetPetDecryptFaultRequest {
            ring_id: ring_id.0.clone(),
            enabled: true,
        })
        .await
        .expect("enable node3 signed PET decrypt-proof fault");

    // Decrypt-phase over-asks the whole committee and only needs `threshold`
    // genuine shares, so PRE still succeeds with node1 + node2 regardless of
    // which two nodes' commits got selected for reveal. As in the PRE
    // share-corruption test, retry once if the report races the
    // post-threshold drain window.
    println!(
        "Triggering PET-gated PRE until node3's invalid decrypt share is reported (PRE succeeds each attempt)..."
    );
    let mut demerits_after_pre = None;
    for attempt in 1..=2 {
        let decrypted = cli_tool::do_pre_with_inline_document(
            endpoint.clone(),
            environment.chain_id(),
            keys.main.clone(),
            pet_object_id.clone(),
            None,
            None,
            None,
            None,
            None,
            inline_document.clone(),
            Some(audit_target_object_id.clone()),
        )
        .await
        .expect("PRE should still succeed with only node3's decrypt share bad");
        assert_eq!(
            decrypted, secret_message,
            "decrypted secret should match the original"
        );
        println!(
            "PET-gated PRE attempt {attempt} succeeded; waiting for node3's invalid-decrypt demerit (up to 150s)..."
        );
        if let Some(demerits) = try_wait_for_demerits(
            &environment,
            &ring_id,
            &node3_key,
            1,
            Duration::from_secs(150),
        )
        .await
        {
            demerits_after_pre = Some(demerits);
            break;
        }
        println!("Invalid-decrypt demerit not seen on attempt {attempt}/2, retrying PRE...");
    }
    let demerits = demerits_after_pre.expect(
        "node3 should accumulate a demerit from an invalid-decrypt report within 2 PRE attempts",
    );
    assert_eq!(
        demerits, 1,
        "node3 should have exactly 1 demerit after the PET invalid-decrypt report"
    );
    println!("node3 demerit points after PET invalid-decrypt report: {demerits}");

    unsafe_client
        .set_pet_decrypt_fault(SetPetDecryptFaultRequest {
            ring_id: ring_id.0.clone(),
            enabled: false,
        })
        .await
        .expect("disable node3 decrypt-proof fault");
    let after = unsafe_client
        .get_local_storage(GetLocalStorageRequest {
            key: Some(storage_key),
            access_mode: LocalStorageAccessMode::Encrypted as i32,
        })
        .await
        .expect("read unchanged node3 PET bundle")
        .into_inner();
    assert!(after.found);
    assert!(
        after.value == stored.value,
        "fault must not corrupt persisted key material"
    );
}
