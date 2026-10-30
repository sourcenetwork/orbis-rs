//! Docker-based integration test: full DKG + PRE + SIGN flow.
//!
//! Spins up a full Docker Compose environment (Vera + 3 orbis-node containers)
//! and exercises the complete DKG → StoreSecret → PRE workflow via CLI commands.
//!
//! Run with:
//!   cargo test --features integration-test -- --nocapture

mod pet_reshare;
#[path = "support/refresh_scenario.rs"]
mod refresh_scenario;
#[path = "support/reshare_scenario.rs"]
mod reshare_scenario;
// `pre_scenario`/`sign_scenario`/`pet_dkg_scenario` and the
// `TestEnvironmentImpl` alias are declared once in `mod.rs` so sibling
// modules (`cancel_ring_reshare.rs`, the `report_*.rs` family) can reuse
// them too — loading the same file as two separate `mod` items trips
// `clippy::duplicate_mod`.
use super::{pet_dkg_scenario, pre_scenario, sign_scenario, TestEnvironmentImpl};

/// Scaffolding proving the harness-unification migration's fixture
/// materialization (rings/policies) actually works against a real cluster,
/// not just compiles — delete once a real scenario test uses
/// `TestEnvironmentImpl` directly.
#[tokio::test]
#[serial_test::serial]
async fn cosmos_test_environment_materializes_standard_fixture() {
    use test_support::fixture::{
        FixtureId, NodeFixture, NodeRef, NodeRole, PolicyFixture, RingFixture, ScenarioFixture,
        TestEnvironment,
    };

    const SCAFFOLD_POLICY_YAML: &str = r#"
name: harness unification scaffold policy
resources:
- name: document
  permissions:
  - name: read
    expr: reader
  relations:
  - name: reader
    types:
    - actor
"#;

    let policy = FixtureId::new("policy");
    let ring = FixtureId::new("ring");
    let fixture = ScenarioFixture {
        nodes: (0..3)
            .map(|_| NodeFixture {
                id: FixtureId::new("node"),
                role: NodeRole::Running,
            })
            .collect(),
        policies: vec![PolicyFixture {
            id: policy.clone(),
            definition: SCAFFOLD_POLICY_YAML.to_string(),
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
            requires_pet: false,
            policy: policy.clone(),
            reporting: Default::default(),
            upgrade: None,
        }],
        ..Default::default()
    };

    let environment = TestEnvironmentImpl::provision(fixture).await;
    assert_eq!(environment.fixture().policies.len(), 1);
    assert_eq!(environment.fixture().rings.len(), 1);
    assert!(!environment.fixture().policies[&policy].id.0.is_empty());
    assert_eq!(environment.fixture().rings[&ring].members.len(), 3);
}

use bulletin::r#trait::{BulletinKind, RingPayload};
use common::blockchain::ChainConfig;
use crypto::r#trait::EncryptionProof;
use tokio::time::{sleep, Duration, Instant};

#[derive(Clone, Debug)]
struct RingStateSnapshot {
    public_polynomial: String,
    last_pss: u64,
}

/// Cosmos half of the `cosmos_*`/`native_*` scenario pair the harness-unification
/// plan asks for (see `native_dkg` in `bin/orbis-node/tests/native_startup.rs`).
/// Proves the shared provision-trigger-finalize-verify scenario on its own, without
/// the additional PET-gated PRE assertions `test_cli_calls_dkg_for_pet_ring`
/// and `test_pet_ring_refresh_and_reshare` layer on top of the same foundation.
#[tokio::test]
#[serial_test::serial]
async fn cosmos_dkg() {
    use test_support::fixture::{
        FixtureId, NodeFixture, NodeRef, NodeRole, RingFixture, ScenarioFixture, TestEnvironment,
    };

    let ring = FixtureId::new("ring");
    let fixture = ScenarioFixture {
        nodes: (0..3)
            .map(|_| NodeFixture {
                id: FixtureId::new("node"),
                role: NodeRole::Running,
            })
            .collect(),
        rings: vec![RingFixture {
            id: ring.clone(),
            members: vec![
                NodeRef::Running(0),
                NodeRef::Running(1),
                NodeRef::Running(2),
            ],
            threshold: 2,
            pss_interval: Duration::from_secs(5),
            requires_pet: true,
            policy: FixtureId::new("ring-policy"),
            reporting: Default::default(),
            upgrade: None,
        }],
        ..Default::default()
    };

    let environment = TestEnvironmentImpl::provision(fixture).await;
    let ring_id = environment.fixture().rings[&ring].id.clone();

    let (keys, _local_state) = pet_dkg_scenario::run_dkg(&environment, &ring_id).await;
    assert!(!keys.main.is_empty(), "DKG must finalize the main key");
    assert!(!keys.pet.is_empty(), "DKG must finalize the PET key");
}

/// Cosmos adapter for the shared standard-DKG lifecycle: StoreSecret,
/// authorized PRE, derived-key signing, refresh, and committee reshare. Its
/// native counterpart runs the same scenario body below the backend boundary
/// in `native_startup.rs`. Replaces the pre-harness-unification
/// `cosmos_dkg_and_pre`/generic-`Backend`-trait version — this one drives
/// `TestEnvironmentImpl` directly, through the compile-time-selected
/// environment every other migrated test already uses.
#[tokio::test]
#[serial_test::serial]
async fn test_cli_calls_dkg_and_pre_endpoint() {
    use test_support::fixture::{
        FixtureId, NodeFixture, NodeRef, NodeRole, PolicyFixture, RingFixture, ScenarioFixture,
        TestEnvironment,
    };

    const DOCUMENT_POLICY_YAML: &str = r#"
name: shared-dkg-pre-policy
resources:
- name: document
  permissions:
  - name: read
    expr: reader
  relations:
  - name: reader
    types:
    - actor
"#;

    let policy = FixtureId::new("policy");
    // Cosmos's ring materializer always substitutes its own
    // content-addressed governance policy for whatever `RingFixture.policy`
    // points at (see `CosmosTestEnvironment::provision`'s ring loop) — a
    // distinct id so that substitution doesn't clobber `policy`'s own
    // `DOCUMENT_POLICY_YAML` content, which the scenario actually needs for
    // document/key-derivation authorization.
    let ring_policy = FixtureId::new("ring-policy");
    let ring = FixtureId::new("ring");
    let fixture = ScenarioFixture {
        nodes: (0..3)
            .map(|_| NodeFixture {
                id: FixtureId::new("node"),
                role: NodeRole::Running,
            })
            .collect(),
        policies: vec![PolicyFixture {
            id: policy.clone(),
            definition: DOCUMENT_POLICY_YAML.to_string(),
        }],
        rings: vec![RingFixture {
            id: ring.clone(),
            members: vec![
                NodeRef::Running(0),
                NodeRef::Running(1),
                NodeRef::Running(2),
            ],
            threshold: 2,
            // Short enough to refresh naturally within the scenario's own
            // wait — genesis-seeded, so the chain's production minimum
            // doesn't apply (see `CosmosTestEnvironment::provision`).
            pss_interval: Duration::from_secs(5),
            requires_pet: false,
            policy: ring_policy,
            reporting: Default::default(),
            upgrade: None,
        }],
        ..Default::default()
    };

    let environment = TestEnvironmentImpl::provision(fixture).await;
    let ring_id = environment.fixture().rings[&ring].id.clone();
    let policy_id = environment.fixture().policies[&policy].id.clone();

    let (keys, local_state, outcome) = pre_scenario::run(&environment, &ring_id, &policy_id).await;
    let sign = sign_scenario::run(&environment, &ring_id, &keys, &policy_id).await;
    refresh_scenario::run(&environment, &ring_id, &keys, &local_state, &outcome, &sign).await;
    reshare_scenario::run(&environment, &ring_id, &keys, &outcome, &sign).await;
    assert!(
        !outcome.object_id.is_empty(),
        "the shared PRE scenario must store a document"
    );
    assert!(
        !sign.derivation_id.is_empty(),
        "the shared Sign scenario must store a key derivation"
    );
}

/// Docker-based integration test: PET-enabled ring, end to end.
///
/// Exercises two things the standard (non-PET) DKG/PRE scenario doesn't
/// cover, both unblocked by the same change (Vera's `MsgCreateRing` no longer
/// rejects `requires_pet: true` now that the checking-key lifecycle — the
/// fresh-DKG auto-chain and combined finalize implemented in
/// `coordinator::phases::phase4`/`network::start_fresh_pet` — actually exists
/// to service such a ring):
///
/// 1. Genesis-seeds a `requires_pet: true` ring (same pss_interval-bypass
///    trick as the reference test) and runs DKG through the CLI. This drives
///    the full auto-chain: the main key's `Fresh` ceremony completes locally,
///    triggers the PET key's own `FreshPet` ceremony internally (no second
///    external trigger), and once both succeed the node submits one combined
///    `MsgFinalizeRing` — `ring_pk` and `pet_pk` land on-chain together in
///    the same commit.
/// 2. A live `MsgCreateRing(requires_pet: true)` against the real chain (not
///    genesis) round-trips correctly — the only place that would catch a
///    proto tag mismatch between orbis-rs's prost types and Vera's gogoproto
///    types for these fields, since neither side's unit tests cross a real
///    wire boundary.
///
/// PET's own check-and-gate (Task 6: threshold PET verification before PRE
/// release) doesn't exist yet, so this test stops at "both keys finalized" —
/// it does not attempt PRE against a PET-gated document.
#[tokio::test]
#[serial_test::serial]
async fn test_cli_calls_dkg_for_pet_ring() {
    use test_support::admin::PolicyId;
    use test_support::fixture::{
        AuthorizationTestDriver, BulletinTestDriver, FixtureId, NetworkTestDriver, NodeFixture,
        NodeRef, NodeRole, RingFixture, ScenarioFixture, TestEnvironment,
    };

    println!("Starting Docker-based PET integration test...");

    let ring = FixtureId::new("ring");
    let fixture = ScenarioFixture {
        nodes: (0..3)
            .map(|_| NodeFixture {
                id: FixtureId::new("node"),
                role: NodeRole::Running,
            })
            .collect(),
        rings: vec![RingFixture {
            id: ring.clone(),
            members: vec![
                NodeRef::Running(0),
                NodeRef::Running(1),
                NodeRef::Running(2),
            ],
            threshold: 2,
            pss_interval: Duration::from_secs(5),
            requires_pet: true,
            policy: FixtureId::new("ring-policy"),
            reporting: Default::default(),
            upgrade: None,
        }],
        ..Default::default()
    };

    let environment = TestEnvironmentImpl::provision(fixture).await;
    let ring_id_handle = environment.fixture().rings[&ring].id.clone();
    let ring_id = ring_id_handle.0.clone();
    let node_keys = environment.fixture().rings[&ring].members.clone();
    let threshold = 2u32;
    let endpoint = environment.nodes()[0].grpc_endpoint.clone();

    let (keys, _local_state) = pet_dkg_scenario::run_dkg(&environment, &ring_id_handle).await;
    let ring_pk_hex = keys.main;
    let pet_pk_hex = keys.pet;

    println!(
        "PET-enabled ring fully finalized: ring_pk={}..., pet_pk={}...",
        &ring_pk_hex[..40.min(ring_pk_hex.len())],
        &pet_pk_hex[..40.min(pet_pk_hex.len())],
    );

    // ========================================================================
    // PRE against the PET-enabled ring: a genuine tag matching the audited
    // owner must succeed; a `requires_pet` ring must reject a document with
    // no tag at all. Both use the inline-document path (never posted to the
    // bulletin) — mirrors `pre::v0::tests::test_pre_with_inline_document_end_to_end`.
    // ========================================================================
    println!("Setting up ACP for PET-gated PRE (document creator/reader, shared with the audit target)...");

    // A single "document" resource, used for *both* checks: ordinary PRE
    // authorization against the document's own `object_id`, and PET's
    // `check_pet_permission` against `audit_target_object_id` — the audit
    // target is just another object under the same resource type, not a
    // separate one. Earlier drafts of this test used a dedicated "owner"
    // resource, reasoning that a document and its audit target could
    // theoretically collide if they ever shared an id; in practice
    // `object_id` is always a SHA256 content hash and `audit_target_object_id`
    // is a human/system-chosen identifier, so that risk is next to
    // impossible and not worth a second resource type for.
    //
    // `audit_target_object_id` itself *is* the plaintext owner identity —
    // the exact value `Pet::owner_fingerprint` is computed over, not a
    // handle ACP resolves to some other identity (there is deliberately no
    // such resolution step — see `pet::v0::coordinator::verification`'s
    // module doc comment). What ACP *does* gate is `check_pet_permission`:
    // does the requesting actor hold `document.permission` (here "read",
    // via `creator`+`reader`) on the audit target — exactly mirroring how
    // `document`'s own `creator`/`reader` govern decrypt access, and what
    // lets the real owner delegate who else may pass PET.
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
    let pet_audit_policy_id = environment.create_policy(PET_AUDIT_POLICY_YAML).await.0;

    let document_resource = "document".to_string();
    let read_permission = "read".to_string();
    // Every grant below is to the default ("test_jwt") requester identity —
    // same default `cli_tool::set_relationship_on_chain_with_config` used
    // when its `reader_did_pk` argument was `None`.
    let test_jwt_did = cli_tool::reader_did_from_seed("test_jwt");

    // The audit target *is* the real data subject's own identity — the
    // exact value `prepare_pet_tag` below builds the tag's fingerprint
    // against. Not a separately-chosen label resolved to an owner via ACP.
    let owner_seed = "pet-audit-owner-seed".to_string();
    let audit_target_object_id = cli_tool::reader_did_from_seed(&owner_seed);
    environment
        .register_object(
            &PolicyId(pet_audit_policy_id.clone()),
            &document_resource,
            &audit_target_object_id,
        )
        .await;
    // The requester below authenticates with the default ("test_jwt")
    // reader identity — the same one granted `reader` on the document —
    // so it also needs `reader` here to pass `check_pet_permission`.
    environment
        .grant(
            &PolicyId(pet_audit_policy_id.clone()),
            &document_resource,
            &audit_target_object_id,
            "reader",
            &test_jwt_did,
        )
        .await;

    println!("Running PRE against the PET-gated document with a genuine tag...");
    let secret_message = b"Hello from a PET-gated PRE request!";
    // Required noncircular construction order: generate the tag *before*
    // encrypting the payload, so the payload's own encryption can bind to
    // it, then prove tag knowledge over the now-completed payload.
    let (generated_tag, tag_r_tag) =
        cli_tool::generate_pet_tag(&pet_pk_hex, &audit_target_object_id)
            .expect("generate a genuine PET tag");
    let pet_tag_binding = crypto::context::PetTagBinding {
        ring_id: ring_id.clone(),
        pet_pk: hex::decode(&pet_pk_hex).expect("decode pet_pk hex"),
        ephemeral_point: generated_tag.ephemeral_point.clone(),
        masked_fingerprint: generated_tag.masked_fingerprint.clone(),
    };
    let prepared = cli_tool::prepare_secret(
        secret_message,
        &ring_pk_hex,
        None,
        pet_audit_policy_id.clone(),
        document_resource.clone(),
        read_permission.clone(),
        None,
        None,
        None,
        Some(pet_tag_binding),
    )
    .expect("prepare_secret for the PET-gated document");

    let pet_tag = cli_tool::prove_pet_tag_knowledge(
        &prepared,
        &ring_id,
        &pet_pk_hex,
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

    let pet_object_id = common::blockchain::orbis::generate_document_id(
        &ring_id,
        &document_json,
        &proof_json,
        &pet_audit_policy_id,
        &document_resource,
        &read_permission,
        None,
        None,
        Some(&tag_json),
        Some(&tag_proof_json),
    )
    .expect("generate PET-gated document id");

    environment
        .register_object(
            &PolicyId(pet_audit_policy_id.clone()),
            &document_resource,
            &pet_object_id,
        )
        .await;
    environment
        .grant(
            &PolicyId(pet_audit_policy_id.clone()),
            &document_resource,
            &pet_object_id,
            "reader",
            &test_jwt_did,
        )
        .await;

    let inline_document = proto::v0::pre::InlineDocument {
        ring_id: ring_id.clone(),
        encrypted_document: prepared.encrypted_document.clone(),
        enc_cmt: prepared.enc_cmt.clone(),
        policy_id: pet_audit_policy_id.clone(),
        resource: document_resource.clone(),
        permission: read_permission.clone(),
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

    let decrypted = do_pre_inline_expect_success(
        "PRE against a genuinely PET-tagged document",
        endpoint.clone(),
        environment.chain_id(),
        ring_pk_hex.clone(),
        pet_object_id.clone(),
        Some(audit_target_object_id.clone()),
        inline_document,
    )
    .await;
    assert_eq!(
        decrypted, secret_message,
        "decrypted secret should match the original"
    );
    println!("PET-gated PRE succeeded and decrypted correctly.");

    // Negative check: the ring requires PET, but this document carries no tag
    // at all — `check_pet_if_required` must reject it before any
    // reencryption is attempted. `audit_target_object_id` is still supplied
    // (and already registered above) so this specifically exercises the
    // missing-tag rejection, not the separate missing-audit-target one.
    println!("Confirming PRE is rejected for a PET-gated ring when no tag is attached...");
    let secret_message_no_tag = b"This document has no PET tag at all.";
    let prepared_no_tag = cli_tool::prepare_secret(
        secret_message_no_tag,
        &ring_pk_hex,
        None,
        pet_audit_policy_id.clone(),
        document_resource.clone(),
        read_permission.clone(),
        None,
        None,
        None,
        None,
    )
    .expect("prepare_secret for the no-tag document");
    let document_json_no_tag = String::from_utf8(prepared_no_tag.encrypted_document.clone())
        .expect("encrypted_document is valid UTF-8");
    let proof_json_no_tag: String = EncryptionProof {
        challenge: prepared_no_tag.challenge.clone(),
        response: prepared_no_tag.response.clone(),
    }
    .try_into()
    .expect("serialize encryption proof");
    let no_tag_object_id = common::blockchain::orbis::generate_document_id(
        &ring_id,
        &document_json_no_tag,
        &proof_json_no_tag,
        &pet_audit_policy_id,
        &document_resource,
        &read_permission,
        None,
        None,
        None,
        None,
    )
    .expect("generate no-tag document id");

    environment
        .register_object(
            &PolicyId(pet_audit_policy_id.clone()),
            &document_resource,
            &no_tag_object_id,
        )
        .await;
    environment
        .grant(
            &PolicyId(pet_audit_policy_id.clone()),
            &document_resource,
            &no_tag_object_id,
            "reader",
            &test_jwt_did,
        )
        .await;

    let inline_document_no_tag = proto::v0::pre::InlineDocument {
        ring_id: ring_id.clone(),
        encrypted_document: prepared_no_tag.encrypted_document.clone(),
        enc_cmt: prepared_no_tag.enc_cmt.clone(),
        policy_id: pet_audit_policy_id.clone(),
        resource: document_resource.clone(),
        permission: read_permission.clone(),
        challenge: prepared_no_tag.challenge.clone(),
        response: prepared_no_tag.response.clone(),
        tier: None,
        timestamp: None,
        pet_tag: None,
    };

    let pre_result_no_tag = cli_tool::do_pre_with_inline_document(
        endpoint.clone(),
        environment.chain_id(),
        ring_pk_hex.clone(),
        no_tag_object_id,
        None,
        None,
        None,
        None,
        None,
        inline_document_no_tag,
        Some(audit_target_object_id.clone()),
    )
    .await;

    assert!(
        pre_result_no_tag.is_err(),
        "PRE must be rejected for a requires_pet ring when the document has no tag"
    );
    // `{:?}` (anyhow's Debug impl), not `{}` (Display): `do_pre_with_inline_document`
    // wraps the underlying tonic::Status in `.context("PRE request failed")`, so
    // `.to_string()` only ever shows that top-level wrapper — the real rejection
    // reason (e.g. "document has no pet_tag but ring requires PET") lives one
    // level down in the error's cause chain, which only the Debug format prints.
    let no_tag_error_message = format!("{:?}", pre_result_no_tag.unwrap_err());
    assert!(
        no_tag_error_message.contains("pet_tag") || no_tag_error_message.contains("PET"),
        "error should indicate the missing PET tag, got: {}",
        no_tag_error_message
    );
    println!(
        "PRE correctly rejected the untagged document: {}",
        no_tag_error_message
    );

    // A live MsgCreateRing(requires_pet: true) against the real chain also
    // round-trips correctly (independent throwaway policy). This ring is
    // never whitelisted or driven through DKG; it only exercises the
    // create-and-read-back wire path. Both helpers need a raw `ChainConfig`
    // and stay outside `environment`'s abstraction entirely — unlike a
    // plain `environment.create_policy`, `create_orbis_ring_policy` also
    // registers the policy's own id as a `ring_policy` ACP object (required
    // for the signer to pass `create_ring`'s permission check below), and
    // `create_ring_on_chain_with_trusted_relays` calls `cli_tool::create_ring`
    // directly — `CosmosAdmin::register_ring` can't do this itself yet
    // (`cli-tool` dependency boundary, see that method's doc comment).
    let live_policy_id =
        test_support::admin::cosmos::create_orbis_ring_policy(&environment.chain_config()).await;
    let live_ring_id = crate::helpers::test_helpers::create_ring_on_chain_with_trusted_relays(
        &environment.chain_config(),
        &node_keys,
        threshold,
        &live_policy_id,
        None,
        vec![],
        true,
    )
    .await;
    let live_ring = environment
        .read_ring(&test_support::admin::RingId(live_ring_id))
        .await
        .expect("live-created ring should exist");
    assert!(
        live_ring.requires_pet,
        "live-created ring should have requires_pet set"
    );
    assert!(
        live_ring.ring_pk.is_empty(),
        "live-created ring should be pending (no ring_pk yet)"
    );
    assert!(
        live_ring.pet_pk.is_none(),
        "live-created ring should have no pet_pk yet"
    );

    // Cleanup happens automatically when network is dropped
}

/// Docker-based integration test: the PET checking key's own PSS lifecycle
/// — independent refresh and committee-atomic reshare, on top of the
/// fresh-DKG finalization `test_cli_calls_dkg_for_pet_ring` already covers.
/// This test covers the two pieces that build on top of it:
///
/// 1. **Independent refresh** (`RefreshPet`): once the ring is live, the PET
///    bundle's own `last_pss` advances via the PSS scheduler exactly like the
///    main key's does, without any second external trigger.
/// 2. **Atomic reshare** (`ResharePet`, gated by `bulletin_update.rs`'s
///    atomicity gate): reshoring the ring's committee produces exactly one
///    bulletin post, and the PET bundle is confirmed to have moved to the new
///    committee on the same confirmation the main key uses.
///
/// Functional correctness of both is confirmed the same way
/// `test_cli_calls_dkg_for_pet_ring` confirms fresh-DKG's checking key works:
/// a genuine PET-gated PRE round, run once before and once after the
/// reshare — proving the reshared committee's shares are actually usable,
/// not just that the bundle bytes changed.
#[tokio::test]
#[serial_test::serial]
async fn test_pet_ring_refresh_and_reshare() {
    use test_support::fixture::{
        BulletinTestDriver, FixtureId, NetworkTestDriver, NodeFixture, NodeRef, NodeRole,
        RingFixture, ScenarioFixture, TestEnvironment,
    };

    println!("Starting Docker-based PET refresh+reshare integration test...");

    let ring = FixtureId::new("ring");
    let fixture = ScenarioFixture {
        nodes: (0..3)
            .map(|_| NodeFixture {
                id: FixtureId::new("node"),
                role: NodeRole::Running,
            })
            .collect(),
        rings: vec![RingFixture {
            id: ring.clone(),
            members: vec![
                NodeRef::Running(0),
                NodeRef::Running(1),
                NodeRef::Running(2),
            ],
            threshold: 2,
            pss_interval: Duration::from_secs(5),
            requires_pet: true,
            policy: FixtureId::new("ring-policy"),
            reporting: Default::default(),
            upgrade: None,
        }],
        ..Default::default()
    };

    let environment = TestEnvironmentImpl::provision(fixture).await;
    let ring_id_handle = environment.fixture().rings[&ring].id.clone();
    let ring_id = ring_id_handle.0.clone();
    let endpoint = environment.nodes()[0].grpc_endpoint.clone();
    let node_endpoints: Vec<String> = environment
        .nodes()
        .iter()
        .map(|node| node.grpc_endpoint.clone())
        .collect();

    println!("Starting DKG for PET-enabled ring {}...", ring_id);
    let (keys, _local_state) = pet_dkg_scenario::run_dkg(&environment, &ring_id_handle).await;
    let ring_pk_hex = keys.main;
    let pet_pk_hex = keys.pet;

    println!(
        "PET-enabled ring finalized: ring_pk={}..., pet_pk={}...",
        &ring_pk_hex[..40.min(ring_pk_hex.len())],
        &pet_pk_hex[..40.min(pet_pk_hex.len())],
    );

    // Baseline PET-gated PRE: confirms the freshly-finalized committee's PET
    // shares are genuinely usable before either ceremony below touches them.
    println!("Running a baseline PET-gated PRE round before refresh...");
    assert_pet_gated_pre_succeeds(
        &environment,
        &endpoint,
        &ring_id,
        &ring_pk_hex,
        &pet_pk_hex,
        b"Hello before PET refresh!",
    )
    .await;

    // ========================================================================
    // RefreshPet: independent of the main key's own refresh (both use the
    // same ring-level pss_interval, but each bundle tracks its own last_pss
    // and is scheduled separately — see pss/v0/mod.rs's pss_ring). This test
    // only confirms RefreshPet actually completes in a real multi-node
    // deployment; independent *scheduling* (one clock overdue, the other
    // not) is already covered at the unit level.
    // ========================================================================
    println!("Waiting for the PET checking key's own PSS refresh (polling all 3 nodes)...");
    let initial_pet_states = wait_for_pet_ring_state_on_all_nodes(
        &node_endpoints,
        &ring_id,
        Duration::from_secs(60),
        Duration::from_millis(500),
    )
    .await;
    let refreshed_pet_states = wait_for_pet_pss_refresh_on_all_nodes(
        &node_endpoints,
        &ring_id,
        &initial_pet_states,
        Duration::from_secs(300),
        Duration::from_secs(2),
    )
    .await;
    for (idx, (before, after)) in initial_pet_states
        .iter()
        .zip(refreshed_pet_states.iter())
        .enumerate()
    {
        println!(
            "  Node {} PET last_pss: {} -> {}",
            idx + 1,
            before.last_pss,
            after.last_pss
        );
    }
    println!("PET checking-key refresh complete.");

    println!("Confirming PET-gated PRE still succeeds after PET refresh...");
    assert_pet_gated_pre_succeeds(
        &environment,
        &endpoint,
        &ring_id,
        &ring_pk_hex,
        &pet_pk_hex,
        b"Hello after PET refresh!",
    )
    .await;

    // ========================================================================
    // ResharePet: chained atomically to the main key's own reshare
    // (bulletin_update.rs's atomicity gate) — shrink the committee to
    // {node1, node2}, dropping node3, and confirm exactly one bulletin post
    // carries both the main key's new committee and the PET bundle's own
    // promotion on the same confirmation.
    // ========================================================================
    println!("Announcing a reshare that also carries the PET checking key...");
    let reshare_peer_ids = vec![
        environment.nodes()[0].node_key.clone(),
        environment.nodes()[1].node_key.clone(),
    ];
    let reshare_threshold = 2u32;

    let (pre_reshare_main_states, pre_reshare_pet_states) = tokio::join!(
        wait_for_ring_state_on_all_nodes(
            &node_endpoints[..2],
            &ring_pk_hex,
            Duration::from_secs(60),
            Duration::from_millis(500),
        ),
        wait_for_pet_ring_state_on_all_nodes(
            &node_endpoints[..2],
            &ring_id,
            Duration::from_secs(60),
            Duration::from_millis(500),
        ),
    );

    environment
        .update_membership(&ring_id_handle, reshare_peer_ids.clone(), reshare_threshold)
        .await;

    let reshared_payload = wait_for_reshare_bulletin_completion(
        &environment.chain_config(),
        &ring_id,
        &ring_pk_hex,
        &reshare_peer_ids,
        reshare_threshold,
        Duration::from_secs(300),
        Duration::from_secs(2),
    )
    .await;
    assert_eq!(
        reshared_payload.ring_pk, ring_pk_hex,
        "reshare should preserve the main ring public key"
    );
    assert!(
        reshared_payload.requires_pet,
        "reshare should preserve requires_pet"
    );
    assert_eq!(
        reshared_payload.pet_pk.as_deref(),
        Some(pet_pk_hex.as_str()),
        "reshare should preserve the PET public key — only the committee's shares move"
    );
    println!(
        "Reshare committed on stable ring_id={}; confirming the PET bundle also promoted...",
        &ring_id[..16.min(ring_id.len())]
    );

    let reshared_pet_states = pet_reshare::wait_for_pet_reshare(
        &environment.chain_config(),
        &node_endpoints[..2],
        &ring_id,
        &reshared_payload,
        &pre_reshare_main_states,
        &pre_reshare_pet_states,
        Duration::from_secs(120),
        Duration::from_secs(2),
    )
    .await;
    for (idx, (before, after)) in pre_reshare_pet_states
        .iter()
        .zip(reshared_pet_states.iter())
        .enumerate()
    {
        println!(
            "  Reshare node {} PET last_pss: {} -> {}",
            idx + 1,
            before.last_pss,
            after.last_pss
        );
    }
    println!(
        "PET checking-key reshare complete — committee is now {} nodes.",
        reshare_peer_ids.len()
    );

    println!("Confirming PET-gated PRE succeeds under the reshared committee...");
    assert_pet_gated_pre_succeeds(
        &environment,
        &endpoint,
        &ring_id,
        &ring_pk_hex,
        &pet_pk_hex,
        b"Hello after PET reshare!",
    )
    .await;

    // Cleanup happens automatically when network is dropped
}

/// Runs a PET-gated PRE round against `ring_id`/`ring_pk_hex`/`pet_pk_hex`
/// with a genuine tag and asserts it succeeds, decrypting to
/// `secret_message`. Creates a throwaway ACP policy/audit-target/document
/// each call, so it's safe to call more than once against the same ring
/// (e.g. before and after a refresh or reshare) with no state collision —
/// each call gets its own fresh `pet_audit_policy_id`. Mirrors
/// `test_cli_calls_dkg_for_pet_ring`'s own positive-path PET-gated PRE check.
async fn assert_pet_gated_pre_succeeds(
    environment: &TestEnvironmentImpl,
    endpoint: &str,
    ring_id: &str,
    ring_pk_hex: &str,
    pet_pk_hex: &str,
    secret_message: &[u8],
) {
    use test_support::admin::PolicyId;
    use test_support::fixture::{AuthorizationTestDriver, TestEnvironment};

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
    let pet_audit_policy_id = environment.create_policy(PET_AUDIT_POLICY_YAML).await.0;

    let document_resource = "document".to_string();
    let read_permission = "read".to_string();
    // Grants the default ("test_jwt") requester identity — the same default
    // `cli_tool::set_relationship_on_chain_with_config` used when its
    // `reader_did_pk` argument was `None`.
    let test_jwt_did = cli_tool::reader_did_from_seed("test_jwt");

    let owner_seed = "pet-audit-owner-seed".to_string();
    let audit_target_object_id = cli_tool::reader_did_from_seed(&owner_seed);
    environment
        .register_object(
            &PolicyId(pet_audit_policy_id.clone()),
            &document_resource,
            &audit_target_object_id,
        )
        .await;
    environment
        .grant(
            &PolicyId(pet_audit_policy_id.clone()),
            &document_resource,
            &audit_target_object_id,
            "reader",
            &test_jwt_did,
        )
        .await;

    // Required noncircular construction order: generate the tag before
    // encrypting the payload, then prove tag knowledge over the
    // now-completed payload.
    let (generated_tag, tag_r_tag) =
        cli_tool::generate_pet_tag(pet_pk_hex, &audit_target_object_id)
            .expect("generate a genuine PET tag");
    let pet_tag_binding = crypto::context::PetTagBinding {
        ring_id: ring_id.to_string(),
        pet_pk: hex::decode(pet_pk_hex).expect("decode pet_pk hex"),
        ephemeral_point: generated_tag.ephemeral_point.clone(),
        masked_fingerprint: generated_tag.masked_fingerprint.clone(),
    };
    let prepared = cli_tool::prepare_secret(
        secret_message,
        ring_pk_hex,
        None,
        pet_audit_policy_id.clone(),
        document_resource.clone(),
        read_permission.clone(),
        None,
        None,
        None,
        Some(pet_tag_binding),
    )
    .expect("prepare_secret for the PET-gated document");

    let pet_tag =
        cli_tool::prove_pet_tag_knowledge(&prepared, ring_id, pet_pk_hex, generated_tag, tag_r_tag)
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

    let pet_object_id = common::blockchain::orbis::generate_document_id(
        ring_id,
        &document_json,
        &proof_json,
        &pet_audit_policy_id,
        &document_resource,
        &read_permission,
        None,
        None,
        Some(&tag_json),
        Some(&tag_proof_json),
    )
    .expect("generate PET-gated document id");

    environment
        .register_object(
            &PolicyId(pet_audit_policy_id.clone()),
            &document_resource,
            &pet_object_id,
        )
        .await;
    environment
        .grant(
            &PolicyId(pet_audit_policy_id.clone()),
            &document_resource,
            &pet_object_id,
            "reader",
            &test_jwt_did,
        )
        .await;

    let inline_document = proto::v0::pre::InlineDocument {
        ring_id: ring_id.to_string(),
        encrypted_document: prepared.encrypted_document.clone(),
        enc_cmt: prepared.enc_cmt.clone(),
        policy_id: pet_audit_policy_id.clone(),
        resource: document_resource.clone(),
        permission: read_permission.clone(),
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

    let decrypted = do_pre_inline_expect_success(
        "PRE against a genuinely PET-tagged document",
        endpoint.to_string(),
        environment.chain_id(),
        ring_pk_hex.to_string(),
        pet_object_id.clone(),
        Some(audit_target_object_id.clone()),
        inline_document,
    )
    .await;
    assert_eq!(
        decrypted, secret_message,
        "decrypted secret should match the original"
    );
}

async fn wait_for_pet_ring_state_on_all_nodes(
    endpoints: &[String],
    ring_id: &str,
    timeout: Duration,
    poll_interval: Duration,
) -> Vec<RingStateSnapshot> {
    let deadline = Instant::now() + timeout;

    loop {
        let mut snapshots = Vec::with_capacity(endpoints.len());
        let mut statuses = Vec::with_capacity(endpoints.len());

        for (idx, endpoint) in endpoints.iter().enumerate() {
            match cli_tool::query_pet_ring_state(endpoint.clone(), ring_id.to_string()).await {
                Ok((public_polynomial, last_pss)) => {
                    statuses.push(format!("node{}: last_pss={}", idx + 1, last_pss));
                    snapshots.push(RingStateSnapshot {
                        public_polynomial,
                        last_pss,
                    });
                }
                Err(e) => {
                    statuses.push(format!("node{}: {}", idx + 1, e));
                    snapshots.clear();
                    break;
                }
            }
        }

        if snapshots.len() == endpoints.len() {
            println!(
                "All nodes have local PET ring state: {}",
                statuses.join("; ")
            );
            return snapshots;
        }

        assert!(
            Instant::now() < deadline,
            "Timed out waiting for all nodes to expose PET ring state. Last observed: {}",
            statuses.join("; ")
        );
        sleep(poll_interval).await;
    }
}

async fn wait_for_pet_pss_refresh_on_all_nodes(
    endpoints: &[String],
    ring_id: &str,
    baselines: &[RingStateSnapshot],
    timeout: Duration,
    poll_interval: Duration,
) -> Vec<RingStateSnapshot> {
    assert_eq!(
        endpoints.len(),
        baselines.len(),
        "PET ring-state baselines must match endpoint count"
    );

    let deadline = Instant::now() + timeout;
    let mut next_status_log = Instant::now() + Duration::from_secs(15);

    loop {
        let mut snapshots = Vec::with_capacity(endpoints.len());
        let mut statuses = Vec::with_capacity(endpoints.len());
        let mut all_refreshed = true;

        for (idx, endpoint) in endpoints.iter().enumerate() {
            match cli_tool::query_pet_ring_state(endpoint.clone(), ring_id.to_string()).await {
                Ok((public_polynomial, last_pss)) => {
                    let baseline = &baselines[idx];
                    let polynomial_changed = public_polynomial != baseline.public_polynomial;
                    let timestamp_advanced = last_pss > baseline.last_pss;
                    if !polynomial_changed && !timestamp_advanced {
                        all_refreshed = false;
                    }
                    statuses.push(format!(
                        "node{}: poly_changed={} timestamp_advanced={} last_pss={} baseline={}",
                        idx + 1,
                        polynomial_changed,
                        timestamp_advanced,
                        last_pss,
                        baseline.last_pss,
                    ));
                    snapshots.push(RingStateSnapshot {
                        public_polynomial,
                        last_pss,
                    });
                }
                Err(e) => {
                    all_refreshed = false;
                    statuses.push(format!("node{}: {}", idx + 1, e));
                }
            }
        }

        if all_refreshed && snapshots.len() == endpoints.len() {
            return snapshots;
        }

        let now = Instant::now();
        assert!(
            now < deadline,
            "PET PSS refresh did not complete on all nodes within {}s. Last observed: {}",
            timeout.as_secs(),
            statuses.join("; ")
        );
        if now >= next_status_log {
            println!("Still waiting for PET PSS refresh: {}", statuses.join("; "));
            next_status_log = now + Duration::from_secs(15);
        }
        sleep(poll_interval).await;
    }
}

async fn wait_for_ring_state_on_all_nodes(
    endpoints: &[String],
    ring_pk_hex: &str,
    timeout: Duration,
    poll_interval: Duration,
) -> Vec<RingStateSnapshot> {
    let deadline = Instant::now() + timeout;

    loop {
        let mut snapshots = Vec::with_capacity(endpoints.len());
        let mut statuses = Vec::with_capacity(endpoints.len());

        for (idx, endpoint) in endpoints.iter().enumerate() {
            match cli_tool::query_ring_state(endpoint.clone(), ring_pk_hex.to_string()).await {
                Ok((public_polynomial, last_pss)) => {
                    statuses.push(format!("node{}: last_pss={}", idx + 1, last_pss));
                    snapshots.push(RingStateSnapshot {
                        public_polynomial,
                        last_pss,
                    });
                }
                Err(e) => {
                    statuses.push(format!("node{}: {}", idx + 1, e));
                    snapshots.clear();
                    break;
                }
            }
        }

        if snapshots.len() == endpoints.len() {
            println!(
                "All nodes have local DKG ring state: {}",
                statuses.join("; ")
            );
            return snapshots;
        }

        assert!(
            Instant::now() < deadline,
            "Timed out waiting for all nodes to expose DKG ring state. Last observed: {}",
            statuses.join("; ")
        );
        sleep(poll_interval).await;
    }
}

async fn wait_for_reshare_bulletin_completion(
    chain_config: &ChainConfig,
    ring_id: &str,
    ring_pk_hex: &str,
    expected_peer_ids: &[String],
    expected_threshold: u32,
    timeout: Duration,
    poll_interval: Duration,
) -> RingPayload {
    let deadline = Instant::now() + timeout;
    let mut next_status_log = Instant::now() + Duration::from_secs(15);
    let expected_sorted = sorted_peer_ids(expected_peer_ids);

    loop {
        let last_status = match cli_tool::read_bulletin_post_with_config(
            ring_id.to_string(),
            BulletinKind::Ring,
            chain_config.clone(),
        )
        .await
        {
            Ok(payload_bytes) => match serde_json::from_slice::<RingPayload>(&payload_bytes) {
                Ok(payload) => {
                    let actual_sorted = sorted_peer_ids(&payload.peer_node_keys);
                    let complete = payload.ring_pk == ring_pk_hex
                        && actual_sorted == expected_sorted
                        && payload.threshold == expected_threshold
                        && payload.new_peer_node_keys.is_none()
                        && payload.new_threshold.is_none();
                    let status = format!(
                        "peer_count={} threshold={} new_peer_node_keys_set={} new_threshold={:?}",
                        payload.peer_node_keys.len(),
                        payload.threshold,
                        payload.new_peer_node_keys.is_some(),
                        payload.new_threshold
                    );
                    if complete {
                        return payload;
                    }
                    status
                }
                Err(e) => format!("parse error: {}", e),
            },
            Err(e) => e.to_string(),
        };

        let now = Instant::now();
        assert!(
            now < deadline,
            "PSS reshare did not update the bulletin within {}s. Last observed: {}",
            timeout.as_secs(),
            last_status
        );
        if now >= next_status_log {
            println!(
                "Still waiting for PSS reshare bulletin update: {}",
                last_status
            );
            next_status_log = now + Duration::from_secs(15);
        }
        sleep(poll_interval).await;
    }
}

fn sorted_peer_ids(peer_ids: &[String]) -> Vec<String> {
    let mut sorted = peer_ids.to_vec();
    sorted.sort();
    sorted
}

/// Same retry contract as the plain `cli_tool::do_pre` path for the
/// inline-document variant: periodic PSS refreshes move the ring generation
/// under an in-flight request, and the responder rejects it as explicitly
/// retryable.
async fn do_pre_inline_expect_success(
    context: &str,
    endpoint: String,
    chain_id: String,
    ring_pk: String,
    object_id: String,
    audit_target_object_id: Option<String>,
    inline_document: proto::v0::pre::InlineDocument,
) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut attempt = 1usize;

    loop {
        match cli_tool::do_pre_with_inline_document(
            endpoint.clone(),
            chain_id.clone(),
            ring_pk.clone(),
            object_id.clone(),
            None,
            None,
            None,
            None,
            None,
            inline_document.clone(),
            audit_target_object_id.clone(),
        )
        .await
        {
            Ok(result) => return result,
            Err(e) => {
                // `{:?}` (anyhow's Debug): the underlying tonic::Status and its
                // rejection reason only surface through the error's cause chain.
                assert!(
                    Instant::now() < deadline,
                    "{} failed after {} attempts: {:?}",
                    context,
                    attempt,
                    e
                );
                println!(
                    "{} attempt {} failed, retrying after transient PRE race: {:?}",
                    context, attempt, e
                );
                attempt += 1;
                sleep(Duration::from_secs(3)).await;
            }
        }
    }
}
