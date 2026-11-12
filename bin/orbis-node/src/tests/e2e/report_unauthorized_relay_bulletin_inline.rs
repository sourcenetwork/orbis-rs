//! Shared integration test: proves `unauthorized_request` reporting works
//! identically whether the request's document came from the bulletin or
//! was supplied inline. For the inline sub-case the ciphertext is never
//! signed into the statement nor put on chain — only the `document_inline`
//! bool is — and the reporting node re-derives `object_id` from the
//! document it was forwarded. The inline report being accepted on-chain is
//! what proves the Vera Go decoder parses the new wire shape (a
//! `document_inline` bool where the evidence blob used to be). Both
//! sub-cases share one DKG/network spin-up.
//!
//! Fully backend-neutral — no `#[cfg]` split in this file. Same reasoning
//! as `report_unauthorized_relay.rs`: `NODE1_SIGNING_KEY_HEX` is node1's
//! real signing key on both backends now, the ring's current state comes
//! from `BulletinTestDriver::read_ring_state_facts`, and document
//! registration goes through `register_document`. The inline sub-case's
//! "what id would this document get if it were stored" question is
//! answered by `BulletinTestDriver::predict_document_id` — a new, pure/sync
//! trait method mirroring `register_document`'s shape without the actual
//! on-chain write, since this sub-case must *not* ever post the document.

use super::pre_scenario;
use super::TestEnvironmentImpl;
use common::blockchain::sign_node_message_with_hex_key;
use crypto::helpers::generate_keypair;
use crypto::r#trait::{EncryptionProof, Secret};
use crypto::CryptoSerialize;
use proto::unsafe_testing::{
    unsafe_testing_service_client::UnsafeTestingServiceClient,
    SubmitUnauthorizedRelayEvidenceRequest,
};
use proto::v0::pre::InlineDocument;
use test_support::admin::RingStateFacts;
use test_support::fixture::{
    AuthorizationTestDriver, BulletinTestDriver, FixtureId, NetworkTestDriver, NodeFixture,
    NodeRef, NodeRole, RingFixture, ScenarioFixture, TestEnvironment,
};
use tokio::time::Duration;

const NODE1_SIGNING_KEY_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000001";

const UNAUTHORIZED_RELAY_TEST_POLICY_YAML: &str = r#"
name: unauthorized-relay-test-policy
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
        expr: reader
      - name: write
        expr: creator
"#;

fn canonical_node_id(node_key: &str, node_keys: &[String]) -> u32 {
    let mut sorted = node_keys.to_vec();
    sorted.sort();
    sorted
        .iter()
        .position(|candidate| candidate == node_key)
        .map(|index| index as u32 + 1)
        .expect("node key should be in committee")
}

fn current_unix_time_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
}

#[allow(clippy::too_many_arguments)]
fn signed_unauthorized_relay_statement(
    chain_id: String,
    ring_id: &str,
    facts: &RingStateFacts,
    origin_protocol: &str,
    accused_node_key: &str,
    accused_signing_key_hex: &str,
    object_id: &str,
    actor_id: &str,
    document_inline: bool,
) -> (crate::reporting::v0::types::RelayRequestStatement, Vec<u8>) {
    use crate::reporting::v0::types::{
        CommitteeScope, RelayRequestStatement, RELAY_REQUEST_DOMAIN,
    };
    let signed_at = current_unix_time_secs();
    let statement = RelayRequestStatement {
        domain: RELAY_REQUEST_DOMAIN.to_string(),
        chain_id,
        ring_id: ring_id.to_string(),
        ring_pk: facts.ring_pk.clone(),
        ring_state_sha256: facts.state_sha256.clone(),
        protocol_version: network::V0.version,
        request_id: format!("unauthorized-relay-{origin_protocol}-{object_id}"),
        signed_at,
        user_signed_at: signed_at,
        relayer_node_key: accused_node_key.to_string(),
        origin_protocol: origin_protocol.to_string(),
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        from_node_id: canonical_node_id(accused_node_key, &facts.peer_node_keys),
        actor_id: actor_id.to_string(),
        object_id: object_id.to_string(),
        valid_window_start: None,
        valid_window_end: None,
        timestamp: None,
        document_inline,
    };
    let signature =
        sign_node_message_with_hex_key(accused_signing_key_hex, &statement.canonical_bytes())
            .expect("sign unauthorized relay statement");
    (statement, signature)
}

#[allow(clippy::too_many_arguments)]
async fn submit_unauthorized_relay_evidence(
    endpoint: String,
    target_peer_id: String,
    statement: crate::reporting::v0::types::RelayRequestStatement,
    relay_signature: Vec<u8>,
    token_string: String,
    pre_reader_pk: Vec<u8>,
    inline_document: Option<InlineDocument>,
) {
    let mut client = UnsafeTestingServiceClient::connect(endpoint)
        .await
        .expect("connect unsafe-testing client for unauthorized relay evidence");
    client
        .submit_unauthorized_relay_evidence(SubmitUnauthorizedRelayEvidenceRequest {
            relay_statement_canonical_bytes: statement.canonical_bytes(),
            relay_signature,
            target_peer_id,
            token_string,
            pre_reader_pk,
            inline_document,
        })
        .await
        .expect("submit unauthorized relay evidence");
}

#[tokio::test]
#[serial_test::serial]
async fn test_pre_unauthorized_relay_bulletin_and_inline_document_triggers_on_chain_report() {
    println!("Starting PRE unauthorized-relay bulletin-vs-inline reporting integration test...");

    let ring = FixtureId::new("ring");
    let fixture = ScenarioFixture {
        requires_unsafe_testing: true,
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
            pss_interval: Duration::from_secs(86_400),
            requires_pet: false,
            policy: FixtureId::new("ring-policy"),
            // kick_threshold=10: two accepted unauthorized_request reports
            // (bulletin + inline sub-cases) must not trigger auto-kick.
            reporting: test_support::fixture::ReportingFixture {
                kick_threshold: 10,
                ..Default::default()
            },
            upgrade: None,
        }],
        ..Default::default()
    };

    let environment = TestEnvironmentImpl::provision(fixture).await;
    let ring_id = environment.fixture().rings[&ring].id.clone();
    let members = environment.fixture().rings[&ring].members.clone();
    let node1_key = members[0].clone();
    let node1_endpoint = environment.nodes()[0].grpc_endpoint.clone();
    let chain_id = environment.chain_id();

    println!("Starting DKG for ring {}...", ring_id.0);
    let (keys, _local_state) = pre_scenario::run_dkg(&environment, &ring_id).await;
    println!(
        "DKG finalized. Ring PK: {}...",
        &keys.main[..40.min(keys.main.len())]
    );

    let facts = environment.read_ring_state_facts(&ring_id).await;
    assert_eq!(
        facts.ring_pk, keys.main,
        "ring state should carry the DKG'd ring_pk"
    );

    let resource = "document".to_string();
    let permission = "read".to_string();

    let policy_id = environment
        .create_policy(UNAUTHORIZED_RELAY_TEST_POLICY_YAML)
        .await;

    let node3_peer_id = environment.reporting_peer_address(2);

    // ── Sub-case 1: document posted to the bulletin (today's existing path) ──────
    println!("Sub-case 1: bulletin-sourced document...");
    let bulletin_document_str = String::from_utf8(
        serde_json::to_vec(&Secret {
            enc_cmt: vec![7u8; 32],
            encrypted_data: vec![10, 11, 12, 13],
            nonce: vec![1u8; 12],
        })
        .expect("serialize bulletin secret"),
    )
    .expect("secret JSON is valid utf8");
    let bulletin_proof_str: String = EncryptionProof {
        challenge: vec![1, 2, 3],
        response: vec![4, 5, 6],
    }
    .try_into()
    .expect("serialize bulletin proof");
    let bulletin_object_id = environment
        .register_document(
            &ring_id,
            &bulletin_document_str,
            &bulletin_proof_str,
            &policy_id,
            &resource,
            &permission,
        )
        .await;
    environment
        .register_object(&policy_id, &resource, &bulletin_object_id)
        .await;

    let (_, bulletin_reader_pk) = generate_keypair().expect("generate PRE reader keypair");
    let bulletin_reader_pk_bytes =
        CryptoSerialize::to_bytes(&bulletin_reader_pk).expect("serialize PRE reader public key");
    let bulletin_jwt_signer = authn::JwtSigner::new();
    let (bulletin_token, _) = bulletin_jwt_signer
        .create_pre_jwt(
            bulletin_reader_pk_bytes.clone(),
            &bulletin_object_id,
            None,
            None,
        )
        .expect("create PRE JWT");

    let (bulletin_statement, bulletin_signature) = signed_unauthorized_relay_statement(
        chain_id.clone(),
        &ring_id.0,
        &facts,
        "pre",
        &node1_key,
        NODE1_SIGNING_KEY_HEX,
        &bulletin_object_id,
        &bulletin_jwt_signer.did_uri,
        false,
    );

    println!(
        "Submitting bulletin-sourced unauthorized relay evidence against node1 through node3..."
    );
    submit_unauthorized_relay_evidence(
        node1_endpoint.clone(),
        node3_peer_id.clone(),
        bulletin_statement,
        bulletin_signature,
        bulletin_token,
        bulletin_reader_pk_bytes,
        None,
    )
    .await;
    println!("Sub-case 1 (bulletin) evidence submitted.");

    // Wait for sub-case 1's report to fully land before starting sub-case 2.
    // Both reports independently re-verify their own `unauthorized_request`
    // access check against a historical anchor; running them concurrently
    // lets each one's own on-chain report submission land inside the
    // other's anchor-capture-to-verify window and intermittently invalidate
    // it (observed in CI). Sequencing them, like `report_unauthorized_relay.rs`
    // already does for its own two cases, removes that timing dependency
    // without changing what this test actually covers.
    super::report_scenario::wait_for_demerits(
        &environment,
        &ring_id,
        &node1_key,
        1,
        Duration::from_secs(180),
    )
    .await;

    // ── Sub-case 2: document supplied inline, never posted to the bulletin ───────
    println!("Sub-case 2: inline document (never posted to the bulletin)...");
    let inline_secret = Secret {
        enc_cmt: vec![9u8; 32],
        encrypted_data: vec![1, 2, 3, 4],
        nonce: vec![0u8; 12],
    };
    let inline_document_bytes =
        serde_json::to_vec(&inline_secret).expect("serialize inline secret");
    let inline_document_str =
        String::from_utf8(inline_document_bytes.clone()).expect("secret JSON is valid utf8");
    let inline_proof = EncryptionProof {
        challenge: vec![4, 5, 6],
        response: vec![7, 8, 9],
    };
    let inline_proof_str: String = inline_proof
        .clone()
        .try_into()
        .expect("serialize inline proof");

    let inline_object_id = environment.predict_document_id(
        &ring_id,
        &inline_document_str,
        &inline_proof_str,
        &policy_id,
        &resource,
        &permission,
    );

    environment
        .register_object(&policy_id, &resource, &inline_object_id)
        .await;

    let (_, inline_reader_pk) = generate_keypair().expect("generate PRE reader keypair");
    let inline_reader_pk_bytes =
        CryptoSerialize::to_bytes(&inline_reader_pk).expect("serialize PRE reader public key");
    let inline_jwt_signer = authn::JwtSigner::new();
    let (inline_token, _) = inline_jwt_signer
        .create_pre_jwt(
            inline_reader_pk_bytes.clone(),
            &inline_object_id,
            None,
            None,
        )
        .expect("create PRE JWT");

    let (inline_statement, inline_signature) = signed_unauthorized_relay_statement(
        chain_id,
        &ring_id.0,
        &facts,
        "pre",
        &node1_key,
        NODE1_SIGNING_KEY_HEX,
        &inline_object_id,
        &inline_jwt_signer.did_uri,
        true,
    );
    let inline_proto_document = InlineDocument {
        ring_id: ring_id.0.clone(),
        encrypted_document: inline_document_bytes,
        enc_cmt: inline_secret.enc_cmt,
        policy_id: policy_id.0.clone(),
        resource: resource.clone(),
        permission: permission.clone(),
        challenge: inline_proof.challenge,
        response: inline_proof.response,
        tier: None,
        timestamp: None,
        pet_tag: None,
    };

    println!(
        "Submitting inline-document unauthorized relay evidence against node1 through node3..."
    );
    submit_unauthorized_relay_evidence(
        node1_endpoint,
        node3_peer_id,
        inline_statement,
        inline_signature,
        inline_token,
        inline_reader_pk_bytes,
        Some(inline_proto_document),
    )
    .await;
    println!("Sub-case 2 (inline) evidence submitted.");

    println!("Waiting for node1's demerits to reflect both reports...");
    let node1_demerits = super::report_scenario::wait_for_demerits(
        &environment,
        &ring_id,
        &node1_key,
        2,
        Duration::from_secs(180),
    )
    .await;
    assert!(
        node1_demerits >= 2,
        "node1 should have at least 2 demerits after the bulletin and inline unauthorized relay reports"
    );
    println!("node1 demerits after both reports: {node1_demerits}");
}
