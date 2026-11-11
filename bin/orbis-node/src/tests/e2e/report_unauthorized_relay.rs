//! Shared integration test: a node forging a relayer-signed statement for
//! PRE/Sign on an actor with no ACP relationship fires `unauthorized_request`
//! reports against the forging relayer.
//!
//! Fully backend-neutral — no `#[cfg]` split in this file. `p2p_address`
//! resolution goes through `NetworkTestDriver::reporting_peer_address`.
//! `NODE1_SIGNING_KEY_HEX`/
//! `NODE2_SIGNING_KEY_HEX` are node1/node2's real signing keys on *both*
//! backends now (see `crates/bulletin/src/native/integration_startup.rs`),
//! so forging evidence "as" them needs no backend-specific key resolution.
//! The ring's current state (needed to build the forged relay statement)
//! comes from `BulletinTestDriver::read_ring_state_facts`, not a
//! Cosmos-only raw cli-tool bulletin read. Document/key-derivation
//! registration goes through `BulletinTestDriver::register_document`/
//! `register_key_derivation`, and the test policy/object registration
//! through `create_policy`/`register_object` — all shared, backend-neutral
//! trait methods. The original Cosmos-only `acp_has_relationship` sanity
//! checks (confirming the forged actor starts with no reader relationship)
//! are dropped: they're guaranteed by test construction (a freshly
//! generated actor id is never registered with any relationship) and have
//! no shared equivalent on the trait.

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
const NODE2_SIGNING_KEY_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000002";

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
        document_inline: false,
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
async fn test_unauthorized_relay_pre_and_sign_triggers_on_chain_report() {
    println!("Starting unauthorized relay reporting integration test...");

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
            // kick_threshold=10: retries can produce more than one accepted
            // unauthorized_request report, but must not trigger auto-kick.
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
    let node2_key = members[1].clone();
    let node1_endpoint = environment.nodes()[0].grpc_endpoint.clone();
    let node2_endpoint = environment.nodes()[1].grpc_endpoint.clone();
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

    // PRE: node1 produced a relayer-signed statement for an actor with no ACP relationship.
    println!("Setting up PRE unauthorized relay fixture...");
    let pre_document_str = String::from_utf8(
        serde_json::to_vec(&Secret {
            enc_cmt: vec![3u8; 32],
            encrypted_data: vec![20, 21, 22, 23],
            nonce: vec![2u8; 12],
        })
        .expect("serialize PRE secret"),
    )
    .expect("secret JSON is valid utf8");
    let pre_proof_str: String = EncryptionProof {
        challenge: vec![9, 8, 7],
        response: vec![6, 5, 4],
    }
    .try_into()
    .expect("serialize PRE proof");
    let pre_object_id = environment
        .register_document(
            &ring_id,
            &pre_document_str,
            &pre_proof_str,
            &policy_id,
            &resource,
            &permission,
        )
        .await;

    environment
        .register_object(&policy_id, &resource, &pre_object_id)
        .await;

    let (_, pre_reader_pk) = generate_keypair().expect("generate PRE reader keypair");
    let pre_reader_pk_bytes =
        CryptoSerialize::to_bytes(&pre_reader_pk).expect("serialize PRE reader public key");
    let pre_jwt_signer = authn::JwtSigner::new();
    let (pre_token, _) = pre_jwt_signer
        .create_pre_jwt(pre_reader_pk_bytes.clone(), &pre_object_id, None, None)
        .expect("create PRE JWT");

    let (pre_statement, pre_signature) = signed_unauthorized_relay_statement(
        chain_id.clone(),
        &ring_id.0,
        &facts,
        "pre",
        &node1_key,
        NODE1_SIGNING_KEY_HEX,
        &pre_object_id,
        &pre_jwt_signer.did_uri,
    );

    let node3_peer_id = environment.reporting_peer_address(2);

    println!("Submitting PRE unauthorized relay evidence against node1 through node3...");
    submit_unauthorized_relay_evidence(
        node1_endpoint.clone(),
        node3_peer_id,
        pre_statement,
        pre_signature,
        pre_token,
        pre_reader_pk_bytes,
        None,
    )
    .await;
    println!("PRE unauthorized relay evidence forwarded.");
    let node1_demerits = super::report_scenario::wait_for_demerits(
        &environment,
        &ring_id,
        &node1_key,
        1,
        Duration::from_secs(180),
    )
    .await;
    println!("node1 demerit points after PRE unauthorized relay report: {node1_demerits}");

    // Sign: node2 produced a relayer-signed statement for another unauthorized actor.
    println!("Setting up Sign unauthorized relay fixture...");
    let sign_derivation = "unauthorized-relay-sign-derivation".to_string();
    let derivation_id = environment
        .register_key_derivation(
            &ring_id,
            &sign_derivation,
            &policy_id,
            &resource,
            &permission,
        )
        .await;

    environment
        .register_object(&policy_id, &resource, &derivation_id)
        .await;

    let sign_message = b"unauthorized relay sign report test message";
    let sign_jwt_signer = authn::JwtSigner::new();
    let sign_token = sign_jwt_signer
        .create_sign_jwt(&derivation_id, sign_message)
        .expect("create Sign JWT");

    let (sign_statement, sign_signature) = signed_unauthorized_relay_statement(
        chain_id,
        &ring_id.0,
        &facts,
        "sign",
        &node2_key,
        NODE2_SIGNING_KEY_HEX,
        &derivation_id,
        &sign_jwt_signer.did_uri,
    );

    let node1_peer_id = environment.reporting_peer_address(0);

    println!("Submitting Sign unauthorized relay evidence against node2 through node1...");
    submit_unauthorized_relay_evidence(
        node2_endpoint,
        node1_peer_id,
        sign_statement,
        sign_signature,
        sign_token,
        Vec::new(),
        None,
    )
    .await;
    println!("Sign unauthorized relay evidence forwarded.");
    let node2_demerits = super::report_scenario::wait_for_demerits(
        &environment,
        &ring_id,
        &node2_key,
        1,
        Duration::from_secs(180),
    )
    .await;
    println!("node2 demerit points after Sign unauthorized relay report: {node2_demerits}");

    assert!(
        node1_demerits >= 1,
        "node1 should have at least 1 demerit after the PRE unauthorized relay report"
    );
    assert!(
        node2_demerits >= 1,
        "node2 should have at least 1 demerit after the Sign unauthorized relay report"
    );
    println!("relayer demerits: node1={node1_demerits}, node2={node2_demerits}");
}
