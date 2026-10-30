//! Shared integration test: a node forging a relayer-signed statement for
//! PRE/Sign on an actor with no ACP relationship fires `unauthorized_request`
//! reports against the forging relayer.
//!
//! Provisioning and DKG are shared (`TestEnvironmentImpl`/`pre_scenario`).
//! Everything after that is Cosmos-specific: it directly writes documents/
//! key-derivations to the bulletin bypassing StoreSecret entirely
//! (`VeraClient::orbis_store_document_get_id`/`orbis_store_key_derivation_
//! get_id` — no `TestEnvironment::store_document` equivalent exists on
//! native, which never implements direct bulletin writes), and it forges
//! the relay statement's signature using Cosmos's own deterministic
//! per-node secp256k1 identity keys (`NODE1_SIGNING_KEY_HEX`/
//! `NODE2_SIGNING_KEY_HEX`, matching docker-compose's `ORBIS_SIGNING_KEY`)
//! — native's node identity/signing scheme hasn't been verified against
//! this forgery technique at all. Not yet ported for native; see the
//! `#[cfg_attr(ignore)]` below.

#[cfg(feature = "integration-test-cosmos")]
use super::pre_scenario;
use super::TestEnvironmentImpl;
#[cfg(feature = "integration-test-native")]
use test_support::fixture::TestEnvironment;
use test_support::fixture::{
    FixtureId, NodeFixture, NodeRef, NodeRole, RingFixture, ScenarioFixture,
};
use tokio::time::Duration;

#[cfg(feature = "integration-test-cosmos")]
const NODE1_SIGNING_KEY_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000001";
#[cfg(feature = "integration-test-cosmos")]
const NODE2_SIGNING_KEY_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000002";

#[tokio::test]
#[serial_test::serial]
#[cfg_attr(
    feature = "integration-test-native",
    ignore = "direct bulletin document/key-derivation writes and the \
              Cosmos-deterministic-signing-key relay-statement forgery \
              this test depends on are both unported for native; fix \
              when native grows a direct-write equivalent and this is \
              re-verified against native's own node-identity scheme"
)]
async fn test_unauthorized_relay_pre_and_sign_triggers_on_chain_report() {
    println!("Starting unauthorized relay reporting integration test...");

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

    #[cfg(feature = "integration-test-native")]
    {
        let _environment = TestEnvironmentImpl::provision(fixture).await;
        unimplemented!(
            "native: direct bulletin writes + Cosmos-signing-key relay forgery not ported"
        );
    }

    #[cfg(feature = "integration-test-cosmos")]
    cosmos::run(fixture).await;
}

#[cfg(feature = "integration-test-cosmos")]
mod cosmos {
    use super::{pre_scenario, TestEnvironmentImpl, NODE1_SIGNING_KEY_HEX, NODE2_SIGNING_KEY_HEX};
    use common::blockchain::{
        acp::Object, events::ReportEventSubscription, sign_node_message_with_hex_key, ChainConfig,
        TxSigner, VeraClient, TEST_ACCOUNT_HEX_KEY,
    };
    use crypto::helpers::generate_keypair;
    use crypto::r#trait::{EncryptionProof, Secret};
    use crypto::CryptoSerialize;
    use proto::unsafe_testing::{
        unsafe_testing_service_client::UnsafeTestingServiceClient,
        SubmitUnauthorizedRelayEvidenceRequest,
    };
    use proto::v0::pre::InlineDocument;
    use test_support::fixture::{
        BulletinTestDriver, NetworkTestDriver, ScenarioFixture, TestEnvironment,
    };
    use tokio::time::Duration;

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
        chain_config: &ChainConfig,
        ring_id: &str,
        ring: &bulletin::r#trait::RingPayload,
        origin_protocol: &str,
        accused_node_key: &str,
        accused_signing_key_hex: &str,
        object_id: &str,
        actor_id: &str,
    ) -> (crate::reporting::v0::types::RelayRequestStatement, Vec<u8>) {
        use crate::reporting::v0::types::{
            ring_state_sha256, CommitteeScope, RelayRequestStatement, RELAY_REQUEST_DOMAIN,
        };
        let signed_at = current_unix_time_secs();
        let statement = RelayRequestStatement {
            domain: RELAY_REQUEST_DOMAIN.to_string(),
            chain_id: chain_config.chain_id.clone(),
            ring_id: ring_id.to_string(),
            ring_pk: ring.ring_pk.clone(),
            ring_state_sha256: ring_state_sha256(ring),
            protocol_version: network::V0.version,
            request_id: format!("unauthorized-relay-{origin_protocol}-{object_id}"),
            signed_at,
            user_signed_at: signed_at,
            relayer_node_key: accused_node_key.to_string(),
            origin_protocol: origin_protocol.to_string(),
            accused_committee_scope: CommitteeScope::Current,
            signing_committee_scope: CommitteeScope::Current,
            from_node_id: canonical_node_id(accused_node_key, &ring.peer_node_keys),
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

    pub(super) async fn run(fixture: ScenarioFixture) {
        let ring = fixture.rings[0].id.clone();
        let environment = TestEnvironmentImpl::provision(fixture).await;
        let ring_id = environment.fixture().rings[&ring].id.clone();
        let members = environment.fixture().rings[&ring].members.clone();
        let node1_key = members[0].clone();
        let node2_key = members[1].clone();
        let node1_endpoint = environment.nodes()[0].grpc_endpoint.clone();
        let node2_endpoint = environment.nodes()[1].grpc_endpoint.clone();
        let chain_config = environment.chain_config();

        println!("Starting DKG for ring {}...", ring_id.0);
        let (keys, _local_state) = pre_scenario::run_dkg(&environment, &ring_id).await;
        println!(
            "DKG finalized. Ring PK: {}...",
            &keys.main[..40.min(keys.main.len())]
        );

        let ring_payload_bytes = cli_tool::read_bulletin_post_with_config(
            ring_id.0.clone(),
            bulletin::r#trait::BulletinKind::Ring,
            chain_config.clone(),
        )
        .await
        .expect("read finalized ring payload");
        let ring_payload: bulletin::r#trait::RingPayload =
            serde_json::from_slice(&ring_payload_bytes).expect("parse finalized RingPayload");
        assert_eq!(
            ring_payload.ring_pk, keys.main,
            "finalized ring payload should carry the DKG'd ring_pk"
        );

        let controller_client = VeraClient::with_signer(
            chain_config.clone(),
            TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, chain_config.clone())
                .expect("test account signer"),
        )
        .await
        .expect("controller chain client");

        let resource = "document".to_string();
        let permission = "read".to_string();

        let policy_ids_before: std::collections::HashSet<String> = controller_client
            .acp_list_policy_ids()
            .await
            .expect("list policy ids before unauthorized relay test policy")
            .ids
            .into_iter()
            .collect();
        controller_client
            .acp_create_policy(UNAUTHORIZED_RELAY_TEST_POLICY_YAML, 1)
            .await
            .expect("create unauthorized relay test policy");
        let policy_id = controller_client
            .acp_list_policy_ids()
            .await
            .expect("list policy ids after unauthorized relay test policy")
            .ids
            .into_iter()
            .find(|id| !policy_ids_before.contains(id))
            .expect("new unauthorized relay test policy ID not found");

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
        let (_, pre_object_id) = controller_client
            .orbis_store_document_get_id(
                &ring_id.0,
                &pre_document_str,
                &pre_proof_str,
                &policy_id,
                &resource,
                &permission,
                None,
                None,
                None,
                None,
            )
            .await
            .expect("store PRE document");

        controller_client
            .acp_register_object(
                &policy_id,
                Object {
                    resource: resource.clone(),
                    id: pre_object_id.clone(),
                },
            )
            .await
            .expect("register PRE unauthorized relay test object");

        let (_, pre_reader_pk) = generate_keypair().expect("generate PRE reader keypair");
        let pre_reader_pk_bytes =
            CryptoSerialize::to_bytes(&pre_reader_pk).expect("serialize PRE reader public key");
        let pre_jwt_signer = authn::JwtSigner::new();
        let (pre_token, _) = pre_jwt_signer
            .create_pre_jwt(pre_reader_pk_bytes.clone(), &pre_object_id, None, None)
            .expect("create PRE JWT");
        let pre_actor_is_reader = controller_client
            .acp_has_relationship(
                &policy_id,
                &pre_jwt_signer.did_uri,
                &resource,
                &pre_object_id,
                "reader",
            )
            .await
            .expect("check PRE reader relationship absence");
        assert!(
            !pre_actor_is_reader,
            "PRE actor must not have a reader relationship"
        );

        let (pre_statement, pre_signature) = signed_unauthorized_relay_statement(
            &chain_config,
            &ring_id.0,
            &ring_payload,
            "pre",
            &node1_key,
            NODE1_SIGNING_KEY_HEX,
            &pre_object_id,
            &pre_jwt_signer.did_uri,
        );

        let node3_peer_id = test_support::CosmosNetwork::transform_p2p_address(
            &environment.nodes()[2].p2p_address,
            test_support::CosmosNetwork::service_name_for_node(3),
        );

        println!("Submitting PRE unauthorized relay evidence against node1 through node3...");
        let pre_sub = ReportEventSubscription::connect(&chain_config.rpc_url)
            .await
            .expect("connect PRE unauthorized report event subscription");
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
        let pre_event = pre_sub
            .wait_for_report_accepted_matching(&ring_id.0, Duration::from_secs(180), |event| {
                event.report_type == crate::reporting::v0::types::UNAUTHORIZED_REQUEST_REPORT_TYPE
                    && event.accused_node_key == node1_key
                    && event.reporter_node_key == members[2]
            })
            .await
            .expect("PRE unauthorized_request EventReportAccepted should be emitted");
        println!(
            "PRE unauthorized relay report accepted: report_id={} accused={} reporter={}",
            pre_event.report_id, pre_event.accused_node_key, pre_event.reporter_node_key
        );

        // Sign: node2 produced a relayer-signed statement for another unauthorized actor.
        println!("Setting up Sign unauthorized relay fixture...");
        let sign_derivation = "unauthorized-relay-sign-derivation".to_string();
        let (_, derivation_id) = controller_client
            .orbis_store_key_derivation_get_id(
                &ring_id.0,
                &sign_derivation,
                &policy_id,
                &resource,
                &permission,
            )
            .await
            .expect("store Sign key derivation");

        controller_client
            .acp_register_object(
                &policy_id,
                Object {
                    resource: resource.clone(),
                    id: derivation_id.clone(),
                },
            )
            .await
            .expect("register Sign unauthorized relay test object");

        let sign_message = b"unauthorized relay sign report test message";
        let sign_jwt_signer = authn::JwtSigner::new();
        let sign_token = sign_jwt_signer
            .create_sign_jwt(&derivation_id, sign_message)
            .expect("create Sign JWT");
        let sign_actor_is_reader = controller_client
            .acp_has_relationship(
                &policy_id,
                &sign_jwt_signer.did_uri,
                &resource,
                &derivation_id,
                "reader",
            )
            .await
            .expect("check Sign reader relationship absence");
        assert!(
            !sign_actor_is_reader,
            "Sign actor must not have a reader relationship"
        );

        let (sign_statement, sign_signature) = signed_unauthorized_relay_statement(
            &chain_config,
            &ring_id.0,
            &ring_payload,
            "sign",
            &node2_key,
            NODE2_SIGNING_KEY_HEX,
            &derivation_id,
            &sign_jwt_signer.did_uri,
        );

        let node1_peer_id = test_support::CosmosNetwork::transform_p2p_address(
            &environment.nodes()[0].p2p_address,
            test_support::CosmosNetwork::service_name_for_node(1),
        );

        println!("Submitting Sign unauthorized relay evidence against node2 through node1...");
        let sign_sub = ReportEventSubscription::connect(&chain_config.rpc_url)
            .await
            .expect("connect Sign unauthorized report event subscription");
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
        let sign_event = sign_sub
            .wait_for_report_accepted_matching(&ring_id.0, Duration::from_secs(180), |event| {
                event.report_type == crate::reporting::v0::types::UNAUTHORIZED_REQUEST_REPORT_TYPE
                    && event.accused_node_key == node2_key
                    && event.reporter_node_key == members[0]
            })
            .await
            .expect("Sign unauthorized_request EventReportAccepted should be emitted");
        println!(
            "Sign unauthorized relay report accepted: report_id={} accused={} reporter={}",
            sign_event.report_id, sign_event.accused_node_key, sign_event.reporter_node_key
        );

        println!("Checking relayer demerit points...");
        let node1_demerits = environment.read_node_demerits(&ring_id, &node1_key).await;
        let node2_demerits = environment.read_node_demerits(&ring_id, &node2_key).await;
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
}
