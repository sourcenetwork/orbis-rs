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
//! Same Cosmos-only dependencies as `report_unauthorized_relay.rs` (direct
//! bulletin document writes, Cosmos-deterministic-signing-key relay-statement
//! forgery) — not yet ported for native; see the `#[cfg_attr(ignore)]` below.

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

#[tokio::test]
#[serial_test::serial]
#[cfg_attr(
    feature = "integration-test-native",
    ignore = "direct bulletin document writes and the \
              Cosmos-deterministic-signing-key relay-statement forgery \
              this test depends on are both unported for native; fix \
              when native grows a direct-write equivalent and this is \
              re-verified against native's own node-identity scheme"
)]
async fn test_pre_unauthorized_relay_bulletin_and_inline_document_triggers_on_chain_report() {
    println!("Starting PRE unauthorized-relay bulletin-vs-inline reporting integration test...");

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
    use super::{pre_scenario, TestEnvironmentImpl, NODE1_SIGNING_KEY_HEX};
    use bulletin::r#trait::RingPayload;
    use common::blockchain::{
        acp::Object, events::ReportEventSubscription, orbis::generate_document_id,
        sign_node_message_with_hex_key, ChainConfig, TxSigner, VeraClient, TEST_ACCOUNT_HEX_KEY,
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
        ring: &RingPayload,
        origin_protocol: &str,
        accused_node_key: &str,
        accused_signing_key_hex: &str,
        object_id: &str,
        actor_id: &str,
        document_inline: bool,
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

    pub(super) async fn run(fixture: ScenarioFixture) {
        let ring = fixture.rings[0].id.clone();
        let environment = TestEnvironmentImpl::provision(fixture).await;
        let ring_id = environment.fixture().rings[&ring].id.clone();
        let members = environment.fixture().rings[&ring].members.clone();
        let node1_key = members[0].clone();
        let node1_endpoint = environment.nodes()[0].grpc_endpoint.clone();
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
        let ring_payload: RingPayload =
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

        let node3_peer_id = test_support::CosmosNetwork::transform_p2p_address(
            &environment.nodes()[2].p2p_address,
            test_support::CosmosNetwork::service_name_for_node(3),
        );

        // ── Sub-case 1: document posted to the bulletin (today's existing path) ──────
        println!("Sub-case 1: bulletin-sourced document...");
        let bulletin_secret = Secret {
            enc_cmt: vec![7u8; 32],
            encrypted_data: vec![10, 11, 12, 13],
            nonce: vec![1u8; 12],
        };
        let bulletin_document_str = String::from_utf8(
            serde_json::to_vec(&bulletin_secret).expect("serialize bulletin secret"),
        )
        .expect("secret JSON is valid utf8");
        let bulletin_proof_str: String = EncryptionProof {
            challenge: vec![1, 2, 3],
            response: vec![4, 5, 6],
        }
        .try_into()
        .expect("serialize bulletin proof");
        let (_, bulletin_object_id) = controller_client
            .orbis_store_document_get_id(
                &ring_id.0,
                &bulletin_document_str,
                &bulletin_proof_str,
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
                    id: bulletin_object_id.clone(),
                },
            )
            .await
            .expect("register bulletin unauthorized relay test object");

        let (_, bulletin_reader_pk) = generate_keypair().expect("generate PRE reader keypair");
        let bulletin_reader_pk_bytes = CryptoSerialize::to_bytes(&bulletin_reader_pk)
            .expect("serialize PRE reader public key");
        let bulletin_jwt_signer = authn::JwtSigner::new();
        let (bulletin_token, _) = bulletin_jwt_signer
            .create_pre_jwt(
                bulletin_reader_pk_bytes.clone(),
                &bulletin_object_id,
                None,
                None,
            )
            .expect("create PRE JWT");
        let bulletin_actor_is_reader = controller_client
            .acp_has_relationship(
                &policy_id,
                &bulletin_jwt_signer.did_uri,
                &resource,
                &bulletin_object_id,
                "reader",
            )
            .await
            .expect("check bulletin reader relationship absence");
        assert!(
            !bulletin_actor_is_reader,
            "bulletin actor must not have a reader relationship"
        );

        let (bulletin_statement, bulletin_signature) = signed_unauthorized_relay_statement(
            &chain_config,
            &ring_id.0,
            &ring_payload,
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
        let bulletin_sub = ReportEventSubscription::connect(&chain_config.rpc_url)
            .await
            .expect("connect bulletin unauthorized report event subscription");
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
        let bulletin_event = bulletin_sub
            .wait_for_report_accepted_matching(&ring_id.0, Duration::from_secs(180), |event| {
                event.report_type == crate::reporting::v0::types::UNAUTHORIZED_REQUEST_REPORT_TYPE
                    && event.accused_node_key == node1_key
                    && event.reporter_node_key == members[2]
            })
            .await
            .expect("bulletin-sourced unauthorized_request EventReportAccepted should be emitted");
        println!(
            "Sub-case 1 (bulletin) report accepted: report_id={}",
            bulletin_event.report_id
        );

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

        let inline_object_id = generate_document_id(
            &ring_id.0,
            &inline_document_str,
            &inline_proof_str,
            &policy_id,
            &resource,
            &permission,
            None,
            None,
            None,
            None,
        )
        .expect("generate inline object_id");

        controller_client
            .acp_register_object(
                &policy_id,
                Object {
                    resource: resource.clone(),
                    id: inline_object_id.clone(),
                },
            )
            .await
            .expect("register inline unauthorized relay test object");

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
        let inline_actor_is_reader = controller_client
            .acp_has_relationship(
                &policy_id,
                &inline_jwt_signer.did_uri,
                &resource,
                &inline_object_id,
                "reader",
            )
            .await
            .expect("check inline reader relationship absence");
        assert!(
            !inline_actor_is_reader,
            "inline actor must not have a reader relationship"
        );

        let (inline_statement, inline_signature) = signed_unauthorized_relay_statement(
            &chain_config,
            &ring_id.0,
            &ring_payload,
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
            policy_id: policy_id.clone(),
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
        let inline_sub = ReportEventSubscription::connect(&chain_config.rpc_url)
            .await
            .expect("connect inline unauthorized report event subscription");
        submit_unauthorized_relay_evidence(
            node1_endpoint.clone(),
            node3_peer_id,
            inline_statement,
            inline_signature,
            inline_token,
            inline_reader_pk_bytes,
            Some(inline_proto_document),
        )
        .await;
        let inline_event = inline_sub
            .wait_for_report_accepted_matching(&ring_id.0, Duration::from_secs(180), |event| {
                event.report_type == crate::reporting::v0::types::UNAUTHORIZED_REQUEST_REPORT_TYPE
                    && event.accused_node_key == node1_key
                    && event.reporter_node_key == members[2]
            })
            .await
            .expect("inline-document unauthorized_request EventReportAccepted should be emitted");
        assert_ne!(
            inline_event.report_id, bulletin_event.report_id,
            "inline report must be distinct from the bulletin report"
        );
        println!(
            "Sub-case 2 (inline) report accepted: report_id={}",
            inline_event.report_id
        );

        println!("Checking node1 demerit points after both reports...");
        let node1_demerits = environment.read_node_demerits(&ring_id, &node1_key).await;
        assert!(
            node1_demerits >= 2,
            "node1 should have at least 2 demerits after the bulletin and inline unauthorized relay reports"
        );
        println!("node1 demerits after both reports: {node1_demerits}");
    }
}
