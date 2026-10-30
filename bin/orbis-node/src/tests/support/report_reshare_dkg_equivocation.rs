//! Shared integration test: verifies the reshare DKG-commitment
//! equivocation relay path — a pure-new receiver (node4) receives two
//! conflicting, signed commitments from an old-committee dealer (node3) and
//! relays them to the current committee, which re-verifies, threshold-signs
//! an `invalid_crypto_response` report, and submits it while the reshare is
//! still pending.
//!
//! Same stalled-reshare mechanics as `report_reshare_bad_dkg_share_relay.rs`
//! (`NODE_KEY_OFFLINE` keeps the new committee from ever completing, holding
//! the pending-reshare window open) — see that file's doc comment for the
//! full reasoning, including why this isn't yet ported for native.

#[cfg(feature = "integration-test-cosmos")]
use super::pre_scenario;
use super::TestEnvironmentImpl;
#[cfg(feature = "integration-test-native")]
use test_support::fixture::TestEnvironment;
use test_support::fixture::{
    FixtureId, NodeFixture, NodeRef, NodeRole, PolicyFixture, RingFixture, ScenarioFixture,
};
use tokio::time::Duration;

#[cfg(feature = "integration-test-cosmos")]
const NODE3_SIGNING_KEY_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000003";
#[cfg(feature = "integration-test-cosmos")]
const NODE_KEY_OFFLINE: &str = "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556";

#[tokio::test]
#[serial_test::serial]
#[cfg_attr(
    feature = "integration-test-native",
    ignore = "NodeRole::Offline isn't supported by NativeTestEnvironment:: \
              provision yet, and the Cosmos-deterministic-signing-key \
              evidence forgery this test depends on hasn't been verified \
              against native's own node-identity scheme; fix when native \
              grows both"
)]
async fn test_reshare_dkg_equivocation_triggers_on_chain_report() {
    println!("Starting PSS reshare DKG equivocation reporting integration test...");

    let ring = FixtureId::new("ring");
    let ring_policy = FixtureId::new("ring-policy");
    let offline_node = FixtureId::new("offline-node");
    let fixture = ScenarioFixture {
        nodes: (0..4)
            .map(|_| NodeFixture {
                id: FixtureId::new("node"),
                role: NodeRole::Running,
            })
            .chain(std::iter::once(NodeFixture {
                id: offline_node,
                role: NodeRole::Offline,
            }))
            .collect(),
        policies: vec![PolicyFixture {
            id: ring_policy.clone(),
            definition: super::report_scenario::STANDARD_RING_POLICY_YAML.to_string(),
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
            policy: ring_policy.clone(),
            reporting: Default::default(),
            upgrade: None,
        }],
        ..Default::default()
    };

    #[cfg(feature = "integration-test-native")]
    {
        let _environment = TestEnvironmentImpl::provision(fixture).await;
        unimplemented!(
            "native: NodeRole::Offline + Cosmos-signing-key reshare evidence forgery not ported"
        );
    }

    #[cfg(feature = "integration-test-cosmos")]
    cosmos::run(fixture).await;
}

#[cfg(feature = "integration-test-cosmos")]
mod cosmos {
    use super::{pre_scenario, TestEnvironmentImpl, NODE3_SIGNING_KEY_HEX, NODE_KEY_OFFLINE};
    use crate::dkg::v0::helpers::serialize_commitment_coefficients;
    use crate::dkg::v0::messages::SignedDkgCommitment;
    use crate::reporting::v0::types::{
        ring_state_sha256, CommitteeScope, DkgCommitmentStatement, DKG_COMMITMENT_DOMAIN,
    };
    use bulletin::r#trait::{BulletinKind, RingPayload};
    use common::blockchain::sign_node_message_with_hex_key;
    use crypto::r#trait::{CryptoDeserialize, Dkg, DkgMode, DkgRole};
    use crypto::{DkgImpl, ScalarField};
    use proto::unsafe_testing::{
        unsafe_testing_service_client::UnsafeTestingServiceClient, GetActivePssSessionRequest,
        SubmitDkgEquivocationEvidenceRequest,
    };
    use test_support::fixture::{
        BulletinTestDriver, NetworkTestDriver, ScenarioFixture, TestEnvironment,
    };
    use tokio::time::{sleep, Duration, Instant};

    fn canonical_node_id(node_key: &str, node_keys: &[String]) -> u32 {
        let mut sorted = node_keys.to_vec();
        sorted.sort();
        sorted
            .iter()
            .position(|candidate| candidate == node_key)
            .map(|index| index as u32 + 1)
            .expect("node key should be in committee")
    }

    fn ring_key_from_ring_pk_hex(ring_pk_hex: &str) -> String {
        let bytes = hex::decode(ring_pk_hex).expect("decode ring_pk hex");
        crypto::GroupAffine::from_bytes(&bytes)
            .expect("deserialize ring_pk")
            .to_string()
    }

    async fn wait_for_active_pss_session(
        endpoint: &str,
        ring_pk: &str,
        timeout: Duration,
    ) -> String {
        let mut client = UnsafeTestingServiceClient::connect(endpoint.to_string())
            .await
            .expect("connect unsafe-testing client for active PSS lookup");
        let deadline = Instant::now() + timeout;
        loop {
            let response = client
                .get_active_pss_session(GetActivePssSessionRequest {
                    ring_pk: ring_pk.to_string(),
                })
                .await
                .expect("query active PSS session")
                .into_inner();
            if response.found {
                return response.session_id;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for active PSS session for ring_pk {ring_pk}"
            );
            sleep(Duration::from_millis(100)).await;
        }
    }

    fn signed_equivocation_commitments(
        chain_id: String,
        ring_id: String,
        ring: &RingPayload,
        session_id: u128,
        accused_node_key: &str,
        accused_signing_key_hex: &str,
    ) -> (SignedDkgCommitment, SignedDkgCommitment) {
        let from_node_id = canonical_node_id(accused_node_key, &ring.peer_node_keys);
        let receiver_node_keys = ring
            .new_peer_node_keys
            .clone()
            .expect("reshare announcement should include new_peer_node_keys");
        let participating_ids: Vec<u32> = (1..=ring.peer_node_keys.len() as u32).collect();
        let new_threshold = ring
            .new_threshold
            .unwrap_or(ring.threshold)
            .try_into()
            .expect("new threshold fits usize");
        let new_total_nodes = receiver_node_keys.len();

        let make_commitment = || {
            let mut dealer = DkgImpl::new(
                from_node_id,
                ring.threshold as usize,
                ring.peer_node_keys.len(),
                session_id,
                DkgRole::Dealer,
            )
            .expect("create reshare dealer");
            dealer
                .generate_polynomial(DkgMode::Reshare {
                    old_share: ScalarField::from(42_u64),
                    participating_ids: participating_ids.clone(),
                    new_threshold,
                    new_total_nodes,
                    new_node_id: None,
                })
                .expect("generate reshare polynomial");
            serialize_commitment_coefficients(&dealer.commitment().coefficients)
                .expect("commitment")
        };

        let commitment_a = make_commitment();
        let commitment_b = make_commitment();
        assert_ne!(
            commitment_a, commitment_b,
            "equivocation evidence must contain two different commitments"
        );

        let make_signed = |commitment: Vec<u8>, signed_at_offset: u64| {
            let signed_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock before unix epoch")
                .as_secs()
                - signed_at_offset;
            let statement = DkgCommitmentStatement {
                domain: DKG_COMMITMENT_DOMAIN.to_string(),
                chain_id: chain_id.clone(),
                ring_id: ring_id.clone(),
                ring_pk: ring.ring_pk.clone(),
                ring_state_sha256: ring_state_sha256(ring),
                protocol_version: network::V0.version,
                request_id: session_id.to_string(),
                signed_at,
                responder_node_key: accused_node_key.to_string(),
                origin_protocol: "pss_reshare".to_string(),
                accused_committee_scope: CommitteeScope::Current,
                signing_committee_scope: CommitteeScope::Current,
                from_node_id,
                commitment,
                session_nonce: [0u8; 16],
                attempt_id: [9; 32],
                crypto_backend: DkgImpl::name(),
            };
            let signature = sign_node_message_with_hex_key(
                accused_signing_key_hex,
                &statement.canonical_bytes(),
            )
            .expect("sign DKG commitment evidence");
            SignedDkgCommitment {
                statement,
                signature,
            }
        };

        (make_signed(commitment_a, 1), make_signed(commitment_b, 0))
    }

    pub(super) async fn run(fixture: ScenarioFixture) {
        let ring = fixture.rings[0].id.clone();
        let environment = TestEnvironmentImpl::provision(fixture).await;
        let ring_id = environment.fixture().rings[&ring].id.clone();
        let members = environment.fixture().rings[&ring].members.clone();
        let node4_key = environment.nodes()[3].node_key.clone();
        let node4_endpoint = environment.nodes()[3].grpc_endpoint.clone();
        let chain_config = environment.chain_config();

        // node4 is a running node but deliberately not an initial ring
        // member — `provision`'s own ring materialization only whitelists/
        // updates the peer id of `ring.members`, so a pure-new reshare
        // target needs this done explicitly before it can be announced.
        environment.whitelist_node_for_ring(&ring_id, 3).await;

        println!("Starting DKG for ring {}...", ring_id.0);
        let (keys, _local_state) = pre_scenario::run_dkg(&environment, &ring_id).await;
        println!(
            "DKG finalized. Ring PK: {}...",
            &keys.main[..40.min(keys.main.len())]
        );

        // NODE_KEY_OFFLINE never acks its shares, so no dealer ever completes
        // and the ring stays in the pending-reshare state (see the test doc
        // comment).
        let reshare_node_keys = vec![
            members[0].clone(),
            members[1].clone(),
            node4_key.clone(),
            NODE_KEY_OFFLINE.to_string(),
        ];
        let reshare_threshold = 2u32;

        println!("Triggering ring reshare to node1/node2/node4/offline, threshold=2...");
        environment
            .update_membership(&ring_id, reshare_node_keys.clone(), reshare_threshold)
            .await;

        let payload_bytes = cli_tool::read_bulletin_post_with_config(
            ring_id.0.clone(),
            BulletinKind::Ring,
            chain_config.clone(),
        )
        .await
        .expect("read ring payload after reshare announcement");
        let ring_payload: RingPayload =
            serde_json::from_slice(&payload_bytes).expect("parse RingPayload");

        let local_ring_key = ring_key_from_ring_pk_hex(&keys.main);
        let (node1_session_id, node2_session_id, node4_session_id) = tokio::join!(
            wait_for_active_pss_session(
                &environment.nodes()[0].grpc_endpoint,
                &local_ring_key,
                Duration::from_secs(180)
            ),
            wait_for_active_pss_session(
                &environment.nodes()[1].grpc_endpoint,
                &local_ring_key,
                Duration::from_secs(180)
            ),
            wait_for_active_pss_session(&node4_endpoint, &local_ring_key, Duration::from_secs(180)),
        );
        assert_eq!(
            node2_session_id, node1_session_id,
            "node2 should join the same active reshare session as node1"
        );
        assert_eq!(
            node4_session_id, node1_session_id,
            "node4 should join the same active reshare session as current signers"
        );
        let session_id = node4_session_id
            .parse::<u128>()
            .expect("active PSS session id should parse");
        println!("node4 active reshare session: {session_id}");

        let (commitment_a, commitment_b) = signed_equivocation_commitments(
            chain_config.chain_id.clone(),
            ring_id.0.clone(),
            &ring_payload,
            session_id,
            &members[2],
            NODE3_SIGNING_KEY_HEX,
        );

        let mut unsafe_client = UnsafeTestingServiceClient::connect(node4_endpoint)
            .await
            .expect("connect unsafe-testing client to node4");
        unsafe_client
            .submit_dkg_equivocation_evidence(SubmitDkgEquivocationEvidenceRequest {
                session_id: session_id.to_string(),
                commitment_a_json: serde_json::to_vec(&commitment_a)
                    .expect("serialize commitment_a evidence"),
                commitment_b_json: serde_json::to_vec(&commitment_b)
                    .expect("serialize commitment_b evidence"),
            })
            .await
            .expect("submit DKG equivocation evidence through pure-new receiver");

        println!("Waiting for node3's demerits to reflect the DKG equivocation report...");
        let demerits = super::super::report_scenario::wait_for_demerits(
            &environment,
            &ring_id,
            &members[2],
            1,
            Duration::from_secs(120),
        )
        .await;
        assert_eq!(
            demerits, 1,
            "node3 should have exactly one demerit after the DKG equivocation report, got {demerits}"
        );
        println!("node3 demerit points: {demerits}");
    }
}
