//! Shared integration test: verifies the reshare bad-DKG-share relay path —
//! a pure-new receiver (node4) that gets provably-bad reshare evidence
//! relays it to the current committee, which re-verifies, threshold-signs an
//! `invalid_crypto_response` report, and lands it on chain while the reshare
//! is still pending.
//!
//! Reshare bad-share reports are only valid while the ring is in the
//! pending-reshare state, and a reshare among healthy nodes completes within
//! seconds — closing that window before the relay/co-sign/tx pipeline can
//! finish. To hold the window open deterministically, the new committee
//! includes `NODE_KEY_OFFLINE` (genesis-seeded NodeInfo, no running node): a
//! dealer only completes once *every* new member acks its share, so the
//! participant set never freezes and the ring stays pending for the whole
//! test. (A bad dealer in a reshare that *does* complete is intentionally
//! unreportable: it is being rotated out anyway.)
//!
//! Provisioning/DKG/reshare-announcement are shared. Forging node3's
//! evidence requires signing *as* node3 using Cosmos's deterministic
//! per-node secp256k1 identity key (`NODE3_SIGNING_KEY_HEX`, matching
//! docker-compose's `ORBIS_SIGNING_KEY`) — native's node-identity scheme
//! hasn't been verified against this forgery technique, and `NodeRole::
//! Offline` (needed for the stalled new committee) doesn't exist on native's
//! fixture materializer either. Not yet ported for native.

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
// Same deterministic test key as `report_reshare_stall_offline.rs`'s own
// `NODE_KEY_OFFLINE`.
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
async fn test_reshare_bad_dkg_share_relay_triggers_on_chain_report() {
    println!("Starting PSS reshare bad DKG-share relay reporting integration test...");

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
    use crate::dkg::v0::messages::SignedDkgShare;
    use crate::reporting::v0::types::{
        ring_state_sha256, CommitteeScope, DkgCommitmentStatement, DkgShareStatement,
        DKG_COMMITMENT_DOMAIN, DKG_SHARE_DOMAIN,
    };
    use crate::ring_state::RingIndexEntry;
    use bulletin::r#trait::{BulletinKind, RingPayload};
    use common::blockchain::sign_node_message_with_hex_key;
    use crypto::r#trait::{CryptoDeserialize, Dkg, DkgMode, DkgRole};
    use crypto::CryptoSerialize;
    use crypto::{DkgImpl, ScalarField};
    use proto::unsafe_testing::{
        unsafe_testing_service_client::UnsafeTestingServiceClient, GetActivePssSessionRequest,
        GetLocalStorageRequest, LocalStorageAccessMode, LocalStorageKey, LocalStorageKeyType,
        SetLocalStorageRequest, SubmitDkgInvalidShareEvidenceRequest,
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

    async fn ensure_ring_index_on_nodes(endpoints: &[String], ring_pk_hex: &str, ring_id: &str) {
        let ring_key = ring_key_from_ring_pk_hex(ring_pk_hex);
        let indexed_at_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_secs();

        for (index, endpoint) in endpoints.iter().enumerate() {
            let mut client = UnsafeTestingServiceClient::connect(endpoint.clone())
                .await
                .expect("connect unsafe-testing client for RingIndex");
            let key = LocalStorageKey {
                key_type: LocalStorageKeyType::RingIndex as i32,
                ring_key: String::new(),
            };
            let stored = client
                .get_local_storage(GetLocalStorageRequest {
                    key: Some(key.clone()),
                    access_mode: LocalStorageAccessMode::Plain as i32,
                })
                .await
                .expect("read RingIndex")
                .into_inner();
            let mut ring_index: Vec<RingIndexEntry> = if stored.found {
                serde_json::from_slice(&stored.value).expect("parse RingIndex")
            } else {
                Vec::new()
            };

            if let Some(entry) = ring_index
                .iter_mut()
                .find(|entry| entry.ring_pk_str == ring_key)
            {
                entry.bulletin_post_id = ring_id.to_string();
            } else {
                ring_index.push(RingIndexEntry {
                    ring_pk_str: ring_key.clone(),
                    bulletin_post_id: ring_id.to_string(),
                    indexed_at_secs,
                });
            }

            client
                .set_local_storage(SetLocalStorageRequest {
                    key: Some(key),
                    access_mode: LocalStorageAccessMode::Plain as i32,
                    value: serde_json::to_vec(&ring_index).expect("serialize RingIndex"),
                })
                .await
                .expect("write RingIndex");
            println!(
                "Ensured RingIndex entry on node{} for local ring key {}...",
                index + 1,
                &ring_key[..40.min(ring_key.len())]
            );
        }
    }

    fn signed_bad_reshare_dkg_share(
        chain_id: String,
        ring_id: String,
        ring: &RingPayload,
        session_id: u128,
        accused_node_key: &str,
        accused_signing_key_hex: &str,
        receiver_node_key: &str,
    ) -> SignedDkgShare {
        let from_node_id = canonical_node_id(accused_node_key, &ring.peer_node_keys);
        let receiver_node_keys = ring
            .new_peer_node_keys
            .clone()
            .expect("reshare announcement should include new_peer_node_keys");
        let to_node_id = canonical_node_id(receiver_node_key, &receiver_node_keys);

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
                participating_ids: (1..=ring.peer_node_keys.len() as u32).collect(),
                new_threshold: ring
                    .new_threshold
                    .unwrap_or(ring.threshold)
                    .try_into()
                    .expect("new threshold fits usize"),
                new_total_nodes: receiver_node_keys.len(),
                new_node_id: None,
            })
            .expect("generate reshare polynomial");

        let commitment = serialize_commitment_coefficients(&dealer.commitment().coefficients)
            .expect("commitment");
        let share = dealer
            .generate_shares()
            .expect("generate reshare shares")
            .into_iter()
            .find(|share| share.to_id == to_node_id)
            .expect("share for receiver");
        let share_value = <ScalarField as CryptoSerialize>::to_bytes(&share.value).expect("share");
        let mut bad_share_value = ScalarField::from_bytes(&share_value).expect("deserialize share");
        bad_share_value += ScalarField::from(1_u64);
        let bad_share_value =
            <ScalarField as CryptoSerialize>::to_bytes(&bad_share_value).expect("bad share");
        assert_ne!(share_value, bad_share_value);

        let signed_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_secs();
        let commitment_statement = DkgCommitmentStatement {
            domain: DKG_COMMITMENT_DOMAIN.to_string(),
            chain_id: chain_id.clone(),
            ring_id: ring_id.clone(),
            ring_pk: ring.ring_pk.clone(),
            ring_state_sha256: ring_state_sha256(ring),
            protocol_version: network::V0.version,
            request_id: session_id.to_string(),
            signed_at: signed_at - 1,
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
        let commitment_signature = sign_node_message_with_hex_key(
            accused_signing_key_hex,
            &commitment_statement.canonical_bytes(),
        )
        .expect("sign DKG commitment evidence");
        let statement = DkgShareStatement {
            domain: DKG_SHARE_DOMAIN.to_string(),
            chain_id,
            ring_id,
            ring_pk: ring.ring_pk.clone(),
            ring_state_sha256: ring_state_sha256(ring),
            protocol_version: network::V0.version,
            request_id: session_id.to_string(),
            signed_at,
            responder_node_key: accused_node_key.to_string(),
            receiver_node_key: receiver_node_key.to_string(),
            origin_protocol: "pss_reshare".to_string(),
            accused_committee_scope: CommitteeScope::Current,
            signing_committee_scope: CommitteeScope::Current,
            from_node_id,
            to_node_id,
            commitment_statement,
            commitment_signature,
            share_value: bad_share_value,
            nonce: share.nonce,
            crypto_backend: DkgImpl::name(),
        };
        let signature =
            sign_node_message_with_hex_key(accused_signing_key_hex, &statement.canonical_bytes())
                .expect("sign DKG share evidence");

        SignedDkgShare {
            statement,
            signature,
        }
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

        let dkg_node_endpoints: Vec<String> = environment.nodes()[..3]
            .iter()
            .map(|node| node.grpc_endpoint.clone())
            .collect();
        ensure_ring_index_on_nodes(&dkg_node_endpoints, &keys.main, &ring_id.0).await;

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

        let evidence = signed_bad_reshare_dkg_share(
            chain_config.chain_id.clone(),
            ring_id.0.clone(),
            &ring_payload,
            session_id,
            &members[2],
            NODE3_SIGNING_KEY_HEX,
            &node4_key,
        );

        let mut unsafe_client = UnsafeTestingServiceClient::connect(node4_endpoint)
            .await
            .expect("connect unsafe-testing client to node4");
        unsafe_client
            .submit_dkg_invalid_share_evidence(SubmitDkgInvalidShareEvidenceRequest {
                session_id: session_id.to_string(),
                signed_share_json: serde_json::to_vec(&evidence)
                    .expect("serialize signed evidence"),
            })
            .await
            .expect("submit bad DKG-share evidence through pure-new receiver");

        println!("Waiting for node3's demerits to reflect the DKG bad-share report...");
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
            "node3 should have exactly one demerit after the DKG bad-share report, got {demerits}"
        );
        println!("node3 demerit points: {demerits}");
    }
}
