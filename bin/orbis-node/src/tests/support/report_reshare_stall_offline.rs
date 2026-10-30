//! Shared integration test: reshare counterpart to
//! `report_refresh_stall_offline.rs`, same technique — a real
//! `AbandonedPssSession` is injected through the drain worker's own logic
//! (`report_abandoned_pss_session`) naming node3 as the silent
//! **old-committee** dealer, with node3 stopped so the co-signer
//! reachability probe passes and the report is accepted.
//!
//! A real mid-reshare stall can't be used here either — old committee
//! [1,2,3] threshold=2 means losing exactly node3 never blocks quorum
//! (dealer selection only needs threshold-many), so the reshare always
//! completes cleanly regardless of node3. The new committee [node2,
//! offline] excludes node3 so it resolves to `Current` (old-only) scope,
//! not `PendingNew` — distinct from `test_reshare_offline_triggers_on_chain_
//! report`, which covers an unreachable *new* member instead.
//!
//! The synthetic offline member in the new committee isn't for
//! reachability-probe purposes — it's there so the real reshare (which
//! every running node starts processing the moment the announcement lands,
//! since reshare bypasses `pss_interval`) can never actually finish: the
//! Prepare barrier requires every new-committee route to respond, which the
//! unroutable placeholder can never do. Without it, the real ceremony
//! completes immediately and finalizes new ring state, making the
//! injected report's `ring_state_sha256` (computed from the pending-reshare
//! snapshot) stale by the time its tx lands on chain.
//!
//! `NodeRole::Offline` is Cosmos-only (`CosmosTestEnvironment::provision`'s
//! genesis-seeding, added for `cancel_ring_reshare.rs`) — native's
//! `NativeTestEnvironment::provision` panics immediately on seeing any
//! non-`Running` role, so this is Cosmos-real/native-`#[ignore]`d, same
//! precedent as `cancel_ring_reshare.rs`/`report_pet_invalid_decrypt_share.rs`.

use super::report_scenario::{wait_for_demerits, STANDARD_RING_POLICY_YAML};
use super::{pre_scenario, TestEnvironmentImpl};
use proto::unsafe_testing::{
    unsafe_testing_service_client::UnsafeTestingServiceClient, SubmitPssStallOfflineReportRequest,
};
use test_support::fixture::{
    BulletinTestDriver, FixtureId, NetworkTestDriver, NodeFixture, NodeRef, NodeRole,
    PolicyFixture, RingFixture, ScenarioFixture, TestEnvironment,
};
use tokio::time::Duration;

// Same deterministic test key as `cancel_ring_reshare.rs`'s own
// `NODE_KEY_OFFLINE` (not reachable from native's separate test crate, so
// duplicated here independently rather than shared).
const NODE_KEY_OFFLINE: &str = "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556";

#[tokio::test]
#[serial_test::serial]
#[cfg_attr(
    feature = "integration-test-native",
    ignore = "commonware/native's NativeTestEnvironment::provision doesn't \
              support NodeRole::Offline yet; fix when native grows that \
              capability (same gap as cancel_ring_reshare.rs)"
)]
async fn test_reshare_stall_offline_triggers_on_chain_report() {
    println!("Starting PSS reshare stall→offline reporting integration test...");

    let ring = FixtureId::new("ring");
    let ring_policy = FixtureId::new("ring-policy");
    let offline_node = FixtureId::new("offline-node");
    let fixture = ScenarioFixture {
        nodes: (0..3)
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
            requires_pet: false,
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

    println!("Starting DKG for ring {}...", ring_id.0);
    let (keys, _local_state) = pre_scenario::run_dkg(&environment, &ring_id).await;
    println!(
        "DKG finalized. Ring PK: {}...",
        &keys.main[..40.min(keys.main.len())]
    );

    // Announce a real reshare targeting [node2, offline] — node3 is
    // deliberately excluded from the new committee so it resolves to
    // Current (old-only) scope, not PendingNew, once stalled. The offline
    // placeholder keeps this reshare permanently pending (see the doc
    // comment above) so the ring state the injected report's digest is
    // computed against never changes out from under it.
    let new_peer_node_keys = vec![members[1].clone(), NODE_KEY_OFFLINE.to_string()];
    let new_threshold = 1u32;
    println!("Announcing reshare to [node2, offline] threshold=1...");
    environment
        .update_membership(&ring_id, new_peer_node_keys.clone(), new_threshold)
        .await;

    #[cfg(feature = "integration-test-cosmos")]
    let node3_peer_id = test_support::CosmosNetwork::transform_p2p_address(
        &environment.nodes()[2].p2p_address,
        test_support::CosmosNetwork::service_name_for_node(3),
    );
    #[cfg(feature = "integration-test-native")]
    let node3_peer_id = environment.nodes()[2].p2p_address.clone();

    // Stop node3 so the co-signer reachability probe finds it unreachable
    // and accepts the report. node3's on-chain NodeInfo (peer id) persists,
    // so the report path still resolves it.
    println!("Stopping node3 so it is unreachable at co-signer probe time...");
    environment.stop_node(2).await;

    // Inject a real AbandonedPssSession through the drain-worker path on
    // node1, naming node3 as the silent old-committee dealer.
    // `new_peer_node_keys` being non-empty is what selects the Reshare
    // branch of `SessionKind` in the unsafe-testing handler.
    let mut unsafe_client = UnsafeTestingServiceClient::connect(endpoint.clone())
        .await
        .expect("connect unsafe-testing client to node1");
    let session_id: u128 = 909_111_222_444_u128;
    unsafe_client
        .submit_pss_stall_offline_report(SubmitPssStallOfflineReportRequest {
            ring_id: ring_id.0.clone(),
            session_id: session_id.to_string(),
            peer_id: node3_peer_id,
            ring_pk_hex: keys.main.clone(),
            new_peer_node_keys,
            new_threshold,
            // Unused by `resolve_pss_offline_report_context` whenever
            // `ring_id` (above) is non-empty, which it always is here.
            bulletin_post_id: String::new(),
        })
        .await
        .expect("submit PSS stall offline report");
    println!("Injected abandoned-PSS-session offline attribution for node3.");

    println!("Waiting for node3's demerits to reflect the reshare stall-offline report...");
    let demerits = wait_for_demerits(
        &environment,
        &ring_id,
        &node3_key,
        1,
        Duration::from_secs(180),
    )
    .await;
    assert_eq!(
        demerits, 1,
        "node3 should have exactly one demerit after a single stall offline report, got {demerits}"
    );
    println!("node3 demerit points: {demerits}");
}
