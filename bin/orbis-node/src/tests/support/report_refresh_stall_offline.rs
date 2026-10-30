//! Shared integration test: exercises the G1 stall→offline **report** path
//! deterministically. A real `AbandonedPssSession` is injected through the
//! drain worker's own logic (`report_abandoned_pss_session`) naming node3
//! as the silent refresh dealer, with node3 stopped so the co-signer
//! reachability probe passes and the report is accepted. A real
//! mid-ceremony crash can't be used because G1 and the send-failure path
//! emit byte-identical `node_offline` reports (same session_id) that
//! dedupe against each other. `pss_interval: 86400` means no background
//! refresh runs, so the injected report is the only one — making the
//! demerit count deterministic.
//!
//! The injection RPC (`UnsafeTestingService::submit_pss_stall_offline_report`)
//! and the underlying report pipeline are backend-neutral production code
//! (`bin/orbis-node/src/unsafe_testing/service.rs`/`reporting/v0/registry`),
//! so this runs as one real test on both backends. The one backend-specific
//! piece is computing node3's on-chain-registered P2P peer id: Cosmos
//! self-reports an address that needs rewriting to its Compose service name
//! (`CosmosNetwork::transform_p2p_address`, same as `provision()`'s own
//! ring materialization already does internally before registering it on
//! chain); native's `NativeTestEnvironment::provision` registers nodes'
//! self-reported `p2p_address` directly, with no rewriting at all
//! (confirmed by reading its `SetPeer` authorization step) — so native uses
//! it as-is.

use super::report_scenario::{wait_for_demerits, STANDARD_RING_POLICY_YAML};
use super::{pre_scenario, TestEnvironmentImpl};
use proto::unsafe_testing::{
    unsafe_testing_service_client::UnsafeTestingServiceClient, SubmitPssStallOfflineReportRequest,
};
use test_support::fixture::{
    FixtureId, NetworkTestDriver, NodeFixture, NodeRef, NodeRole, PolicyFixture, RingFixture,
    ScenarioFixture, TestEnvironment,
};
use tokio::time::Duration;

#[tokio::test]
#[serial_test::serial]
async fn test_refresh_stall_offline_triggers_on_chain_report() {
    println!("Starting PSS refresh stall→offline reporting integration test...");

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
    // node1, naming node3 as the silent refresh dealer. This is the exact
    // per-event logic the expiration sweep would drive.
    let mut unsafe_client = UnsafeTestingServiceClient::connect(endpoint.clone())
        .await
        .expect("connect unsafe-testing client to node1");
    let session_id: u128 = 909_111_222_333_u128;
    unsafe_client
        .submit_pss_stall_offline_report(SubmitPssStallOfflineReportRequest {
            ring_id: ring_id.0.clone(),
            session_id: session_id.to_string(),
            peer_id: node3_peer_id,
            ring_pk_hex: keys.main.clone(),
            new_peer_node_keys: Vec::new(),
            new_threshold: 0,
            bulletin_post_id: String::new(),
        })
        .await
        .expect("submit PSS stall offline report");
    println!("Injected abandoned-PSS-session offline attribution for node3.");

    println!("Waiting for node3's demerits to reflect the stall-offline report...");
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
