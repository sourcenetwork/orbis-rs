//! Shared integration test: exercises the refresh **leader** being offline
//! before any Prepare exists, distinct from
//! `report_refresh_offline.rs` (which stops a non-leader mid-Prepare-fanout).
//! With the canonical leader (lexicographically smallest node key —
//! `dkg::v0::transport::digest::canonical_leader`, confirmed backend-neutral
//! production code operating purely on `peer_node_keys`) stopped before
//! `pss_interval` elapses, a non-leader's periodic health check forwards
//! `StartRefresh` to the dead leader and hits `PssOfflineStage::StartForward`
//! (`network.rs`) — a report path that fires before a Prepare is ever sent.
//!
//! Which fixture-declared node actually becomes the canonical leader depends
//! on each backend's own node-identity-key assignment (Cosmos's is a fixed,
//! deterministic test constant list; native's is reported live by each
//! node), so this resolves the real leader key dynamically (`members.iter().
//! min()`) rather than assuming a fixed index — correct on both backends
//! regardless of how keys are assigned under the hood.
//!
//! Same `pss_interval`/`force_refresh_due` backend split as
//! `report_refresh_offline.rs` — see that file's doc comment for the full
//! reasoning. Verification is `report_scenario::wait_for_demerits`, trading
//! the original's `ReportEventSubscription` metadata assertions for a
//! portable dual-backend check.

use super::report_scenario::{wait_for_demerits, STANDARD_RING_POLICY_YAML};
use super::{pre_scenario, TestEnvironmentImpl};
use test_support::fixture::{
    BulletinTestDriver, FixtureId, NetworkTestDriver, NodeFixture, NodeRef, NodeRole,
    PolicyFixture, RingFixture, ScenarioFixture, TestEnvironment,
};
use tokio::time::Duration;

#[tokio::test]
#[serial_test::serial]
async fn test_refresh_leader_offline_before_preparation_triggers_on_chain_report() {
    println!(
        "Starting PSS refresh leader-offline-before-preparation reporting integration test..."
    );

    #[cfg(feature = "integration-test-cosmos")]
    let pss_interval = Duration::from_secs(5);
    #[cfg(feature = "integration-test-native")]
    let pss_interval = Duration::from_secs(86_400);

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
            pss_interval,
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

    println!("Starting DKG for ring {}...", ring_id.0);
    let (keys, _local_state) = pre_scenario::run_dkg(&environment, &ring_id).await;
    println!(
        "DKG finalized. Ring PK: {}...",
        &keys.main[..40.min(keys.main.len())]
    );

    // The canonical refresh leader is the lexicographically smallest member
    // key — resolve it dynamically rather than assuming a fixed index.
    let leader_key = members
        .iter()
        .min()
        .cloned()
        .expect("ring must have at least one member");
    let leader_index = members
        .iter()
        .position(|key| key == &leader_key)
        .expect("leader key must be a ring member");
    println!("Resolved canonical refresh leader: {leader_key}");

    // Make every node's refresh become due *before* stopping the leader —
    // native's backdate reads/writes every node's local storage, so all
    // three must still be reachable when this runs.
    println!("Forcing PSS refresh due on all nodes...");
    environment
        .force_refresh_due(&ring_id, &keys.main, &members)
        .await;

    println!("Stopping the refresh leader before preparation begins...");
    environment.stop_node(leader_index).await;

    println!("Waiting for the organic PSS-refresh node_offline report against the leader...");
    let demerits = wait_for_demerits(
        &environment,
        &ring_id,
        &leader_key,
        1,
        Duration::from_secs(180),
    )
    .await;
    assert_eq!(
        demerits, 1,
        "leader should have exactly one demerit after the organic refresh-leader-offline report, got {demerits}"
    );
    println!("leader demerit points: {demerits}");
}
