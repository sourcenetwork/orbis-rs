//! Shared integration test: exercises the **organic** PSS-refresh-discovers
//! -offline path, distinct from `report_refresh_stall_offline.rs` (which
//! injects a synthetic `AbandonedPssSession` report directly). Here, a real
//! refresh ceremony is made due via `BulletinTestDriver::force_refresh_due`
//! (backdating every running node's locally-persisted `last_pss`, same
//! mechanism PR4's `refresh_scenario.rs` already relies on). Node3 is stopped
//! first. The native scheduler polls every few seconds, so backdating while
//! node3 is still up lets the refresh pass Prepare; a participant that dies
//! after that is only reported at the 15-minute attempt deadline, past this
//! test's wait. With node3 already down, the ceremony's own co-signer
//! reachability check discovers and reports it — no test-only
//! report-injection RPC involved.
//!
//! `pss_interval` is deliberately backend-split: native's live
//! `RingCommand::Create` enforces a >=86400s minimum (`vera-modules::vera::
//! rings::types::RingConfig::validate`), so native always relies on
//! `force_refresh_due`'s backdating regardless of the configured value
//! (confirmed in PR4); Cosmos's genesis-seeded ring has no such floor, and
//! keeping its original short interval (5s) lets the refresh become due
//! organically within the same window DKG itself takes, matching the
//! original test's own "no test-only hook needed on Cosmos" framing as
//! closely as a shared fixture allows. `force_refresh_due` is still called
//! unconditionally on both backends: Cosmos's implementation is a no-op (the
//! short interval already made it due), native's is the real backdate.
//!
//! The pass/fail signal is `report_scenario::wait_for_demerits` rather than
//! Cosmos's `ReportEventSubscription` — same simplification as every other
//! migrated `reporting.rs` test, trading the event's richer per-report
//! metadata (report_id/reporter_node_key) for a portable, dual-backend check
//! that the right node actually got demerited.

use super::report_scenario::{wait_for_demerits, STANDARD_RING_POLICY_YAML};
use super::{pre_scenario, TestEnvironmentImpl};
use test_support::fixture::{
    BulletinTestDriver, FixtureId, NetworkTestDriver, NodeFixture, NodeRef, NodeRole,
    PolicyFixture, RingFixture, ScenarioFixture, TestEnvironment,
};
use tokio::time::Duration;

#[tokio::test]
#[serial_test::serial]
async fn test_refresh_offline_triggers_on_chain_report() {
    println!("Starting organic PSS refresh offline reporting integration test...");

    #[cfg(all(feature = "integration-test", feature = "cosmos"))]
    let pss_interval = Duration::from_secs(5);
    #[cfg(all(feature = "integration-test", feature = "native"))]
    let pss_interval = Duration::from_secs(86_400);

    let ring = FixtureId::new("ring");
    let ring_policy = FixtureId::new("ring-policy");
    let fixture = ScenarioFixture {
        requires_unsafe_testing: true,
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
    let node3_key = members[2].clone();

    println!("Starting DKG for ring {}...", ring_id.0);
    let (keys, _local_state) = pre_scenario::run_dkg(&environment, &ring_id).await;
    println!(
        "DKG finalized. Ring PK: {}...",
        &keys.main[..40.min(keys.main.len())]
    );

    // Stop node3 before any live bundle is made due. Native's scheduler
    // polls every 5s, and a refresh that has already passed Prepare only
    // reports a later death at the 15-minute attempt deadline. The stopped
    // member is skipped by the backdate; its scheduler is not running.
    // Cosmos's own implementation is a no-op; its short `pss_interval`
    // already made the refresh due.
    println!("Stopping node3 so the refresh ceremony finds it unreachable...");
    environment.stop_node(2).await;

    println!("Forcing PSS refresh due on the running nodes...");
    environment
        .force_refresh_due(&ring_id, &keys.main, &members)
        .await;

    println!("Waiting for the organic PSS-refresh node_offline report to land on node3...");
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
        "node3 should have exactly one demerit after the organic refresh-offline report, got {demerits}"
    );
    println!("node3 demerit points: {demerits}");
}
