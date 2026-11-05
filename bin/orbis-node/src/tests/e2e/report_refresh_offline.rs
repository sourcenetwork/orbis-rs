//! Shared integration test: exercises the **organic** PSS-refresh-discovers
//! -offline path, distinct from `report_refresh_stall_offline.rs` (which
//! injects a synthetic `AbandonedPssSession` report directly). Here, a real
//! refresh ceremony is made due by backdating every running node's
//! locally-persisted `last_pss` after node3 has stopped. Backdating while
//! node3 is still up lets the refresh pass Prepare; a participant that dies
//! after that is only reported at the 15-minute attempt deadline, past this
//! test's wait. With node3 already down, the ceremony's own co-signer
//! reachability check discovers and reports it — no test-only
//! report-injection RPC involved.
//!
//! Both backends use a day-long interval and backdate the running members
//! only after node3 has stopped. A 5-second Cosmos interval is already
//! inside the 10-second scheduler grace window, so the refresh starts as
//! soon as DKG stores the bundle. A ceremony that passes Prepare before the
//! stop reports that later death only at the 15-minute attempt deadline.
//!
//! The pass/fail signal is `report_scenario::wait_for_demerits` rather than
//! Cosmos's `ReportEventSubscription` — same simplification as every other
//! migrated `reporting.rs` test, trading the event's richer per-report
//! metadata (report_id/reporter_node_key) for a portable, dual-backend check
//! that the right node actually got demerited.

use super::report_scenario::STANDARD_RING_POLICY_YAML;
use super::{pre_scenario, TestEnvironmentImpl};
use crate::constants::PSS_GRACE_PERIOD_SECS;
use proto::info_service::{info_service_client::InfoServiceClient, GetRingStateRequest};
use std::time::{SystemTime, UNIX_EPOCH};
use test_support::admin::RingId;
use test_support::fixture::{
    BulletinTestDriver, FixtureId, NetworkTestDriver, NodeFixture, NodeRef, NodeRole,
    PolicyFixture, RingFixture, ScenarioFixture, TestEnvironment,
};
use tokio::time::{sleep, Duration, Instant};

#[tokio::test]
#[serial_test::serial]
async fn test_refresh_offline_triggers_on_chain_report() {
    println!("Starting organic PSS refresh offline reporting integration test...");

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
    let leader_key = members.iter().min().cloned().expect("ring has a member");
    println!(
        "refresh leader is {} (node3 is the leader: {})",
        leader_key,
        leader_key == node3_key
    );
    // A 5s interval is the old Cosmos fixture. Logging it next to the
    // day-long interval shows whether that fixture was already due before
    // the stop, which a longer demerit wait cannot repair.
    log_refresh_clocks("before stop", environment.nodes(), &keys.main, pss_interval).await;

    // Stop node3 before any bundle is made due. The scheduler polls every
    // 5s, and a refresh that has already passed Prepare only reports a
    // later death at the 15-minute attempt deadline.
    println!("Stopping node3 so the refresh ceremony finds it unreachable...");
    environment.stop_node(2).await;
    log_refresh_clocks(
        "after stop, before backdate",
        environment.nodes(),
        &keys.main,
        pss_interval,
    )
    .await;

    println!("Forcing PSS refresh due on the running nodes...");
    let running: Vec<(String, String)> = environment
        .nodes()
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != 2)
        .map(|(_, node)| (node.grpc_endpoint.clone(), node.node_key.clone()))
        .collect();
    super::stored_bundle::backdate_live_main_ring(&running, &keys.main, &members).await;
    log_refresh_clocks(
        "after backdate",
        &environment.nodes()[..2],
        &keys.main,
        pss_interval,
    )
    .await;

    // An unreachable peer is retried until the 120s preparation deadline
    // (150s when the dead node is the leader and the start is forwarded).
    // The report is submitted only after that.
    println!("Waiting for the organic PSS-refresh node_offline report to land on node3...");
    let demerits = wait_for_demerit_with_clock(
        &environment,
        &ring_id,
        &node3_key,
        &keys.main,
        pss_interval,
        Duration::from_secs(240),
    )
    .await;
    assert_eq!(
        demerits, 1,
        "node3 should have exactly one demerit after the organic refresh-offline report, got {demerits}"
    );
    println!("node3 demerit points: {demerits}");
}

fn refresh_is_due(elapsed: u64, interval: Duration) -> bool {
    elapsed + PSS_GRACE_PERIOD_SECS >= interval.as_secs()
}

async fn log_refresh_clocks(
    label: &str,
    nodes: &[test_support::NodeInfo],
    ring_pk: &str,
    interval: Duration,
) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs();
    println!(
        "refresh clock [{label}] now={now} configured_interval={}s grace={PSS_GRACE_PERIOD_SECS}s",
        interval.as_secs()
    );
    for (index, node) in nodes.iter().enumerate() {
        let mut client = match InfoServiceClient::connect(node.grpc_endpoint.clone()).await {
            Ok(client) => client,
            Err(error) => {
                println!("  node{} unreachable: {error}", index + 1);
                continue;
            }
        };
        match client
            .get_ring_state(GetRingStateRequest {
                ring_pk_hex: ring_pk.to_string(),
            })
            .await
        {
            Ok(state) => {
                let last_pss = state.into_inner().last_pss;
                let elapsed = now.saturating_sub(last_pss);
                println!(
                    "  node{} last_pss={last_pss} elapsed={elapsed}s due_at_{}s={} due_at_5s={}",
                    index + 1,
                    interval.as_secs(),
                    refresh_is_due(elapsed, interval),
                    refresh_is_due(elapsed, Duration::from_secs(5))
                );
            }
            Err(error) => println!("  node{} ring state unavailable: {error}", index + 1),
        }
    }
}

async fn wait_for_demerit_with_clock(
    environment: &TestEnvironmentImpl,
    ring: &RingId,
    node_key: &str,
    ring_pk: &str,
    interval: Duration,
    timeout: Duration,
) -> u64 {
    let started = Instant::now();
    let deadline = started + timeout;
    let mut next_log = started;
    loop {
        let demerits = environment.read_node_demerits(ring, node_key).await;
        let elapsed = started.elapsed();
        if demerits >= 1 {
            println!(
                "demerit reached {demerits} after {}s (wait budget {}s)",
                elapsed.as_secs(),
                timeout.as_secs()
            );
            log_refresh_clocks(
                "when demerit landed",
                &environment.nodes()[..2],
                ring_pk,
                interval,
            )
            .await;
            return demerits;
        }
        if Instant::now() >= next_log {
            println!(
                "still waiting {}s/{timeout}s, demerits={demerits}",
                elapsed.as_secs(),
                timeout = timeout.as_secs()
            );
            log_refresh_clocks("during wait", &environment.nodes()[..2], ring_pk, interval).await;
            next_log += Duration::from_secs(15);
        }
        assert!(
            Instant::now() < deadline,
            "node {node_key} demerits did not reach 1 within {}s (last observed: {demerits})",
            timeout.as_secs(),
        );
        sleep(Duration::from_millis(500)).await;
    }
}
