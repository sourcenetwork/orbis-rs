//! Shared integration test: exercises organic Reshare transport reporting
//! through a pure-new leader. Node4 leads a pending committee containing one
//! unreachable member (`NODE_KEY_OFFLINE`, genesis-seeded but never
//! running), relays the terminal preparation candidate to a current signer,
//! and the resulting `node_offline` report lands on chain against the
//! offline pending member — no stop/injection needed, this is fully organic.
//!
//! `NodeRole::Offline` is Cosmos-only (same gap as
//! `report_reshare_stall_offline.rs`/`cancel_ring_reshare.rs`), so this is
//! Cosmos-real/native-`#[ignore]`d.

use super::report_scenario::{wait_for_demerits, STANDARD_RING_POLICY_YAML};
use super::{pre_scenario, TestEnvironmentImpl};
use test_support::fixture::{
    BulletinTestDriver, FixtureId, NetworkTestDriver, NodeFixture, NodeRef, NodeRole,
    PolicyFixture, RingFixture, ScenarioFixture, TestEnvironment,
};
use tokio::time::Duration;

// Same deterministic test key as `report_reshare_stall_offline.rs`'s own
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
async fn test_reshare_offline_triggers_on_chain_report() {
    println!("Starting PSS reshare offline reporting integration test...");

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
            definition: STANDARD_RING_POLICY_YAML.to_string(),
        }],
        rings: vec![RingFixture {
            id: ring.clone(),
            // node4 (index 3) is deliberately not an initial member — it's
            // the pure-new canonical Reshare leader for the pending
            // committee below.
            members: vec![
                NodeRef::Running(0),
                NodeRef::Running(1),
                NodeRef::Running(2),
            ],
            threshold: 2,
            // pss_interval=86400 prevents any PSS refresh from firing during
            // the test window; reshare bypasses this check entirely.
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
    let node4_key = environment.nodes()[3].node_key.clone();

    // node4 is a running node but deliberately not an initial ring member —
    // `provision`'s own ring materialization only whitelists/updates the
    // peer id of `ring.members`, so a pure-new reshare target needs this
    // done explicitly before it can be announced.
    #[cfg(feature = "integration-test-cosmos")]
    environment.whitelist_node_for_ring(&ring_id, 3).await;

    println!("Starting DKG for ring {}...", ring_id.0);
    let (keys, _local_state) = pre_scenario::run_dkg(&environment, &ring_id).await;
    println!(
        "DKG finalized. Ring PK: {}...",
        &keys.main[..40.min(keys.main.len())]
    );

    // node4 sorts before the synthetic offline key and is not in the
    // current committee, making it the pure-new canonical Reshare leader.
    println!("Triggering ring reshare to [node4, offline] threshold=1...");
    environment
        .update_membership(
            &ring_id,
            vec![node4_key.clone(), NODE_KEY_OFFLINE.to_string()],
            1,
        )
        .await;

    let announced = environment
        .read_ring(&ring_id)
        .await
        .expect("ring must exist after announcing the reshare");
    let mut announced_target = announced.new_peer_node_keys.clone();
    announced_target.sort();
    let mut expected_target = vec![node4_key.clone(), NODE_KEY_OFFLINE.to_string()];
    expected_target.sort();
    assert_eq!(
        announced_target, expected_target,
        "reshare should target the pure-new leader and offline member"
    );
    println!("Reshare announced on-chain.");

    println!("Waiting for the organic Reshare node_offline report against the offline member...");
    let demerits = wait_for_demerits(
        &environment,
        &ring_id,
        NODE_KEY_OFFLINE,
        1,
        Duration::from_secs(180),
    )
    .await;
    assert_eq!(
        demerits, 1,
        "the offline pending member should receive exactly one report's worth of demerits, got {demerits}"
    );
    println!("offline pending-member demerit points: {demerits}");
}
