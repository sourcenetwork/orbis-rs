//! Docker-based integration test: cancel a permanently-stuck ring reshare.
//!
//! Spins up a full Docker Compose environment (Vera + 3 orbis-node containers),
//! runs a real DKG, announces a reshare into a committee that can never complete
//! (it includes a genesis-seeded but never-running node key), cancels it via the
//! new `CancelRingReshareByAcp` chain message, and confirms the ring reverts to its
//! original committee/threshold with the original committee still able to Sign.
//!
//! Run with:
//!   cargo test -p orbis-node --features integration-test -- test_cancel_stuck_reshare_reverts_ring_and_preserves_signing --nocapture

use super::constants::NODE_KEY_OFFLINE;
use super::{pre_scenario, sign_scenario, TestEnvironmentImpl};
use test_support::fixture::{
    BulletinTestDriver, FixtureId, NodeFixture, NodeRef, NodeRole, PolicyFixture, RingFixture,
    ScenarioFixture, TestEnvironment,
};
use tokio::time::{sleep, Duration, Instant};

const RESHARE_THRESHOLD: u32 = 2;

#[tokio::test]
#[serial_test::serial]
async fn test_cancel_stuck_reshare_reverts_ring_and_preserves_signing() {
    println!("Starting cancel-stuck-reshare integration test...");

    const DOCUMENT_POLICY_YAML: &str = r#"
name: cancel-ring-reshare-policy
resources:
- name: document
  permissions:
  - name: read
    expr: reader
  relations:
  - name: reader
    types:
    - actor
"#;

    let policy = FixtureId::new("policy");
    let ring = FixtureId::new("ring");
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
            id: policy.clone(),
            definition: DOCUMENT_POLICY_YAML.to_string(),
        }],
        rings: vec![RingFixture {
            id: ring.clone(),
            // NODE_KEY_OFFLINE (seeded on-chain but never running) is
            // deliberately *not* an initial member here — it only ever
            // becomes a reshare target below, same as the pre-fixture test.
            members: vec![
                NodeRef::Running(0),
                NodeRef::Running(1),
                NodeRef::Running(2),
            ],
            threshold: 2,
            pss_interval: Duration::from_secs(5),
            requires_pet: false,
            policy: FixtureId::new("ring-policy"),
            reporting: Default::default(),
            upgrade: None,
        }],
        ..Default::default()
    };

    let environment = TestEnvironmentImpl::provision(fixture).await;
    let ring_id = environment.fixture().rings[&ring].id.clone();
    let policy_id = environment.fixture().policies[&policy].id.clone();
    let original_members = environment.fixture().rings[&ring].members.clone();

    // ====================================================================
    // Step 1: Real DKG, so the ring holds genuine, mutually-consistent
    // shares before we ever try to reshare it.
    // ====================================================================
    println!("Starting DKG for ring {}...", ring_id.0);
    let (keys, _local_state) = pre_scenario::run_dkg(&environment, &ring_id).await;
    println!(
        "DKG finalized. Ring PK: {}...",
        &keys.main[..40.min(keys.main.len())]
    );

    // ====================================================================
    // Step 2: Baseline Sign, proving the original committee works before we
    // ever attempt (and abandon) a reshare.
    // ====================================================================
    let sign = sign_scenario::run(&environment, &ring_id, &keys, &policy_id).await;
    println!("Baseline Sign verified — original committee is healthy.");

    // ====================================================================
    // Step 3: Announce a reshare that can never complete (new committee
    // includes the never-running NODE_KEY_OFFLINE).
    // ====================================================================
    let certified_before = environment
        .read_ring(&ring_id)
        .await
        .expect("ring must exist before the stuck reshare");
    let mut stuck_target = original_members.clone();
    stuck_target.push(NODE_KEY_OFFLINE.to_string());

    println!("Announcing a reshare that includes the offline node (must never complete)...");
    environment
        .update_membership(&ring_id, stuck_target.clone(), RESHARE_THRESHOLD)
        .await;

    let announced = environment
        .read_ring(&ring_id)
        .await
        .expect("ring must exist after announcing the stuck reshare");
    let mut announced_target = announced.new_peer_node_keys.clone();
    announced_target.sort();
    let mut expected_target = stuck_target.clone();
    expected_target.sort();
    assert_eq!(
        announced_target, expected_target,
        "reshare announcement should set the stuck target committee"
    );
    assert_eq!(
        announced.new_threshold,
        Some(RESHARE_THRESHOLD),
        "reshare announcement should set the stuck target threshold"
    );

    // ====================================================================
    // Step 4: Confirm it's genuinely stuck, not just "not yet finished" —
    // the pending fields must still be set after a bounded wait.
    // ====================================================================
    println!("Confirming the reshare does not complete on its own...");
    sleep(Duration::from_secs(15)).await;
    let still_pending = environment
        .read_ring(&ring_id)
        .await
        .expect("ring must still exist while confirming the stall");
    assert!(
        still_pending.pending_reshare(),
        "reshare unexpectedly completed on its own; the offline-member stall fixture is broken"
    );

    // ====================================================================
    // Step 5: Cancel it, and confirm the ring reverts (not just clears).
    // ====================================================================
    println!("Cancelling the stuck reshare...");
    environment.cancel_reshare(&ring_id).await;

    let cancel_deadline = Instant::now() + Duration::from_secs(30);
    let reverted_ring = loop {
        let view = environment
            .read_ring(&ring_id)
            .await
            .expect("ring must still exist after cancel");
        if !view.pending_reshare() {
            break view;
        }
        assert!(
            Instant::now() < cancel_deadline,
            "reshare was not cancelled within 30 seconds"
        );
        sleep(Duration::from_secs(1)).await;
    };
    let mut reverted_members = reverted_ring.peer_node_keys.clone();
    reverted_members.sort();
    let mut expected_members = original_members.clone();
    expected_members.sort();
    assert_eq!(
        reverted_members, expected_members,
        "cancelling the reshare must leave the original committee in place"
    );
    assert_eq!(
        reverted_ring.threshold, 2,
        "cancelling the reshare must leave the original threshold in place"
    );
    assert_eq!(
        reverted_ring.ring_pk, certified_before.ring_pk,
        "cancelling the reshare must not change the ring's public key"
    );
    println!("Reshare cancelled; ring reverted to the original committee/threshold.");

    // ====================================================================
    // Step 6: Post-cancel Sign — the strongest proof available that no
    // node's share was corrupted by the aborted reshare attempt.
    // ====================================================================
    sign_scenario::verify_existing(&environment, &keys, &sign).await;
    println!("Post-cancel Sign verified — the original committee is still fully functional.");
}
