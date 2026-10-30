//! Shared integration test: verifies the on-chain kick + backup-node
//! promotion flow. node3 starts with `kick_threshold - 1` demerits seeded
//! in genesis; a single accepted offline report pushes it over the
//! threshold, and the chain schedules an auto-reshare that swaps node3 out
//! for the backup node in the ring's `new_peer_node_keys`.
//!
//! Reshare completion is out of scope: the backup node has no running
//! container, so the test asserts the announced pending committee, not the
//! finalized one.
//!
//! `NodeRole::Backup` and fixture-driven `node_demerits` genesis seeding are
//! both Cosmos-only today (`CosmosTestEnvironment::provision`'s new
//! `backup_node_infos_json`/`node_demerits_genesis_json` — native's
//! `NativeTestEnvironment::provision` still panics on both), so this is
//! Cosmos-real/native-`#[ignore]`d. The one other Cosmos-specific piece —
//! confirming the promoted key was consumed from `reporting.
//! backup_node_keys` — needs a raw `Ring` read (`VeraClient::
//! orbis_read_ring`, no portable equivalent exposed via `RingView`); kept
//! as the function's last statement so it can be `#[cfg]`-split without any
//! unreachable-code fallout on native.

use super::report_scenario::{pre_with_retry, store_secret_with_retry, STANDARD_RING_POLICY_YAML};
use super::{pre_scenario, TestEnvironmentImpl};
use test_support::fixture::{
    AuthorizationTestDriver, BulletinTestDriver, FixtureId, NetworkTestDriver, NodeDemeritFixture,
    NodeFixture, NodeRef, NodeRole, PolicyFixture, RingFixture, ScenarioFixture, TestEnvironment,
};
use tokio::time::{sleep, Duration, Instant};

// Same deterministic test key as `bin/orbis-node/src/tests/constants.rs`'s
// `NODE_KEY_4` (not reachable from native's separate test crate, so
// duplicated here independently). Doubles as the backup-promotion target in
// this fixture, same as the pre-fixture test's own `NODE_KEY_4` usage.
const NODE_KEY_BACKUP: &str = "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13";

#[tokio::test]
#[serial_test::serial]
#[cfg_attr(
    feature = "integration-test-native",
    ignore = "commonware/native's NativeTestEnvironment::provision doesn't \
              support NodeRole::Backup or fixture-driven node_demerits \
              genesis seeding yet; fix when native grows both"
)]
async fn test_report_kick_promotes_backup_node() {
    println!("Starting backup-node promotion integration test...");

    let ring = FixtureId::new("ring");
    let policy = FixtureId::new("policy");
    let ring_policy = FixtureId::new("ring-policy");
    let backup_node = FixtureId::new("backup-node");
    let fixture = ScenarioFixture {
        nodes: (0..3)
            .map(|_| NodeFixture {
                id: FixtureId::new("node"),
                role: NodeRole::Running,
            })
            .chain(std::iter::once(NodeFixture {
                id: backup_node.clone(),
                role: NodeRole::Backup,
            }))
            .collect(),
        policies: vec![
            PolicyFixture {
                id: policy.clone(),
                definition: STANDARD_RING_POLICY_YAML.to_string(),
            },
            PolicyFixture {
                id: ring_policy.clone(),
                definition: STANDARD_RING_POLICY_YAML.to_string(),
            },
        ],
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
            reporting: test_support::fixture::ReportingFixture {
                backup_node_keys: vec![NodeRef::Backup(backup_node.clone())],
                kick_threshold: 3,
                ..Default::default()
            },
            upgrade: None,
        }],
        // Seed node3 at kick_threshold - 1 so a single accepted report kicks
        // it. `window_started_offset: 0` anchors the window at provisioning
        // time, same reasoning as the pre-fixture test's own `window_started_at`.
        node_demerits: vec![NodeDemeritFixture {
            ring: ring.clone(),
            node: NodeRef::Running(2),
            points: 2,
            window_started_offset: Duration::ZERO,
        }],
        ..Default::default()
    };

    let environment = TestEnvironmentImpl::provision(fixture).await;
    let ring_id = environment.fixture().rings[&ring].id.clone();
    let members = environment.fixture().rings[&ring].members.clone();
    let node3_key = members[2].clone();
    let endpoint = environment.nodes()[0].grpc_endpoint.clone();
    let policy_id = environment.fixture().policies[&policy].id.clone();

    // Sanity check: the genesis-seeded demerits for node3 are visible on-chain.
    let seeded_demerits = environment.read_node_demerits(&ring_id, &node3_key).await;
    assert_eq!(
        seeded_demerits, 2,
        "genesis should seed node3 with kick_threshold - 1 demerits"
    );

    println!("Starting DKG for ring {}...", ring_id.0);
    let (keys, _local_state) = pre_scenario::run_dkg(&environment, &ring_id).await;
    println!(
        "DKG finalized. Ring PK: {}...",
        &keys.main[..40.min(keys.main.len())]
    );

    // Set up ACP policy and a secret so PRE has something to decrypt.
    let resource = "document";
    let permission = "read";
    let did_pk_string = "backup-kick-test-did".to_string();

    let prepared = cli_tool::prepare_secret(
        b"backup-kick-test-secret",
        &keys.main,
        None,
        policy_id.0.clone(),
        resource.to_string(),
        permission.to_string(),
        None,
        None,
        None,
        None,
    )
    .expect("prepare_secret");

    let store_result = store_secret_with_retry(
        endpoint.clone(),
        &prepared,
        ring_id.0.clone(),
        Some(did_pk_string.clone()),
    )
    .await;
    let object_id = store_result.object_id.clone();

    let reader_did = cli_tool::reader_did_from_seed(&did_pk_string);
    environment
        .register_object(&policy_id, resource, &object_id)
        .await;
    environment
        .grant(&policy_id, resource, &object_id, "reader", &reader_did)
        .await;

    // Stop node3 to trigger an offline observation during PRE.
    println!("Stopping node3 to simulate offline node...");
    environment.stop_node(2).await;

    // PRE succeeds with 2/3 shares (threshold=2) and fires an offline report for node3.
    println!("Triggering PRE (expects success with node3 offline)...");
    let _plaintext = pre_with_retry(
        endpoint.clone(),
        environment.chain_id(),
        keys.main.clone(),
        object_id.clone(),
        did_pk_string.clone(),
    )
    .await;
    println!("PRE succeeded (2/3 shares collected).");

    // The kick happens in the same tx as the threshold-crossing report; poll
    // briefly for the auto-reshare announcement to land in queryable state.
    println!("Waiting for auto-reshare announcement on the ring...");
    let deadline = Instant::now() + Duration::from_secs(30);
    let ring_view = loop {
        let view = environment
            .read_ring(&ring_id)
            .await
            .expect("ring should exist");
        if !view.new_peer_node_keys.is_empty() {
            break view;
        }
        assert!(
            Instant::now() < deadline,
            "ring never announced new_peer_node_keys after the kick-threshold report"
        );
        sleep(Duration::from_secs(1)).await;
    };

    // The chain stores the pending committee in canonical (sorted) order.
    let mut expected_committee = vec![
        members[0].clone(),
        members[1].clone(),
        NODE_KEY_BACKUP.to_string(),
    ];
    expected_committee.sort();
    assert_eq!(
        ring_view.new_peer_node_keys, expected_committee,
        "pending committee should swap node3 out for the backup node"
    );
    assert!(
        !ring_view.new_peer_node_keys.contains(&node3_key),
        "kicked node3 must not be in the pending committee"
    );
    assert!(
        ring_view.peer_node_keys.contains(&node3_key),
        "active committee is unchanged until the reshare finalizes"
    );
    assert!(
        ring_view.new_threshold.is_none(),
        "auto-reshare must not change the threshold"
    );

    println!("Checking node3 demerit points...");
    let demerits = environment.read_node_demerits(&ring_id, &node3_key).await;
    assert!(
        demerits >= 3,
        "node3 should have at least kick_threshold demerits after the accepted offline report, got {demerits}"
    );
    println!("node3 demerit points: {demerits}");

    #[cfg(feature = "integration-test-cosmos")]
    {
        let client = common::blockchain::VeraClient::new(environment.chain_config())
            .await
            .expect("unsigned chain client for raw ring read");
        let ring = client
            .orbis_read_ring(&ring_id.0)
            .await
            .expect("read ring")
            .expect("ring should exist");
        let reporting = ring.reporting.expect("ring reporting config");
        assert!(
            !reporting
                .backup_node_keys
                .contains(&NODE_KEY_BACKUP.to_string()),
            "promoted backup key should be consumed from backup_node_keys"
        );
    }
    #[cfg(feature = "integration-test-native")]
    unimplemented!(
        "native: backup_node_keys consumption check not ported (raw Ring read is Cosmos-only)"
    );
}
