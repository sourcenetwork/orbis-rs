//! A running node that was not in the original committee replaces one member.
//!
//! The spare is provisioned with the fixture. Each adapter makes that node
//! eligible before the scenario announces the new committee. The departed
//! process is left running. Departed-node store cleanup and PET-specific
//! replacement are deferred coverage; see `docs/e2e-deferred-coverage.md`.

use super::{pre_scenario, reshare_scenario, sign_scenario, standard_dkg_pre, TestEnvironmentImpl};
use std::time::Duration;
use test_support::fixture::{
    BulletinTestDriver, FixtureId, NetworkTestDriver, NodeFixture, NodeRef, NodeRole,
    PolicyFixture, RingFixture, ScenarioFixture, TestEnvironment,
};

const THRESHOLD: u32 = 2;
const SPARE: usize = 3;
const DEPARTED: usize = 2;

#[tokio::test]
#[serial_test::serial]
async fn test_spare_member_replaces_original() {
    let ring = FixtureId::new("ring");
    let ring_policy = FixtureId::new("ring-policy");
    let document_policy = FixtureId::new("document-policy");
    let fixture = ScenarioFixture {
        nodes: (0..4)
            .map(|_| NodeFixture {
                id: FixtureId::new("node"),
                role: NodeRole::Running,
            })
            .collect(),
        policies: vec![
            PolicyFixture {
                id: document_policy.clone(),
                definition: standard_dkg_pre::POLICY_YAML.to_string(),
            },
            PolicyFixture {
                id: ring_policy.clone(),
                definition: standard_dkg_pre::POLICY_YAML.to_string(),
            },
        ],
        rings: vec![RingFixture {
            id: ring.clone(),
            members: vec![
                NodeRef::Running(0),
                NodeRef::Running(1),
                NodeRef::Running(DEPARTED),
            ],
            threshold: THRESHOLD,
            // Long enough that a share refresh cannot rotate the polynomial
            // while the reshare is the change under test.
            pss_interval: Duration::from_secs(86_400),
            requires_pet: false,
            policy: ring_policy,
            reporting: Default::default(),
            upgrade: None,
        }],
        ..Default::default()
    };

    let environment = TestEnvironmentImpl::provision(fixture).await;
    let ring_id = environment.fixture().rings[&ring].id.clone();
    let policy_id = environment.fixture().policies[&document_policy].id.clone();
    environment
        .authorize_reshare_candidate(&ring_id, SPARE)
        .await;

    let (keys, _local_state, pre) = pre_scenario::run(&environment, &ring_id, &policy_id).await;
    let sign = sign_scenario::run(&environment, &ring_id, &keys, &policy_id).await;

    let nodes = environment.nodes();
    let spare_key = nodes[SPARE].node_key.clone();
    let departed_key = nodes[DEPARTED].node_key.clone();
    let continuing = [nodes[0].clone(), nodes[1].clone()];
    let baselines =
        pre_scenario::wait_for_polynomials(&continuing, &keys.main, None, Duration::from_secs(60))
            .await;

    let mut target = vec![
        continuing[0].node_key.clone(),
        continuing[1].node_key.clone(),
        spare_key.clone(),
    ];
    target.sort();
    assert!(!target.contains(&departed_key));

    let before = environment
        .read_ring(&ring_id)
        .await
        .expect("ring must exist before replacement");
    environment
        .update_membership(&ring_id, target.clone(), THRESHOLD)
        .await;
    let after =
        reshare_scenario::wait_for_reshare_completion(&environment, &ring_id, &target, THRESHOLD)
            .await;

    assert_eq!(after.ring_pk, before.ring_pk);
    assert_eq!(after.threshold, THRESHOLD);
    let mut settled = after.peer_node_keys.clone();
    settled.sort();
    assert_eq!(settled, target);
    assert!(!settled.contains(&departed_key));

    let mut committee = continuing.to_vec();
    committee.push(nodes[SPARE].clone());
    let mut previous = baselines;
    // The spare had no commitment for this ring. Any real polynomial differs
    // from the empty baseline, which is the same "changed" check the
    // continuing members use against their pre-reshare commitments.
    previous.push(String::new());
    let reshared = pre_scenario::wait_for_polynomials(
        &committee,
        &keys.main,
        Some(&previous),
        Duration::from_secs(120),
    )
    .await;
    for state in &reshared {
        pre_scenario::assert_polynomial(state, &keys.main);
    }

    pre_scenario::verify_existing(&environment, &keys, &pre).await;
    sign_scenario::verify_existing(&environment, &keys, &sign).await;
}
