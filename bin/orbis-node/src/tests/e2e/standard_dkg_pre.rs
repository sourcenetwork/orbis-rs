//! Backend-neutral DKG, PRE, signing, refresh, and reshare contract.
//!
//! The fixture and assertions in this file are the product behavior. Backend
//! adapters may materialize the fixture differently, but must expose the same
//! `TestEnvironment` contract to this scenario.

use super::{pre_scenario, refresh_scenario, reshare_scenario, sign_scenario, TestEnvironmentImpl};
use std::time::Duration;
use test_support::fixture::{
    FixtureId, NodeFixture, NodeRef, NodeRole, PolicyFixture, RingFixture, ScenarioFixture,
    TestEnvironment,
};

pub(super) const POLICY_YAML: &str = r#"
name: shared-dkg-pre-policy
resources:
  - name: ring_policy
    relations:
      - name: creator
    permissions:
      - name: create_ring
        expr: creator
  - name: ring
    relations:
      - name: operator
    permissions:
      - name: update_ring
        expr: operator
  - name: key
    relations:
      - name: signer
    permissions:
      - name: sign
        expr: signer
  - name: document
    relations:
      - name: reader
    permissions:
      - name: read
        expr: reader
"#;

#[tokio::test]
#[serial_test::serial]
async fn test_cli_calls_dkg_and_pre_endpoint() {
    let document_policy = FixtureId::new("document-policy");
    let ring_policy = FixtureId::new("ring-policy");
    let ring = FixtureId::new("ring");
    let fixture = ScenarioFixture {
        requires_unsafe_testing: true,
        nodes: (0..3)
            .map(|_| NodeFixture {
                id: FixtureId::new("node"),
                role: NodeRole::Running,
            })
            .collect(),
        policies: vec![
            PolicyFixture {
                id: document_policy.clone(),
                definition: POLICY_YAML.to_string(),
            },
            PolicyFixture {
                id: ring_policy.clone(),
                definition: POLICY_YAML.to_string(),
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
            // Cosmos materializes this in genesis and lets it expire. Native
            // clamps the live chain value to its production minimum and uses
            // its diagnostic driver to make the refresh due. That difference
            // belongs to the adapters, not this scenario.
            pss_interval: Duration::from_secs(5),
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

    let (keys, local_state, outcome) = pre_scenario::run(&environment, &ring_id, &policy_id).await;
    let sign = sign_scenario::run(&environment, &ring_id, &keys, &policy_id).await;
    refresh_scenario::run(&environment, &ring_id, &keys, &local_state, &outcome, &sign).await;
    reshare_scenario::run(&environment, &ring_id, &keys, &outcome, &sign).await;

    assert!(
        !outcome.object_id.is_empty(),
        "the shared PRE scenario must store a document"
    );
    assert!(
        !sign.derivation_id.is_empty(),
        "the shared Sign scenario must store a key derivation"
    );
}
