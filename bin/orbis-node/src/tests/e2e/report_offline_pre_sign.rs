//! Shared integration test: a node going offline mid-PRE/Sign fires an
//! on-chain `node_offline` report and accumulates demerits against it.
//!
//! The node-offline detection-and-reporting logic itself
//! (`crate::reporting::v0::registry::node_offline`) is backend-neutral
//! production code — it operates on the generic `bulletin` trait, not
//! either chain directly — so this is written as one real, non-ignored
//! test on both backends. Verification is via `report_scenario::
//! wait_for_demerits` (polling the chain's own demerit count) rather than
//! Cosmos's `ReportEventSubscription` (a Tendermint-WebSocket subscription
//! with no native equivalent): a coarser signal than the original's
//! per-report event metadata, but the same underlying claim — accepted
//! reports accumulate demerits for the accused node — proven on both
//! backends instead of asserted only on one.

use super::report_scenario::{
    pre_with_retry, sign_with_retry, store_secret_with_retry, STANDARD_RING_POLICY_YAML,
};
use super::{pre_scenario, TestEnvironmentImpl};
use test_support::fixture::{
    AuthorizationTestDriver, BulletinTestDriver, FixtureId, NetworkTestDriver, NodeFixture,
    NodeRef, NodeRole, PolicyFixture, RingFixture, ScenarioFixture, TestEnvironment,
};
use tokio::time::Duration;

#[tokio::test]
#[serial_test::serial]
async fn test_pre_and_sign_offline_triggers_on_chain_report() {
    println!("Starting reporting integration test...");

    let ring = FixtureId::new("ring");
    let policy = FixtureId::new("policy");
    // A *separate* FixtureId from `policy`, same policy content, for the
    // ring's own governance slot. Cosmos's ring materializer always
    // overwrites whatever `RingFixture.policy` resolves to with its own
    // content-addressed governance policy (confirmed: reusing `policy` for
    // both caused the *document* ACP lookup to resolve to that governance
    // policy too, since the overwrite is keyed by the ring's policy
    // `FixtureId`, not by whether something else already claimed it) — so
    // `ring_policy`'s own real id is always discarded there and only
    // matters to native, which has no such substitution and genuinely
    // needs a real, hex-encoded policy for ring creation.
    let ring_policy = FixtureId::new("ring-policy");
    let fixture = ScenarioFixture {
        nodes: (0..3)
            .map(|_| NodeFixture {
                id: FixtureId::new("node"),
                role: NodeRole::Running,
            })
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
            // kick_threshold=10: this test accumulates two accepted offline
            // reports against node3 and must not trigger the auto-kick reshare.
            reporting: test_support::fixture::ReportingFixture {
                kick_threshold: 10,
                ..Default::default()
            },
            upgrade: None,
        }],
        ..Default::default()
    };

    let environment = TestEnvironmentImpl::provision(fixture).await;
    let ring_id = environment.fixture().rings[&ring].id.clone();
    let members = environment.fixture().rings[&ring].members.clone();
    let node3_key = members[2].clone();
    let endpoint = environment.nodes()[0].grpc_endpoint.clone();
    let policy_id = environment.fixture().policies[&policy].id.clone();

    println!("Starting DKG for ring {}...", ring_id.0);
    let (keys, _local_state) = pre_scenario::run_dkg(&environment, &ring_id).await;
    println!(
        "DKG finalized. Ring PK: {}...",
        &keys.main[..40.min(keys.main.len())]
    );

    // A secret for PRE to decrypt, against the fixture-materialized policy.
    let resource = "document";
    let permission = "read";
    let did_pk_string = "report-test-did".to_string();

    let prepared = cli_tool::prepare_secret(
        b"report-test-secret",
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

    // `store_secret_with_retry`/`pre_with_retry`'s `reader_did_pk` arguments
    // are *seeds* — `cli_tool`'s own request builders turn them into a DID
    // internally (`did_seed`+`generate::<DidEd25519KeyPair>`), same as
    // `reader_did_from_seed` does here — so the ACP grant needs the derived
    // DID itself, not the raw seed string.
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

    println!("Waiting for node3's demerits to reflect the accepted PRE offline report...");
    let demerits_after_pre = super::report_scenario::wait_for_demerits(
        &environment,
        &ring_id,
        &node3_key,
        1,
        Duration::from_secs(120),
    )
    .await;
    println!("node3 demerit points after PRE: {demerits_after_pre}");

    // ── Sign: node3 is still offline ────────────────────────────────────────
    println!("Setting up Sign key derivation (node3 still offline)...");
    let sign_did_pk = "sign-report-test-did".to_string();
    let derivation_id = environment
        .register_key_derivation(
            &ring_id,
            "sign-report-derivation",
            &policy_id,
            resource,
            permission,
        )
        .await;
    let sign_reader_did = cli_tool::reader_did_from_seed(&sign_did_pk);
    environment
        .register_object(&policy_id, resource, &derivation_id)
        .await;
    environment
        .grant(
            &policy_id,
            resource,
            &derivation_id,
            "reader",
            &sign_reader_did,
        )
        .await;

    // Sign succeeds with 2/3 shares (node3 still offline) and fires an offline report.
    println!("Triggering Sign (expects success with node3 still offline)...");
    let sign_result = sign_with_retry(
        endpoint.clone(),
        b"sign-offline-report-test-message".to_vec(),
        derivation_id.clone(),
        sign_did_pk.clone(),
    )
    .await;
    println!("Sign succeeded: status={}", sign_result.status);

    // Both the PRE and Sign reports were accepted: node3 should have exactly 2 demerits.
    println!("Checking node3 demerit points...");
    let demerits = super::report_scenario::wait_for_demerits(
        &environment,
        &ring_id,
        &node3_key,
        2,
        Duration::from_secs(120),
    )
    .await;
    assert_eq!(
        demerits, 2,
        "node3 should have exactly 2 demerits after 2 accepted offline reports"
    );
    println!("node3 demerit points: {demerits}");
}
