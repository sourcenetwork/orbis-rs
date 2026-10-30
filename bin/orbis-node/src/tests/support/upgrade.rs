//! Shared integration test: protocol version upgrade enforcement.
//!
//! Genesis-seeds a ring at current_version=0 with a scheduled upgrade to
//! version 1 (activation_time = provisioning-start + ACTIVATION_LEAD_SECS).
//! Verifies:
//!   Phase 1 — before activation: v0 operations are NOT version-gated (gate doesn't fire early)
//!   Phase 2 — after activation:  v0 operations ARE version-gated (all three refuse the ring)
//!
//! Tendermint/Cosmos genesis-seeds this directly — the correct,
//! authoritative behavior this test asserts. Commonware/native has no
//! genesis-injection facility at all yet (deferred cross-repo work — see
//! the harness-unification plan), and even its live equivalent
//! (`RingUpdate::ScheduleUpgrade`) wouldn't give parity: it requires the
//! ring to already be `RingState::Active` and enforces a 600-second
//! minimum lead time, a fundamentally different timing model from "already
//! mid-upgrade-schedule before any node boots." Ignored there for now
//! rather than reshaping the test around native's constraints; see the
//! `#[cfg_attr]` below.
//!
//! Run with:
//!   cargo test --features integration-test -- test_v0_services_rejected_after_ring_upgrade --nocapture

use std::time::{SystemTime, UNIX_EPOCH};

use test_support::fixture::{
    DocumentFixture, FixtureId, KeyDerivationFixture, NetworkTestDriver, NodeFixture, NodeRef,
    NodeRole, RingFixture, ScenarioFixture, TestEnvironment, UpgradeFixture,
};
use tokio::time::{sleep, Duration};

use super::TestEnvironmentImpl;

// Lead between genesis write and activation. This covers Docker image build/startup under
// full-suite contention; Phase 1 only requires the node's gRPC services, not funding readiness.
const ACTIVATION_LEAD_SECS: u64 = 180;
const MIN_PRE_ACTIVATION_SLACK_SECS: u64 = 10;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs()
}

fn assert_before_activation(operation: &str, activation_time: u64) -> u64 {
    let now = unix_now();
    let remaining_slack = activation_time.saturating_sub(now);
    assert!(
        remaining_slack >= MIN_PRE_ACTIVATION_SLACK_SECS,
        "{operation}: pre-activation check missed its window \
         (current_time={now}, activation_time={activation_time}, \
         remaining_slack={remaining_slack}, required_slack={MIN_PRE_ACTIVATION_SLACK_SECS})"
    );
    remaining_slack
}

fn assert_pre_activation_response<T>(operation: &str, result: &anyhow::Result<T>) {
    if let Err(error) = result {
        let message = error.to_string();
        assert!(
            !message.contains("Operation is not implemented") && !message.contains("Unimplemented"),
            "{operation} did not reach the full v0 service: {error}"
        );
        assert!(
            !message.contains("effective_version=1"),
            "{operation} version-gated too early (before activation_time): {error}"
        );
    }
}

fn assert_server_version_rejection(operation: &str, error: &anyhow::Error) {
    let status = error
        .downcast_ref::<tonic::Status>()
        .unwrap_or_else(|| panic!("{operation}: expected tonic::Status source, got: {error:#}"));
    assert_eq!(
        status.code(),
        tonic::Code::FailedPrecondition,
        "{operation}: unexpected server status: {status}"
    );

    let message = status.message();
    for expected in [
        "effective_version=1",
        "installed_versions=[0]",
        "route_version=0",
    ] {
        assert!(
            message.contains(expected),
            "{operation}: expected {expected:?} in server error, got: {status}"
        );
    }
}

#[tokio::test]
#[serial_test::serial]
#[cfg_attr(
    feature = "integration-test-native",
    ignore = "commonware/native has no genesis-injection facility yet \
              (deferred cross-repo work), and its live ScheduleUpgrade \
              equivalent requires an already-Active ring plus a \
              600s-minimum lead — a different timing model from this \
              test's already-mid-upgrade-before-boot design; fix when \
              native grows one of these capabilities"
)]
async fn test_v0_services_rejected_after_ring_upgrade() {
    let ring = FixtureId::new("ring");
    let document = FixtureId::new("document");
    let derivation = FixtureId::new("derivation");
    // Dangling placeholder, deliberately not backed by a `PolicyFixture` —
    // same reasoning as the raw test's own non-existent "upgrade-test-policy"
    // string: genesis-seeded documents/key-derivations here are never
    // actually decrypted or ACP-checked, only routed, so nothing ever
    // validates this value against a real policy.
    let policy = FixtureId::new("policy");

    // Captured immediately before `provision`, which captures its own
    // "now" a few instructions later when building genesis — close enough
    // (milliseconds) next to a 180s lead/5s buffer that both sides agree on
    // the same `activation_time` for all practical purposes. See
    // `CosmosTestEnvironment::provision`'s matching capture.
    let provision_started_at = unix_now();
    let activation_time = provision_started_at + ACTIVATION_LEAD_SECS;
    println!("activation_time={activation_time} (in {ACTIVATION_LEAD_SECS}s from now)");

    let fixture = ScenarioFixture {
        // The Compose topology only supports 3 or 4 nodes
        // (`CosmosNetwork::with_node_count`) — the ring itself still only
        // ever references one of them.
        nodes: (0..3)
            .map(|_| NodeFixture {
                id: FixtureId::new("node"),
                role: NodeRole::Running,
            })
            .collect(),
        rings: vec![RingFixture {
            id: ring.clone(),
            members: vec![NodeRef::Running(0)],
            threshold: 1,
            pss_interval: Duration::from_secs(86_400),
            requires_pet: false,
            policy: FixtureId::new("ring-policy"),
            reporting: Default::default(),
            upgrade: Some(UpgradeFixture {
                current_version: 0,
                next_version: 1,
                activation_offset: Duration::from_secs(ACTIVATION_LEAD_SECS),
            }),
        }],
        documents: vec![DocumentFixture {
            id: document.clone(),
            ring: ring.clone(),
            policy: policy.clone(),
            resource: "document".to_string(),
            permission: "read".to_string(),
            payload: b"upgrade-test-ciphertext".to_vec(),
        }],
        key_derivations: vec![KeyDerivationFixture {
            id: derivation.clone(),
            ring: ring.clone(),
            policy: policy.clone(),
            derivation: "upgrade-test-derivation".to_string(),
            resource: "document".to_string(),
            permission: "read".to_string(),
        }],
        ..Default::default()
    };

    let environment = TestEnvironmentImpl::provision(fixture).await;
    let ring_id = environment.fixture().rings[&ring].id.0.clone();
    let document_id = document.0.clone();
    let derivation_id = derivation.0.clone();
    let endpoint = environment.nodes()[0].grpc_endpoint.clone();
    cli_tool::query_node_info(endpoint.clone())
        .await
        .expect("node 1 gRPC services must be available before Phase 1");

    // ─── Phase 1: pre-activation — version gate must NOT fire ────────────────
    let phase_1_slack = assert_before_activation("Phase 1", activation_time);
    println!(
        "Phase 1: confirming v0 gate does not fire before activation ({} s remaining)...",
        phase_1_slack
    );

    let _ = assert_before_activation("DKG", activation_time);
    let dkg_result = cli_tool::do_dkg(endpoint.clone(), ring_id.clone()).await;
    assert_pre_activation_response("DKG", &dkg_result);
    println!(
        "DKG before activation: {}",
        dkg_result
            .as_ref()
            .map(|_| "ok".to_string())
            .unwrap_or_else(|e| format!("non-version err: {e}"))
    );

    let _ = assert_before_activation("Sign", activation_time);
    let sign_result = cli_tool::do_sign(
        endpoint.clone(),
        b"upgrade-pre-activation".to_vec(),
        derivation_id.clone(),
        None,
        None,
        None,
    )
    .await;
    assert_pre_activation_response("Sign", &sign_result);
    println!(
        "Sign before activation: {}",
        sign_result
            .as_ref()
            .map(|_| "ok".to_string())
            .unwrap_or_else(|e| format!("non-version err: {e}"))
    );

    let _ = assert_before_activation("PRE", activation_time);
    let pre_result = cli_tool::do_pre(
        endpoint.clone(),
        environment.chain_id(),
        String::new(),
        document_id.clone(),
        None,
        None,
        None,
        None,
        None,
    )
    .await;
    assert_pre_activation_response("PRE", &pre_result);
    println!(
        "PRE before activation: {}",
        pre_result
            .as_ref()
            .map(|_| "ok".to_string())
            .unwrap_or_else(|e| format!("non-version err: {e}"))
    );

    // ─── Phase 2: wait for activation_time to pass ───────────────────────────
    let now = unix_now();
    let target = activation_time + 5; // small buffer so block time is clearly past
    if now < target {
        let wait_secs = target - now;
        println!(
            "Phase 2: waiting {wait_secs}s for activation_time to pass \
             (activation_time={activation_time})..."
        );
        sleep(Duration::from_secs(wait_secs)).await;
    }
    assert!(
        unix_now() >= activation_time,
        "post-activation checks started before activation_time"
    );
    println!("Phase 2 complete: wall clock is now past activation_time.");

    // ─── Phase 3: post-activation — all v0 operations must be refused ─────────
    println!("Phase 3: confirming all v0 operations are refused after upgrade...");

    let dkg_err = cli_tool::do_dkg(endpoint.clone(), ring_id.clone())
        .await
        .expect_err("v0 DKG must refuse a v1 ring after activation");
    assert_server_version_rejection("DKG", &dkg_err);
    println!("DKG correctly rejected: {dkg_err}");

    let sign_err = cli_tool::do_sign(
        endpoint.clone(),
        b"upgrade-post-activation".to_vec(),
        derivation_id.clone(),
        None,
        None,
        None,
    )
    .await
    .expect_err("v0 Sign must refuse a derivation whose ring activated to v1");
    assert_server_version_rejection("Sign", &sign_err);
    println!("Sign correctly rejected: {sign_err}");

    let pre_err = cli_tool::do_pre(
        endpoint.clone(),
        environment.chain_id(),
        String::new(),
        document_id.clone(),
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .expect_err("v0 PRE must refuse a document whose ring activated to v1");
    assert_server_version_rejection("PRE", &pre_err);
    println!("PRE correctly rejected: {pre_err}");

    println!("Upgrade integration test passed: v0 flipped to v1 at activation_time.");
}
