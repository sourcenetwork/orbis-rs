//! Shared integration test: protocol version upgrade enforcement.
//!
//! Runs a real DKG to finalize the ring, then schedules a v0→v1 upgrade via
//! `BulletinTestDriver::schedule_ring_upgrade` (activation_time = now +
//! ACTIVATION_LEAD_SECS). Verifies:
//!   Phase 1 — before activation: v0 operations are NOT version-gated (gate doesn't fire early)
//!   Phase 2 — after activation:  v0 operations ARE version-gated (all three refuse the ring)
//!
//! Fully backend-neutral — no `#[cfg]` split in this file. Cosmos's
//! `ScheduleRingUpgradeByAcp` and native's `RingUpdate::ScheduleUpgrade`
//! turned out to have identical constraints (ring must already be
//! finalized, both enforce the same 600-second minimum lead) — see
//! `schedule_ring_upgrade`'s doc comment. Unlike the original Cosmos-only
//! version of this test, the upgrade is scheduled live (after DKG) rather
//! than genesis-seeded before boot, so `ACTIVATION_LEAD_SECS` must clear
//! both backends' 600s floor — a real (if minor) cost of staying
//! backend-neutral, accepted in exchange for not needing a native
//! genesis-injection facility at all.
//!
//! Run with:
//!   cargo test --features integration-test -- test_v0_services_rejected_after_ring_upgrade --nocapture

use std::time::{SystemTime, UNIX_EPOCH};

use super::{pre_scenario, TestEnvironmentImpl};
use crypto::r#trait::{EncryptionProof, Secret};
use test_support::fixture::{
    AuthorizationTestDriver, BulletinTestDriver, FixtureId, NetworkTestDriver, NodeFixture,
    NodeRef, NodeRole, RingFixture, ScenarioFixture, TestEnvironment,
};
use tokio::time::{sleep, Duration};

// Both backends' live schedule-upgrade path enforces a 600s minimum lead
// between "now" (as the chain sees it) and `activation_time`; the extra 20s
// covers tx-inclusion lag between capturing `now` here and the chain
// actually validating the schedule request.
const ACTIVATION_LEAD_SECS: u64 = 620;
const MIN_PRE_ACTIVATION_SLACK_SECS: u64 = 10;

const UPGRADE_TEST_POLICY_YAML: &str = r#"
name: upgrade-test-policy
resources:
  - name: document
    relations:
      - name: creator
        types:
          - actor
      - name: reader
        types:
          - actor
    permissions:
      - name: read
        expr: reader
      - name: write
        expr: creator
"#;

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
async fn test_v0_services_rejected_after_ring_upgrade() {
    let ring = FixtureId::new("ring");
    let fixture = ScenarioFixture {
        // The Compose topology only supports 3 or 4 nodes
        // (`CosmosNetwork::with_node_count`) — the ring itself only ever
        // references two of them (DKG requires at least two participants).
        nodes: (0..3)
            .map(|_| NodeFixture {
                id: FixtureId::new("node"),
                role: NodeRole::Running,
            })
            .collect(),
        rings: vec![RingFixture {
            id: ring.clone(),
            members: vec![NodeRef::Running(0), NodeRef::Running(1)],
            threshold: 2,
            pss_interval: Duration::from_secs(86_400),
            requires_pet: false,
            policy: FixtureId::new("ring-policy"),
            reporting: Default::default(),
            upgrade: None,
        }],
        ..Default::default()
    };

    let environment = TestEnvironmentImpl::provision(fixture).await;
    let ring_id = environment.fixture().rings[&ring].id.clone();
    let endpoint = environment.nodes()[0].grpc_endpoint.clone();
    cli_tool::query_node_info(endpoint.clone())
        .await
        .expect("node 1 gRPC services must be available before DKG");

    println!("Starting DKG for ring {}...", ring_id.0);
    let (keys, _local_state) = pre_scenario::run_dkg(&environment, &ring_id).await;
    println!(
        "DKG finalized. Ring PK: {}...",
        &keys.main[..40.min(keys.main.len())]
    );

    // A real but otherwise irrelevant policy: these records are only ever
    // routed to the right ring by the version gate, never actually
    // decrypted or ACP-checked, so nothing here ever validates this policy
    // beyond its existence. Unlike the original genesis-placeholder version
    // of this test, native's live `register_document`/`register_key_derivation`
    // validate `policy_id`'s *format* (a real content-addressed id) even
    // though nothing ever checks it against this policy's actual content,
    // so a dangling free-form string id doesn't work here as it did there.
    let policy_id = environment.create_policy(UPGRADE_TEST_POLICY_YAML).await;
    let document_str = String::from_utf8(
        serde_json::to_vec(&Secret {
            enc_cmt: vec![5u8; 32],
            encrypted_data: b"upgrade-test-ciphertext".to_vec(),
            nonce: vec![6u8; 12],
        })
        .expect("serialize upgrade-test secret"),
    )
    .expect("secret JSON is valid utf8");
    let proof_str: String = EncryptionProof {
        challenge: vec![1, 2, 3],
        response: vec![4, 5, 6],
    }
    .try_into()
    .expect("serialize upgrade-test proof");
    let document_id = environment
        .register_document(
            &ring_id,
            &document_str,
            &proof_str,
            &policy_id,
            "document",
            "read",
        )
        .await;
    let derivation_id = environment
        .register_key_derivation(
            &ring_id,
            "upgrade-test-derivation",
            &policy_id,
            "document",
            "read",
        )
        .await;

    let provision_started_at = unix_now();
    let activation_time = provision_started_at + ACTIVATION_LEAD_SECS;
    println!("activation_time={activation_time} (in {ACTIVATION_LEAD_SECS}s from now)");
    environment
        .schedule_ring_upgrade(&ring_id, 1, activation_time)
        .await;

    // ─── Phase 1: pre-activation — version gate must NOT fire ────────────────
    let phase_1_slack = assert_before_activation("Phase 1", activation_time);
    println!(
        "Phase 1: confirming v0 gate does not fire before activation ({} s remaining)...",
        phase_1_slack
    );

    let _ = assert_before_activation("DKG", activation_time);
    let dkg_result = cli_tool::do_dkg(endpoint.clone(), ring_id.0.clone()).await;
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

    let dkg_err = cli_tool::do_dkg(endpoint.clone(), ring_id.0.clone())
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
