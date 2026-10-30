//! Shared helpers for the `report_*.rs` family of on-chain-report tests
//! (originally `reporting.rs`, fully migrated and deleted — harness-
//! unification migration, PR 5f). Backend-neutral retry wrappers around the
//! plain `cli_tool` v0 calls, plus `wait_for_demerits`, the cross-backend
//! pass/fail signal for a report actually landing — replacing Cosmos's
//! `ReportEventSubscription` (a Tendermint-WebSocket subscription with no
//! native equivalent).

use super::TestEnvironmentImpl;
use test_support::admin::RingId;
use test_support::fixture::BulletinTestDriver;
use tokio::time::{sleep, Duration, Instant};

/// Shared policy shape for every `reporting.rs` test that needs a real,
/// live-provisioned ring: `ring_policy`/`creator`/`create_ring` and
/// `ring`/`operator`/`update_ring` are unused by Cosmos (its ring
/// materializer always substitutes its own content-addressed governance
/// policy regardless of what `RingFixture.policy` names) but required by
/// native — ring creation needs the submitter to hold `creator` on a
/// `ring_policy` object (`NativeTestEnvironment::provision` registers/
/// grants that automatically per distinct policy, but only once the
/// policy itself defines the resource), and `RingCommand::Create` itself
/// *always* auto-registers a new `ring`-resource object (the created
/// ring's own id) under that same policy as part of creation (confirmed
/// by reading `vera-modules::vera::rings::ring_command`'s
/// `RingCommand::Create` handler) — which fails outright if `ring` isn't
/// a resource the policy defines at all. The `ring` resource's `operator`/
/// `update_ring` shape mirrors `policy_generations::definition`'s own,
/// already-proven-working one; nothing in these tests ever exercises it.
/// `document`/`reader`/`read` is what each test's own document/
/// key-derivation ACP checks actually use.
pub(super) const STANDARD_RING_POLICY_YAML: &str = r#"
name: reporting test ring policy
resources:
- name: ring_policy
  relations:
  - name: creator
    types:
    - actor
  permissions:
  - name: create_ring
    expr: creator
- name: ring
  relations:
  - name: operator
    types:
    - actor
  permissions:
  - name: update_ring
    expr: operator
- name: document
  permissions:
  - name: read
    expr: reader
  relations:
  - name: reader
    types:
    - actor
"#;

pub(super) async fn store_secret_with_retry(
    endpoint: String,
    prepared: &cli_tool::PreparedSecret,
    ring_id: String,
    reader_did_pk: Option<String>,
) -> cli_tool::StoreSecretResult {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut attempt = 1usize;
    loop {
        match cli_tool::store_prepared_secret(
            endpoint.clone(),
            prepared,
            ring_id.clone(),
            reader_did_pk.clone(),
            true,
            None,
        )
        .await
        {
            Ok(result) => return result,
            Err(e) => {
                assert!(
                    Instant::now() < deadline,
                    "StoreSecret failed after {attempt} attempts: {e}"
                );
                println!("StoreSecret attempt {attempt} failed, retrying: {e}");
                attempt += 1;
                sleep(Duration::from_secs(3)).await;
            }
        }
    }
}

pub(super) async fn pre_with_retry(
    endpoint: String,
    chain_id: String,
    ring_pk: String,
    object_id: String,
    reader_did_pk: String,
) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut attempt = 1usize;
    loop {
        match cli_tool::do_pre(
            endpoint.clone(),
            chain_id.clone(),
            ring_pk.clone(),
            object_id.clone(),
            Some(reader_did_pk.clone()),
            None,
            None,
            None,
            None,
        )
        .await
        {
            Ok(result) => return result,
            Err(e) => {
                assert!(
                    Instant::now() < deadline,
                    "PRE failed after {attempt} attempts: {e}"
                );
                println!("PRE attempt {attempt} failed, retrying: {e}");
                attempt += 1;
                sleep(Duration::from_secs(3)).await;
            }
        }
    }
}

pub(super) async fn sign_with_retry(
    endpoint: String,
    message: Vec<u8>,
    derivation_id: String,
    did_pk: String,
) -> cli_tool::SignResult {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut attempt = 1usize;
    loop {
        match cli_tool::do_sign(
            endpoint.clone(),
            message.clone(),
            derivation_id.clone(),
            Some(did_pk.clone()),
            None,
            None,
        )
        .await
        {
            Ok(result) => return result,
            Err(e) => {
                assert!(
                    Instant::now() < deadline,
                    "Sign failed after {attempt} attempts: {e}"
                );
                println!("Sign attempt {attempt} failed, retrying: {e}");
                attempt += 1;
                sleep(Duration::from_secs(3)).await;
            }
        }
    }
}

/// Poll `node_key`'s demerit points on `ring` until they reach `expected`,
/// confirming an accepted report actually landed on chain. Replaces
/// Cosmos's `ReportEventSubscription`-based wait — coarser (no per-report
/// metadata), but the same underlying claim (accepted reports accumulate
/// demerits for the accused node) and portable to both backends.
pub(super) async fn wait_for_demerits(
    environment: &TestEnvironmentImpl,
    ring: &RingId,
    node_key: &str,
    expected: u64,
    timeout: Duration,
) -> u64 {
    let deadline = Instant::now() + timeout;
    loop {
        let demerits = environment.read_node_demerits(ring, node_key).await;
        if demerits >= expected {
            return demerits;
        }
        assert!(
            Instant::now() < deadline,
            "node {node_key} demerits did not reach {expected} within {}s (last observed: {demerits})",
            timeout.as_secs(),
        );
        sleep(Duration::from_millis(500)).await;
    }
}

/// Non-panicking variant of [`wait_for_demerits`] — `None` on timeout
/// instead of asserting, for scenarios where the triggering operation
/// itself is probabilistic (e.g. a corrupted node's response racing the
/// threshold drain window) and the caller needs to retry the whole
/// operation a bounded number of times, same as the raw tests' own
/// `ReportEventSubscription`-based retry loops did. Only
/// `report_invalid_crypto_response.rs` needs this today, and that file is
/// `#[cfg(not(feature = "jubjub"))]` (FROST's signing set deterministically
/// excludes the corrupted node) — `#[allow(dead_code)]` rather than
/// gating this generic helper itself on the one current consumer's cfg.
#[allow(dead_code)]
pub(super) async fn try_wait_for_demerits(
    environment: &TestEnvironmentImpl,
    ring: &RingId,
    node_key: &str,
    expected: u64,
    timeout: Duration,
) -> Option<u64> {
    let deadline = Instant::now() + timeout;
    loop {
        let demerits = environment.read_node_demerits(ring, node_key).await;
        if demerits >= expected {
            return Some(demerits);
        }
        if Instant::now() >= deadline {
            return None;
        }
        sleep(Duration::from_millis(500)).await;
    }
}
