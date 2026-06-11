//! Docker-based integration test: protocol version upgrade enforcement.
//!
//! Uses genesis injection to pre-seed a ring at current_version=0 with a scheduled upgrade to
//! version 1 (activation_time = test-start + ACTIVATION_LEAD_SECS). The test verifies:
//!   Phase 1 — before activation: v0 operations are NOT version-gated (gate doesn't fire early)
//!   Phase 2 — after activation:  v0 operations ARE version-gated (all three refuse the ring)
//!
//! Run with:
//!   cargo test --features integration-test -- test_v0_services_rejected_after_ring_upgrade --nocapture

use std::time::{SystemTime, UNIX_EPOCH};

use common::IntegrationTestNetwork;
use crypto::helpers::generate_keypair;
use crypto::CryptoSerialize;
use tokio::time::{sleep, Duration};

const RING_ID: &str = "upgrade-v0-ring";
const DERIVATION_ID: &str = "upgrade-v0-derivation";
const DOCUMENT_ID: &str = "upgrade-v0-document";
// Compressed secp256k1 key matching the --node-controller-key in docker-compose
const NODE_KEY: &str = "024f4e2ad99c34d60b9ba6283c9431a8418af8673212961f97a77b6377fcd05b62";
// Lead between genesis write and activation. Must exceed Docker image build time.
// Warm-cache CI builds complete in ~60s; 120s gives comfortable margin.
const ACTIVATION_LEAD_SECS: u64 = 120;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs()
}

#[tokio::test]
#[serial_test::serial]
async fn test_v0_services_rejected_after_ring_upgrade() {
    // Compute activation_time before build() so it can be baked into genesis.
    // The 120s lead absorbs Docker startup time; the dynamic wait below handles
    // any remaining gap so this test is robust on both warm and cold caches.
    let activation_time = unix_now() + ACTIVATION_LEAD_SECS;
    println!(
        "activation_time={activation_time} (in {ACTIVATION_LEAD_SECS}s from now)"
    );

    let _network = IntegrationTestNetwork::builder()
        .with_module_genesis(
            "orbis",
            serde_json::json!({
                "rings": [{
                    "id": RING_ID,
                    "ring_pk": "",             // unfinalized — DKG can proceed
                    "peer_node_keys": [NODE_KEY],
                    "threshold": 1,
                    "policy_id": "upgrade-test-policy",
                    "upgrade_info": {
                        "current_version": 0,
                        "next_version": 1,
                        "activation_time": activation_time
                    }
                }],
                "key_derivations": [{
                    "id": DERIVATION_ID,
                    "ring_id": RING_ID,
                    "derivation": "upgrade-test-derivation",
                    "policy_id": "upgrade-test-policy",
                    "resource": "document",
                    "permission": "read"
                }],
                "documents": [{
                    "id": DOCUMENT_ID,
                    "ring_id": RING_ID,
                    "document": "upgrade-test-ciphertext",
                    "proof": "upgrade-test-proof",
                    "policy_id": "upgrade-test-policy",
                    "resource": "document",
                    "permission": "read"
                }]
            }),
        )
        .build();

    let endpoint = IntegrationTestNetwork::NODE1_GRPC.to_string();

    // do_pre validates reader_pk before the version check — need a real keypair
    let (reader_sk, reader_pk) = generate_keypair().expect("generate reader keypair");
    let reader_pk_hex = hex::encode(CryptoSerialize::to_bytes(&reader_pk).expect("serialize pk"));
    let reader_sk_hex = hex::encode(CryptoSerialize::to_bytes(&reader_sk).expect("serialize sk"));

    // ─── Phase 1: pre-activation — version gate must NOT fire ────────────────
    // If Docker startup consumed all of ACTIVATION_LEAD_SECS (cold cache, first
    // run), skip this phase gracefully rather than asserting a stale state.
    if unix_now() < activation_time {
        println!(
            "Phase 1: confirming v0 gate does not fire before activation ({} s remaining)...",
            activation_time - unix_now()
        );

        let dkg_result = cli_tool::do_dkg(endpoint.clone(), RING_ID.to_string()).await;
        if let Err(ref e) = dkg_result {
            assert!(
                !e.to_string().contains("protocol version 1"),
                "DKG version-gated too early (before activation_time): {e}"
            );
        }
        println!(
            "DKG before activation: {}",
            dkg_result
                .as_ref()
                .map(|_| "ok".to_string())
                .unwrap_or_else(|e| format!("non-version err: {e}"))
        );

        let sign_result = cli_tool::do_sign(
            endpoint.clone(),
            b"upgrade-pre-activation".to_vec(),
            DERIVATION_ID.to_string(),
            None,
            None,
            None,
        )
        .await;
        if let Err(ref e) = sign_result {
            assert!(
                !e.to_string().contains("protocol version 1"),
                "Sign version-gated too early (before activation_time): {e}"
            );
        }
        println!(
            "Sign before activation: {}",
            sign_result
                .as_ref()
                .map(|_| "ok".to_string())
                .unwrap_or_else(|e| format!("non-version err: {e}"))
        );

        let pre_result = cli_tool::do_pre(
            endpoint.clone(),
            String::new(),
            reader_pk_hex.clone(),
            Some(reader_sk_hex.clone()),
            DOCUMENT_ID.to_string(),
            None,
            None,
            None,
            None,
            None,
            false,
        )
        .await;
        if let Err(ref e) = pre_result {
            assert!(
                !e.to_string().contains("protocol version 1"),
                "PRE version-gated too early (before activation_time): {e}"
            );
        }
        println!(
            "PRE before activation: {}",
            pre_result
                .as_ref()
                .map(|_| "ok".to_string())
                .unwrap_or_else(|e| format!("non-version err: {e}"))
        );
    } else {
        println!(
            "Skipping pre-activation phase: Docker startup consumed the {ACTIVATION_LEAD_SECS}s lead time."
        );
    }

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
    println!("Phase 2 complete: wall clock is now past activation_time.");

    // ─── Phase 3: post-activation — all v0 operations must be refused ─────────
    println!("Phase 3: confirming all v0 operations are refused after upgrade...");

    let dkg_err = cli_tool::do_dkg(endpoint.clone(), RING_ID.to_string())
        .await
        .expect_err("v0 DKG must refuse a v1 ring after activation");
    assert!(
        dkg_err.to_string().contains("protocol version 1"),
        "DKG: expected 'protocol version 1' in error, got: {dkg_err}"
    );
    println!("DKG correctly rejected: {dkg_err}");

    let sign_err = cli_tool::do_sign(
        endpoint.clone(),
        b"upgrade-post-activation".to_vec(),
        DERIVATION_ID.to_string(),
        None,
        None,
        None,
    )
    .await
    .expect_err("v0 Sign must refuse a derivation whose ring activated to v1");
    assert!(
        sign_err.to_string().contains("protocol version 1"),
        "Sign: expected 'protocol version 1' in error, got: {sign_err}"
    );
    println!("Sign correctly rejected: {sign_err}");

    let pre_err = cli_tool::do_pre(
        endpoint.clone(),
        String::new(),
        reader_pk_hex,
        Some(reader_sk_hex),
        DOCUMENT_ID.to_string(),
        None,
        None,
        None,
        None,
        None,
        false,
    )
    .await
    .expect_err("v0 PRE must refuse a document whose ring activated to v1");
    assert!(
        pre_err.to_string().contains("protocol version 1"),
        "PRE: expected 'protocol version 1' in error, got: {pre_err}"
    );
    println!("PRE correctly rejected: {pre_err}");

    println!("Upgrade integration test passed: v0 flipped to v1 at activation_time.");
}
