//! Two DKG sessions initiated simultaneously on the same in-process network
//! must both complete independently without cross-session interference.
//!
//! Harness-unification migration, PR 6: the first test migrated off
//! `concurrent.rs`'s own Cosmos-only in-process bootstrap onto
//! [`super::live_node`]'s shared one. Fully dual-backend — no `#[ignore]`
//! needed on either side.

use super::live_node::setup_live_node_network;
use std::time::Duration;

/// Exercises `SessionStateManager` under concurrent load: both sessions are
/// created at the same time, each producing its own ring key and bulletin
/// post, with no deadlock or state leakage between them.
#[tokio::test]
#[serial_test::serial]
async fn test_two_simultaneous_dkg_sessions() {
    let net = setup_live_node_network(3, "dual_dkg", 51051).await;

    let endpoint = net.node(0).grpc_endpoint.clone();

    // Create two separate rings (different nonces -> different ring IDs).
    // Sequential, not concurrent: both ring-creation txs sign from the same
    // test account, and concurrent submission races on its on-chain sequence
    // number (confirmed via Docker: "account sequence mismatch" on the
    // second tx) — only the DKG triggering/finalization below is meant to
    // run concurrently, matching the original (pre-migration) test.
    let ring_id_1 = net.create_ring(2, Some("session-1")).await;
    let ring_id_2 = net.create_ring(2, Some("session-2")).await;

    assert_ne!(
        ring_id_1, ring_id_2,
        "distinct nonces must produce distinct ring IDs"
    );

    // Launch both DKG sessions concurrently from the same endpoint
    let (r1, r2) = tokio::join!(
        cli_tool::do_dkg(endpoint.clone(), ring_id_1.clone()),
        cli_tool::do_dkg(endpoint.clone(), ring_id_2.clone()),
    );

    let session1 = r1.expect("DKG 1 initiation failed").session_id;
    let session2 = r2.expect("DKG 2 initiation failed").session_id;
    assert_ne!(
        session1, session2,
        "concurrent DKGs must receive distinct session IDs"
    );

    let timeout = Duration::from_secs(90);
    let (pk1, pk2) = tokio::join!(
        net.wait_for_ring_finalized(&ring_id_1, timeout),
        net.wait_for_ring_finalized(&ring_id_2, timeout),
    );

    assert!(!pk1.is_empty(), "DKG 1 must produce a ring key");
    assert!(!pk2.is_empty(), "DKG 2 must produce a ring key");

    println!(
        "Both DKGs completed successfully:\n  ring1={} pk={}\n  ring2={} pk={}",
        ring_id_1,
        &pk1[..8.min(pk1.len())],
        ring_id_2,
        &pk2[..8.min(pk2.len())],
    );
}
