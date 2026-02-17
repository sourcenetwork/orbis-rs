//! Node failure tests: verify threshold tolerance.
//!
//! An N=3, T=2 ring should continue operating when 1 node fails.
//! It should fail when 2 nodes are down (below threshold).
//!
//! Requires: DKG + PRE implementation

use std::time::Duration;

use orbis_e2e::ring::OrbisRing;

/// Kill 1 of 3 nodes in a T=2 ring. PRE should still work.
#[tokio::test]
#[ignore = "requires working DKG + PRE"]
async fn one_node_down_still_reencrypts() {
    let ring = OrbisRing::builder()
        .nodes(3)
        .threshold(2)
        .log_level("debug")
        .build()
        .await
        .expect("ring should start");

    ring.wait_ready(Duration::from_secs(30))
        .await
        .expect("all nodes should be healthy");

    // TODO: Form ring and complete DKG
    // TODO: Store a secret
    // TODO: Kill node 2
    // TODO: Request reencrypt — should succeed with 2 remaining nodes
    todo!("implement when PRE is working");
}

/// Kill 2 of 3 nodes in a T=2 ring. PRE should fail (below threshold).
#[tokio::test]
#[ignore = "requires working DKG + PRE"]
async fn two_nodes_down_reencrypt_fails() {
    let ring = OrbisRing::builder()
        .nodes(3)
        .threshold(2)
        .build()
        .await
        .expect("ring should start");

    ring.wait_ready(Duration::from_secs(30))
        .await
        .expect("all nodes should be healthy");

    // TODO: Form ring and complete DKG
    // TODO: Store a secret
    // TODO: Kill nodes 1 and 2
    // TODO: Request reencrypt — should fail (only 1 node, need 2)
    todo!("implement when PRE is working");
}

/// Verify a killed node's process is actually dead (framework sanity check).
#[tokio::test]
#[ignore = "requires working node startup"]
async fn killed_node_process_exits() {
    let ring = OrbisRing::builder()
        .nodes(2)
        .threshold(2)
        .build()
        .await
        .expect("ring should start");

    ring.wait_ready(Duration::from_secs(15))
        .await
        .expect("nodes should be healthy");

    // Kill node 1 and verify it's no longer running
    // Note: need mutable access to ring for this
    // TODO: Add a kill_node method to OrbisRing
    todo!("implement kill_node method");
}
