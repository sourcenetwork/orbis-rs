//! Ring formation tests: verify DKG ceremony completes and collective key is produced.
//!
//! These tests exercise the core Orbis use case: N nodes form a ring, run DKG,
//! and produce a collective public key. The ring state should transition through:
//!   UNSPECIFIED -> INITIALIZED -> STARTED -> ... -> CERTIFIED
//!
//! Requires: DKG service, P2P transport, bulletin board (at least in-memory)

use std::time::Duration;

use orbis_e2e::ring::OrbisRing;

/// N=3, T=2 ring formation with DKG.
///
/// 1. Start 3 nodes
/// 2. Get peer IDs from each node (InfoService.GetNodeInfo)
/// 3. POST StartDkg to each node with the other nodes' peer IDs
/// 4. Wait for DKG to complete (all nodes reach CERTIFIED state)
/// 5. Verify collective public key exists and is consistent across nodes
#[tokio::test]
#[ignore = "requires DKG implementation with bulletin board"]
async fn ring_n3_t2_forms_and_certifies() {
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

    // TODO: Get peer IDs from each node via InfoService
    // TODO: Send StartDkg request to each node
    // TODO: Wait for DKG state to reach CERTIFIED
    // TODO: Verify collective public key is consistent across all nodes
    todo!("implement when DKG e2e flow is working");
}

/// N=5, T=3 ring — larger ring to test scalability.
#[tokio::test]
#[ignore = "requires DKG implementation"]
async fn ring_n5_t3_forms() {
    let ring = OrbisRing::builder()
        .nodes(5)
        .threshold(3)
        .build()
        .await
        .expect("ring should start");

    ring.wait_ready(Duration::from_secs(30))
        .await
        .expect("all nodes should be healthy");

    todo!("implement when DKG e2e flow is working");
}

/// Minimum viable ring: N=3, T=2 (Rabin DKG requires T >= 2).
#[tokio::test]
#[ignore = "requires DKG implementation"]
async fn minimum_viable_ring() {
    let ring = OrbisRing::builder()
        .nodes(3)
        .threshold(2)
        .build()
        .await
        .expect("ring should start");

    ring.wait_ready(Duration::from_secs(30))
        .await
        .expect("all nodes should be healthy");

    // Verify minimum threshold is enforced
    assert!(ring.threshold() >= 2, "Rabin DKG requires T >= 2");

    todo!("implement when DKG e2e flow is working");
}
