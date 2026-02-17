//! Connectivity test: verify orbis-node processes can start and respond to gRPC.
//!
//! These tests start a SourceHub devnet, then spawn orbis-node processes
//! pointed at it. Validates the full startup path.

use std::time::Duration;

use orbis_e2e::ring::OrbisRing;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .try_init();
}

/// Start SourceHub + 3 orbis-node processes and verify they all respond to GetNodeInfo.
#[tokio::test]
async fn three_nodes_with_sourcehub() {
    init_tracing();

    let ring = OrbisRing::builder()
        .nodes(3)
        .threshold(2)
        .log_level("debug")
        .with_sourcehub()
        .build()
        .await
        .expect("ring should start with SourceHub");

    assert_eq!(ring.node_count(), 3);
    assert_eq!(ring.threshold(), 2);
    assert!(ring.sourcehub().is_some(), "SourceHub should be running");

    // Verify all nodes become responsive within 60 seconds
    ring.wait_ready(Duration::from_secs(60))
        .await
        .expect("all nodes should become healthy");

    // Verify each node has log files
    for i in 0..ring.node_count() {
        let node = ring.node(i);
        assert!(
            node.stdout_log().exists() || node.stderr_log().exists(),
            "node{} should have log files",
            i
        );
    }
}

/// Start SourceHub + a single node.
#[tokio::test]
async fn single_node_with_sourcehub() {
    init_tracing();

    let ring = OrbisRing::builder()
        .nodes(1)
        .threshold(1)
        .with_sourcehub()
        .build()
        .await
        .expect("single node should start");

    assert_eq!(ring.node_count(), 1);

    ring.wait_ready(Duration::from_secs(60))
        .await
        .expect("single node should become healthy");
}
