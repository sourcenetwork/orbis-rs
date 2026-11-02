//! DKG fails when a required node is unreachable.
//!
//! Node 2 is aborted before DKG is initiated. Neither node 0 nor node 1 can
//! connect to node 2 for the DKG protocol messages. DKG requires all-node
//! participation, so the service returns an error immediately when it
//! cannot establish connections to all participants.
//!
//! Harness-unification migration, PR 6: migrated off `fault_injection.rs`'s
//! Cosmos-only in-process bootstrap onto [`super::live_node`]'s shared one
//! — ported from blocking node 2's hex id on the other two nodes'
//! `FaultNetworkController`s to simply aborting node 2 outright before
//! `do_dkg`, same "the outcome is what's under test" reasoning as the
//! below-threshold siblings. Fully dual-backend — no `#[ignore]` needed.

#[tokio::test]
#[serial_test::serial]
async fn test_dkg_fails_when_node_unreachable() {
    let net = super::live_node::setup_live_node_network(3, "fault_dkg_unreachable", 51072).await;
    let endpoint = net.node(0).grpc_endpoint.clone();

    // Create the ring on-chain before taking node 2 down.
    let ring_id = net.create_ring(2, None).await;

    // Crash node 2 so it's unreachable for DKG.
    net.node(2).stop();
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Initiate DKG — the DKG service checks connectivity to all peers
    // upfront. Because node 2 is down, node 0 cannot reach it and the DKG
    // call must return an error immediately.
    let dkg_result = cli_tool::do_dkg(endpoint.to_string(), ring_id).await;

    assert!(
        dkg_result.is_err(),
        "DKG should fail when node 2 is unreachable, but it succeeded: {:?}",
        dkg_result
    );

    println!(
        "DKG correctly failed with node 2 down: {:?}",
        dkg_result.unwrap_err()
    );
}
