//! DKG must complete when `StartDkg` is invoked on any ring participant,
//! not just the one driving the overall flow.
//!
//! Harness-unification migration, PR 6: migrated off `concurrent.rs`'s
//! Cosmos-only in-process bootstrap onto [`super::live_node`]'s shared one.
//! Verifies the Phase 1 fix: every participant starts phase 1 upon
//! receiving `SessionInit` without waiting for the initiator to drive them.
//! The four-node setup lets us confirm DKG completes even when initiated
//! from the last node. Fully dual-backend -- no `#[ignore]` needed.

use proto::info_service::{info_service_client::InfoServiceClient, GetRingStateRequest};
use tonic::Request;

async fn assert_has_ring_state(grpc_endpoint: &str, ring_pk_hex: &str) {
    let mut client = InfoServiceClient::connect(grpc_endpoint.to_string())
        .await
        .expect("connect InfoService");
    let resp = client
        .get_ring_state(Request::new(GetRingStateRequest {
            ring_pk_hex: ring_pk_hex.to_string(),
        }))
        .await
        .expect("participant must store ring state after DKG");
    assert!(
        !resp.into_inner().public_polynomial.is_empty(),
        "public_polynomial must be populated"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn test_dkg_non_participant_initiator_completes() {
    let net = super::live_node::setup_live_node_network(4, "dkg_non_participant").await;

    // Create a ring with all four nodes as participants (threshold=2)
    let ring_id = net.create_ring(2, None).await;

    // Initiate DKG from the last node's endpoint
    cli_tool::do_dkg(net.node(3).grpc_endpoint.clone(), ring_id.clone())
        .await
        .expect("DKG from last-node initiator");

    let ring_pk_hex = net
        .wait_for_ring_finalized(&ring_id, std::time::Duration::from_secs(90))
        .await;

    assert_has_ring_state(&net.node(0).grpc_endpoint, &ring_pk_hex).await;
    assert_has_ring_state(&net.node(1).grpc_endpoint, &ring_pk_hex).await;
    assert_has_ring_state(&net.node(2).grpc_endpoint, &ring_pk_hex).await;
    assert_has_ring_state(&net.node(3).grpc_endpoint, &ring_pk_hex).await;
}
