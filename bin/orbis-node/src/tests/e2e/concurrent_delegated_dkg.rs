//! DKG triggered via a relay-signed delegated-auth token must succeed the
//! same as a direct node-operator call.
//!
//! Runs on [`super::live_node`]'s in-process bootstrap.

use authn::{create_authenticated_request, DkgClaims, JwtSigner};
use proto::v0::dkg::{dkg_service_client::DkgServiceClient, StartDkgRequest};

#[tokio::test]
#[serial_test::serial]
async fn test_delegated_dkg_with_vera_end_to_end() {
    let relay = JwtSigner::new();
    let net = super::live_node::setup_live_node_network(3, "delegated_dkg_vera").await;

    let ring_id = net
        .create_ring_with_trusted_relays(2, None, vec![relay.did_uri.clone()])
        .await;

    let token = relay
        .sign_for_actor(
            "did:opk:integration-user".to_string(),
            DkgClaims {
                ring_id: ring_id.clone(),
            },
            std::time::Duration::from_secs(60),
        )
        .expect("create delegated DKG token");
    let request = create_authenticated_request(
        StartDkgRequest {
            ring_id: ring_id.clone(),
        },
        &token,
    )
    .expect("create authenticated DKG request");

    let response = DkgServiceClient::connect(net.node(0).grpc_endpoint.clone())
        .await
        .expect("connect DKG client")
        .start_dkg(request)
        .await
        .expect("start delegated DKG")
        .into_inner();
    assert!(
        !response.session_id.is_empty(),
        "DKG session ID is required"
    );

    let ring_pk = net
        .wait_for_ring_finalized(&ring_id, std::time::Duration::from_secs(90))
        .await;
    assert!(!ring_pk.is_empty(), "delegated DKG must finalize the ring");
}
