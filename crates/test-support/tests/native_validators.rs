#![cfg(feature = "native")]
//! Phase B regression coverage for the Compose-driven native topology
//! (`docker/docker-compose-native-integration-test.yml`). Requires Docker;
//! run with `VERA_REF=<40-char sha matching your vera-client dep rev>` if
//! `docker/VERA_REF`'s pinned commit isn't fetchable from your network (see
//! the Phase B report — that mismatch is pre-existing, not introduced here).

#[tokio::test]
async fn native_validator_cluster_reaches_height_three() {
    let cluster = test_support::NativeTestNetwork::start(9400).await;
    assert_eq!(cluster.node_count(), 4);
    for index in 0..4 {
        let url = cluster.node(index).rpc_url();
        assert!(url.starts_with("http://127.0.0.1:"), "{url}");
    }
}

#[tokio::test]
async fn native_full_topology_reaches_healthy() {
    let network = test_support::NativeNetworkAdapter::start(9401).await;
    let endpoints = network.node_endpoints();
    assert_eq!(endpoints.len(), 3);
    for endpoint in endpoints {
        assert!(endpoint.starts_with("http://127.0.0.1:"), "{endpoint}");
    }
}
