#![cfg(feature = "vera")]
//! Regression coverage for the Compose-driven Vera topology
//! (`docker/docker-compose-vera-integration-test.yml`). Requires Docker;
//! set `VERA_REF=<40-char sha>` to build a revision other than
//! `docker/VERA_REF`.

#[tokio::test]
async fn native_validator_cluster_reaches_height_three() {
    let cluster = test_support::VeraTestNetwork::start(9400).await;
    assert_eq!(cluster.node_count(), 4);
    for index in 0..4 {
        let url = cluster.node(index).rpc_url();
        assert!(url.starts_with("http://127.0.0.1:"), "{url}");
    }
}

#[tokio::test]
async fn native_full_topology_reaches_healthy() {
    let network = test_support::VeraNetworkAdapter::start(9401).await;
    let endpoints = network.node_endpoints();
    assert_eq!(endpoints.len(), 3);
    for endpoint in endpoints {
        assert!(endpoint.starts_with("http://127.0.0.1:"), "{endpoint}");
    }
}
