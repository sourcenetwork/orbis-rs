//! The diagnostic `UnsafeTestingService` stays unregistered unless both the
//! build and the runtime opt in.
//!
//! A production image is built without the service. A diagnostic image has it
//! compiled in but registers it only when `ORBIS_ENABLE_INTEGRATION_TEST` is
//! `true`; the adapter passes `false` here.

use crate::helpers::test_helpers::wait_for_nodes_ready;
use proto::unsafe_testing::{
    unsafe_testing_service_client::UnsafeTestingServiceClient, GetLocalStorageRequest,
    LocalStorageAccessMode, LocalStorageKey, LocalStorageKeyType,
};
use std::time::Duration;
use test_support::VeraNetworkAdapter;
use tonic::Code;
use vera_harness::cluster::GenesisBuilder;

async fn assert_unsafe_testing_unimplemented(endpoint: &str) {
    let mut client = UnsafeTestingServiceClient::connect(endpoint.to_string())
        .await
        .unwrap_or_else(|error| panic!("connect unsafe testing client to {endpoint}: {error}"));
    let error = client
        .get_local_storage(GetLocalStorageRequest {
            key: Some(LocalStorageKey {
                key_type: LocalStorageKeyType::RingIndex as i32,
                ring_key: String::new(),
            }),
            access_mode: LocalStorageAccessMode::Plain as i32,
        })
        .await
        .expect_err("node unexpectedly exposed the unsafe testing service");
    assert_eq!(
        error.code(),
        Code::Unimplemented,
        "node {endpoint} returned an unexpected status: {error}",
    );
}

#[tokio::test]
#[serial_test::serial]
async fn production_docker_nodes_do_not_expose_unsafe_testing_service() {
    // Registration is decided by the image and the runtime variable, both
    // shared by every node, so one node covers all of them.
    let network =
        VeraNetworkAdapter::start_configured(9101, 1, true, false, false, GenesisBuilder::devnet())
            .await;
    let endpoint = network.node1_endpoint();
    wait_for_nodes_ready(&[endpoint.as_str()], 90, Duration::from_secs(1)).await;
    assert_unsafe_testing_unimplemented(&endpoint).await;
}

#[tokio::test]
#[serial_test::serial]
async fn unsafe_testing_docker_nodes_require_runtime_opt_in() {
    let network = VeraNetworkAdapter::start_configured(
        9102,
        3,
        false,
        false,
        false,
        GenesisBuilder::devnet(),
    )
    .await;
    let endpoints = network.node_endpoints();
    let endpoint_refs: Vec<&str> = endpoints.iter().map(String::as_str).collect();
    wait_for_nodes_ready(&endpoint_refs, 90, Duration::from_secs(1)).await;
    for endpoint in &endpoints {
        assert_unsafe_testing_unimplemented(endpoint).await;
    }
}
