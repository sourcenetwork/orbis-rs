use super::service::UnsafeTestingServiceImpl;
use crate::helpers::test_helpers::{cleanup_db, test_db_path};
use local_storage::{r#trait::LocalStorage, LocalStorageImpl};
#[cfg(feature = "integration-test")]
use proto::unsafe_testing::unsafe_testing_service_client::UnsafeTestingServiceClient;
use proto::unsafe_testing::{
    unsafe_testing_service_server::UnsafeTestingService, DeleteLocalStorageRequest,
    GetLocalStorageRequest, LocalStorageAccessMode, LocalStorageKey, LocalStorageKeyType,
    SetLocalStorageRequest,
};
use tonic::{Code, Request};

fn key(key_type: LocalStorageKeyType, ring_key: &str) -> LocalStorageKey {
    LocalStorageKey {
        key_type: key_type as i32,
        ring_key: ring_key.to_string(),
    }
}

fn service(name: &str) -> (UnsafeTestingServiceImpl, String) {
    let path = test_db_path(name);
    let storage = LocalStorageImpl::new(Some("unsafe-testing-password".to_string()), path.clone())
        .expect("create local storage");
    (UnsafeTestingServiceImpl::new(storage), path)
}


#[tokio::test]
async fn plain_get_set_and_missing_get() {
    let (service, path) = service("unsafe_testing_plain_get_set");
    let storage_key = key(LocalStorageKeyType::RingIndex, "");

    let missing = service
        .get_local_storage(Request::new(GetLocalStorageRequest {
            key: Some(storage_key.clone()),
            access_mode: LocalStorageAccessMode::Plain as i32,
        }))
        .await
        .expect("get missing value")
        .into_inner();
    assert!(!missing.found);
    assert!(missing.value.is_empty());

    service
        .set_local_storage(Request::new(SetLocalStorageRequest {
            key: Some(storage_key.clone()),
            access_mode: LocalStorageAccessMode::Plain as i32,
            value: b"ring-index-json".to_vec(),
        }))
        .await
        .expect("set plain value");

    let stored = service
        .get_local_storage(Request::new(GetLocalStorageRequest {
            key: Some(storage_key),
            access_mode: LocalStorageAccessMode::Plain as i32,
        }))
        .await
        .expect("get plain value")
        .into_inner();
    assert!(stored.found);
    assert_eq!(stored.value, b"ring-index-json");

    cleanup_db(&path);
}

#[tokio::test]
async fn encrypted_get_set_round_trip() {
    let (service, path) = service("unsafe_testing_encrypted_get_set");
    let storage_key = key(LocalStorageKeyType::RingKey, "ring-key");

    service
        .set_local_storage(Request::new(SetLocalStorageRequest {
            key: Some(storage_key.clone()),
            access_mode: LocalStorageAccessMode::Encrypted as i32,
            value: b"secret-share".to_vec(),
        }))
        .await
        .expect("set encrypted value");

    let stored = service
        .get_local_storage(Request::new(GetLocalStorageRequest {
            key: Some(storage_key),
            access_mode: LocalStorageAccessMode::Encrypted as i32,
        }))
        .await
        .expect("get encrypted value")
        .into_inner();
    assert!(stored.found);
    assert_eq!(stored.value, b"secret-share");

    cleanup_db(&path);
}

#[tokio::test]
async fn delete_is_idempotent_and_reports_existence() {
    let (service, path) = service("unsafe_testing_delete");
    let storage_key = key(LocalStorageKeyType::NodeSecretKey, "");

    service
        .set_local_storage(Request::new(SetLocalStorageRequest {
            key: Some(storage_key.clone()),
            access_mode: LocalStorageAccessMode::Plain as i32,
            value: b"node-secret".to_vec(),
        }))
        .await
        .expect("set value");

    let first = service
        .delete_local_storage(Request::new(DeleteLocalStorageRequest {
            key: Some(storage_key.clone()),
        }))
        .await
        .expect("delete existing value")
        .into_inner();
    assert!(first.existed);

    let second = service
        .delete_local_storage(Request::new(DeleteLocalStorageRequest {
            key: Some(storage_key),
        }))
        .await
        .expect("delete missing value")
        .into_inner();
    assert!(!second.existed);

    cleanup_db(&path);
}

#[tokio::test]
async fn rejects_invalid_keys_and_access_modes() {
    let (service, path) = service("unsafe_testing_validation");

    let missing_key = service
        .get_local_storage(Request::new(GetLocalStorageRequest {
            key: None,
            access_mode: LocalStorageAccessMode::Plain as i32,
        }))
        .await
        .expect_err("missing key should fail");
    assert_eq!(missing_key.code(), Code::InvalidArgument);

    let unspecified_key = service
        .get_local_storage(Request::new(GetLocalStorageRequest {
            key: Some(key(LocalStorageKeyType::Unspecified, "")),
            access_mode: LocalStorageAccessMode::Plain as i32,
        }))
        .await
        .expect_err("unspecified key should fail");
    assert_eq!(unspecified_key.code(), Code::InvalidArgument);

    let empty_ring_key = service
        .get_local_storage(Request::new(GetLocalStorageRequest {
            key: Some(key(LocalStorageKeyType::RingKey, "")),
            access_mode: LocalStorageAccessMode::Plain as i32,
        }))
        .await
        .expect_err("empty ring key should fail");
    assert_eq!(empty_ring_key.code(), Code::InvalidArgument);

    let unexpected_ring_key = service
        .get_local_storage(Request::new(GetLocalStorageRequest {
            key: Some(key(LocalStorageKeyType::RingIndex, "unexpected")),
            access_mode: LocalStorageAccessMode::Plain as i32,
        }))
        .await
        .expect_err("ring key on RingIndex should fail");
    assert_eq!(unexpected_ring_key.code(), Code::InvalidArgument);

    let unspecified_mode = service
        .get_local_storage(Request::new(GetLocalStorageRequest {
            key: Some(key(LocalStorageKeyType::NodeSigningKey, "")),
            access_mode: LocalStorageAccessMode::Unspecified as i32,
        }))
        .await
        .expect_err("unspecified access mode should fail");
    assert_eq!(unspecified_mode.code(), Code::InvalidArgument);

    cleanup_db(&path);
}

#[cfg(feature = "integration-test")]
#[tokio::test]
#[serial_test::serial]
async fn production_docker_nodes_do_not_expose_unsafe_testing_service() {
    let network = common::IntegrationTestNetwork::builder()
        .with_production_node_build()
        .build();
    let endpoints = network.all_endpoints();

    // Production builds do not contain the integration-test faucet hook or
    // deterministic signing-key override, so fund each generated node address
    // through the test account before waiting for the full server to replace
    // the bootstrap information server.
    let chain_config = network.chain_config();
    let mut addresses = Vec::with_capacity(endpoints.len());
    for (index, endpoint) in endpoints.iter().enumerate() {
        addresses.push(
            cli_tool::query_node_info((*endpoint).to_string())
                .await
                .unwrap_or_else(|error| {
                    panic!(
                        "query production node {} bootstrap info: {error}",
                        index + 1
                    )
                })
                .public_address,
        );
    }
    for (index, address) in addresses.into_iter().enumerate() {
        cli_tool::fund(address, chain_config.clone())
            .await
            .unwrap_or_else(|error| panic!("fund production node {}: {error}", index + 1));
    }

    // The first process initialized its signer before the newly funded account
    // existed. Restart against the persisted signing key so the production
    // node initializes with the account metadata now present on-chain.
    let restarted_endpoints = network.restart_nodes();
    let endpoints = [
        restarted_endpoints[0].as_str(),
        restarted_endpoints[1].as_str(),
        restarted_endpoints[2].as_str(),
    ];
    crate::helpers::test_helpers::wait_for_nodes_ready(
        &endpoints,
        90,
        std::time::Duration::from_secs(1),
    )
    .await;

    for (index, endpoint) in endpoints.iter().enumerate() {
        let mut client = UnsafeTestingServiceClient::connect((*endpoint).to_string())
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "connect to production node {} unsafe testing client: {error}",
                    index + 1
                )
            });
        let result = client
            .get_local_storage(GetLocalStorageRequest {
                key: Some(key(LocalStorageKeyType::RingIndex, "")),
                access_mode: LocalStorageAccessMode::Plain as i32,
            })
            .await;
        let error = match result {
            Ok(_) => {
                panic!(
                    "production node {} unexpectedly exposed unsafe testing service",
                    index + 1
                )
            }
            Err(error) => error,
        };
        assert_eq!(
            error.code(),
            Code::Unimplemented,
            "production node {} returned an unexpected status: {error}",
            index + 1
        );
    }
}

#[cfg(feature = "integration-test")]
#[tokio::test]
#[serial_test::serial]
async fn unsafe_testing_docker_nodes_require_runtime_opt_in() {
    let network = common::IntegrationTestNetwork::builder()
        .with_unsafe_testing_runtime_disabled()
        .build();
    let endpoints = network.all_endpoints();
    crate::helpers::test_helpers::wait_for_nodes_ready(
        &endpoints,
        90,
        std::time::Duration::from_secs(1),
    )
    .await;

    for (index, endpoint) in endpoints.iter().enumerate() {
        let mut client = UnsafeTestingServiceClient::connect((*endpoint).to_string())
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "connect to runtime-disabled node {} unsafe testing client: {error}",
                    index + 1
                )
            });
        let error = client
            .get_local_storage(GetLocalStorageRequest {
                key: Some(key(LocalStorageKeyType::RingIndex, "")),
                access_mode: LocalStorageAccessMode::Plain as i32,
            })
            .await
            .expect_err("runtime-disabled node unexpectedly exposed unsafe testing service");
        assert_eq!(
            error.code(),
            Code::Unimplemented,
            "runtime-disabled node {} returned an unexpected status: {error}",
            index + 1
        );
    }
}
