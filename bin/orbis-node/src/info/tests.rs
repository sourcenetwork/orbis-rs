use crate::helpers::launch::create_and_store_node_key;
use crate::helpers::test_helpers::{cleanup_db, create_test_app_state_default, test_db_path};
use crate::info::InfoServiceImpl;
use crate::ring_state::RingIndexEntry;
use common::blockchain::ChainConfigBuilder;
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use proto::info_service::{info_service_server::InfoService, GetNodeInfoRequest, NodeStatus};
use tonic::Request;

// Concrete crypto implementation for tests (selected via crypto crate features)
use crypto::DkgImpl;

/// Test that get_node_info returns zero managed rings before any DKG result is stored.
#[tokio::test]
async fn test_get_node_info_reports_zero_managed_ring_count_without_ring_index() {
    let db_name = "test_get_node_info_reports_zero_managed_ring_count";
    let db_path = test_db_path(db_name);
    let app_state = create_test_app_state_default(db_name).await;

    // Create and store a node signing key so get_node_signer can retrieve it
    let config = ChainConfigBuilder::default().build();
    let runtime_base_path = project_root::get_project_root().expect("resolve project root");
    create_and_store_node_key(
        app_state.local_storage.clone(),
        config.clone(),
        &runtime_base_path,
    )
    .expect("Failed to create and store node key");

    // Create the info service
    let service = InfoServiceImpl::<DkgImpl>::new(app_state);

    // Create a request
    let request = Request::new(GetNodeInfoRequest {});

    // Call get_node_info
    let result = service.get_node_info(request).await;

    // Verify the request succeeds
    assert!(result.is_ok(), "get_node_info should succeed");

    let response = result.unwrap();
    let node_info = response.into_inner();

    // Verify response contains public_address
    assert!(
        !node_info.public_address.is_empty(),
        "public_address should not be empty"
    );

    // Verify response contains peer_id
    assert!(!node_info.peer_id.is_empty(), "peer_id should not be empty");
    assert_eq!(node_info.status, NodeStatus::Ready as i32);
    assert_eq!(node_info.managed_ring_count, 0);
    assert_eq!(node_info.supported_protocol_versions, vec![0]);

    // Verify peer_id is valid hex (since it's encoded from bytes)
    assert!(
        hex::decode(&node_info.peer_id).is_ok(),
        "peer_id should be valid hex"
    );

    cleanup_db(&db_path);
}

#[tokio::test]
async fn test_get_node_info_reports_managed_ring_count_from_ring_index() {
    let db_name = "test_get_node_info_reports_managed_ring_count";
    let db_path = test_db_path(db_name);
    let app_state = create_test_app_state_default(db_name).await;

    let config = ChainConfigBuilder::default().build();
    let runtime_base_path = project_root::get_project_root().expect("resolve project root");
    create_and_store_node_key(
        app_state.local_storage.clone(),
        config.clone(),
        &runtime_base_path,
    )
    .expect("Failed to create and store node key");

    let ring_index = vec![
        RingIndexEntry {
            ring_pk_str: "ring-key-1".to_string(),
            bulletin_post_id: "post-1".to_string(),
            indexed_at_secs: 0,
        },
        RingIndexEntry {
            ring_pk_str: "ring-key-2".to_string(),
            bulletin_post_id: "post-2".to_string(),
            indexed_at_secs: 0,
        },
    ];
    app_state
        .local_storage
        .set(
            LocalStorageKeys::RingIndex,
            serde_json::to_vec(&ring_index).expect("serialize ring index"),
        )
        .expect("Failed to store ring index");

    let service = InfoServiceImpl::<DkgImpl>::new(app_state);
    let response = service
        .get_node_info(Request::new(GetNodeInfoRequest {}))
        .await
        .expect("get_node_info should succeed");

    let node_info = response.into_inner();
    assert_eq!(node_info.status, NodeStatus::Ready as i32);
    assert_eq!(node_info.managed_ring_count, 2);
    assert_eq!(node_info.supported_protocol_versions, vec![0]);

    cleanup_db(&db_path);
}
