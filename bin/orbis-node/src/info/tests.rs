use crate::helpers::launch::create_and_store_node_key;
use crate::helpers::test_helpers::{cleanup_db, create_test_app_state_default, test_db_path};
use crate::info::InfoServiceImpl;
use common::blockchain::ChainConfigBuilder;
use proto::info_service::{info_service_server::InfoService, GetNodeInfoRequest};
use tonic::Request;

// Concrete crypto implementation for tests (selected via crypto crate features)
use crypto::DkgImpl;

/// Test that get_node_info returns both public_address and peer_id
#[tokio::test]
async fn test_get_node_info() {
    let db_name = "test_get_node_info";
    let db_path = test_db_path(db_name);
    let app_state = create_test_app_state_default(db_name).await;

    // Create and store a node signing key so get_node_signer can retrieve it
    let config = ChainConfigBuilder::default().build();
    create_and_store_node_key(app_state.local_storage.clone(), config.clone(), None)
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

    // Verify peer_id is valid hex (since it's encoded from bytes)
    assert!(
        hex::decode(&node_info.peer_id).is_ok(),
        "peer_id should be valid hex"
    );

    cleanup_db(&db_path);
}
