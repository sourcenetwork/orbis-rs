//! Tests for the orbis-node main module
//!
//! These tests verify the node initialization and configuration logic.

use crate::{init_node, Args, NodeConfig};
use local_storage::memory::MemoryStorage;
use local_storage::r#trait::LocalStorage;
use network::Network;
use std::sync::Arc;

/// Test that the node initializes successfully with valid configuration
#[tokio::test]
async fn test_init_node_success() {
    // Create a real network for testing
    let network: Arc<dyn Network> = Arc::new(
        network::IrohNetwork::new()
            .await
            .expect("Failed to create network"),
    );

    let config = NodeConfig {
        args: Args {
            addr: "127.0.0.1:0".to_string(), // Use port 0 to let OS assign
        },
        network,
        local_storage: MemoryStorage::new(None),
    };

    let result = init_node(config).await;
    assert!(result.is_ok(), "Node initialization should succeed");

    let node = result.unwrap();

    // Verify the node was initialized correctly
    assert!(
        !node.local_address.is_empty(),
        "Local address should be set"
    );

    // Clean up
    node.router
        .shutdown()
        .await
        .expect("Router shutdown failed");
}

/// Test that the node fails with invalid address
#[tokio::test]
async fn test_init_node_invalid_address() {
    let network: Arc<dyn Network> = Arc::new(
        network::IrohNetwork::new()
            .await
            .expect("Failed to create network"),
    );

    let config = NodeConfig {
        args: Args {
            addr: "not-a-valid-address".to_string(),
        },
        network,
        local_storage: MemoryStorage::new(None),
    };

    let result = init_node(config).await;
    assert!(
        result.is_err(),
        "Node initialization should fail with invalid address"
    );
}

/// Test that AppState is properly configured after initialization
#[tokio::test]
async fn test_init_node_app_state_configuration() {
    let network: Arc<dyn Network> = Arc::new(
        network::IrohNetwork::new()
            .await
            .expect("Failed to create network"),
    );

    let bind_addr = "127.0.0.1:0".to_string();
    let config = NodeConfig {
        args: Args {
            addr: bind_addr.clone(),
        },
        network,
        local_storage: MemoryStorage::new(None),
    };

    let node = init_node(config).await.expect("Node initialization failed");

    // Verify AppState configuration
    assert_eq!(
        node.app_state.config.bind_address, bind_addr,
        "Bind address should match"
    );

    // Verify no sessions exist initially
    assert_eq!(
        node.app_state.session_count().await,
        0,
        "Should have no sessions initially"
    );

    // Clean up
    node.router
        .shutdown()
        .await
        .expect("Router shutdown failed");
}

/// Test that multiple nodes can be initialized concurrently
#[tokio::test]
async fn test_init_multiple_nodes() {
    let network1: Arc<dyn Network> = Arc::new(
        network::IrohNetwork::new()
            .await
            .expect("Failed to create network 1"),
    );
    let network2: Arc<dyn Network> = Arc::new(
        network::IrohNetwork::new()
            .await
            .expect("Failed to create network 2"),
    );

    let config1 = NodeConfig {
        args: Args {
            addr: "127.0.0.1:0".to_string(),
        },
        network: network1,
        local_storage: MemoryStorage::new(None),
    };

    let config2 = NodeConfig {
        args: Args {
            addr: "127.0.0.1:0".to_string(),
        },
        network: network2,
        local_storage: MemoryStorage::new(None),
    };

    let node1 = init_node(config1)
        .await
        .expect("Node 1 initialization failed");
    let node2 = init_node(config2)
        .await
        .expect("Node 2 initialization failed");

    // Verify both nodes have different addresses
    assert_ne!(
        node1.local_address, node2.local_address,
        "Nodes should have different P2P addresses"
    );

    // Clean up
    node1
        .router
        .shutdown()
        .await
        .expect("Router 1 shutdown failed");
    node2
        .router
        .shutdown()
        .await
        .expect("Router 2 shutdown failed");
}

/// Test Args default values
#[test]
fn test_args_default() {
    use clap::Parser;

    // Parse with no arguments (uses defaults)
    let args = Args::parse_from(["orbis-node"]);
    assert_eq!(
        args.addr, "[::1]:50051",
        "Default address should be [::1]:50051"
    );
}

/// Test Args custom address
#[test]
fn test_args_custom_address() {
    use clap::Parser;

    let args = Args::parse_from(["orbis-node", "--addr", "0.0.0.0:8080"]);
    assert_eq!(args.addr, "0.0.0.0:8080");

    // Test short form
    let args = Args::parse_from(["orbis-node", "-a", "127.0.0.1:9000"]);
    assert_eq!(args.addr, "127.0.0.1:9000");
}

/// Test that encrypted storage works with the node
#[tokio::test]
async fn test_init_node_with_encrypted_storage() {
    let network: Arc<dyn Network> = Arc::new(
        network::IrohNetwork::new()
            .await
            .expect("Failed to create network"),
    );

    // Create storage with a password
    let password = "test-password-123".to_string();
    let local_storage = MemoryStorage::new(Some(password));

    let config = NodeConfig {
        args: Args {
            addr: "127.0.0.1:0".to_string(),
        },
        network,
        local_storage,
    };

    let result = init_node(config).await;
    assert!(
        result.is_ok(),
        "Node should initialize with encrypted storage"
    );

    let node = result.unwrap();
    node.router
        .shutdown()
        .await
        .expect("Router shutdown failed");
}
