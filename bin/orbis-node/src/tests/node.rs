//! Node initialization, configuration, and key management tests.

use crate::{
    helpers::{
        launch::{create_and_store_node_key, derive_secret_key_bytes, LogLevel},
        test_helpers::{cleanup_db, test_db_path},
    },
    init_node, Args, NodeConfig,
};
use authz::r#trait::Authz;
use authz::AuthzImpl;
use bulletin::dummy::DummyBulletin;
use bulletin::r#trait::Bulletin;
use common::blockchain::ChainConfigBuilder;
use local_storage::{r#trait::LocalStorage, LocalStorageImpl};
use network::{Network, NetworkImpl};
use std::sync::Arc;

/// Test that the node initializes successfully with valid configuration
#[tokio::test]
async fn test_init_node_success() {
    let db_path = test_db_path("test_init_node_success");

    // Create a real network for testing
    let network: Arc<dyn Network> =
        Arc::new(NetworkImpl::new().await.expect("Failed to create network"));

    let authz: Arc<dyn Authz> = Arc::new(
        AuthzImpl::new(ChainConfigBuilder::default())
            .await
            .expect("Failed to initialize Authz"),
    );

    let bulletin: Arc<dyn Bulletin + Send + Sync> = Arc::new(
        DummyBulletin::new()
            .await
            .expect("Failed to initialize bulletin"),
    );

    let config = NodeConfig {
        args: Args {
            addr: "127.0.0.1:0".to_string(), // Use port 0 to let OS assign
            log_level: LogLevel::Info,
            authz_grpc: None,
            bulletin_grpc: None,
            chain_rest: None,
            chain_rpc: None,
            denom: None,
            metrics_addr: None,
            loki_url: None,
        },
        network,
        local_storage: LocalStorageImpl::new(None, db_path.clone())
            .expect("Failed to create local storage"),
        authz,
        bulletin,
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
    cleanup_db(&db_path);
}

/// Test that the node fails with invalid address
#[tokio::test]
async fn test_init_node_invalid_address() {
    let db_path = test_db_path("test_init_node_invalid_address");

    let network: Arc<dyn Network> =
        Arc::new(NetworkImpl::new().await.expect("Failed to create network"));

    let authz: Arc<dyn Authz> = Arc::new(
        AuthzImpl::new(ChainConfigBuilder::default())
            .await
            .expect("Failed to initialize Authz"),
    );

    let bulletin: Arc<dyn Bulletin + Send + Sync> = Arc::new(
        DummyBulletin::new()
            .await
            .expect("Failed to initialize bulletin"),
    );

    let config = NodeConfig {
        args: Args {
            addr: "not-a-valid-address".to_string(),
            log_level: LogLevel::Info,
            authz_grpc: None,
            bulletin_grpc: None,
            chain_rest: None,
            chain_rpc: None,
            denom: None,
            metrics_addr: None,
            loki_url: None,
        },
        network,
        local_storage: LocalStorageImpl::new(None, db_path.clone())
            .expect("Failed to create local storage"),
        authz,
        bulletin,
    };

    let result = init_node(config).await;
    assert!(
        result.is_err(),
        "Node initialization should fail with invalid address"
    );
    cleanup_db(&db_path);
}

/// Test that AppState is properly configured after initialization
#[tokio::test]
async fn test_init_node_app_state_configuration() {
    let db_path = test_db_path("test_init_node_app_state_configuration");

    let network: Arc<dyn Network> =
        Arc::new(NetworkImpl::new().await.expect("Failed to create network"));

    let authz: Arc<dyn Authz> = Arc::new(
        AuthzImpl::new(ChainConfigBuilder::default())
            .await
            .expect("Failed to initialize Authz"),
    );

    let bulletin: Arc<dyn Bulletin + Send + Sync> = Arc::new(
        DummyBulletin::new()
            .await
            .expect("Failed to initialize bulletin"),
    );

    let bind_addr = "127.0.0.1:0".to_string();
    let config = NodeConfig {
        args: Args {
            addr: bind_addr.clone(),
            log_level: LogLevel::Info,
            authz_grpc: None,
            bulletin_grpc: None,
            chain_rest: None,
            chain_rpc: None,
            denom: None,
            metrics_addr: None,
            loki_url: None,
        },
        network,
        local_storage: LocalStorageImpl::new(None, db_path.clone())
            .expect("Failed to create local storage"),
        authz,
        bulletin,
    };

    let node = init_node(config).await.expect("Node initialization failed");

    // Verify AppState configuration
    assert_eq!(
        node.app_state.config.bind_address, bind_addr,
        "Bind address should match"
    );

    // Verify no sessions exist initially
    assert_eq!(
        node.app_state.dkg_session_state.session_count().await,
        0,
        "Should have no sessions initially"
    );

    // Clean up
    node.router
        .shutdown()
        .await
        .expect("Router shutdown failed");
    cleanup_db(&db_path);
}

/// Test that multiple nodes can be initialized concurrently
#[tokio::test]
async fn test_init_multiple_nodes() {
    let db_path1 = test_db_path("test_init_multiple_nodes_1");
    let db_path2 = test_db_path("test_init_multiple_nodes_2");

    let network1: Arc<dyn Network> = Arc::new(
        NetworkImpl::new()
            .await
            .expect("Failed to create network 1"),
    );
    let network2: Arc<dyn Network> = Arc::new(
        NetworkImpl::new()
            .await
            .expect("Failed to create network 2"),
    );

    let authz1: Arc<dyn Authz> = Arc::new(
        AuthzImpl::new(ChainConfigBuilder::default())
            .await
            .expect("Failed to initialize Authz"),
    );
    let authz2: Arc<dyn Authz> = Arc::new(
        AuthzImpl::new(ChainConfigBuilder::default())
            .await
            .expect("Failed to initialize Authz"),
    );

    let bulletin1: Arc<dyn Bulletin + Send + Sync> = Arc::new(
        DummyBulletin::new()
            .await
            .expect("Failed to initialize bulletin"),
    );

    let bulletin2: Arc<dyn Bulletin + Send + Sync> = Arc::new(
        DummyBulletin::new()
            .await
            .expect("Failed to initialize bulletin"),
    );

    let config1 = NodeConfig {
        args: Args {
            addr: "127.0.0.1:0".to_string(),
            log_level: LogLevel::Info,
            authz_grpc: None,
            bulletin_grpc: None,
            chain_rest: None,
            chain_rpc: None,
            denom: None,
            metrics_addr: None,
            loki_url: None,
        },
        network: network1,
        local_storage: LocalStorageImpl::new(None, db_path1.clone())
            .expect("Failed to create local storage"),
        authz: authz1,
        bulletin: bulletin1,
    };

    let config2 = NodeConfig {
        args: Args {
            addr: "127.0.0.1:0".to_string(),
            log_level: LogLevel::Info,
            authz_grpc: None,
            bulletin_grpc: None,
            chain_rest: None,
            chain_rpc: None,
            denom: None,
            metrics_addr: None,
            loki_url: None,
        },
        network: network2,
        local_storage: LocalStorageImpl::new(None, db_path2.clone())
            .expect("Failed to create local storage"),
        authz: authz2,
        bulletin: bulletin2,
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
    cleanup_db(&db_path1);
    cleanup_db(&db_path2);
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

/// ThresholdDealer::name() reflects the compiled crypto backend (elgamal/decaf377 vs elgamal/bls12_381).
#[test]
fn test_pre_impl_name_matches_backend() {
    use crypto::r#trait::ThresholdDealer;
    use crypto::PreImpl;

    #[cfg(feature = "decaf377")]
    assert_eq!(
        PreImpl::name(),
        "elgamal/decaf377",
        "decaf377 build should report elgamal/decaf377"
    );
    #[cfg(feature = "bls12-381")]
    assert_eq!(
        PreImpl::name(),
        "elgamal/bls12_381",
        "bls12-381 build should report elgamal/bls12_381"
    );
}

/// Test that encrypted storage works with the node
#[tokio::test]
#[serial_test::serial]
async fn test_init_node_with_encrypted_storage() {
    let db_path = test_db_path("test_init_node_with_encrypted_storage");

    let network: Arc<dyn Network> =
        Arc::new(NetworkImpl::new().await.expect("Failed to create network"));

    // Create storage with a password
    let password = "test-password-123".to_string();
    let local_storage = LocalStorageImpl::new(Some(password), db_path.clone())
        .expect("Failed to create local storage");
    let authz: Arc<dyn Authz> = Arc::new(
        AuthzImpl::new(ChainConfigBuilder::default())
            .await
            .expect("Failed to initialize Authz"),
    );

    let bulletin: Arc<dyn Bulletin + Send + Sync> = Arc::new(
        DummyBulletin::new()
            .await
            .expect("Failed to initialize bulletin"),
    );

    let config = NodeConfig {
        args: Args {
            addr: "127.0.0.1:0".to_string(),
            log_level: LogLevel::Info,
            authz_grpc: None,
            bulletin_grpc: None,
            chain_rest: None,
            chain_rpc: None,
            denom: None,
            metrics_addr: None,
            loki_url: None,
        },
        network,
        local_storage,
        authz,
        bulletin,
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
    cleanup_db(&db_path);
}

// ============================================================================
// derive_secret_key_bytes tests
// ============================================================================

#[test]
fn test_valid_hex_input() {
    // 64-char hex (32 bytes) should be decoded directly
    let hex_input = "a".repeat(64);
    let result = derive_secret_key_bytes(&hex_input);
    assert!(result.is_ok());

    let bytes = result.unwrap();
    assert_eq!(bytes, [0xaa; 32]);
}

#[test]
fn test_valid_passphrase() {
    // 16+ char passphrase should be hashed
    let passphrase = "this-is-a-valid-passphrase";
    let result = derive_secret_key_bytes(passphrase);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 32);
}

#[test]
fn test_short_passphrase_rejected() {
    // Less than 16 chars should fail
    let short = "tooshort";
    let result = derive_secret_key_bytes(short);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("at least 16 characters"));
}

#[test]
fn test_deterministic_output() {
    // Same input should always produce same output
    let input = "my-deterministic-secret";
    let result1 = derive_secret_key_bytes(input).unwrap();
    let result2 = derive_secret_key_bytes(input).unwrap();
    assert_eq!(result1, result2);
}

#[tokio::test]
async fn test_deterministic_peer_id_from_secret() {
    // Same secret should produce same peer ID across network instances
    let secret = "my-deterministic-node-identity";
    let secret_key_bytes = derive_secret_key_bytes(secret).unwrap();

    // Create first network with secret key
    let secret_key1 = network::SecretKey::from_bytes(&secret_key_bytes);
    let network1 = NetworkImpl::builder()
        .secret_key(secret_key1)
        .build()
        .await
        .expect("Failed to create first network");
    let peer_id1 = network1.local_peer_id();

    // Create second network with same secret key
    let secret_key2 = network::SecretKey::from_bytes(&secret_key_bytes);
    let network2 = NetworkImpl::builder()
        .secret_key(secret_key2)
        .build()
        .await
        .expect("Failed to create second network");
    let peer_id2 = network2.local_peer_id();

    // Peer IDs should be identical
    assert_eq!(
        peer_id1.as_bytes(),
        peer_id2.as_bytes(),
        "Same secret should produce same peer ID"
    );
}

// ============================================================================
// create_and_store_node_key tests
// ============================================================================

#[test]
fn test_create_and_store_node_key() {
    use common::blockchain::ChainConfig;

    let db_path = test_db_path("test_create_and_store_node_key");
    let local_storage = LocalStorageImpl::new(Some("test-password".to_string()), db_path.clone())
        .expect("Failed to create local storage");

    let config = ChainConfig::local();

    // First call should create a new key
    let result = create_and_store_node_key(local_storage.clone(), config.clone());
    assert!(
        result.is_ok(),
        "Should create key successfully: {:?}",
        result.err()
    );

    let signer1 = result.unwrap();
    let address1 = signer1.address();
    assert!(
        address1.starts_with("source1"),
        "Address should be bech32 with source1 prefix, got: {}",
        address1
    );

    // Second call should return the same address (idempotent)
    let result2 = create_and_store_node_key(local_storage.clone(), config);
    assert!(result2.is_ok(), "Second call should succeed");

    let signer2 = result2.unwrap();
    let address2 = signer2.address();
    assert_eq!(
        address1, address2,
        "Same key should be returned on subsequent calls"
    );

    cleanup_db(&db_path);
}
