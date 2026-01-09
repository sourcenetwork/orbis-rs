//! Tests for the orbis-node main module
//!
//! These tests verify the node initialization and configuration logic,
//! as well as compatibility with cli-tool.

use crate::{
    helpers::{
        launch::{derive_secret_key_bytes, LogLevel},
        test_helpers::{cleanup_db, test_db_path},
    },
    init_node, Args, NodeConfig,
};
use authz::r#trait::Authz;
use authz::sourcehub::SourceHubAuth;
use bulletin::dummy::DummyBulletin;
use bulletin::r#trait::Bulletin;
use common::blockchain::ChainConfigBuilder;
use local_storage::{r#trait::LocalStorage, LocalStorageImpl};
use network::Network;
use std::sync::Arc;

/// Test that the node initializes successfully with valid configuration
#[tokio::test]
async fn test_init_node_success() {
    let db_path = test_db_path("test_init_node_success");

    // Create a real network for testing
    let network: Arc<dyn Network> = Arc::new(
        network::IrohNetwork::new()
            .await
            .expect("Failed to create network"),
    );

    let authz: Arc<dyn Authz> = Arc::new(
        SourceHubAuth::new(ChainConfigBuilder::default())
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

    let network: Arc<dyn Network> = Arc::new(
        network::IrohNetwork::new()
            .await
            .expect("Failed to create network"),
    );

    let authz: Arc<dyn Authz> = Arc::new(
        SourceHubAuth::new(ChainConfigBuilder::default())
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

    let network: Arc<dyn Network> = Arc::new(
        network::IrohNetwork::new()
            .await
            .expect("Failed to create network"),
    );

    let authz: Arc<dyn Authz> = Arc::new(
        SourceHubAuth::new(ChainConfigBuilder::default())
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
        node.app_state.session_count().await,
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
        network::IrohNetwork::new()
            .await
            .expect("Failed to create network 1"),
    );
    let network2: Arc<dyn Network> = Arc::new(
        network::IrohNetwork::new()
            .await
            .expect("Failed to create network 2"),
    );

    let authz1: Arc<dyn Authz> = Arc::new(
        SourceHubAuth::new(ChainConfigBuilder::default())
            .await
            .expect("Failed to initialize Authz"),
    );
    let authz2: Arc<dyn Authz> = Arc::new(
        SourceHubAuth::new(ChainConfigBuilder::default())
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

/// Test that encrypted storage works with the node
#[tokio::test]
async fn test_init_node_with_encrypted_storage() {
    let db_path = test_db_path("test_init_node_with_encrypted_storage");

    let network: Arc<dyn Network> = Arc::new(
        network::IrohNetwork::new()
            .await
            .expect("Failed to create network"),
    );

    // Create storage with a password
    let password = "test-password-123".to_string();
    let local_storage = LocalStorageImpl::new(Some(password), db_path.clone())
        .expect("Failed to create local storage");
    let authz: Arc<dyn Authz> = Arc::new(
        SourceHubAuth::new(ChainConfigBuilder::default())
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
// CLI-TOOL INTEGRATION TESTS
// ============================================================================
// These tests spin up real orbis-node servers and call cli-tool functions
// against them. If orbis-node changes break cli-tool, these tests will fail.

mod cli_tool_integration {
    use crate::dkg::coordinator::DkgCoordinator;
    use crate::dkg::service::DkgServiceImpl;
    use crate::helpers::test_helpers::{
        cleanup_db, setup_three_node_network_with_pre, test_db_path,
    };
    use crate::pre::service::PreServiceImpl;
    use crate::{DkgImpl, PreImpl};
    use ark_bls12_381::{Fr, G1Affine, G1Projective};
    use ark_ec::Group;
    use ark_std::UniformRand;
    use common::SourceHubTestContainer;
    use crypto::r#trait::Dkg;
    use crypto::CryptoSerialize;
    use proto::dkg_service::dkg_service_server::DkgServiceServer;
    use proto::pre_service::pre_service_server::PreServiceServer;
    use rand_core::OsRng;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::time::{sleep, Duration};
    /// End-to-end test: Run DKG, then call cli-tool's do_pre function
    /// Tests cli-tool and just full integration test
    ///
    /// This tests the full user workflow:
    /// 1. Run DKG to generate distributed keys
    /// 2. Run PRE to re-encrypt a secret
    #[tokio::test]
    #[serial_test::serial]
    async fn test_cli_calls_dkg_and_pre_endpoint() {
        let db_name = "test_cli_calls_dkg_and_pre_endpoint";
        let db_paths = [
            test_db_path(&format!("{}_1", db_name)),
            test_db_path(&format!("{}_2", db_name)),
            test_db_path(&format!("{}_3", db_name)),
        ];

        // Spin up SourceHub container
        let _container = SourceHubTestContainer::new();
        // Set up three nodes
        let mut network = setup_three_node_network_with_pre(true, false, false, db_name).await;

        let peer_ids = network.get_all_peer_ids();

        // Start gRPC server for Alice
        let alice_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let dkg_service = DkgServiceImpl::<DkgImpl>::new(network.alice.app_state.clone());
        let pre_service = PreServiceImpl::<DkgImpl, PreImpl>::new(network.alice.app_state.clone());

        let listener = tokio::net::TcpListener::bind(alice_addr).await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let endpoint = format!("http://{}", server_addr);

        let server_handle = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(DkgServiceServer::new(dkg_service))
                .add_service(PreServiceServer::new(pre_service))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
        });

        sleep(Duration::from_millis(100)).await;

        // Step 1: Run DKG via CLI to get a ring public key
        let dkg_result = cli_tool::do_dkg(endpoint.clone(), 2, peer_ids.clone()).await;
        assert!(
            dkg_result.is_ok(),
            "DKG should succeed: {:?}",
            dkg_result.err()
        );
        let dkg_response = dkg_result.unwrap();
        let session_id: u64 = dkg_response.session_id.parse().expect("parse session_id");

        // Wait for DKG to complete and get the ring public key
        let max_wait = Duration::from_secs(30);
        let start = std::time::Instant::now();
        let mut ring_pk_hex = String::new();

        let alice_coordinator = DkgCoordinator::new(Arc::new(network.alice.app_state.clone()));

        while start.elapsed() < max_wait {
            if let Some(session) = alice_coordinator.get_session(&session_id).await {
                let session_guard = session.read().await;
                if let Ok(agg_key) = session_guard.compute_aggregate_public_key() {
                    // Serialize to bytes then hex (same format cli-tool uses)
                    let ring_pk_bytes = agg_key.to_bytes().expect("serialize ring pk");
                    ring_pk_hex = hex::encode(&ring_pk_bytes);
                    println!(
                        "DKG completed! Ring PK: {}...",
                        &ring_pk_hex[..40.min(ring_pk_hex.len())]
                    );
                    break;
                }
            }
            sleep(Duration::from_millis(500)).await;
        }

        assert!(
            !ring_pk_hex.is_empty(),
            "Should have ring public key after DKG"
        );

        // Step 2: Generate reader keypair (same as cli-tool generate-reader-key)
        let mut rng = OsRng;
        let reader_sk = Fr::rand(&mut rng);
        let reader_pk: G1Affine = (G1Projective::generator() * reader_sk).into();

        let reader_sk_bytes = reader_sk.to_bytes().expect("serialize reader sk");
        let reader_pk_bytes = reader_pk.to_bytes().expect("serialize reader pk");
        let reader_sk_hex = hex::encode(&reader_sk_bytes);
        let reader_pk_hex = hex::encode(&reader_pk_bytes);

        let resource = "document".to_string();
        let object_id = "object_id-123".to_string();
        let relation = "reader".to_string();
        let permission = "read".to_string();
        let did_pk_string = "test_did_secret".to_string();
        let policy_id = cli_tool::add_policy_to_chain().await.expect("policy_id");

        cli_tool::register_object_to_chain(policy_id.clone(), object_id.clone(), resource.clone())
            .await
            .expect("register_object_to_chain");

        cli_tool::set_relationship_on_chain(
            policy_id.clone(),
            object_id.clone(),
            resource.clone(),
            relation.clone(),
            Some(did_pk_string.clone()),
        )
        .await
        .expect("set_relationship_on_chain");
        // Step 3: Run PRE via CLI
        let secret = "Hello from CLI integration test!";

        let pre_result = cli_tool::do_pre(
            endpoint.clone(),
            ring_pk_hex,
            secret.to_string(),
            reader_pk_hex,
            reader_sk_hex,
            peer_ids,
            policy_id,
            resource,
            object_id,
            permission,
            Some(did_pk_string),
        )
        .await;

        // The key test: CLI do_pre should succeed against orbis-node
        assert!(
            pre_result.is_ok(),
            "cli-tool do_pre should succeed against orbis-node: {:?}",
            pre_result.err()
        );

        // Clean up
        server_handle.abort();
        network.shutdown_routers().await.unwrap();
        for path in &db_paths {
            cleanup_db(path);
        }
    }
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
    let network1 = network::IrohNetwork::builder()
        .secret_key(secret_key1)
        .build()
        .await
        .expect("Failed to create first network");
    let peer_id1 = network1.local_peer_id();

    // Create second network with same secret key
    let secret_key2 = network::SecretKey::from_bytes(&secret_key_bytes);
    let network2 = network::IrohNetwork::builder()
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
