//! Tests for the orbis-node main module
//!
//! These tests verify the node initialization and configuration logic,
//! as well as compatibility with cli-tool.

use crate::{
    helpers::{
        launch::{create_and_store_node_key, derive_secret_key_bytes, LogLevel},
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

/// Test that encrypted storage works with the node
#[tokio::test]
#[serial_test::serial]
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
// CLI-TOOL INTEGRATION TESTS
// ============================================================================
// These tests spin up real orbis-node servers and call cli-tool functions
// against them. If orbis-node changes break cli-tool, these tests will fail.

mod cli_tool_integration {
    use crate::constants::{BULLETIN_PLACEHOLDER_PROOF, BULLETIN_RING_NAMESPACE};
    use ark_bls12_381::{Fr, G1Affine, G1Projective};
    use ark_ec::Group;
    use ark_std::UniformRand;
    use bulletin::r#trait::{BulletinPost, DocumentPayload, RingPayload};
    use bulletin::sourcehub::SourceHubBulletin;
    use common::IntegrationTestNetwork;
    use crypto::bls12_381::pre::ThresholdDealerNode;
    use crypto::bls12_381::sign::ThresholdBlsSigner;
    use crypto::r#trait::{ThresholdDealer, ThresholdSigner};
    use crypto::{CryptoDeserialize, CryptoSerialize};
    use rand_core::OsRng;
    use tokio::time::{sleep, Duration};

    /// Docker-based integration test: Run DKG and PRE using Docker Compose
    ///
    /// This test spins up a full integration environment with:
    /// - SourceHub chain
    /// - 3 Orbis nodes
    ///
    /// Then runs the full DKG -> PRE workflow via CLI commands.
    #[tokio::test]
    #[serial_test::serial]
    async fn test_cli_calls_dkg_and_pre_endpoint() {
        // use tracing_subscriber;
        // // Initialize tracing for debugging
        // let _ = tracing_subscriber::fmt()
        //     .with_max_level(tracing::Level::DEBUG)
        //     .with_test_writer()
        //     .try_init();

        println!("Starting Docker-based integration test...");

        // Start the full integration network (sourcehub + 3 nodes)
        let _network = IntegrationTestNetwork::new();

        // Wait for all nodes to be ready by polling their gRPC endpoints
        crate::helpers::test_helpers::wait_for_nodes_ready(
            &[
                IntegrationTestNetwork::NODE1_GRPC,
                IntegrationTestNetwork::NODE2_GRPC,
                IntegrationTestNetwork::NODE3_GRPC,
            ],
            90,
            Duration::from_secs(1),
        )
        .await;

        // Query node info from all three nodes to get their peer IDs
        let node1_info = cli_tool::query_node_info(IntegrationTestNetwork::NODE1_GRPC.to_string())
            .await
            .expect("Failed to query node1 info");
        let node2_info = cli_tool::query_node_info(IntegrationTestNetwork::NODE2_GRPC.to_string())
            .await
            .expect("Failed to query node2 info");
        let node3_info = cli_tool::query_node_info(IntegrationTestNetwork::NODE3_GRPC.to_string())
            .await
            .expect("Failed to query node3 info");
        let node1_address = node1_info.public_address.clone();
        println!("Node 1 P2P address: {}", node1_info.p2p_address);
        println!("Node 2 P2P address: {}", node2_info.p2p_address);
        println!("Node 3 P2P address: {}", node3_info.p2p_address);

        // Register the namespace and add collaborators
        cli_tool::register_bulletin_namespace(BULLETIN_RING_NAMESPACE.to_string())
            .await
            .expect("Failed to register namespace");
        cli_tool::add_bulletin_collaborator(
            BULLETIN_RING_NAMESPACE.to_string(),
            node1_info.public_address.clone(),
        )
        .await
        .expect("add_bulletin_collaborator");
        cli_tool::add_bulletin_collaborator(
            BULLETIN_RING_NAMESPACE.to_string(),
            node2_info.public_address.clone(),
        )
        .await
        .expect("add_bulletin_collaborator");
        cli_tool::add_bulletin_collaborator(
            BULLETIN_RING_NAMESPACE.to_string(),
            node3_info.public_address.clone(),
        )
        .await
        .expect("add_bulletin_collaborator");
        // Transform P2P addresses for inter-container communication
        // The addresses from nodes will be like "peer_id@0.0.0.0:port"
        // We need to replace 0.0.0.0 with the container name for Docker networking
        let peer1_addr = IntegrationTestNetwork::transform_p2p_address(
            &node1_info.p2p_address,
            IntegrationTestNetwork::NODE1_CONTAINER,
        );
        let peer2_addr = IntegrationTestNetwork::transform_p2p_address(
            &node2_info.p2p_address,
            IntegrationTestNetwork::NODE2_CONTAINER,
        );
        let peer3_addr = IntegrationTestNetwork::transform_p2p_address(
            &node3_info.p2p_address,
            IntegrationTestNetwork::NODE3_CONTAINER,
        );

        println!("Transformed peer addresses for Docker networking:");
        println!("  Node 1: {}", peer1_addr);
        println!("  Node 2: {}", peer2_addr);
        println!("  Node 3: {}", peer3_addr);

        let peer_ids = vec![peer1_addr, peer2_addr, peer3_addr];
        let threshold = 2;
        let endpoint = IntegrationTestNetwork::NODE1_GRPC.to_string();

        let ring_namespace = BULLETIN_RING_NAMESPACE.to_string();

        // Step 1: Run DKG via CLI to get a ring public key
        println!(
            "Starting DKG with threshold {} and {} peers...",
            threshold,
            peer_ids.len()
        );
        let dkg_result = cli_tool::do_dkg(endpoint.clone(), threshold, peer_ids.clone()).await;
        assert!(
            dkg_result.is_ok(),
            "DKG should succeed: {:?}",
            dkg_result.err()
        );

        let _dkg_result = dkg_result.unwrap();
        println!("DKG initiated, waiting for completion...");

        // Wait for DKG to complete by polling the bulletin for the ring payload
        let max_wait = Duration::from_secs(60);
        let start = std::time::Instant::now();
        let mut ring_pk_hex = String::new();
        let mut ring_id = String::new();
        let mut dkg_ring_payload: Option<RingPayload> = None;

        // Poll bulletin until ring payload is posted (indicates DKG complete)
        // Bad way to handle this but wtv it is a test
        while start.elapsed() < max_wait {
            if let Ok(posts) = cli_tool::list_bulletin_posts(ring_namespace.clone()).await {
                if !posts.is_empty() {
                    // Parse the first post as RingPayload to get ring_pk (JSON serialized)
                    let ring_payload: RingPayload =
                        serde_json::from_slice(&posts[0]).expect("parse RingPayload");
                    ring_pk_hex = ring_payload.ring_pk.clone();

                    // Compute the ring_id from the post (it's deterministic based on namespace + payload)
                    let full_namespace = format!("bulletin/{}", ring_namespace);
                    ring_id = SourceHubBulletin::compute_post_id(&full_namespace, &posts[0]);
                    dkg_ring_payload = Some(ring_payload);
                    println!(
                        "DKG completed! Ring PK: {}..., Ring ID: {}",
                        &ring_pk_hex[..40.min(ring_pk_hex.len())],
                        &ring_id[..16.min(ring_id.len())]
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
        assert!(!ring_id.is_empty(), "Should have ring ID after DKG");
        let _dkg_ring_payload = dkg_ring_payload.expect("Should have ring payload after DKG");

        // Step 2: Generate reader keypair
        let mut rng = OsRng;
        let reader_sk = Fr::rand(&mut rng);
        let reader_pk: G1Affine = (G1Projective::generator() * reader_sk).into();

        let reader_sk_bytes = reader_sk.to_bytes().expect("serialize reader sk");
        let reader_pk_bytes = reader_pk.to_bytes().expect("serialize reader pk");
        let reader_sk_hex = hex::encode(&reader_sk_bytes);
        let reader_pk_hex = hex::encode(&reader_pk_bytes);

        let resource = "document".to_string();
        let relation = "reader".to_string();
        let permission = "read".to_string();
        let did_pk_string = "test_did_secret".to_string();
        let namespace = "docker_test_namespace".to_string();
        let full_namespace = format!("bulletin/{}", namespace);
        let policy_id = cli_tool::add_policy_to_chain().await.expect("policy_id");
        let proof = vec![0x01];

        cli_tool::register_bulletin_namespace(namespace.clone())
            .await
            .expect("Failed to register namespace");

        // Add node1 as collaborator on the user namespace so it can post on user's behalf
        cli_tool::add_bulletin_collaborator(namespace.clone(), node1_info.public_address.clone())
            .await
            .expect("add node as collaborator on user namespace");

        // ====================================================================
        // Create objects: MANUAL vs SERVICE
        // Both paths encrypt locally first, then post to bulletin
        // ====================================================================

        // Parse ring public key for encryption
        let ring_pk_bytes = hex::decode(&ring_pk_hex).expect("decode ring_pk hex");
        let ring_pk_point = G1Affine::from_bytes(&ring_pk_bytes).expect("deserialize ring_pk");

        // MANUAL PATH: Encrypt and post directly to bulletin
        let object_id_manual = {
            let (_enc_cmt, encrypted_secret, _proof) = ThresholdDealerNode::encrypt_secret(
                &ring_pk_point,
                b"Hello from manual path!",
                None,
            )
            .expect("encrypt secret");
            let payload = DocumentPayload {
                ring_id: ring_id.clone(),
                document: serde_json::to_string(&encrypted_secret).expect("serialize"),
                policy_id: policy_id.clone(),
                resource: resource.clone(),
                permission: permission.clone(),
            };
            let serialized: Vec<u8> = payload.try_into().expect("serialize payload");
            cli_tool::create_bulletin_post(namespace.clone(), serialized, proof)
                .await
                .expect("create_bulletin_post")
        };
        let secret = b"Hello from StoreSecret!";

        // SERVICE PATH: Prepare secret once (encrypt locally), then store
        // This allows testing idempotency by reusing the same prepared data
        let prepared_secret = cli_tool::prepare_secret(secret, &ring_pk_hex, None)
            .expect("prepare_secret should succeed");

        // Get sequence before first store to verify transaction is broadcast
        let sequence_before_first = cli_tool::get_account_sequence(&node1_address)
            .await
            .expect("get sequence before first store");
        println!(
            "Node1 sequence before first store: {}",
            sequence_before_first
        );

        let object_response = cli_tool::store_prepared_secret(
            endpoint.clone(),
            &prepared_secret,
            ring_id.clone(),
            namespace.clone(),
            policy_id.clone(),
            resource.clone(),
            permission.clone(),
            Some(did_pk_string.clone()),
            true,
        )
        .await
        .expect("store_prepared_secret");
        let object_id_service = object_response.object_id.clone();
        let signature_hex = object_response.signature.clone();

        // Wait for block confirmation and check sequence incremented
        sleep(Duration::from_secs(2)).await;
        let sequence_after_first = cli_tool::get_account_sequence(&node1_address)
            .await
            .expect("get sequence after first store");
        println!("Node1 sequence after first store: {}", sequence_after_first);
        assert!(
            sequence_after_first > sequence_before_first,
            "Sequence should increment after first store (tx was broadcast)"
        );

        // Read both from bulletin and compare metadata
        let manual_bytes =
            cli_tool::read_bulletin_post(full_namespace.clone(), object_id_manual.clone())
                .await
                .expect("read manual post");
        let service_bytes =
            cli_tool::read_bulletin_post(full_namespace.clone(), object_id_service.clone())
                .await
                .expect("read service post");

        let manual: DocumentPayload = serde_json::from_slice(&manual_bytes).expect("parse manual");
        let service: DocumentPayload =
            serde_json::from_slice(&service_bytes).expect("parse service");
        let bulletin_post = BulletinPost {
            id: object_id_service.clone(),
            namespace: namespace.clone(),
            payload: service_bytes.clone(),
            proof: BULLETIN_PLACEHOLDER_PROOF.to_vec(),
        };

        // Serialize BulletinPost to bytes (this is what was signed)
        let message_bytes: Vec<u8> = bulletin_post
            .try_into()
            .expect("serialize BulletinPost to bytes");

        assert_eq!(manual.ring_id, service.ring_id, "ring_id mismatch");
        assert_eq!(manual.policy_id, service.policy_id, "policy_id mismatch");
        assert_eq!(manual.resource, service.resource, "resource mismatch");
        assert_eq!(manual.permission, service.permission, "permission mismatch");

        // Verify the BLS signature against the ring public key
        // The signature was created over the serialized BulletinPost
        let signature_bytes = hex::decode(&signature_hex).expect("decode signature hex");
        let signature =
            <ThresholdBlsSigner as ThresholdSigner>::Signature::from_bytes(&signature_bytes)
                .expect("deserialize BLS signature");

        let ring_pk_bytes = hex::decode(&ring_pk_hex).expect("decode ring_pk hex");
        let ring_pk = G1Affine::from_bytes(&ring_pk_bytes).expect("deserialize ring public key");

        let signer = ThresholdBlsSigner::new();
        signer
            .verify(&ring_pk, &message_bytes, &signature)
            .expect("BLS signature should verify against ring public key");

        // Run PRE to verify full flow works
        cli_tool::register_object_to_chain(
            policy_id.clone(),
            object_id_manual.clone(),
            resource.clone(),
        )
        .await
        .expect("register_object_to_chain");

        cli_tool::set_relationship_on_chain(
            policy_id.clone(),
            object_id_manual.clone(),
            resource.clone(),
            relation,
            Some(did_pk_string.clone()),
        )
        .await
        .expect("set_relationship_on_chain");
        // Step 3: Run PRE via CLI
        println!("Running PRE...");
        let pre_result = cli_tool::do_pre(
            endpoint.clone(),
            ring_pk_hex.clone(),
            reader_pk_hex.clone(),
            reader_sk_hex.clone(),
            object_id_service.clone(),
            Some(did_pk_string.clone()),
            full_namespace.clone(),
            None,
        )
        .await;

        // The key test: CLI do_pre should succeed and return the original plaintext
        assert!(
            pre_result.is_ok(),
            "cli-tool do_pre should succeed against Docker orbis-nodes: {:?}",
            pre_result.err()
        );

        let decrypted = pre_result.unwrap();

        assert_eq!(
            decrypted, secret,
            "Decrypted secret should match original plaintext"
        );
        println!("PRE decryption verified: decrypted data matches original secret!");

        // Test idempotency: store the same prepared secret again
        // This should succeed and return the same object_id (no duplicate post)
        println!("Testing idempotency: storing same secret again...");

        // Get sequence before second store
        let sequence_before_second = cli_tool::get_account_sequence(&node1_address)
            .await
            .expect("get sequence before second store");
        println!(
            "Node1 sequence before second store: {}",
            sequence_before_second
        );

        let object_response_2 = cli_tool::store_prepared_secret(
            endpoint.clone(),
            &prepared_secret, // Same prepared data as first call
            ring_id.clone(),
            namespace.clone(),
            policy_id.clone(),
            resource.clone(),
            permission.clone(),
            Some(did_pk_string.clone()),
            true,
        )
        .await
        .expect("store_prepared_secret (idempotent call)");

        // Wait and check sequence did NOT change (no tx broadcast for idempotent call)
        sleep(Duration::from_secs(2)).await;
        let sequence_after_second = cli_tool::get_account_sequence(&node1_address)
            .await
            .expect("get sequence after second store");
        println!(
            "Node1 sequence after second store: {}",
            sequence_after_second
        );

        // Verify idempotency: same object_id should be returned
        assert_eq!(
            object_id_service, object_response_2.object_id,
            "Idempotency check: second store should return same object_id"
        );

        // Verify no transaction was broadcast (sequence unchanged)
        assert_eq!(
            sequence_before_second, sequence_after_second,
            "Idempotency check: sequence should NOT change (no tx broadcast for duplicate)"
        );

        println!(
            "Idempotency verified: both calls returned object_id {}, sequence unchanged at {}",
            object_id_service, sequence_after_second
        );

        // Cleanup happens automatically when _network is dropped
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
