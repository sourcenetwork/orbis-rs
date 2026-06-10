//! In-process protocol tests with real SourceHub.
//!
//! Spins up three orbis nodes IN-PROCESS (no Docker node images) and runs full
//! DKG/PRE/SIGN protocols against them via gRPC, while SourceHub runs in Docker
//! (docker-compose-sourcehub-test.yml).
//!
//! Run with:
//!   cargo test --features integration-test -- --nocapture

use crate::{
    constants::{
        GRPC_CONCURRENCY_LIMIT_PER_CONNECTION, GRPC_MAX_CONCURRENT_STREAMS, MIN_NODE_BALANCE,
    },
    dkg::v0::service::DkgServiceImpl,
    helpers::{
        launch::{create_and_store_node_key, LogLevel},
        test_helpers::{
            cleanup_db, create_orbis_ring_policy, create_ring_on_chain, test_db_path,
            wait_for_nodes_ready, wait_for_ring_finalized,
        },
    },
    info::InfoServiceImpl,
    init_node,
    pre::v0::service::PreServiceImpl,
    sign::v0::service::SignServiceImpl,
    store_secret::StoreSecretServiceImpl,
    Args, NodeConfig,
};
use authz::r#trait::Authz;
use authz::AuthzImpl;
use bulletin::r#trait::{Bulletin, BulletinWriteKind, NodeInfo};
use bulletin::BulletinImpl;
use common::{blockchain::ChainConfigBuilder, SourceHubTestContainer};
use crypto::{helpers::generate_keypair, CryptoSerialize, DkgImpl, PreImpl, SignImpl};
use local_storage::{r#trait::LocalStorage, LocalStorageImpl};
use network::{Network, NetworkImpl};
use proto::{
    info_service::{
        info_service_client::InfoServiceClient, info_service_server::InfoServiceServer,
        GetRingStateRequest,
    },
    v0::dkg::dkg_service_server::DkgServiceServer,
    v0::pre::pre_service_server::PreServiceServer,
    v0::sign::sign_service_server::SignServiceServer,
    v0::store_secret::store_secret_service_server::StoreSecretServiceServer,
};
use std::sync::Arc;
use tokio::time::Duration;
use tonic::Request;

/// A running in-process orbis node with its gRPC server.
struct LiveNodeHandle {
    grpc_endpoint: String,
    _peer_addr: String,
    _public_address: String,
    db_path: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for LiveNodeHandle {
    fn drop(&mut self) {
        self.task.abort();
        cleanup_db(&self.db_path);
    }
}

/// Three in-process orbis nodes backed by a real SourceHub chain.
struct LiveThreeNodeNetwork {
    alice: LiveNodeHandle,
    _bob: LiveNodeHandle,
    _charlie: LiveNodeHandle,
    /// ACP policy ID all three nodes are whitelisted for.
    policy_id: String,
    /// Compressed pubkeys of alice, bob, charlie (in that order).
    node_keys: Vec<String>,
    /// Keeps the SourceHub Docker container alive via RAII.
    _chain: SourceHubTestContainer,
}

/// Four in-process nodes: all four participate in DKG.
struct LiveFourNodeNetwork {
    alice: LiveNodeHandle,
    bob: LiveNodeHandle,
    charlie: LiveNodeHandle,
    non_participant: LiveNodeHandle,
    /// ACP policy ID all four nodes are whitelisted for.
    policy_id: String,
    /// Compressed pubkeys of alice, bob, charlie, non_participant (in that order).
    node_keys: Vec<String>,
    _chain: SourceHubTestContainer,
}

/// Build and spawn a gRPC server from an `InitializedNode`.
///
/// Returns a `JoinHandle<()>` — abort it to stop the server.
/// Unlike `run_server`, this skips metrics registration (test-only).
fn spawn_test_grpc_server(node: crate::InitializedNode) -> tokio::task::JoinHandle<()> {
    let dkg_service = DkgServiceImpl::<DkgImpl>::new((*node.app_state).clone());
    let pre_service = PreServiceImpl::<DkgImpl, PreImpl>::new((*node.app_state).clone());
    let info_service = InfoServiceImpl::<DkgImpl>::new((*node.app_state).clone());
    let store_secret_service =
        StoreSecretServiceImpl::<DkgImpl, SignImpl>::new((*node.app_state).clone());
    let sign_service = SignServiceImpl::<DkgImpl, SignImpl>::new((*node.app_state).clone());

    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(DkgServiceServer::new(dkg_service))
            .add_service(PreServiceServer::new(pre_service))
            .add_service(InfoServiceServer::new(info_service))
            .add_service(StoreSecretServiceServer::new(store_secret_service))
            .add_service(SignServiceServer::new(sign_service))
            .serve(node.grpc_addr)
            .await;
        // Best-effort router cleanup when the server stops (e.g. on task abort)
        let _ = node.router.shutdown().await;
    })
}

/// Start SourceHub (via Docker) and three in-process orbis nodes.
///
/// Each node gets:
/// - A unique funded signing key (for bulletin posting)
/// - Its own local-storage DB at `test_dbs/<db_prefix>_<i>.redb`
/// - A gRPC server on `127.0.0.1:(base_port + i)`
/// - An OS-assigned iroh P2P port
/// - NodeInfo registered on-chain (whitelisted for the shared policy)
///
/// Waits until all three gRPC servers are ready before returning.
async fn setup_live_three_node_network(db_prefix: &str, base_port: u16) -> LiveThreeNodeNetwork {
    let chain = SourceHubTestContainer::new();

    let policy_id = create_orbis_ring_policy().await;

    let mut handles: Vec<LiveNodeHandle> = Vec::new();
    let mut node_keys: Vec<String> = Vec::new();

    for i in 0..3u16 {
        let port = base_port + i;
        let db_path = test_db_path(&format!("{}_{}", db_prefix, i));
        cleanup_db(&db_path); // clear any leftover from a previous failed run

        let local_storage = LocalStorageImpl::new(None, db_path.clone()).expect("local storage");

        // Create signing key (stored in local_storage) and fund it via the faucet
        let signer =
            create_and_store_node_key(local_storage.clone(), ChainConfigBuilder::default().build())
                .expect("create node signing key");
        let public_address = signer.address();
        let node_key = signer.public_key_hex();

        cli_tool::fund(
            public_address.clone(),
            ChainConfigBuilder::default().build(),
        )
        .await
        .expect("fund node account via faucet");

        // Real bulletin backed by SourceHub (uses the funded signer to post)
        let bulletin: Arc<dyn Bulletin + Send + Sync> = Arc::new(
            BulletinImpl::with_signer(
                ChainConfigBuilder::default(),
                signer,
                Some(MIN_NODE_BALANCE),
            )
            .await
            .expect("BulletinImpl with signer"),
        );

        // Real authz backed by SourceHub
        let authz: Arc<dyn Authz> = Arc::new(
            AuthzImpl::new(ChainConfigBuilder::default())
                .await
                .expect("AuthzImpl"),
        );

        // Iroh P2P network (loopback, OS-assigned port)
        let network: Arc<dyn Network> = Arc::new(NetworkImpl::new().await.expect("NetworkImpl"));

        let local_address = network.local_address().expect("network local_address");
        let p2p_socket = network
            .bound_addresses()
            .first()
            .copied()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "127.0.0.1:0".to_string());
        let peer_addr = format!("{}@{}", local_address, p2p_socket);

        // Register NodeInfo on-chain so the DKG service can look up this node's peer_id.
        let node_info_bytes: Vec<u8> = NodeInfo {
            peer_id: peer_addr.clone(),
            controller_key: node_key.clone(),
            whitelisted_policy_ids: vec![policy_id.clone()],
            whitelisted_ring_ids: vec![],
        }
        .try_into()
        .expect("serialize NodeInfo");
        bulletin
            .post(BulletinWriteKind::NodeInfo, node_info_bytes)
            .await
            .expect("register NodeInfo on-chain");

        node_keys.push(node_key.clone());

        let grpc_bind = format!("127.0.0.1:{}", port);
        let config = NodeConfig {
            args: Args {
                addr: grpc_bind.clone(),
                log_level: LogLevel::Info,
                authz_grpc: None,
                bulletin_grpc: None,
                chain_rest: None,
                chain_rpc: None,
                denom: None,
                metrics_addr: None,
                loki_url: None,
                reshare_interval_secs: 0,
                node_controller_key: node_key.clone(),
                node_peer_id: None,
                node_whitelisted_policy_ids: vec![policy_id.clone()],
                node_whitelisted_ring_ids: vec![],
                grpc_concurrency_limit_per_connection: GRPC_CONCURRENCY_LIMIT_PER_CONNECTION,
                grpc_max_concurrent_streams: GRPC_MAX_CONCURRENT_STREAMS,
            },
            node_key,
            network,
            local_storage,
            authz,
            bulletin,
        };

        let node = init_node(config).await.expect("init_node");
        let task = spawn_test_grpc_server(node);

        handles.push(LiveNodeHandle {
            grpc_endpoint: format!("http://{}", grpc_bind),
            _peer_addr: peer_addr,
            _public_address: public_address,
            db_path,
            task,
        });
    }

    // Wait until all three gRPC servers are accepting connections
    let endpoints: Vec<&str> = handles.iter().map(|h| h.grpc_endpoint.as_str()).collect();
    wait_for_nodes_ready(&endpoints, 30, Duration::from_millis(200)).await;

    let mut it = handles.into_iter();
    LiveThreeNodeNetwork {
        alice: it.next().unwrap(),
        _bob: it.next().unwrap(),
        _charlie: it.next().unwrap(),
        policy_id,
        node_keys,
        _chain: chain,
    }
}

async fn setup_live_four_node_network(db_prefix: &str, base_port: u16) -> LiveFourNodeNetwork {
    let chain = SourceHubTestContainer::new();

    let policy_id = create_orbis_ring_policy().await;

    let mut handles: Vec<LiveNodeHandle> = Vec::new();
    let mut node_keys: Vec<String> = Vec::new();

    for i in 0..4u16 {
        let port = base_port + i;
        let db_path = test_db_path(&format!("{}_{}", db_prefix, i));
        cleanup_db(&db_path);

        let local_storage = LocalStorageImpl::new(None, db_path.clone()).expect("local storage");

        let signer =
            create_and_store_node_key(local_storage.clone(), ChainConfigBuilder::default().build())
                .expect("create node signing key");
        let public_address = signer.address();
        let node_key = signer.public_key_hex();

        cli_tool::fund(
            public_address.clone(),
            ChainConfigBuilder::default().build(),
        )
        .await
        .expect("fund node account via faucet");

        let bulletin: Arc<dyn Bulletin + Send + Sync> = Arc::new(
            BulletinImpl::with_signer(
                ChainConfigBuilder::default(),
                signer,
                Some(MIN_NODE_BALANCE),
            )
            .await
            .expect("BulletinImpl with signer"),
        );

        let authz: Arc<dyn Authz> = Arc::new(
            AuthzImpl::new(ChainConfigBuilder::default())
                .await
                .expect("AuthzImpl"),
        );

        let network: Arc<dyn Network> = Arc::new(NetworkImpl::new().await.expect("NetworkImpl"));

        let local_address = network.local_address().expect("network local_address");
        let p2p_socket = network
            .bound_addresses()
            .first()
            .copied()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "127.0.0.1:0".to_string());
        let peer_addr = format!("{}@{}", local_address, p2p_socket);

        let node_info_bytes: Vec<u8> = NodeInfo {
            peer_id: peer_addr.clone(),
            controller_key: node_key.clone(),
            whitelisted_policy_ids: vec![policy_id.clone()],
            whitelisted_ring_ids: vec![],
        }
        .try_into()
        .expect("serialize NodeInfo");
        bulletin
            .post(BulletinWriteKind::NodeInfo, node_info_bytes)
            .await
            .expect("register NodeInfo on-chain");

        node_keys.push(node_key.clone());

        let grpc_bind = format!("127.0.0.1:{}", port);
        let config = NodeConfig {
            args: Args {
                addr: grpc_bind.clone(),
                log_level: LogLevel::Info,
                authz_grpc: None,
                bulletin_grpc: None,
                chain_rest: None,
                chain_rpc: None,
                denom: None,
                metrics_addr: None,
                loki_url: None,
                reshare_interval_secs: 0,
                node_controller_key: node_key.clone(),
                node_peer_id: None,
                node_whitelisted_policy_ids: vec![policy_id.clone()],
                node_whitelisted_ring_ids: vec![],
                grpc_concurrency_limit_per_connection: GRPC_CONCURRENCY_LIMIT_PER_CONNECTION,
                grpc_max_concurrent_streams: GRPC_MAX_CONCURRENT_STREAMS,
            },
            node_key,
            network,
            local_storage,
            authz,
            bulletin,
        };

        let node = init_node(config).await.expect("init_node");
        let task = spawn_test_grpc_server(node);

        handles.push(LiveNodeHandle {
            grpc_endpoint: format!("http://{}", grpc_bind),
            _peer_addr: peer_addr,
            _public_address: public_address,
            db_path,
            task,
        });
    }

    let endpoints: Vec<&str> = handles.iter().map(|h| h.grpc_endpoint.as_str()).collect();
    wait_for_nodes_ready(&endpoints, 30, Duration::from_millis(200)).await;

    let mut it = handles.into_iter();
    LiveFourNodeNetwork {
        alice: it.next().unwrap(),
        bob: it.next().unwrap(),
        charlie: it.next().unwrap(),
        non_participant: it.next().unwrap(),
        policy_id,
        node_keys,
        _chain: chain,
    }
}

// =========================================================================
// Shared helpers
// =========================================================================

/// Create a ring on-chain, run DKG, and return `(ring_pk_hex, ring_id)` once
/// all participant nodes have called FinalizeRing and the chain confirms.
async fn setup_ring(
    endpoint: &str,
    node_keys: &[String],
    threshold: u32,
    policy_id: &str,
) -> (String, String) {
    let ring_id = create_ring_on_chain(node_keys, threshold, policy_id, None).await;

    cli_tool::do_dkg(endpoint.to_string(), ring_id.clone())
        .await
        .expect("DKG initiation");

    let ring_pk = wait_for_ring_finalized(&ring_id, Duration::from_secs(90)).await;
    (ring_pk, ring_id)
}

// =========================================================================
// Tests
// =========================================================================

/// Two DKG sessions initiated simultaneously on the same three-node network
/// must both complete independently without cross-session interference.
///
/// This exercises `SessionStateManager` under concurrent load: both sessions
/// are created at the same time, each producing its own ring key and bulletin
/// post, with no deadlock or state leakage between them.
#[tokio::test]
#[serial_test::serial]
async fn test_two_simultaneous_dkg_sessions() {
    let net = setup_live_three_node_network("dual_dkg", 51051).await;

    let endpoint = net.alice.grpc_endpoint.clone();

    // Create two separate rings (different nonces → different ring IDs)
    let ring_id_1 =
        create_ring_on_chain(&net.node_keys, 2, &net.policy_id, Some("session-1")).await;
    let ring_id_2 =
        create_ring_on_chain(&net.node_keys, 2, &net.policy_id, Some("session-2")).await;

    assert_ne!(
        ring_id_1, ring_id_2,
        "distinct nonces must produce distinct ring IDs"
    );

    // Launch both DKG sessions concurrently from the same endpoint
    let (r1, r2) = tokio::join!(
        cli_tool::do_dkg(endpoint.clone(), ring_id_1.clone()),
        cli_tool::do_dkg(endpoint.clone(), ring_id_2.clone()),
    );

    let session1 = r1.expect("DKG 1 initiation failed").session_id;
    let session2 = r2.expect("DKG 2 initiation failed").session_id;
    assert_ne!(
        session1, session2,
        "concurrent DKGs must receive distinct session IDs"
    );

    let timeout = Duration::from_secs(90);
    let (pk1, pk2) = tokio::join!(
        wait_for_ring_finalized(&ring_id_1, timeout),
        wait_for_ring_finalized(&ring_id_2, timeout),
    );

    assert!(!pk1.is_empty(), "DKG 1 must produce a ring key");
    assert!(!pk2.is_empty(), "DKG 2 must produce a ring key");

    println!(
        "Both DKGs completed successfully:\n  ring1={} pk={}\n  ring2={} pk={}",
        ring_id_1,
        &pk1[..8.min(pk1.len())],
        ring_id_2,
        &pk2[..8.min(pk2.len())],
    );
}

/// Three PRE decryption requests on the same ciphertext must all complete
/// concurrently and return the original plaintext.
///
/// This exercises `PreResponseManager` under concurrent load: all three
/// requests are in flight simultaneously, each collecting threshold
/// re-encryption shares from the responder nodes.
#[tokio::test]
#[serial_test::serial]
async fn test_concurrent_pre_requests() {
    let net = setup_live_three_node_network("concurrent_pre", 51054).await;
    let endpoint = net.alice.grpc_endpoint.clone();

    // Step 1: DKG → ring
    let (ring_pk_hex, ring_id) = setup_ring(&endpoint, &net.node_keys, 2, &net.policy_id).await;

    // Step 2: Store one encrypted secret on the bulletin
    let policy_id = cli_tool::add_policy_to_chain().await.expect("add policy");
    let resource = "document".to_string();
    let permission = "read".to_string();
    let secret = b"concurrent-pre-plaintext";

    let prepared = cli_tool::prepare_secret(
        secret,
        &ring_pk_hex,
        None,
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        None,
        None,
        None,
    )
    .expect("prepare secret");

    let obj_resp = cli_tool::store_prepared_secret(
        endpoint.clone(),
        &prepared,
        ring_id.clone(),
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        None,
        true,
        None,
        None,
    )
    .await
    .expect("store prepared secret");
    let object_id = obj_resp.object_id;

    // Step 3: Authz — register the object and grant read access to the test DID
    let did = "pre_reader".to_string();
    cli_tool::register_object_to_chain(policy_id.clone(), object_id.clone(), resource.clone())
        .await
        .expect("register object to chain");
    cli_tool::set_relationship_on_chain(
        policy_id.clone(),
        object_id.clone(),
        resource.clone(),
        "reader".to_string(),
        Some(did.clone()),
    )
    .await
    .expect("set relationship on chain");

    // Step 4: Generate a reader keypair
    let (reader_sk, reader_pk) = generate_keypair().expect("generate reader keypair");
    let reader_sk_hex =
        hex::encode(CryptoSerialize::to_bytes(&reader_sk).expect("serialize reader sk"));
    let reader_pk_hex =
        hex::encode(CryptoSerialize::to_bytes(&reader_pk).expect("serialize reader pk"));

    // Step 5: Three concurrent PRE decryptions
    let (r1, r2, r3) = tokio::join!(
        cli_tool::do_pre(
            endpoint.clone(),
            ring_pk_hex.clone(),
            reader_pk_hex.clone(),
            Some(reader_sk_hex.clone()),
            object_id.clone(),
            Some(did.clone()),
            None,
            None,
            None,
            None,
            false,
        ),
        cli_tool::do_pre(
            endpoint.clone(),
            ring_pk_hex.clone(),
            reader_pk_hex.clone(),
            Some(reader_sk_hex.clone()),
            object_id.clone(),
            Some(did.clone()),
            None,
            None,
            None,
            None,
            false,
        ),
        cli_tool::do_pre(
            endpoint.clone(),
            ring_pk_hex.clone(),
            reader_pk_hex.clone(),
            Some(reader_sk_hex.clone()),
            object_id.clone(),
            Some(did.clone()),
            None,
            None,
            None,
            None,
            false,
        ),
    );

    let d1 = r1.expect("PRE 1 failed");
    let d2 = r2.expect("PRE 2 failed");
    let d3 = r3.expect("PRE 3 failed");

    assert_eq!(d1.as_slice(), secret.as_ref(), "PRE 1 plaintext mismatch");
    assert_eq!(d2.as_slice(), secret.as_ref(), "PRE 2 plaintext mismatch");
    assert_eq!(d3.as_slice(), secret.as_ref(), "PRE 3 plaintext mismatch");

    println!("All 3 concurrent PRE requests decrypted successfully.");
}

/// Three threshold-BLS signing requests on the same ring running simultaneously
/// must all complete without deadlock or nonce reuse.
///
/// This exercises `SignResponseManager` and `NonceStateManager` under concurrent
/// load: all three FROST signing sessions are in flight at the same time, each
/// collecting commitment and signing shares from the responder nodes.
#[tokio::test]
#[serial_test::serial]
async fn test_concurrent_sign_requests() {
    let net = setup_live_three_node_network("concurrent_sign", 51057).await;
    let endpoint = net.alice.grpc_endpoint.clone();

    // Step 1: DKG → ring
    let (ring_pk_hex, ring_id) = setup_ring(&endpoint, &net.node_keys, 2, &net.policy_id).await;

    // Step 2: Add a policy (required as payload metadata; authz enforcement is PRE-only)
    let policy_id = cli_tool::add_policy_to_chain().await.expect("add policy");
    let resource = "document".to_string();
    let permission = "read".to_string();

    // Prepare three distinct secrets — each produces a separate bulletin post + signature
    let secrets: [&[u8]; 3] = [b"sign-secret-one", b"sign-secret-two", b"sign-secret-three"];
    let preps: Vec<_> = secrets
        .iter()
        .map(|s| {
            cli_tool::prepare_secret(
                s,
                &ring_pk_hex,
                None,
                policy_id.clone(),
                resource.clone(),
                permission.clone(),
                None,
                None,
                None,
            )
            .expect("prepare secret")
        })
        .collect();

    // Step 3: Three concurrent store_prepared_secret calls
    //         Each triggers a full FROST threshold BLS signing round-trip
    let (r1, r2, r3) = tokio::join!(
        cli_tool::store_prepared_secret(
            endpoint.clone(),
            &preps[0],
            ring_id.clone(),
            policy_id.clone(),
            resource.clone(),
            permission.clone(),
            None,
            true,
            None,
            None,
        ),
        cli_tool::store_prepared_secret(
            endpoint.clone(),
            &preps[1],
            ring_id.clone(),
            policy_id.clone(),
            resource.clone(),
            permission.clone(),
            None,
            true,
            None,
            None,
        ),
        cli_tool::store_prepared_secret(
            endpoint.clone(),
            &preps[2],
            ring_id.clone(),
            policy_id.clone(),
            resource.clone(),
            permission.clone(),
            None,
            true,
            None,
            None,
        ),
    );

    let resp1 = r1.expect("SIGN 1 failed");
    let resp2 = r2.expect("SIGN 2 failed");
    let resp3 = r3.expect("SIGN 3 failed");

    // Each distinct secret must produce a distinct object and a non-empty signature
    assert!(
        !resp1.object_id.is_empty(),
        "SIGN 1 must produce an object_id"
    );
    assert!(
        !resp2.object_id.is_empty(),
        "SIGN 2 must produce an object_id"
    );
    assert!(
        !resp3.object_id.is_empty(),
        "SIGN 3 must produce an object_id"
    );
    assert!(
        !resp1.signature.is_empty(),
        "SIGN 1 must produce a signature"
    );
    assert!(
        !resp2.signature.is_empty(),
        "SIGN 2 must produce a signature"
    );
    assert!(
        !resp3.signature.is_empty(),
        "SIGN 3 must produce a signature"
    );
    assert_ne!(
        resp1.object_id, resp2.object_id,
        "distinct secrets must produce distinct bulletin posts"
    );
    assert_ne!(
        resp1.object_id, resp3.object_id,
        "distinct secrets must produce distinct bulletin posts"
    );
    assert_ne!(
        resp2.object_id, resp3.object_id,
        "distinct secrets must produce distinct bulletin posts"
    );

    println!(
        "All 3 concurrent SIGN requests completed:\n  obj1={}\n  obj2={}\n  obj3={}",
        resp1.object_id, resp2.object_id, resp3.object_id,
    );
}

/// DKG must complete when `StartDkg` is invoked on any ring participant.
///
/// Verifies the Phase 1 fix: every participant starts phase 1 upon receiving
/// `SessionInit` without waiting for the initiator to drive them. The four-node
/// setup lets us confirm DKG completes even when initiated from the last node
/// (non_participant here is also a ring participant).
#[tokio::test]
#[serial_test::serial]
async fn test_dkg_non_participant_initiator_completes() {
    let net = setup_live_four_node_network("dkg_non_participant", 51070).await;

    // Create a ring with all four nodes as participants (threshold=2)
    let ring_id = create_ring_on_chain(&net.node_keys, 2, &net.policy_id, None).await;

    // Initiate DKG from the last node's endpoint (non_participant)
    cli_tool::do_dkg(net.non_participant.grpc_endpoint.clone(), ring_id.clone())
        .await
        .expect("DKG from non_participant initiator");

    let ring_pk_hex = wait_for_ring_finalized(&ring_id, Duration::from_secs(90)).await;

    async fn assert_has_ring_state(grpc_endpoint: &str, ring_pk_hex: &str) {
        let mut client = InfoServiceClient::connect(grpc_endpoint.to_string())
            .await
            .expect("connect InfoService");
        let resp = client
            .get_ring_state(Request::new(GetRingStateRequest {
                ring_pk_hex: ring_pk_hex.to_string(),
            }))
            .await
            .expect("participant must store ring state after DKG");
        assert!(
            !resp.into_inner().public_polynomial.is_empty(),
            "public_polynomial must be populated"
        );
    }

    assert_has_ring_state(&net.alice.grpc_endpoint, &ring_pk_hex).await;
    assert_has_ring_state(&net.bob.grpc_endpoint, &ring_pk_hex).await;
    assert_has_ring_state(&net.charlie.grpc_endpoint, &ring_pk_hex).await;
    assert_has_ring_state(&net.non_participant.grpc_endpoint, &ring_pk_hex).await;
}
