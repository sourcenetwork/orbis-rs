//! In-process protocol tests with real SourceHub.
//!
//! Spins up three orbis nodes IN-PROCESS (no Docker node images) and runs full
//! DKG/PRE/SIGN protocols against them via gRPC, while SourceHub runs in Docker
//! (docker-compose-sourcehub-test.yml).
//!
//! Run with:
//!   cargo test --features integration-test -- --nocapture

use crate::helpers::test_helpers::{BULLETIN_RING_NAMESPACE, TEST_FRESH_DKG_RING_ID};
use crate::{
    constants::MIN_NODE_BALANCE,
    dkg::service::DkgServiceImpl,
    helpers::{
        launch::{create_and_store_node_key, LogLevel},
        test_helpers::{cleanup_db, test_db_path, wait_for_nodes_ready},
    },
    info::InfoServiceImpl,
    init_node,
    pre::service::PreServiceImpl,
    sign::service::SignServiceImpl,
    store_secret::StoreSecretServiceImpl,
    Args, NodeConfig,
};
use authz::r#trait::Authz;
use authz::AuthzImpl;
use bulletin::r#trait::{Bulletin, BulletinKind, RingPayload};
use bulletin::BulletinImpl;
use common::{
    blockchain::{events::BulletinEventSubscription, ChainConfigBuilder},
    SourceHubTestContainer, SOURCEHUB_RPC_URL,
};
use crypto::{helpers::generate_keypair, CryptoSerialize, DkgImpl, PreImpl, SignImpl};
use local_storage::{r#trait::LocalStorage, LocalStorageImpl};
use network::{Network, NetworkImpl};
use proto::{
    dkg_service::dkg_service_server::DkgServiceServer,
    info_service::{
        info_service_client::InfoServiceClient, info_service_server::InfoServiceServer,
        GetRingStateRequest,
    },
    pre_service::pre_service_server::PreServiceServer,
    sign_service::sign_service_server::SignServiceServer,
    store_secret_service::store_secret_service_server::StoreSecretServiceServer,
};
use std::sync::Arc;
use tokio::time::Duration;
use tonic::Request;

/// A running in-process orbis node with its gRPC server.
struct LiveNodeHandle {
    grpc_endpoint: String,
    peer_addr: String,
    public_address: String,
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
    bob: LiveNodeHandle,
    charlie: LiveNodeHandle,
    /// Keeps the SourceHub Docker container alive via RAII.
    _chain: SourceHubTestContainer,
}

impl LiveThreeNodeNetwork {
    fn peer_addrs(&self) -> Vec<String> {
        vec![
            self.alice.peer_addr.clone(),
            self.bob.peer_addr.clone(),
            self.charlie.peer_addr.clone(),
        ]
    }
}

/// Four in-process nodes: three DKG participants plus one extra used only as gRPC initiator.
struct LiveFourNodeNetwork {
    alice: LiveNodeHandle,
    bob: LiveNodeHandle,
    charlie: LiveNodeHandle,
    /// gRPC-only coordinator: not included in DKG `peer_ids`.
    non_participant: LiveNodeHandle,
    _chain: SourceHubTestContainer,
}

impl LiveFourNodeNetwork {
    /// Peer addresses for the three DKG participants (same order as `LiveThreeNodeNetwork::peer_addrs`).
    fn participant_peer_addrs(&self) -> Vec<String> {
        vec![
            self.alice.peer_addr.clone(),
            self.bob.peer_addr.clone(),
            self.charlie.peer_addr.clone(),
        ]
    }
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
///
/// Waits until all three gRPC servers are ready before returning.
async fn setup_live_three_node_network(db_prefix: &str, base_port: u16) -> LiveThreeNodeNetwork {
    let chain = SourceHubTestContainer::new();

    let mut handles: Vec<LiveNodeHandle> = Vec::new();
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

        // Iroh P2P network (OS-assigned port)
        let network: Arc<dyn Network> = Arc::new(NetworkImpl::new().await.expect("NetworkImpl"));

        let local_address = network.local_address().expect("network local_address");
        let p2p_socket = network
            .bound_addresses()
            .first()
            .copied()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "127.0.0.1:0".to_string());
        let peer_addr = format!("{}@{}", local_address, p2p_socket);

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
                node_controller_key: "test-controller-key".to_string(),
                node_peer_id: None,
                node_whitelisted_policy_ids: vec![],
                node_whitelisted_ring_ids: vec![],
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
            peer_addr,
            public_address,
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
        bob: it.next().unwrap(),
        charlie: it.next().unwrap(),
        _chain: chain,
    }
}

async fn setup_live_four_node_network(db_prefix: &str, base_port: u16) -> LiveFourNodeNetwork {
    let chain = SourceHubTestContainer::new();

    let mut handles: Vec<LiveNodeHandle> = Vec::new();
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
                node_controller_key: "test-controller-key".to_string(),
                node_peer_id: None,
                node_whitelisted_policy_ids: vec![],
                node_whitelisted_ring_ids: vec![],
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
            peer_addr,
            public_address,
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
        _chain: chain,
    }
}

// =========================================================================
// Shared helpers
// =========================================================================

/// Register the ring namespace, add all three nodes as collaborators, run DKG,
/// and return `(ring_pk_hex, ring_id)` once the bulletin post is confirmed.
async fn setup_ring(
    endpoint: &str,
    threshold: u32,
    peer_ids: Vec<String>,
    node_public_addresses: &[&str],
) -> (String, String) {
    cli_tool::register_bulletin_namespace(BULLETIN_RING_NAMESPACE.to_string())
        .await
        .expect("register ring namespace");
    for addr in node_public_addresses {
        cli_tool::add_bulletin_collaborator(BULLETIN_RING_NAMESPACE.to_string(), addr.to_string())
            .await
            .expect("add ring collaborator");
    }

    let sub = BulletinEventSubscription::connect(SOURCEHUB_RPC_URL)
        .await
        .expect("ring event subscription");

    let dkg_result = cli_tool::do_dkg(
        endpoint.to_string(),
        threshold,
        peer_ids,
        None,
        None,
        TEST_FRESH_DKG_RING_ID.to_string(),
    )
    .await
    .expect("DKG initiation");

    let post_event = sub
        .wait_for_artifact(&dkg_result.session_id, Duration::from_secs(90))
        .await
        .expect("DKG completion event");

    let post_payload = cli_tool::read_bulletin_post(post_event.ring_id.clone(), BulletinKind::Ring)
        .await
        .expect("read ring post");

    let ring_payload: RingPayload =
        serde_json::from_slice(&post_payload).expect("parse RingPayload");

    (ring_payload.ring_pk, post_event.ring_id)
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
    let peer_ids = net.peer_addrs();
    let threshold = 2u32;

    // Register the ring namespace and authorise all three nodes to post to it
    cli_tool::register_bulletin_namespace(BULLETIN_RING_NAMESPACE.to_string())
        .await
        .expect("register ring namespace");
    for addr in [
        &net.alice.public_address,
        &net.bob.public_address,
        &net.charlie.public_address,
    ] {
        cli_tool::add_bulletin_collaborator(BULLETIN_RING_NAMESPACE.to_string(), addr.clone())
            .await
            .expect("add collaborator to ring namespace");
    }

    // Subscribe to bulletin events BEFORE initiating DKGs to avoid missing events
    let sub1 = BulletinEventSubscription::connect(SOURCEHUB_RPC_URL)
        .await
        .expect("event subscription 1");
    let sub2 = BulletinEventSubscription::connect(SOURCEHUB_RPC_URL)
        .await
        .expect("event subscription 2");

    // Launch both DKG sessions concurrently from the same endpoint
    let (r1, r2) = tokio::join!(
        cli_tool::do_dkg(
            endpoint.clone(),
            threshold,
            peer_ids.clone(),
            None,
            None,
            TEST_FRESH_DKG_RING_ID.to_string()
        ),
        cli_tool::do_dkg(
            endpoint.clone(),
            threshold,
            peer_ids.clone(),
            None,
            None,
            TEST_FRESH_DKG_RING_ID.to_string()
        ),
    );

    let session1 = r1.expect("DKG 1 initiation failed").session_id;
    let session2 = r2.expect("DKG 2 initiation failed").session_id;
    assert_ne!(
        session1, session2,
        "concurrent DKGs must receive distinct session IDs"
    );

    // Wait for both DKG completion events (each DKG posts its ring to the bulletin)
    let timeout = Duration::from_secs(90);
    let (ev1, ev2) = tokio::join!(
        sub1.wait_for_artifact(&session1, timeout),
        sub2.wait_for_artifact(&session2, timeout),
    );

    let ev1 = ev1.expect("timed out waiting for DKG 1 completion event");
    let ev2 = ev2.expect("timed out waiting for DKG 2 completion event");

    assert!(!ev1.ring_id.is_empty(), "DKG 1 must produce a ring ID");
    assert!(!ev2.ring_id.is_empty(), "DKG 2 must produce a ring ID");
    assert_ne!(
        ev1.ring_id, ev2.ring_id,
        "each DKG must produce a distinct ring ID (no session state leakage)"
    );

    println!(
        "Both DKGs completed successfully:\n  ring1 ring_id={}\n  ring2 ring_id={}",
        ev1.ring_id, ev2.ring_id,
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
    let peer_ids = net.peer_addrs();
    let node_addrs = [
        net.alice.public_address.as_str(),
        net.bob.public_address.as_str(),
        net.charlie.public_address.as_str(),
    ];

    // Step 1: DKG → ring
    let (ring_pk_hex, ring_id) = setup_ring(&endpoint, 2, peer_ids, &node_addrs).await;

    // Step 2: User namespace + node as collaborator
    let user_namespace = "pre_ns".to_string();
    cli_tool::register_bulletin_namespace(user_namespace.clone())
        .await
        .expect("register user namespace");
    cli_tool::add_bulletin_collaborator(user_namespace.clone(), net.alice.public_address.clone())
        .await
        .expect("add alice to user namespace");

    // Step 3: Store one encrypted secret on the bulletin
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

    // Step 4: Authz — register the object and grant read access to the test DID
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

    // Step 5: Generate a reader keypair
    let (reader_sk, reader_pk) = generate_keypair().expect("generate reader keypair");
    let reader_sk_hex =
        hex::encode(CryptoSerialize::to_bytes(&reader_sk).expect("serialize reader sk"));
    let reader_pk_hex =
        hex::encode(CryptoSerialize::to_bytes(&reader_pk).expect("serialize reader pk"));

    // Step 6: Three concurrent PRE decryptions
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
    let peer_ids = net.peer_addrs();
    let node_addrs = [
        net.alice.public_address.as_str(),
        net.bob.public_address.as_str(),
        net.charlie.public_address.as_str(),
    ];

    // Step 1: DKG → ring
    let (ring_pk_hex, ring_id) = setup_ring(&endpoint, 2, peer_ids, &node_addrs).await;

    // Step 2: User namespace + node as collaborator
    let user_namespace = "sign_ns".to_string();
    cli_tool::register_bulletin_namespace(user_namespace.clone())
        .await
        .expect("register user namespace");
    cli_tool::add_bulletin_collaborator(user_namespace.clone(), net.alice.public_address.clone())
        .await
        .expect("add alice to user namespace");

    // Step 3: Add a policy (required as payload metadata; authz enforcement is PRE-only)
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

    // Step 4: Three concurrent store_prepared_secret calls
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

/// DKG must complete when `StartDkg` is invoked on a node that is **not** in `peer_ids`
/// (pure coordinator). Participants used to stall because only the initiator called
/// `initiate_phase1_commitments`; node 1 now starts Phase 1 upon `SessionInit`.
#[tokio::test]
#[serial_test::serial]
async fn test_dkg_non_participant_initiator_completes() {
    let net = setup_live_four_node_network("dkg_non_participant", 51070).await;

    cli_tool::register_bulletin_namespace(BULLETIN_RING_NAMESPACE.to_string())
        .await
        .expect("register ring namespace");
    for addr in [
        &net.alice.public_address,
        &net.bob.public_address,
        &net.charlie.public_address,
    ] {
        cli_tool::add_bulletin_collaborator(BULLETIN_RING_NAMESPACE.to_string(), addr.clone())
            .await
            .expect("add collaborator to ring namespace");
    }

    let sub = BulletinEventSubscription::connect(SOURCEHUB_RPC_URL)
        .await
        .expect("ring event subscription");

    let peer_ids = net.participant_peer_addrs();
    let threshold = 2u32;

    let dkg_result = cli_tool::do_dkg(
        net.non_participant.grpc_endpoint.clone(),
        threshold,
        peer_ids,
        None,
        None,
        TEST_FRESH_DKG_RING_ID.to_string(),
    )
    .await
    .expect("DKG from non-participant initiator");

    let post_event = sub
        .wait_for_artifact(&dkg_result.session_id, Duration::from_secs(90))
        .await
        .expect("timed out waiting for DKG completion (non-participant initiator)");

    assert!(
        !post_event.ring_id.is_empty(),
        "DKG must produce a ring bulletin post"
    );

    let post_payload = cli_tool::read_bulletin_post(post_event.ring_id.clone(), BulletinKind::Ring)
        .await
        .expect("read ring post");

    let ring_payload: RingPayload =
        serde_json::from_slice(&post_payload).expect("parse RingPayload");
    let ring_pk_hex = ring_payload.ring_pk;

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

    let mut np_client = InfoServiceClient::connect(net.non_participant.grpc_endpoint.clone())
        .await
        .expect("connect InfoService on non-participant");
    let np_ring = np_client
        .get_ring_state(Request::new(GetRingStateRequest {
            ring_pk_hex: ring_pk_hex.clone(),
        }))
        .await;
    assert!(
        np_ring.is_err(),
        "non-participant initiator must not persist ring state for the ceremony it coordinated"
    );
}
