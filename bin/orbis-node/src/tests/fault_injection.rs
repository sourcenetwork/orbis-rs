//! Fault-injection integration tests: node dropout and network partition.
//!
//! These tests verify that threshold operations (PRE and SIGN) gracefully handle
//! node failures: they succeed when enough nodes are available and fail fast when
//! too few nodes are reachable. DKG is verified to stall when a required node is
//! unreachable (DKG requires all-node participation).
//!
//! Requires both `fault-injection` and `integration-test` features.
//! Run with:
//!   cargo test --bin orbis-node --features "integration-test,fault-injection" \
//!     -- fault_injection --nocapture

use crate::dkg::service::DkgServiceImpl;
use crate::info::InfoServiceImpl;
use crate::pre::service::PreServiceImpl;
use crate::sign::service::SignServiceImpl;
use crate::store_secret::StoreSecretServiceImpl;
use crate::{
    constants::{
        BULLETIN_RING_NAMESPACE, MIN_NODE_BALANCE, PRE_COLLECTION_TIMEOUT, SIGN_COLLECTION_TIMEOUT,
    },
    helpers::{
        launch::{create_and_store_node_key, LogLevel},
        test_helpers::{cleanup_db, test_db_path, wait_for_nodes_ready},
    },
    init_node, Args, NodeConfig,
};
use authz::r#trait::Authz;
use authz::AuthzImpl;
use bulletin::r#trait::{Bulletin, RingPayload};
use bulletin::BulletinImpl;
use common::{
    blockchain::{events::BulletinEventSubscription, ChainConfigBuilder},
    SourceHubTestContainer, SOURCEHUB_RPC_URL,
};
use crypto::{helpers::generate_keypair, CryptoSerialize, DkgImpl, PreImpl, SignImpl};
use local_storage::{r#trait::LocalStorage, LocalStorageImpl};
use network::{FaultNetwork, FaultNetworkController, Network, NetworkImpl};
use proto::{
    dkg_service::dkg_service_server::DkgServiceServer,
    info_service::info_service_server::InfoServiceServer,
    pre_service::pre_service_server::PreServiceServer,
    sign_service::sign_service_server::SignServiceServer,
    store_secret_service::store_secret_service_server::StoreSecretServiceServer,
};
use std::sync::Arc;
use tokio::time::Duration;

// =========================================================================
// Test infrastructure
// =========================================================================

/// A running in-process orbis node backed by a FaultNetwork.
struct FaultableNodeHandle {
    grpc_endpoint: String,
    peer_addr: String,
    public_address: String,
    db_path: String,
    task: tokio::task::JoinHandle<()>,
    /// 64-char hex node ID — used to block this node on other nodes' controllers.
    peer_hex: String,
    /// Fault controller for this node's outbound connections.
    fault_ctrl: FaultNetworkController,
}

impl Drop for FaultableNodeHandle {
    fn drop(&mut self) {
        self.task.abort();
        cleanup_db(&self.db_path);
    }
}

/// Three in-process orbis nodes where each node's outbound connections can be
/// blocked via its `FaultNetworkController`.
struct FaultableThreeNodeNetwork {
    alice: FaultableNodeHandle,
    bob: FaultableNodeHandle,
    charlie: FaultableNodeHandle,
    /// Keeps the SourceHub Docker container alive via RAII.
    _chain: SourceHubTestContainer,
}

impl FaultableThreeNodeNetwork {
    fn peer_addrs(&self) -> Vec<String> {
        vec![
            self.alice.peer_addr.clone(),
            self.bob.peer_addr.clone(),
            self.charlie.peer_addr.clone(),
        ]
    }
}

/// Build and spawn a gRPC server from an `InitializedNode`.
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
        let _ = node.router.shutdown().await;
    })
}

/// Start SourceHub (via Docker) and three in-process orbis nodes, each wrapped
/// with a `FaultNetwork` for test-time network partition simulation.
async fn setup_fault_three_node_network(
    db_prefix: &str,
    base_port: u16,
) -> FaultableThreeNodeNetwork {
    let chain = SourceHubTestContainer::new();

    let mut handles: Vec<FaultableNodeHandle> = Vec::new();
    for i in 0..3u16 {
        let port = base_port + i;
        let db_path = test_db_path(&format!("{}_{}", db_prefix, i));
        cleanup_db(&db_path);

        let local_storage = LocalStorageImpl::new(None, db_path.clone()).expect("local storage");

        let signer =
            create_and_store_node_key(local_storage.clone(), ChainConfigBuilder::default().build(), None)
                .expect("create node signing key");
        let public_address = signer.address();

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

        // Create the real iroh network first to extract peer info
        let real_net = NetworkImpl::new().await.expect("NetworkImpl");

        // Extract peer addressing info before wrapping (local_address = 64-char hex node ID)
        let peer_hex = real_net.local_address().expect("network local_address");
        let p2p_socket = real_net
            .bound_addresses()
            .first()
            .copied()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "127.0.0.1:0".to_string());
        let peer_addr = format!("{}@{}", peer_hex, p2p_socket);

        // Wrap with FaultNetwork to enable test-time connection blocking
        let (fault_net, fault_ctrl) = FaultNetwork::new(Arc::new(real_net));
        let network: Arc<dyn Network> = Arc::new(fault_net);

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
                data_dir: None,
                metrics_addr: None,
                loki_url: None,
                hub_rpc: None,
                hub_ws: None,
                hub_chain_id: 9944,
            },
            network,
            local_storage,
            authz,
            bulletin,
            acp_light_client: None,
        };

        let node = init_node(config).await.expect("init_node");
        let task = spawn_test_grpc_server(node);

        handles.push(FaultableNodeHandle {
            grpc_endpoint: format!("http://{}", grpc_bind),
            peer_addr,
            public_address,
            db_path,
            task,
            peer_hex,
            fault_ctrl,
        });
    }

    let endpoints: Vec<&str> = handles.iter().map(|h| h.grpc_endpoint.as_str()).collect();
    wait_for_nodes_ready(&endpoints, 30, Duration::from_millis(200)).await;

    let mut it = handles.into_iter();
    FaultableThreeNodeNetwork {
        alice: it.next().unwrap(),
        bob: it.next().unwrap(),
        charlie: it.next().unwrap(),
        _chain: chain,
    }
}

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

    let dkg_result = cli_tool::do_dkg(endpoint.to_string(), threshold, peer_ids)
        .await
        .expect("DKG initiation");

    let post_event = sub
        .wait_for_artifact(&dkg_result.session_id, Duration::from_secs(90))
        .await
        .expect("DKG completion event");

    let post_payload = cli_tool::read_bulletin_post(
        BULLETIN_RING_NAMESPACE.to_string(),
        post_event.post_id.clone(),
    )
    .await
    .expect("read ring post");

    let ring_payload: RingPayload =
        serde_json::from_slice(&post_payload).expect("parse RingPayload");

    (ring_payload.ring_pk, post_event.post_id)
}

// =========================================================================
// Tests
// =========================================================================

/// PRE succeeds when one of three nodes is down (threshold=2, one node crashed).
///
/// Alice and Bob are alive. Charlie's process is aborted before the PRE request.
/// With threshold=2, alice+bob's shares are enough to recover the re-encrypted
/// commitment, so the PRE decryption should complete successfully.
#[tokio::test]
#[serial_test::serial]
async fn test_pre_one_node_down_succeeds() {
    let net = setup_fault_three_node_network("fault_pre_1node_down", 51060).await;

    let endpoint = net.alice.grpc_endpoint.clone();
    let peer_ids = net.peer_addrs();
    let node_addrs = [
        net.alice.public_address.as_str(),
        net.bob.public_address.as_str(),
        net.charlie.public_address.as_str(),
    ];

    // Step 1: DKG → ring (threshold=2)
    let (ring_pk_hex, ring_id) = setup_ring(&endpoint, 2, peer_ids, &node_addrs).await;

    // Step 2: User namespace + alice as collaborator
    let user_namespace = "fault_pre_ns1".to_string();
    let full_namespace = format!("bulletin/{}", user_namespace);
    cli_tool::register_bulletin_namespace(user_namespace.clone())
        .await
        .expect("register user namespace");
    cli_tool::add_bulletin_collaborator(user_namespace.clone(), net.alice.public_address.clone())
        .await
        .expect("add alice to user namespace");

    // Step 3: Add policy + prepare + store secret + authz relationship
    let policy_id = cli_tool::add_policy_to_chain().await.expect("add policy");
    let resource = "document".to_string();
    let permission = "read".to_string();
    let secret = b"fault-pre-one-down-plaintext";

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
        user_namespace.clone(),
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        None,
        None,
        true,
        None,
        None,
        None,
    )
    .await
    .expect("store prepared secret");
    let object_id = obj_resp.object_id;

    let did = "fault_reader_1".to_string();
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

    let (reader_sk, reader_pk) = generate_keypair().expect("generate reader keypair");
    let reader_sk_hex =
        hex::encode(CryptoSerialize::to_bytes(&reader_sk).expect("serialize reader sk"));
    let reader_pk_hex =
        hex::encode(CryptoSerialize::to_bytes(&reader_pk).expect("serialize reader pk"));

    // Step 4: Crash charlie (abort its task)
    net.charlie.task.abort();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Step 5: PRE request — should succeed with alice + bob shares (threshold=2)
    let result = cli_tool::do_pre(
        endpoint.clone(),
        ring_pk_hex.clone(),
        reader_pk_hex.clone(),
        Some(reader_sk_hex.clone()),
        object_id.clone(),
        Some(did.clone()),
        full_namespace.clone(),
        None,
        None,
        None,
        None,
        false,
    )
    .await
    .expect("PRE should succeed with one node down (threshold=2)");

    assert_eq!(
        result.as_slice(),
        secret.as_ref(),
        "Decrypted plaintext must match original with one node down"
    );

    println!(
        "PRE succeeded with charlie down: {} bytes decrypted",
        result.len()
    );
}

/// PRE fails fast when fewer than threshold nodes are reachable.
///
/// Alice's FaultNetworkController blocks outbound connections to both bob and
/// charlie. Alice can contribute her own local share but cannot reach bob or
/// charlie, leaving only 1 share out of the required 2. The operation should
/// return an error quickly (not hang for PRE_COLLECTION_TIMEOUT).
#[tokio::test]
#[serial_test::serial]
async fn test_pre_below_threshold_nodes_down_fails_fast() {
    let net = setup_fault_three_node_network("fault_pre_below_threshold", 51063).await;

    let endpoint = net.alice.grpc_endpoint.clone();
    let peer_ids = net.peer_addrs();
    let node_addrs = [
        net.alice.public_address.as_str(),
        net.bob.public_address.as_str(),
        net.charlie.public_address.as_str(),
    ];

    // Step 1: DKG → ring (threshold=2)
    let (ring_pk_hex, ring_id) = setup_ring(&endpoint, 2, peer_ids, &node_addrs).await;

    // Step 2: User namespace + alice as collaborator
    let user_namespace = "fault_pre_ns2".to_string();
    let full_namespace = format!("bulletin/{}", user_namespace);
    cli_tool::register_bulletin_namespace(user_namespace.clone())
        .await
        .expect("register user namespace");
    cli_tool::add_bulletin_collaborator(user_namespace.clone(), net.alice.public_address.clone())
        .await
        .expect("add alice to user namespace");

    // Step 3: Add policy + prepare + store secret + authz relationship
    let policy_id = cli_tool::add_policy_to_chain().await.expect("add policy");
    let resource = "document".to_string();
    let permission = "read".to_string();
    let secret = b"fault-pre-below-threshold-plaintext";

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
        user_namespace.clone(),
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        None,
        None,
        true,
        None,
        None,
        None,
    )
    .await
    .expect("store prepared secret");
    let object_id = obj_resp.object_id;

    let did = "fault_reader_2".to_string();
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

    let (reader_sk, reader_pk) = generate_keypair().expect("generate reader keypair");
    let reader_sk_hex =
        hex::encode(CryptoSerialize::to_bytes(&reader_sk).expect("serialize reader sk"));
    let reader_pk_hex =
        hex::encode(CryptoSerialize::to_bytes(&reader_pk).expect("serialize reader pk"));

    // Step 4: Block bob AND charlie on alice's fault controller (network partition)
    net.alice.fault_ctrl.block_peer(&net.bob.peer_hex).await;
    net.alice.fault_ctrl.block_peer(&net.charlie.peer_hex).await;

    // Step 5: PRE request — should fail (insufficient shares) and complete well
    //         within PRE_COLLECTION_TIMEOUT + 5s (not hang indefinitely).
    let deadline = PRE_COLLECTION_TIMEOUT + Duration::from_secs(5);
    let timed = tokio::time::timeout(
        deadline,
        cli_tool::do_pre(
            endpoint.clone(),
            ring_pk_hex.clone(),
            reader_pk_hex.clone(),
            Some(reader_sk_hex.clone()),
            object_id.clone(),
            Some(did.clone()),
            full_namespace.clone(),
            None,
            None,
            None,
            None,
            false,
        ),
    )
    .await;

    match timed {
        Err(_) => panic!(
            "PRE with no reachable peers hung past PRE_COLLECTION_TIMEOUT + 5s — \
             JoinSet timeout not working"
        ),
        Ok(inner) => {
            assert!(
                inner.is_err(),
                "PRE should return an error when bob and charlie are unreachable, \
                 but it returned Ok"
            );
            println!("PRE failed fast as expected: {:?}", inner.unwrap_err());
        }
    }
}

/// SIGN (store_prepared_secret) succeeds when one of three nodes is down (threshold=2).
///
/// Alice and Bob are alive. Charlie's process is aborted before the SIGN request.
/// With threshold=2, alice+bob's signature shares are enough to recover the full
/// signature, so store_prepared_secret should complete successfully.
#[tokio::test]
#[serial_test::serial]
async fn test_sign_one_node_down_succeeds() {
    let net = setup_fault_three_node_network("fault_sign_1node_down", 51066).await;

    let endpoint = net.alice.grpc_endpoint.clone();
    let peer_ids = net.peer_addrs();
    let node_addrs = [
        net.alice.public_address.as_str(),
        net.bob.public_address.as_str(),
        net.charlie.public_address.as_str(),
    ];

    // Step 1: DKG → ring (threshold=2)
    let (ring_pk_hex, ring_id) = setup_ring(&endpoint, 2, peer_ids, &node_addrs).await;

    // Step 2: User namespace + alice as collaborator
    let user_namespace = "fault_sign_ns1".to_string();
    cli_tool::register_bulletin_namespace(user_namespace.clone())
        .await
        .expect("register user namespace");
    cli_tool::add_bulletin_collaborator(user_namespace.clone(), net.alice.public_address.clone())
        .await
        .expect("add alice to user namespace");

    // Step 3: Prepare secret (local, no network needed)
    let policy_id = cli_tool::add_policy_to_chain().await.expect("add policy");
    let resource = "document".to_string();
    let permission = "read".to_string();
    let secret = b"fault-sign-one-down-secret";

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

    // Step 4: Crash charlie before the SIGN operation
    net.charlie.task.abort();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Step 5: store_prepared_secret triggers FROST signing — should succeed with alice+bob
    let resp = cli_tool::store_prepared_secret(
        endpoint.clone(),
        &prepared,
        ring_id.clone(),
        user_namespace.clone(),
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        None,
        None,
        true,
        None,
        None,
        None,
    )
    .await
    .expect("SIGN should succeed with one node down (threshold=2)");

    assert!(
        !resp.object_id.is_empty(),
        "store_prepared_secret must return an object_id"
    );
    assert!(
        !resp.signature.is_empty(),
        "store_prepared_secret must return a signature"
    );

    println!(
        "SIGN succeeded with charlie down: object_id={}, sig_len={}",
        resp.object_id,
        resp.signature.len()
    );
}

/// SIGN fails fast when fewer than threshold nodes are reachable.
///
/// Alice's FaultNetworkController blocks outbound connections to both bob and
/// charlie. Alice can contribute her own local signing share but cannot reach
/// bob or charlie, leaving only 1 share out of the required 2. The operation
/// should return an error quickly (not hang for SIGN_COLLECTION_TIMEOUT).
#[tokio::test]
#[serial_test::serial]
async fn test_sign_below_threshold_nodes_down_fails_fast() {
    let net = setup_fault_three_node_network("fault_sign_below_threshold", 51069).await;

    let endpoint = net.alice.grpc_endpoint.clone();
    let peer_ids = net.peer_addrs();
    let node_addrs = [
        net.alice.public_address.as_str(),
        net.bob.public_address.as_str(),
        net.charlie.public_address.as_str(),
    ];

    // Step 1: DKG → ring (threshold=2)
    let (ring_pk_hex, ring_id) = setup_ring(&endpoint, 2, peer_ids, &node_addrs).await;

    // Step 2: User namespace + alice as collaborator
    let user_namespace = "fault_sign_ns2".to_string();
    cli_tool::register_bulletin_namespace(user_namespace.clone())
        .await
        .expect("register user namespace");
    cli_tool::add_bulletin_collaborator(user_namespace.clone(), net.alice.public_address.clone())
        .await
        .expect("add alice to user namespace");

    // Step 3: Prepare secret (local)
    let policy_id = cli_tool::add_policy_to_chain().await.expect("add policy");
    let resource = "document".to_string();
    let permission = "read".to_string();
    let secret = b"fault-sign-below-threshold-secret";

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

    // Step 4: Block bob AND charlie on alice's fault controller (network partition)
    net.alice.fault_ctrl.block_peer(&net.bob.peer_hex).await;
    net.alice.fault_ctrl.block_peer(&net.charlie.peer_hex).await;

    // Step 5: store_prepared_secret — should fail (insufficient shares) and complete
    //         well within SIGN_COLLECTION_TIMEOUT + 5s (not hang indefinitely).
    let deadline = SIGN_COLLECTION_TIMEOUT + Duration::from_secs(5);
    let timed = tokio::time::timeout(
        deadline,
        cli_tool::store_prepared_secret(
            endpoint.clone(),
            &prepared,
            ring_id.clone(),
            user_namespace.clone(),
            policy_id.clone(),
            resource.clone(),
            permission.clone(),
            None,
            None,
            true,
            None,
            None,
            None,
        ),
    )
    .await;

    match timed {
        Err(_) => panic!(
            "SIGN with no reachable peers hung past SIGN_COLLECTION_TIMEOUT + 5s — \
             JoinSet timeout not working"
        ),
        Ok(inner) => {
            assert!(
                inner.is_err(),
                "SIGN should return an error when bob and charlie are unreachable, \
                 but it returned Ok"
            );
            println!("SIGN failed fast as expected: {:?}", inner.unwrap_err());
        }
    }
}

/// DKG fails when a required node is unreachable.
///
/// Charlie's hex node ID is blocked on both alice's and bob's fault controllers.
/// Neither alice nor bob can connect to charlie for the DKG protocol messages.
/// DKG requires all-node participation, so the service returns an error
/// immediately when it cannot establish connections to all participants.
#[tokio::test]
#[serial_test::serial]
async fn test_dkg_fails_when_node_unreachable() {
    let net = setup_fault_three_node_network("fault_dkg_unreachable", 51072).await;

    let endpoint = net.alice.grpc_endpoint.clone();
    let peer_ids = net.peer_addrs();

    // Register the ring namespace and authorise all three nodes to post
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
            .expect("add ring collaborator");
    }

    // Block charlie on alice AND bob so charlie is unreachable for DKG
    let charlie_hex = net.charlie.peer_hex.clone();
    net.alice.fault_ctrl.block_peer(&charlie_hex).await;
    net.bob.fault_ctrl.block_peer(&charlie_hex).await;

    // Initiate DKG — the DKG service checks connectivity to all peers upfront.
    // Because charlie is blocked on alice's outbound controller, alice cannot
    // reach charlie and the DKG call must return an error immediately.
    let dkg_result = cli_tool::do_dkg(endpoint.to_string(), 2, peer_ids).await;

    assert!(
        dkg_result.is_err(),
        "DKG should fail when charlie is unreachable, but it succeeded: {:?}",
        dkg_result
    );

    println!(
        "DKG correctly failed with charlie blocked: {:?}",
        dkg_result.unwrap_err()
    );
}
