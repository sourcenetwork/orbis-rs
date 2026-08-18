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

use crate::dkg::v0::service::DkgServiceImpl;
use crate::info::InfoServiceImpl;
use crate::pre::v0::service::PreServiceImpl;
use crate::sign::v0::service::SignServiceImpl;
use crate::store_secret::StoreSecretServiceImpl;
use crate::{
    constants::{
        GRPC_CONCURRENCY_LIMIT_PER_CONNECTION, GRPC_MAX_CONCURRENT_STREAMS, MAX_SIGN_REQUEST_BYTES,
        MAX_SMALL_GRPC_REQUEST_BYTES, MAX_STORE_SECRET_REQUEST_BYTES, MIN_NODE_BALANCE,
        PEER_RESPONSE_TIMEOUT, PRE_COLLECTION_TIMEOUT, SIGN_COLLECTION_TIMEOUT,
    },
    dkg::v0::transport::{self, DkgControlMessage, DkgPrivateMessage},
    helpers::{
        launch::{create_and_store_node_key, LogLevel},
        test_helpers::{
            cleanup_db, create_orbis_ring_policy, create_ring_on_chain, test_db_path,
            wait_for_nodes_ready, wait_for_ring_finalized,
        },
    },
    init_node, Args, NodeConfig,
};
use authz::r#trait::Authz;
use authz::AuthzImpl;
use bulletin::r#trait::{Bulletin, BulletinWriteKind, NodeInfo};
use bulletin::BulletinImpl;
use common::{
    blockchain::{
        events::ReportEventSubscription, ChainConfig, SourceHubClient, TxSigner,
        TEST_ACCOUNT_HEX_KEY,
    },
    SourceHubTestContainer,
};
use crypto::{helpers::generate_keypair, CryptoSerialize, DkgImpl, PreImpl, SignImpl};
use local_storage::{r#trait::LocalStorage, LocalStorageImpl};
use network::{FaultNetwork, FaultNetworkController, Network, NetworkImpl};
use proto::{
    info_service::info_service_server::InfoServiceServer,
    v0::dkg::dkg_service_server::DkgServiceServer, v0::pre::pre_service_server::PreServiceServer,
    v0::sign::sign_service_server::SignServiceServer,
    v0::store_secret::store_secret_service_server::StoreSecretServiceServer,
};
use std::sync::Arc;
use tokio::time::Duration;

const MAX_TEST_CONTROL_MESSAGE_BYTES: usize = 2 * 1024 * 1024;

// =========================================================================
// Test infrastructure
// =========================================================================

/// A running in-process orbis node backed by a FaultNetwork.
struct FaultableNodeHandle {
    grpc_endpoint: String,
    _peer_addr: String,
    _public_address: String,
    db_path: String,
    task: tokio::task::JoinHandle<()>,
    /// 64-char hex node ID — used to block this node on other nodes' controllers.
    peer_hex: String,
    /// Fault controller for this node's outbound connections.
    fault_ctrl: FaultNetworkController,
    /// `None` when `reshare_interval_secs` is 0. Dropping this (implicitly, with the rest of
    /// the handle) closes its internal shutdown channel, which is what actually stops the
    /// scheduler's background task — see the comment where it's spawned for why this needs to
    /// be spawned here at all rather than coming for free from `init_node`.
    _pss_scheduler: Option<crate::pss::v0::PssSchedulerHandle>,
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
    /// ACP policy ID all three nodes are whitelisted for.
    policy_id: String,
    /// Compressed pubkeys of alice, bob, charlie (in that order).
    node_keys: Vec<String>,
    chain_config: ChainConfig,
    /// Keeps the SourceHub Docker container alive via RAII.
    _chain: SourceHubTestContainer,
}

/// Build and spawn a gRPC server from an `InitializedNode`.
fn spawn_test_grpc_server(node: crate::InitializedNode) -> tokio::task::JoinHandle<()> {
    let dkg_service = DkgServiceImpl::<DkgImpl>::with_routes(node.app_state.clone(), &network::V0);
    let pre_service =
        PreServiceImpl::<DkgImpl, PreImpl>::with_routes(node.app_state.clone(), &network::V0);
    let info_service = InfoServiceImpl::<DkgImpl>::new((*node.app_state).clone());
    let store_secret_service = StoreSecretServiceImpl::<DkgImpl, SignImpl>::with_routes(
        node.app_state.clone(),
        &network::V0,
    );
    let sign_service =
        SignServiceImpl::<DkgImpl, SignImpl>::with_routes(node.app_state.clone(), &network::V0);

    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(
                DkgServiceServer::new(dkg_service)
                    .max_decoding_message_size(MAX_SMALL_GRPC_REQUEST_BYTES),
            )
            .add_service(
                PreServiceServer::new(pre_service)
                    .max_decoding_message_size(MAX_SMALL_GRPC_REQUEST_BYTES),
            )
            .add_service(
                InfoServiceServer::new(info_service)
                    .max_decoding_message_size(MAX_SMALL_GRPC_REQUEST_BYTES),
            )
            .add_service(
                StoreSecretServiceServer::new(store_secret_service)
                    .max_decoding_message_size(MAX_STORE_SECRET_REQUEST_BYTES),
            )
            .add_service(
                SignServiceServer::new(sign_service)
                    .max_decoding_message_size(MAX_SIGN_REQUEST_BYTES),
            )
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
    setup_fault_three_node_network_with_reshare_interval(db_prefix, base_port, 0).await
}

/// Same as [`setup_fault_three_node_network`], but lets the caller enable the
/// background PSS scheduler (`reshare_interval_secs = 0` disables it
/// entirely — see `pss::spawn_pss_scheduler`'s own doc comment). Needed by
/// any test that expects a pending on-chain reshare/refresh to be picked up
/// and driven automatically, the way a real node would, rather than relying
/// on an explicit client-triggered ceremony like `do_dkg`.
async fn setup_fault_three_node_network_with_reshare_interval(
    db_prefix: &str,
    base_port: u16,
    reshare_interval_secs: u64,
) -> FaultableThreeNodeNetwork {
    let chain = SourceHubTestContainer::new();
    let chain_config = chain.chain_config();
    let runtime_base_path = project_root::get_project_root().expect("resolve project root");

    let policy_id = create_orbis_ring_policy(&chain_config).await;

    let mut handles: Vec<FaultableNodeHandle> = Vec::new();
    let mut node_keys: Vec<String> = Vec::new();

    for i in 0..3u16 {
        let port = base_port + i;
        let db_path = test_db_path(&format!("{}_{}", db_prefix, i));
        cleanup_db(&db_path);

        let local_storage = LocalStorageImpl::new("test-password".to_string(), db_path.clone())
            .expect("local storage");

        let signer = create_and_store_node_key(
            local_storage.clone(),
            chain_config.clone(),
            &runtime_base_path,
        )
        .expect("create node signing key");
        let public_address = signer.address();
        let node_key = signer.public_key_hex();

        cli_tool::fund(public_address.clone(), chain_config.clone())
            .await
            .expect("fund node account via faucet");

        let bulletin: Arc<dyn Bulletin + Send + Sync> = Arc::new(
            BulletinImpl::with_signer(chain.chain_config_builder(), signer, Some(MIN_NODE_BALANCE))
                .await
                .expect("BulletinImpl with signer"),
        );

        let authz: Arc<dyn Authz> = Arc::new(
            AuthzImpl::new(chain.chain_config_builder())
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
                chain_id: None,
                denom: None,
                fee_granter: None,
                chain_gas_multiplier: None,
                metrics_addr: None,
                loki_url: None,
                runtime_base_path: None,
                reshare_interval_secs,
                network_private_routes_only: false,
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
        // `init_node` alone never starts this — the production binary only spawns it from
        // `run_server` (`runtime.rs`), which this harness deliberately doesn't call (it builds
        // its own minimal tonic server in `spawn_test_grpc_server` instead of the full
        // production server loop). Must spawn it here, before `node` moves into
        // `spawn_test_grpc_server`, for any test that needs a pending on-chain reshare/refresh
        // to be picked up and driven automatically.
        let pss_scheduler =
            crate::pss::spawn_pss_scheduler(node.app_state.clone(), node.reshare_interval);
        let task = spawn_test_grpc_server(node);

        handles.push(FaultableNodeHandle {
            grpc_endpoint: format!("http://{}", grpc_bind),
            _peer_addr: peer_addr,
            _public_address: public_address,
            db_path,
            task,
            peer_hex,
            fault_ctrl,
            _pss_scheduler: pss_scheduler,
        });
    }

    let endpoints: Vec<&str> = handles.iter().map(|h| h.grpc_endpoint.as_str()).collect();
    wait_for_nodes_ready(&endpoints, 30, Duration::from_millis(200)).await;

    let mut it = handles.into_iter();
    FaultableThreeNodeNetwork {
        alice: it.next().unwrap(),
        bob: it.next().unwrap(),
        charlie: it.next().unwrap(),
        policy_id,
        node_keys,
        chain_config,
        _chain: chain,
    }
}

/// Create a ring on-chain, run DKG, and return `(ring_pk_hex, ring_id)` once
/// all participant nodes have called FinalizeRing and the chain confirms.
async fn setup_ring(
    chain_config: &ChainConfig,
    endpoint: &str,
    node_keys: &[String],
    threshold: u32,
    policy_id: &str,
) -> (String, String) {
    let ring_id = create_ring_on_chain(chain_config, node_keys, threshold, policy_id, None).await;

    cli_tool::do_dkg(endpoint.to_string(), ring_id.clone())
        .await
        .expect("DKG initiation");

    let ring_pk = wait_for_ring_finalized(chain_config, &ring_id, Duration::from_secs(90)).await;
    (ring_pk, ring_id)
}

// =========================================================================
// Tests
// =========================================================================

/// Fresh DKG retransmits a silently lost topology probe and does not turn
/// transient Gossip neighbor changes into a rejoin cascade.
#[tokio::test]
#[serial_test::serial]
async fn test_dkg_recovers_lost_topology_probe_and_neighbor_flaps() {
    let net = setup_fault_three_node_network("fault_dkg_topology_recovery", 51057).await;

    let leader_node_key = net.node_keys.iter().min().expect("committee").clone();

    for controller in [
        &net.alice.fault_ctrl,
        &net.bob.fault_ctrl,
        &net.charlie.fault_ctrl,
    ] {
        controller.drop_gossip_broadcasts_after(0, 1).await;
        controller.inject_gossip_neighbor_flaps(2).await;
        controller
            .fail_protocol_responses_after(network::V0.dkg_control_alpn, 0, 1)
            .await;
    }

    let initiator = [
        (&net.node_keys[0], &net.alice.grpc_endpoint),
        (&net.node_keys[1], &net.bob.grpc_endpoint),
        (&net.node_keys[2], &net.charlie.grpc_endpoint),
    ]
    .into_iter()
    .min_by(|left, right| left.0.cmp(right.0))
    .expect("committee")
    .1
    .clone();

    let (ring_pk, ring_id) = setup_ring(
        &net.chain_config,
        &initiator,
        &net.node_keys,
        2,
        &net.policy_id,
    )
    .await;

    assert!(!ring_pk.is_empty(), "retransmitted-probe DKG must finalize");
    assert!(
        !ring_id.is_empty(),
        "retransmitted-probe DKG keeps its ring ID"
    );

    for (node_key, controller) in [
        (&net.node_keys[0], &net.alice.fault_ctrl),
        (&net.node_keys[1], &net.bob.fault_ctrl),
        (&net.node_keys[2], &net.charlie.fault_ctrl),
    ] {
        if node_key == &leader_node_key {
            continue;
        }
        let acknowledgements = controller
            .sent_protocol_messages(network::V0.dkg_control_alpn)
            .await
            .into_iter()
            .filter(|bytes| {
                matches!(
                    transport::decode::<DkgControlMessage>(bytes, MAX_TEST_CONTROL_MESSAGE_BYTES,),
                    Ok(DkgControlMessage::TopologyProbeAck { .. })
                )
            })
            .collect::<Vec<_>>();
        assert!(
            acknowledgements.len() >= 2,
            "lost acknowledgement response must cause a retransmission"
        );
        assert!(
            acknowledgements.windows(2).all(|pair| pair[0] == pair[1]),
            "topology acknowledgement retries must be byte-identical"
        );
    }
}

/// A nonleader API node must preserve the leader's concrete preparation error
/// instead of hiding it behind the forwarded StartFresh response timeout.
#[tokio::test]
#[serial_test::serial]
async fn test_nonleader_dkg_start_returns_leader_preparation_error() {
    let net = setup_fault_three_node_network("fault_dkg_forwarded_error", 51075).await;
    let leader_index = net
        .node_keys
        .iter()
        .enumerate()
        .min_by(|left, right| left.1.cmp(right.1))
        .expect("committee")
        .0;
    let controllers = [
        &net.alice.fault_ctrl,
        &net.bob.fault_ctrl,
        &net.charlie.fault_ctrl,
    ];
    controllers[leader_index]
        .corrupt_protocol_responses_after(network::V0.dkg_control_alpn, 0, 1)
        .await;

    let endpoints = [
        &net.alice.grpc_endpoint,
        &net.bob.grpc_endpoint,
        &net.charlie.grpc_endpoint,
    ];
    let initiator_index = (0..endpoints.len())
        .find(|index| *index != leader_index)
        .expect("nonleader API node");
    let ring_id =
        create_ring_on_chain(&net.chain_config, &net.node_keys, 2, &net.policy_id, None).await;
    let error = cli_tool::do_dkg(endpoints[initiator_index].clone(), ring_id)
        .await
        .expect_err("malformed Prepared response must fail the attempt");
    let error = format!("{error:#}");

    assert!(
        error.contains("Deserialization error"),
        "forwarded caller must receive the leader's preparation error: {error}"
    );
    assert!(
        !error.contains("control start-fresh response timed out"),
        "leader error must arrive before the forwarded response margin: {error}"
    );
}

/// Fresh DKG completes after public Gossip loss and retryable private QUIC
/// stream failures.
///
/// Every subscriber accepts the first public delivery (the topology probe),
/// then loses the next four public deliveries. The fault wrapper reports those
/// losses as subscriber lag so the production rejoin/direct-repair path runs.
/// The first private pair stream opened by every possible deterministic opener
/// fails, and the next response silently stalls beyond the peer timeout. This
/// proves both failure modes retry without regenerating share bytes.
#[tokio::test]
#[serial_test::serial]
async fn test_dkg_repairs_gossip_loss_and_private_disconnects() {
    let net = setup_fault_three_node_network("fault_dkg_transport_repair", 51058).await;

    for controller in [
        &net.alice.fault_ctrl,
        &net.bob.fault_ctrl,
        &net.charlie.fault_ctrl,
    ] {
        controller.drop_gossip_deliveries_after(1, 4).await;
        controller
            .fail_protocol_streams_after(network::V0.dkg_private_alpn, 0, 1)
            .await;
        controller
            .stall_protocol_responses_after(
                network::V0.dkg_private_alpn,
                0,
                1,
                PEER_RESPONSE_TIMEOUT + Duration::from_secs(1),
            )
            .await;
    }

    let (ring_pk, ring_id) = setup_ring(
        &net.chain_config,
        &net.alice.grpc_endpoint,
        &net.node_keys,
        2,
        &net.policy_id,
    )
    .await;

    assert!(
        !ring_pk.is_empty(),
        "repaired DKG must finalize a public key"
    );
    assert!(
        !ring_id.is_empty(),
        "repaired DKG must preserve its ring ID"
    );

    let mut saw_identical_retransmission = false;
    for controller in [
        &net.alice.fault_ctrl,
        &net.bob.fault_ctrl,
        &net.charlie.fault_ctrl,
    ] {
        let mut deliveries = std::collections::HashMap::<_, Vec<_>>::new();
        for bytes in controller
            .sent_protocol_messages(network::V0.dkg_private_alpn)
            .await
        {
            if let Ok(DkgPrivateMessage::ShareDelivery { message_id, .. }) =
                transport::decode(&bytes, MAX_TEST_CONTROL_MESSAGE_BYTES)
            {
                deliveries.entry(message_id).or_default().push(bytes);
            }
        }
        saw_identical_retransmission |= deliveries.values().any(|attempts| {
            attempts.len() >= 2 && attempts.windows(2).all(|pair| pair[0] == pair[1])
        });
    }
    assert!(
        saw_identical_retransmission,
        "a silently stalled private response must retransmit the exact cached share"
    );
}

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

    // Step 1: DKG → ring (threshold=2)
    let (ring_pk_hex, ring_id) = setup_ring(
        &net.chain_config,
        &endpoint,
        &net.node_keys,
        2,
        &net.policy_id,
    )
    .await;

    // Step 2: Add policy + prepare + store secret + authz relationship
    let policy_id = cli_tool::add_policy_to_chain_with_config(net.chain_config.clone())
        .await
        .expect("add policy");
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

    let did = "fault_reader_1".to_string();
    cli_tool::register_object_to_chain_with_config(
        policy_id.clone(),
        object_id.clone(),
        resource.clone(),
        net.chain_config.clone(),
    )
    .await
    .expect("register object to chain");
    cli_tool::set_relationship_on_chain_with_config(
        policy_id.clone(),
        object_id.clone(),
        resource.clone(),
        "reader".to_string(),
        Some(did.clone()),
        net.chain_config.clone(),
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

    // Step 1: DKG → ring (threshold=2)
    let (ring_pk_hex, ring_id) = setup_ring(
        &net.chain_config,
        &endpoint,
        &net.node_keys,
        2,
        &net.policy_id,
    )
    .await;

    // Step 2: Add policy + prepare + store secret + authz relationship
    let policy_id = cli_tool::add_policy_to_chain_with_config(net.chain_config.clone())
        .await
        .expect("add policy");
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

    let did = "fault_reader_2".to_string();
    cli_tool::register_object_to_chain_with_config(
        policy_id.clone(),
        object_id.clone(),
        resource.clone(),
        net.chain_config.clone(),
    )
    .await
    .expect("register object to chain");
    cli_tool::set_relationship_on_chain_with_config(
        policy_id.clone(),
        object_id.clone(),
        resource.clone(),
        "reader".to_string(),
        Some(did.clone()),
        net.chain_config.clone(),
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

    // Step 1: DKG → ring (threshold=2)
    let (ring_pk_hex, ring_id) = setup_ring(
        &net.chain_config,
        &endpoint,
        &net.node_keys,
        2,
        &net.policy_id,
    )
    .await;

    // Step 2: Prepare secret (local, no network needed)
    let policy_id = cli_tool::add_policy_to_chain_with_config(net.chain_config.clone())
        .await
        .expect("add policy");
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
        policy_id.clone(),
        resource.clone(),
        permission.clone(),
        None,
        true,
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

    // Step 1: DKG → ring (threshold=2)
    let (ring_pk_hex, ring_id) = setup_ring(
        &net.chain_config,
        &endpoint,
        &net.node_keys,
        2,
        &net.policy_id,
    )
    .await;

    // Step 2: Prepare secret (local)
    let policy_id = cli_tool::add_policy_to_chain_with_config(net.chain_config.clone())
        .await
        .expect("add policy");
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
            policy_id.clone(),
            resource.clone(),
            permission.clone(),
            None,
            true,
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

    // Create the ring on-chain before blocking charlie
    let ring_id =
        create_ring_on_chain(&net.chain_config, &net.node_keys, 2, &net.policy_id, None).await;

    // Block charlie on alice AND bob so charlie is unreachable for DKG
    let charlie_hex = net.charlie.peer_hex.clone();
    net.alice.fault_ctrl.block_peer(&charlie_hex).await;
    net.bob.fault_ctrl.block_peer(&charlie_hex).await;

    // Initiate DKG — the DKG service checks connectivity to all peers upfront.
    // Because charlie is blocked on alice's outbound controller, alice cannot
    // reach charlie and the DKG call must return an error immediately.
    let dkg_result = cli_tool::do_dkg(endpoint.to_string(), ring_id).await;

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

/// A private DKG-share pair partner that silently stalls every response (never
/// hangs up, never replies) is reported `node_offline` once the ceremony's
/// hard attempt deadline passes — distinct from `test_dkg_repairs_gossip_loss_
/// and_private_disconnects` above, which stalls exactly one response and
/// proves the retry path recovers. Here every response stalls for the whole
/// ceremony, so retries never succeed and the sender's terminal-offline check
/// (`open_private_pair` in `network.rs`) fires at the deadline.
///
/// Fault injection here only wraps a node's own *outbound* connections, not
/// its inbound/server side, and is scoped by protocol, not by peer — so it
/// can't target "peer X's responses to peer Y" directly. Instead this stalls
/// the canonical-middle node's outbound view: in a 3-node ring the two lower
/// node IDs each open exactly one private pair with a higher ID, and the
/// middle ID opens a stream only to the highest ID (it's a pure responder for
/// the lowest ID's pair) — so stalling the middle node's outbound private
/// responses deterministically implicates only the highest-ID node.
#[tokio::test]
#[serial_test::serial]
async fn test_dkg_private_pair_terminal_stall_triggers_on_chain_report() {
    let net = setup_fault_three_node_network("fault_dkg_private_terminal", 51078).await;

    let mut ordered: Vec<(&str, &str, &FaultNetworkController)> = vec![
        (
            net.node_keys[0].as_str(),
            net.alice.grpc_endpoint.as_str(),
            &net.alice.fault_ctrl,
        ),
        (
            net.node_keys[1].as_str(),
            net.bob.grpc_endpoint.as_str(),
            &net.bob.fault_ctrl,
        ),
        (
            net.node_keys[2].as_str(),
            net.charlie.grpc_endpoint.as_str(),
            &net.charlie.fault_ctrl,
        ),
    ];
    ordered.sort_by(|left, right| left.0.cmp(right.0));
    let (_lowest_key, lowest_endpoint, _) = ordered[0];
    let (_middle_key, _middle_endpoint, middle_ctrl) = ordered[1];
    let (highest_key, _highest_endpoint, _) = ordered[2];

    // Every private-plane response the middle node's own outbound connections
    // receive stalls for the rest of the ceremony (a huge pass-through-0
    // count), well past PEER_RESPONSE_TIMEOUT, so retries never succeed and
    // the sender never observes a real reply from its higher-ID partner.
    middle_ctrl
        .stall_protocol_responses_after(
            network::V0.dkg_private_alpn,
            0,
            1000,
            PEER_RESPONSE_TIMEOUT + Duration::from_secs(1),
        )
        .await;

    let ring_id =
        create_ring_on_chain(&net.chain_config, &net.node_keys, 2, &net.policy_id, None).await;

    println!("Subscribing to report events...");
    let sub = ReportEventSubscription::connect(&net.chain_config.rpc_url)
        .await
        .expect("connect report event subscription");

    // Fire-and-forget: the ceremony runs to its hard deadline in the
    // background regardless of whether this triggering RPC call is still
    // being awaited.
    tokio::spawn(cli_tool::do_dkg(
        lowest_endpoint.to_string(),
        ring_id.clone(),
    ));

    println!("Waiting for organic private-pair-stall EventReportAccepted on chain (up to 240s)...");
    let event = sub
        .wait_for_report_accepted_matching(&ring_id, Duration::from_secs(240), |event| {
            event.report_type == "node_offline" && event.accused_node_key == highest_key
        })
        .await
        .expect("stalled private pair should organically report the silent partner");

    println!(
        "Private-pair-stall report accepted on chain: report_id={} accused={} reporter={}",
        event.report_id, event.accused_node_key, event.reporter_node_key
    );

    assert_eq!(event.report_type, "node_offline", "unexpected report_type");
    assert_eq!(
        event.accused_node_key, highest_key,
        "the highest-ID node should be accused, since only the middle node's \
         outbound pair to it was stalled"
    );
    assert_eq!(event.ring_id, ring_id, "ring_id mismatch");
    assert!(!event.report_id.is_empty(), "report_id should be set");
    assert_ne!(
        event.reporter_node_key, highest_key,
        "the accused node should not be its own reporter"
    );

    let controller_client = SourceHubClient::with_signer(
        net.chain_config.clone(),
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, net.chain_config.clone())
            .expect("test account signer"),
    )
    .await
    .expect("controller chain client");
    let demerits = controller_client
        .orbis_read_node_demerits(&ring_id, highest_key)
        .await
        .expect("query accused demerits");
    assert!(
        demerits > 0,
        "silent private-pair partner should receive at least one demerit"
    );
}

/// A committee member that never receives (hence never acks) the leader's
/// Gossip topology probe during a **Reshare** is reported `node_offline` and
/// the ceremony aborts at the preparation barrier — gated by
/// `DKG_PREPARATION_TIMEOUT` (2 minutes, unaffected by the `DKG_ATTEMPT_
/// TIMEOUT` test-mode shrink), not the ceremony's overall hard deadline.
///
/// This must be a Reshare (not a Fresh DKG): `spawn_pss_offline_observations`
/// (`dkg/v0/coordinator/reporting.rs`) unconditionally skips
/// `SessionKind::Fresh`, because every report is threshold-signed under the
/// ring's own key (`sign_and_submit_report` → `SignCoordinator::
/// initiate_signing`) — a Fresh DKG that fails before completing has no key
/// yet to sign with, so a Fresh-DKG topology-ack failure can never
/// organically produce a signed report. Reusing the same 3-node committee
/// for both old and new (triggered by an ACP threshold-only change, no
/// membership change) is the simplest way to get a Reshare with a real,
/// already-completed ring key to sign under.
///
/// `drop_gossip_deliveries_after` drops every authenticated Gossip delivery
/// the accused's own subscription receives, not just the topology probe —
/// but nothing else is gossiped this early in a ceremony, so it's an
/// effective stand-in for "the probe specifically never arrived." It's
/// applied only after the initial DKG succeeds, so the accused participates
/// normally in establishing the ring key and only goes silent for the
/// reshare. The accused must not be the reshare's canonical leader — a
/// leader self-acks its own topology probe immediately
/// (`begin_topology_probe`) and never needs to receive it via Gossip, so
/// blocking a leader's inbound Gossip would be a no-op (the ceremony
/// completes normally in under a second and no report is ever due). Node
/// keys are freshly randomized every run, so which physical node ends up as
/// leader (`transport::canonical_leader`, `.min()` of the committee's keys)
/// isn't fixed — the test picks whichever committee member is guaranteed
/// *not* to be leader (the one with the largest key) as the accused.
///
/// Uses `setup_fault_three_node_network_with_reshare_interval` (not the
/// plain helper) — a pending on-chain reshare is only ever picked up and
/// driven by each node's own background PSS scheduler
/// (`pss::spawn_pss_scheduler`), which every other test in this file
/// deliberately disables (`reshare_interval_secs: 0`). Unlike Fresh DKG
/// there is no explicit client RPC to start a reshare ceremony directly, so
/// without a running scheduler the on-chain announcement here would never
/// be discovered by anyone and the ceremony would simply never start.
#[tokio::test]
#[serial_test::serial]
async fn test_reshare_missing_topology_ack_triggers_on_chain_report() {
    let net =
        setup_fault_three_node_network_with_reshare_interval("fault_reshare_topology_ack", 51084, 1)
            .await;

    // The reshare's canonical leader is whichever committee member has the lexicographically
    // *smallest* node key (`transport::canonical_leader`, `.min()`) — a leader self-acks its own
    // topology probe immediately (`begin_topology_probe` inserts itself before broadcasting) and
    // never needs to receive it via Gossip at all, so blocking a leader's inbound Gossip is a
    // no-op: the ceremony completes normally in well under a second and no report is ever due.
    // Node keys are freshly randomized every run, so which of our three handles ends up as leader
    // isn't fixed — accuse whichever one is guaranteed *not* to be it (the largest key) instead.
    let handles = [&net.alice, &net.bob, &net.charlie];
    let (accused_index, _) = net
        .node_keys
        .iter()
        .enumerate()
        .max_by_key(|(_, key)| key.as_str())
        .expect("three node keys");
    let accused = handles[accused_index];
    let accused_key = net.node_keys[accused_index].clone();
    let signers: Vec<&FaultableNodeHandle> = handles
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != accused_index)
        .map(|(_, handle)| *handle)
        .collect();

    let ring_id =
        create_ring_on_chain(&net.chain_config, &net.node_keys, 2, &net.policy_id, None).await;

    println!("Running the initial DKG so the ring has a real key to reshare...");
    cli_tool::do_dkg(net.alice.grpc_endpoint.clone(), ring_id.clone())
        .await
        .expect("initial DKG should succeed");
    wait_for_ring_finalized(&net.chain_config, &ring_id, Duration::from_secs(90)).await;

    println!("The accused (non-leader) member will never see the reshare's topology probe...");
    accused
        .fault_ctrl
        .drop_gossip_deliveries_after(0, usize::MAX)
        .await;
    // Blocking Gossip alone isn't enough to make the eventual `node_offline` report land:
    // an independent co-signer separately health-probes the accused over a dedicated direct
    // QUIC protocol (`reporting_health_alpn`, unaffected by the Gossip fault above) before
    // signing, and correctly refuses to sign a report against a peer that's still reachable
    // (`require_peer_offline`, `reporting/v0/health.rs`). `FaultNetworkController` only
    // intercepts outbound connections, not inbound/server-side ones, so the accused's own
    // controller can't block it from *answering* the probe — instead, block the other two
    // members' outbound probes to it (the only ones who could ever be asked to co-sign here).
    for signer in &signers {
        signer
            .fault_ctrl
            .fail_protocol_responses_after(network::V0.reporting_health_alpn, 0, 1000)
            .await;
    }

    println!("Subscribing to report events...");
    let sub = ReportEventSubscription::connect(&net.chain_config.rpc_url)
        .await
        .expect("connect report event subscription");

    println!("Triggering reshare (same committee, new threshold)...");
    cli_tool::start_ring_reshare_by_acp_with_config(
        ring_id.clone(),
        net.node_keys.clone(),
        Some(3u32),
        net.chain_config.clone(),
    )
    .await
    .expect("start ring reshare announcement");

    println!(
        "Waiting for organic missing-topology-ack EventReportAccepted on chain (up to 180s)..."
    );
    let event = sub
        .wait_for_report_accepted_matching(&ring_id, Duration::from_secs(180), |event| {
            event.report_type == "node_offline" && event.accused_node_key == accused_key
        })
        .await
        .expect("aborted reshare topology barrier should organically report the silent member");

    println!(
        "Missing-topology-ack report accepted on chain: report_id={} accused={} reporter={}",
        event.report_id, event.accused_node_key, event.reporter_node_key
    );

    assert_eq!(event.report_type, "node_offline", "unexpected report_type");
    assert_eq!(
        event.accused_node_key, accused_key,
        "the member that never received the reshare's topology probe should be accused"
    );
    assert_eq!(event.ring_id, ring_id, "ring_id mismatch");
    assert!(!event.report_id.is_empty(), "report_id should be set");
    assert_ne!(
        event.reporter_node_key, accused_key,
        "the accused node should not be its own reporter"
    );

    let controller_client = SourceHubClient::with_signer(
        net.chain_config.clone(),
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, net.chain_config.clone())
            .expect("test account signer"),
    )
    .await
    .expect("controller chain client");
    let demerits = controller_client
        .orbis_read_node_demerits(&ring_id, &accused_key)
        .await
        .expect("query accused demerits");
    assert!(
        demerits > 0,
        "silent topology-probe partner should receive at least one demerit"
    );
}
