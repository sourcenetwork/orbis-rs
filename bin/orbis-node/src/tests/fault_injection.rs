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
use common::{blockchain::ChainConfig, SourceHubTestContainer};
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
                denom: None,
                chain_gas_multiplier: None,
                metrics_addr: None,
                loki_url: None,
                runtime_base_path: None,
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

        handles.push(FaultableNodeHandle {
            grpc_endpoint: format!("http://{}", grpc_bind),
            _peer_addr: peer_addr,
            _public_address: public_address,
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
    let net = setup_fault_three_node_network("fault_dkg_hybrid_repair", 51058).await;

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
