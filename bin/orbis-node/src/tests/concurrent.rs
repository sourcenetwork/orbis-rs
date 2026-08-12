//! In-process protocol tests with real SourceHub.
//!
//! Spins up three orbis nodes IN-PROCESS (no Docker node images) and runs full
//! DKG/PRE/SIGN protocols against them via gRPC, while SourceHub runs in Docker
//! (docker-compose-sourcehub-test.yml).
//!
//! Run with:
//!   cargo test --features integration-test -- --nocapture

use crate::{
    app_state::AppState,
    constants::{
        GRPC_CONCURRENCY_LIMIT_PER_CONNECTION, GRPC_MAX_CONCURRENT_STREAMS, MAX_SIGN_REQUEST_BYTES,
        MAX_SMALL_GRPC_REQUEST_BYTES, MAX_STORE_SECRET_REQUEST_BYTES, MIN_NODE_BALANCE,
    },
    dkg::v0::helpers::serialize_commitment_coefficients,
    dkg::v0::service::DkgServiceImpl,
    helpers::{
        launch::{create_and_store_node_key, LogLevel},
        test_helpers::{
            cleanup_db, create_authenticated_request, create_orbis_ring_policy,
            create_ring_on_chain, test_db_path, wait_for_nodes_ready, wait_for_ring_finalized,
            TestKeyPair,
        },
    },
    info::InfoServiceImpl,
    init_node,
    pre::v0::service::PreServiceImpl,
    reporting::v0::{
        observation::{InvalidCryptoResponseObservation, ReportObservation},
        queue_report,
        types::{
            ring_state_sha256, CommitteeScope, DkgCommitmentStatement, DkgShareStatement,
            InvalidCryptoResponse, CHAIN_BLOCK_GRACE_SECS, DKG_COMMITMENT_DOMAIN, DKG_SHARE_DOMAIN,
        },
    },
    sign::v0::service::SignServiceImpl,
    store_secret::StoreSecretServiceImpl,
    Args, NodeConfig,
};
use authn::DkgClaims;
use authz::r#trait::Authz;
use authz::AuthzImpl;
use bulletin::r#trait::{Bulletin, BulletinKind, BulletinWriteKind, NodeInfo, RingPayload};
use bulletin::BulletinImpl;
use common::{
    blockchain::{
        events::ReportEventSubscription, sign_node_message_with_hex_key, ChainConfig,
        SourceHubClient, TxSigner, TEST_ACCOUNT_HEX_KEY,
    },
    SourceHubTestContainer,
};
use crypto::{
    helpers::generate_keypair,
    r#trait::{CryptoDeserialize, Dkg, DkgMode, DkgRole},
    CryptoSerialize, DkgImpl, PreImpl, ScalarField, SignImpl,
};
use local_storage::{
    r#trait::{LocalStorage, LocalStorageKeys},
    LocalStorageImpl,
};
use network::{Network, NetworkImpl};
use proto::{
    info_service::{
        info_service_client::InfoServiceClient, info_service_server::InfoServiceServer,
        GetRingStateRequest,
    },
    v0::dkg::{
        dkg_service_client::DkgServiceClient, dkg_service_server::DkgServiceServer, StartDkgRequest,
    },
    v0::pre::pre_service_server::PreServiceServer,
    v0::sign::sign_service_server::SignServiceServer,
    v0::store_secret::store_secret_service_server::StoreSecretServiceServer,
};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{collections::HashSet, sync::Arc};
use tokio::time::{sleep, Duration, Instant};
use tonic::Request;

/// A running in-process orbis node with its gRPC server.
struct LiveNodeHandle {
    grpc_endpoint: String,
    peer_addr: String,
    _public_address: String,
    db_path: String,
    app_state: Arc<AppState<DkgImpl>>,
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
    /// ACP policy ID all three nodes are whitelisted for.
    policy_id: String,
    /// Compressed pubkeys of alice, bob, charlie (in that order).
    node_keys: Vec<String>,
    chain_config: ChainConfig,
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
    chain_config: ChainConfig,
    _chain: SourceHubTestContainer,
}

/// Build and spawn a gRPC server from an `InitializedNode`.
///
/// Returns a `JoinHandle<()>` — abort it to stop the server.
/// Unlike `run_server`, this skips metrics registration (test-only).
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
    setup_live_three_node_network_with_trusted_relays(db_prefix, base_port, HashSet::new()).await
}

async fn setup_live_three_node_network_with_trusted_relays(
    db_prefix: &str,
    base_port: u16,
    trusted_auth_relay_dids: HashSet<String>,
) -> LiveThreeNodeNetwork {
    let chain = SourceHubTestContainer::new();
    let chain_config = chain.chain_config();
    let runtime_base_path = project_root::get_project_root()
        .expect("resolve project root")
        .join("target")
        .join("test-runtime")
        .join(db_prefix);

    let policy_id = create_orbis_ring_policy(&chain_config).await;

    let mut handles: Vec<LiveNodeHandle> = Vec::new();
    let mut node_keys: Vec<String> = Vec::new();

    for i in 0..3u16 {
        let port = base_port + i;
        let db_path = test_db_path(&format!("{}_{}", db_prefix, i));
        cleanup_db(&db_path); // clear any leftover from a previous failed run

        let local_storage = LocalStorageImpl::new("test-password".to_string(), db_path.clone())
            .expect("local storage");

        // Create signing key (stored in local_storage) and fund it via the faucet
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

        // Real bulletin backed by SourceHub (uses the funded signer to post)
        let bulletin: Arc<dyn Bulletin + Send + Sync> = Arc::new(
            BulletinImpl::with_signer(chain.chain_config_builder(), signer, Some(MIN_NODE_BALANCE))
                .await
                .expect("BulletinImpl with signer"),
        );

        // Real authz backed by SourceHub
        let authz: Arc<dyn Authz> = Arc::new(
            AuthzImpl::new(chain.chain_config_builder())
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
                chain_id: None,
                denom: None,
                chain_gas_multiplier: None,
                metrics_addr: None,
                loki_url: None,
                runtime_base_path: None,
                reshare_interval_secs: 0,
                network_private_routes_only: false,
                node_controller_key: node_key.clone(),
                node_peer_id: None,
                node_whitelisted_policy_ids: vec![policy_id.clone()],
                node_whitelisted_ring_ids: vec![],
                trusted_auth_relay_dids: trusted_auth_relay_dids.iter().cloned().collect(),
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
        let app_state = node.app_state.clone();
        let task = spawn_test_grpc_server(node);

        handles.push(LiveNodeHandle {
            grpc_endpoint: format!("http://{}", grpc_bind),
            peer_addr,
            _public_address: public_address,
            db_path,
            app_state,
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
        policy_id,
        node_keys,
        chain_config,
        _chain: chain,
    }
}

async fn setup_live_four_node_network(db_prefix: &str, base_port: u16) -> LiveFourNodeNetwork {
    let chain = SourceHubTestContainer::new();
    let chain_config = chain.chain_config();
    let runtime_base_path = project_root::get_project_root()
        .expect("resolve project root")
        .join("target")
        .join("test-runtime")
        .join(db_prefix);

    let policy_id = create_orbis_ring_policy(&chain_config).await;

    let mut handles: Vec<LiveNodeHandle> = Vec::new();
    let mut node_keys: Vec<String> = Vec::new();

    for i in 0..4u16 {
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
                chain_id: None,
                denom: None,
                chain_gas_multiplier: None,
                metrics_addr: None,
                loki_url: None,
                runtime_base_path: None,
                reshare_interval_secs: 0,
                network_private_routes_only: false,
                node_controller_key: node_key.clone(),
                node_peer_id: None,
                node_whitelisted_policy_ids: vec![policy_id.clone()],
                node_whitelisted_ring_ids: vec![],
                trusted_auth_relay_dids: vec![],
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
        let app_state = node.app_state.clone();
        let task = spawn_test_grpc_server(node);

        handles.push(LiveNodeHandle {
            grpc_endpoint: format!("http://{}", grpc_bind),
            peer_addr,
            _public_address: public_address,
            db_path,
            app_state,
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
        chain_config,
        _chain: chain,
    }
}

// =========================================================================
// Shared helpers
// =========================================================================

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

async fn read_ring_payload(chain_config: &ChainConfig, ring_id: &str) -> RingPayload {
    let payload_bytes = cli_tool::read_bulletin_post_with_config(
        ring_id.to_string(),
        BulletinKind::Ring,
        chain_config.clone(),
    )
    .await
    .expect("read ring bulletin post");
    serde_json::from_slice(&payload_bytes).expect("parse RingPayload")
}

async fn wait_for_live_ring_states(nodes: &[&LiveNodeHandle], ring_pk_hex: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let mut all_ready = true;
        for node in nodes {
            let Ok(mut client) = InfoServiceClient::connect(node.grpc_endpoint.clone()).await
            else {
                all_ready = false;
                break;
            };
            let Ok(resp) = client
                .get_ring_state(Request::new(GetRingStateRequest {
                    ring_pk_hex: ring_pk_hex.to_string(),
                }))
                .await
            else {
                all_ready = false;
                break;
            };
            if resp.into_inner().public_polynomial.is_empty() {
                all_ready = false;
                break;
            }
        }
        if all_ready {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "live nodes did not persist ring state in time"
        );
        sleep(Duration::from_millis(250)).await;
    }
}

fn signed_bad_refresh_dkg_share_observation(
    chain_id: String,
    ring_id: String,
    ring: &RingPayload,
    accused_node_key: String,
    accused_peer_id: String,
    accused_app_state: &AppState<DkgImpl>,
) -> InvalidCryptoResponseObservation {
    let from_node_id = sorted_node_id(&accused_node_key, &ring.peer_node_keys);
    let to_node_id = (1..=ring.peer_node_keys.len() as u32)
        .find(|candidate| {
            *candidate != from_node_id
                && ring
                    .peer_node_keys
                    .get(candidate.saturating_sub(1) as usize)
                    .is_some_and(|node_key| node_key != &accused_node_key)
        })
        .expect("non-accused receiver");
    let receiver_node_key = ring.peer_node_keys[to_node_id.saturating_sub(1) as usize].clone();

    let dkg_session_id = 424_242_171_u128;
    let request_id = dkg_session_id.to_string();
    let mut dealer = DkgImpl::new(
        from_node_id,
        ring.threshold as usize,
        ring.peer_node_keys.len(),
        dkg_session_id,
        DkgRole::Standard,
    )
    .expect("create DKG dealer");
    dealer
        .generate_polynomial(DkgMode::Refresh)
        .expect("generate refresh polynomial");
    let commitment =
        serialize_commitment_coefficients(&dealer.commitment().coefficients).expect("commitment");
    let share = dealer
        .generate_shares()
        .expect("generate shares")
        .into_iter()
        .find(|share| share.to_id == to_node_id)
        .expect("share for receiver");
    let share_value = <ScalarField as CryptoSerialize>::to_bytes(&share.value).expect("share");
    let mut bad_share_value = ScalarField::from_bytes(&share_value).expect("deserialize share");
    bad_share_value += ScalarField::from(1_u64);
    let bad_share_value =
        <ScalarField as CryptoSerialize>::to_bytes(&bad_share_value).expect("bad share");
    assert_ne!(share_value, bad_share_value);

    let signed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs();
    let commitment_statement = DkgCommitmentStatement {
        domain: DKG_COMMITMENT_DOMAIN.to_string(),
        chain_id: chain_id.clone(),
        ring_id: ring_id.clone(),
        ring_pk: ring.ring_pk.clone(),
        ring_state_sha256: ring_state_sha256(ring),
        protocol_version: network::V0.version,
        request_id: request_id.clone(),
        signed_at: signed_at - 1,
        responder_node_key: accused_node_key.clone(),
        origin_protocol: "pss_refresh".to_string(),
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        from_node_id,
        commitment,
        session_nonce: [0u8; 16],
        crypto_backend: DkgImpl::name(),
    };
    let signing_key = accused_app_state
        .local_storage
        .get_encrypted(LocalStorageKeys::NodeSigningKey)
        .expect("read node signing key")
        .expect("node signing key exists");
    let signing_key_hex = String::from_utf8(signing_key.to_vec()).expect("signing key hex");
    let commitment_signature =
        sign_node_message_with_hex_key(&signing_key_hex, &commitment_statement.canonical_bytes())
            .expect("sign DKG commitment evidence");
    let statement = DkgShareStatement {
        domain: DKG_SHARE_DOMAIN.to_string(),
        chain_id,
        ring_id: ring_id.clone(),
        ring_pk: ring.ring_pk.clone(),
        ring_state_sha256: ring_state_sha256(ring),
        protocol_version: network::V0.version,
        request_id,
        signed_at,
        responder_node_key: accused_node_key.clone(),
        receiver_node_key,
        origin_protocol: "pss_refresh".to_string(),
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        from_node_id,
        to_node_id,
        commitment_statement,
        commitment_signature,
        share_value: bad_share_value,
        nonce: share.nonce,
        crypto_backend: DkgImpl::name(),
    };
    let response_signature =
        sign_node_message_with_hex_key(&signing_key_hex, &statement.canonical_bytes())
            .expect("sign DKG share evidence");
    let observed_at = signed_at - CHAIN_BLOCK_GRACE_SECS;
    InvalidCryptoResponseObservation {
        ring_id,
        accused_node_key,
        accused_peer_id,
        observed_at,
        evidence: InvalidCryptoResponse::DkgShare {
            statement: Box::new(statement),
            response_signature,
        },
    }
}

fn sorted_node_id(node_key: &str, peer_node_keys: &[String]) -> u32 {
    let mut sorted_node_keys = peer_node_keys.to_vec();
    sorted_node_keys.sort();
    sorted_node_keys
        .iter()
        .position(|candidate| candidate == node_key)
        .map(|index| index as u32 + 1)
        .expect("node key in ring")
}

// =========================================================================
// Tests
// =========================================================================

#[tokio::test]
#[serial_test::serial]
async fn test_delegated_dkg_with_sourcehub_end_to_end() {
    let relay = TestKeyPair::new();
    let net = setup_live_three_node_network_with_trusted_relays(
        "delegated_dkg_sourcehub",
        51120,
        HashSet::from([relay.did_uri.clone()]),
    )
    .await;
    let ring_id =
        create_ring_on_chain(&net.chain_config, &net.node_keys, 2, &net.policy_id, None).await;
    let token = relay
        .sign_for_actor(
            "did:opk:integration-user".to_string(),
            DkgClaims {
                ring_id: ring_id.clone(),
            },
            Duration::from_secs(60),
        )
        .expect("create delegated DKG token");
    let request = create_authenticated_request(
        StartDkgRequest {
            ring_id: ring_id.clone(),
        },
        &token,
    )
    .expect("create authenticated DKG request");

    let response = DkgServiceClient::connect(net.alice.grpc_endpoint.clone())
        .await
        .expect("connect DKG client")
        .start_dkg(request)
        .await
        .expect("start delegated DKG")
        .into_inner();
    assert!(
        !response.session_id.is_empty(),
        "DKG session ID is required"
    );

    let ring_pk =
        wait_for_ring_finalized(&net.chain_config, &ring_id, Duration::from_secs(90)).await;
    assert!(!ring_pk.is_empty(), "delegated DKG must finalize the ring");
}

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
    let ring_id_1 = create_ring_on_chain(
        &net.chain_config,
        &net.node_keys,
        2,
        &net.policy_id,
        Some("session-1"),
    )
    .await;
    let ring_id_2 = create_ring_on_chain(
        &net.chain_config,
        &net.node_keys,
        2,
        &net.policy_id,
        Some("session-2"),
    )
    .await;

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
        wait_for_ring_finalized(&net.chain_config, &ring_id_1, timeout),
        wait_for_ring_finalized(&net.chain_config, &ring_id_2, timeout),
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

#[tokio::test]
#[serial_test::serial]
async fn test_sourcehub_accepts_invalid_crypto_dkg_share_report_from_live_nodes() {
    let net = setup_live_three_node_network("reporting_dkg_share_sourcehub", 51080).await;
    let endpoint = net.alice.grpc_endpoint.clone();

    let (ring_pk_hex, ring_id) = setup_ring(
        &net.chain_config,
        &endpoint,
        &net.node_keys,
        2,
        &net.policy_id,
    )
    .await;
    wait_for_live_ring_states(&[&net.alice, &net.bob, &net.charlie], &ring_pk_hex).await;
    let ring = read_ring_payload(&net.chain_config, &ring_id).await;

    let accused_node_key = net.node_keys[2].clone();
    let observation = signed_bad_refresh_dkg_share_observation(
        net.chain_config.chain_id.clone(),
        ring_id.clone(),
        &ring,
        accused_node_key.clone(),
        net.charlie.peer_addr.clone(),
        &net.charlie.app_state,
    );

    let sub = ReportEventSubscription::connect(&net.chain_config.rpc_url)
        .await
        .expect("connect report event subscription");
    assert!(
        queue_report::<DkgImpl, SignImpl>(
            net.alice.app_state.clone(),
            &network::V0,
            ReportObservation::InvalidCryptoResponse(Box::new(observation)),
        )
        .await
        .expect("queue invalid DKG-share report"),
        "report should be queued"
    );
    net.alice.app_state.reporting_state.shutdown().await;

    let event = sub
        .wait_for_report_accepted(&ring_id, Duration::from_secs(120))
        .await
        .expect("DKG-share invalid-crypto report should be accepted on SourceHub");

    assert_eq!(event.report_type, "invalid_crypto_response");
    assert_eq!(event.accused_node_key, accused_node_key);
    assert_eq!(event.ring_id, ring_id);
    assert!(!event.report_id.is_empty(), "report_id should be set");
    assert!(
        [net.node_keys[0].as_str(), net.node_keys[1].as_str()]
            .contains(&event.reporter_node_key.as_str()),
        "reporter should be a non-accused current-committee member, got {}",
        event.reporter_node_key
    );

    let controller_client = SourceHubClient::with_signer(
        net.chain_config.clone(),
        TxSigner::from_hex_key(TEST_ACCOUNT_HEX_KEY, net.chain_config.clone())
            .expect("test account signer"),
    )
    .await
    .expect("controller chain client");
    let demerits = controller_client
        .orbis_read_node_demerits(&ring_id, &accused_node_key)
        .await
        .expect("query accused demerits");
    assert_eq!(
        demerits, 1,
        "invalid DKG-share report should add one demerit"
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
    let (ring_pk_hex, ring_id) = setup_ring(
        &net.chain_config,
        &endpoint,
        &net.node_keys,
        2,
        &net.policy_id,
    )
    .await;

    // Step 2: Store one encrypted secret on the bulletin
    let policy_id = cli_tool::add_policy_to_chain_with_config(net.chain_config.clone())
        .await
        .expect("add policy");
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
    let (ring_pk_hex, ring_id) = setup_ring(
        &net.chain_config,
        &endpoint,
        &net.node_keys,
        2,
        &net.policy_id,
    )
    .await;

    // Step 2: Add a policy (required as payload metadata; authz enforcement is PRE-only)
    let policy_id = cli_tool::add_policy_to_chain_with_config(net.chain_config.clone())
        .await
        .expect("add policy");
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
    let ring_id =
        create_ring_on_chain(&net.chain_config, &net.node_keys, 2, &net.policy_id, None).await;

    // Initiate DKG from the last node's endpoint (non_participant)
    cli_tool::do_dkg(net.non_participant.grpc_endpoint.clone(), ring_id.clone())
        .await
        .expect("DKG from non_participant initiator");

    let ring_pk_hex =
        wait_for_ring_finalized(&net.chain_config, &ring_id, Duration::from_secs(90)).await;

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
