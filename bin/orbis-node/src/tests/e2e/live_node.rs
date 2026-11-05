//! Shared in-process node bootstrap for the `concurrent`/`fault_injection`
//! test families (harness-unification migration, PR 6).
//!
//! Spins up real orbis nodes IN-PROCESS (no Docker node images) against a
//! chain-only Docker container — Cosmos/Vera via [`test_support::VeraTestContainer`],
//! native Vera via [`test_support::NativeTestNetwork`] directly (not through
//! `NativeNetworkAdapter`, which also launches `node1..4` Docker images this
//! layer doesn't want). Every per-node gRPC server is a bare
//! `tonic::transport::Server` built from an `InitializedNode`
//! ([`spawn_test_grpc_server`]), giving test code a direct, in-process handle
//! to each node's `Network`/`AppState` — the thing Docker-Compose's
//! `stop_node`/`UnsafeTestingService` can't offer, and the reason this family
//! of tests doesn't use `TestEnvironmentImpl`.
//!
//! `#[allow(dead_code)]`: only [`setup_live_node_network`]'s one current
//! consumer (`concurrent_simultaneous_dkg.rs`) is migrated so far — most of
//! `Chain`'s surface (`node_keys`, `policy_id`) and the 4-node shape are here
//! for the next migration batch (the other 10 Bucket A/B tests in
//! `concurrent.rs`/`fault_injection.rs`), not yet exercised. Same precedent as
//! `native_environment.rs`'s own module-level `#![allow(dead_code)]`.
#![allow(dead_code)]

// `crate::` is the `orbis-node` lib. This module is part of that lib's
// `#[cfg(test)]` tree (`src/tests/e2e/mod.rs`). The two import lists stay
// cfg-gated on the backend the same way `pending_ring_cancellation.rs`
// gates `RingIndexEntry`, covering a much larger import list.
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
use crate::{
    app_state::AppState,
    constants::{
        GRPC_CONCURRENCY_LIMIT_PER_CONNECTION, GRPC_MAX_CONCURRENT_STREAMS, MAX_PRE_REQUEST_BYTES,
        MAX_SIGN_REQUEST_BYTES, MAX_SMALL_GRPC_REQUEST_BYTES, MAX_STORE_SECRET_REQUEST_BYTES,
    },
    dkg::v0::service::DkgServiceImpl,
    helpers::test_helpers::{create_ring_on_chain, create_ring_on_chain_with_trusted_relays},
    helpers::{
        launch::{create_and_store_node_key, CorsPolicy, LogLevel},
        test_helpers::{cleanup_db, test_db_path, wait_for_nodes_ready},
    },
    info::InfoServiceImpl,
    init_node,
    pre::v0::service::PreServiceImpl,
    sign::v0::service::SignServiceImpl,
    store_secret::StoreSecretServiceImpl,
    Args, InitializedNode, NetworkIngressArgs, NodeConfig,
};
#[cfg(all(feature = "integration-test", feature = "native"))]
use crate::{
    app_state::AppState,
    constants::{
        GRPC_CONCURRENCY_LIMIT_PER_CONNECTION, GRPC_MAX_CONCURRENT_STREAMS, MAX_PRE_REQUEST_BYTES,
        MAX_SIGN_REQUEST_BYTES, MAX_SMALL_GRPC_REQUEST_BYTES, MAX_STORE_SECRET_REQUEST_BYTES,
    },
    dkg::v0::service::DkgServiceImpl,
    helpers::{
        launch::{CorsPolicy, LogLevel},
        test_helpers::{cleanup_db, test_db_path, wait_for_nodes_ready},
    },
    info::InfoServiceImpl,
    init_node,
    pre::v0::service::PreServiceImpl,
    sign::v0::service::SignServiceImpl,
    store_secret::StoreSecretServiceImpl,
    Args, InitializedNode, NetworkIngressArgs, NodeConfig,
};
use authz::r#trait::Authz;
use bulletin::r#trait::{Bulletin, BulletinKind, BulletinWriteKind, NodeInfo, RingPayload};
use crypto::DkgImpl;
use local_storage::{r#trait::LocalStorage, LocalStorageImpl};
use network::{Network, NetworkImpl};
use proto::info_service::{info_service_client::InfoServiceClient, GetRingStateRequest};
use proto::{
    info_service::info_service_server::InfoServiceServer,
    v0::dkg::dkg_service_server::DkgServiceServer, v0::pre::pre_service_server::PreServiceServer,
    v0::sign::sign_service_server::SignServiceServer,
    v0::store_secret::store_secret_service_server::StoreSecretServiceServer,
};
use std::path::Path;
use std::sync::Arc;
use tokio::time::Duration;
use tonic::Request;

#[cfg(all(feature = "integration-test", feature = "cosmos"))]
use {
    authz::AuthzImpl,
    bulletin::vera::startup::MIN_NODE_BALANCE,
    bulletin::BulletinImpl,
    common::blockchain::{ChainConfig, VeraClient},
    test_support::VeraTestContainer,
};

#[cfg(all(feature = "integration-test", feature = "native"))]
use {
    alloy_primitives::B256,
    authz::native::NativeAuth,
    bulletin::native::{startup::initialize_identity, NativeBulletin, NativeVeraClient},
    commonware_codec::DecodeExt,
    test_support::NativeTestNetwork,
    vera_client::{
        create_scoped_bearer_token,
        rings::{encode_ring_command, ReportingConfig, RingCommand, RingConfig, RingState},
        BlsSigner, DelegationScope, VeraClient,
    },
    vera_domain::{ConsensusPublicKey, NativeTx},
};

/// A running in-process orbis node with its gRPC server.
pub struct LiveNodeHandle {
    pub grpc_endpoint: String,
    pub peer_addr: String,
    /// The node's on-chain identity key (compressed secp256k1 pubkey hex) --
    /// NOT `public_address` (Cosmos's bech32 funding address; native's own
    /// `public_address` happens to equal `node_key`, but Cosmos's doesn't).
    pub node_key: String,
    pub public_address: String,
    db_path: String,
    /// Native only: the node's own journal/worker-store directory, cleaned up
    /// alongside `db_path`. Always `None` on Cosmos.
    extra_cleanup_dir: Option<std::path::PathBuf>,
    pub app_state: Arc<AppState<DkgImpl>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for LiveNodeHandle {
    fn drop(&mut self) {
        self.task.abort();
        cleanup_db(&self.db_path);
        if let Some(dir) = &self.extra_cleanup_dir {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

impl LiveNodeHandle {
    /// Hard-kill this node's gRPC server task, simulating a crashed/offline
    /// node for fault-injection tests — a direct in-process abort rather than
    /// `FaultNetworkController::block_peer`'s network-level partition, since
    /// the tests built on this (PR 6's "Bucket B") only assert the outcome
    /// (an unreachable node is unreachable, full stop) and not which
    /// mechanism caused it.
    pub fn stop(&self) {
        self.task.abort();
    }
}

/// Three (or more) in-process orbis nodes backed by a real, chain-only Vera
/// container — Cosmos/SourceHub or native, picked at compile time.
pub struct LiveNodeNetwork {
    pub nodes: Vec<LiveNodeHandle>,
    policy_id: String,
    node_keys: Vec<String>,
    chain: Chain,
}

impl LiveNodeNetwork {
    pub fn node(&self, index: usize) -> &LiveNodeHandle {
        &self.nodes[index]
    }

    /// Create a ring on-chain over every node in this network. `nonce`
    /// distinguishes otherwise-identical rings (same members/threshold/
    /// policy) the way `create_ring_on_chain`'s own `nonce` parameter does on
    /// Cosmos — `None` reuses this layer's fixed default.
    pub async fn create_ring(&self, threshold: u32, nonce: Option<&str>) -> String {
        self.chain
            .create_ring(&self.node_keys, threshold, &self.policy_id, nonce)
            .await
    }

    pub async fn wait_for_ring_finalized(&self, ring_id: &str, timeout: Duration) -> String {
        self.chain.wait_for_ring_finalized(ring_id, timeout).await
    }

    /// Same as [`Self::create_ring`], but announces `trusted_relay_dids` as
    /// the ring's trusted auth-relay set (delegated-auth-token DKG tests).
    pub async fn create_ring_with_trusted_relays(
        &self,
        threshold: u32,
        nonce: Option<&str>,
        trusted_relay_dids: Vec<String>,
    ) -> String {
        self.chain
            .create_ring_with_trusted_relays(
                &self.node_keys,
                threshold,
                &self.policy_id,
                nonce,
                trusted_relay_dids,
            )
            .await
    }

    /// Create a fresh document-access ACP policy (`document`/`creator`/
    /// `reader`/`read`/`write`) — independent of this network's ring-
    /// creation policy, same as the original Cosmos-only tests always kept
    /// them separate.
    pub async fn create_document_policy(&self) -> String {
        self.chain.create_document_policy().await
    }

    pub async fn register_object(&self, policy_id: &str, resource: &str, object_id: &str) {
        self.chain
            .register_object(policy_id, resource, object_id)
            .await
    }

    /// `did_seed` is a raw seed string (not a derived DID) — each backend
    /// derives the real reader DID from it internally, the way
    /// `cli_tool::do_pre`/`do_sign`'s own callers already do.
    pub async fn grant(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
        did_seed: &str,
    ) {
        self.chain
            .grant(policy_id, resource, object_id, relation, did_seed)
            .await
    }

    pub async fn read_node_demerits(&self, ring_id: &str, node_key: &str) -> u64 {
        self.chain.read_node_demerits(ring_id, node_key).await
    }

    /// Read a ring's full bulletin-posted [`RingPayload`] via node 0's own
    /// in-process `Bulletin` handle — backend-neutral (`Bulletin::read` +
    /// `RingPayload::try_from` are shared trait/type machinery), so this
    /// needs no cfg-split.
    pub async fn read_ring_payload(&self, ring_id: &str) -> RingPayload {
        let post = self
            .node(0)
            .app_state
            .bulletin
            .read(ring_id.to_string(), BulletinKind::Ring)
            .await
            .expect("read ring bulletin post");
        RingPayload::try_from(post).expect("parse RingPayload")
    }
}

/// Create a ring on-chain, run DKG, and return `(ring_pk_hex, ring_id)` once
/// every participant has called FinalizeRing and the chain confirms.
pub async fn setup_ring(net: &LiveNodeNetwork, endpoint: &str, threshold: u32) -> (String, String) {
    let ring_id = net.create_ring(threshold, None).await;
    cli_tool::do_dkg(endpoint.to_string(), ring_id.clone())
        .await
        .expect("DKG initiation");
    let ring_pk = net
        .wait_for_ring_finalized(&ring_id, Duration::from_secs(90))
        .await;
    (ring_pk, ring_id)
}

/// Poll every given node's `InfoService.GetRingState` until each reports a
/// non-empty public polynomial for `ring_pk_hex` (i.e. has locally persisted
/// the finalized ring state), or panic after 30s.
pub async fn wait_for_live_ring_states(nodes: &[&LiveNodeHandle], ring_pk_hex: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
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
            tokio::time::Instant::now() < deadline,
            "live nodes did not persist ring state in time"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Build and spawn a gRPC server from an `InitializedNode`.
///
/// Listens on an ephemeral loopback port. The fixed ports these tests used to
/// request sit inside the kernel's ephemeral range, so an iroh or Docker bind
/// of port 0 can take one before this server starts and every readiness probe
/// is connection-refused.
///
/// Returns the bound address and a `JoinHandle<()>` — abort the handle to stop
/// the server. Unlike `run_server`, this skips metrics registration (test-only).
pub fn spawn_test_grpc_server(
    node: InitializedNode,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listen_addr: std::net::SocketAddr = "127.0.0.1:0".parse().expect("loopback ephemeral addr");
    let incoming =
        tonic::transport::server::TcpIncoming::bind(listen_addr).expect("bind test gRPC server");
    let local_addr = incoming.local_addr().expect("test gRPC local addr");
    let dkg_service = DkgServiceImpl::<DkgImpl>::with_routes(node.app_state.clone(), &network::V0);
    let pre_service = PreServiceImpl::<DkgImpl, crypto::PreImpl>::with_routes(
        node.app_state.clone(),
        &network::V0,
    );
    let info_service =
        InfoServiceImpl::<DkgImpl>::new((*node.app_state).clone(), node.identity.clone());
    let store_secret_service = StoreSecretServiceImpl::<DkgImpl, crypto::SignImpl>::with_routes(
        node.app_state.clone(),
        &network::V0,
    );
    let sign_service = SignServiceImpl::<DkgImpl, crypto::SignImpl>::with_routes(
        node.app_state.clone(),
        &network::V0,
    );

    let task = tokio::spawn(async move {
        let result = tonic::transport::Server::builder()
            .add_service(
                DkgServiceServer::new(dkg_service)
                    .max_decoding_message_size(MAX_SMALL_GRPC_REQUEST_BYTES),
            )
            .add_service(
                PreServiceServer::new(pre_service).max_decoding_message_size(MAX_PRE_REQUEST_BYTES),
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
            .serve_with_incoming(incoming)
            .await;
        if let Err(error) = result {
            eprintln!("test gRPC server on {local_addr} stopped: {error}");
        }
        // Best-effort router cleanup when the server stops (e.g. on task abort)
        let _ = node.router.shutdown().await;
    });
    (local_addr, task)
}

/// Start Vera (chain only, no orbis-node images) and `node_count` in-process
/// orbis nodes. Each node gets a unique signing key, its own local-storage DB
/// at `test_dbs/<db_prefix>_<i>.redb`, a gRPC server on an ephemeral loopback
/// port, an OS-assigned iroh P2P port, and NodeInfo registered on-chain
/// (self-whitelisted for the shared policy). Waits until every gRPC server is
/// ready before returning.
pub async fn setup_live_node_network(node_count: usize, db_prefix: &str) -> LiveNodeNetwork {
    let chain = Chain::start().await;
    let policy_id = chain.create_ring_policy().await;
    let runtime_base_path = project_root::get_project_root()
        .expect("resolve project root")
        .join("target")
        .join("test-runtime")
        .join(db_prefix);

    let mut nodes: Vec<LiveNodeHandle> = Vec::new();
    let mut node_keys: Vec<String> = Vec::new();

    for i in 0..node_count {
        let db_path = test_db_path(&format!("{db_prefix}_{i}"));
        cleanup_db(&db_path); // clear any leftover from a previous failed run

        let local_storage = LocalStorageImpl::new("test-password".to_string(), db_path.clone())
            .expect("local storage");

        let (bulletin, authz, node_key, public_address, extra_cleanup_dir) = chain
            .bootstrap_identity(&local_storage, &runtime_base_path, i)
            .await;

        // Iroh P2P network (loopback, OS-assigned port)
        let network: Arc<dyn Network> = Arc::new(NetworkImpl::new().await.expect("NetworkImpl"));
        let local_address = network.local_address().expect("network local_address");
        let p2p_socket = network
            .bound_addresses()
            .first()
            .copied()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "127.0.0.1:0".to_string());
        let peer_addr = format!("{local_address}@{p2p_socket}");

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

        let config = NodeConfig {
            args: Args {
                services_config: None,
                addr: "127.0.0.1:0".to_string(),
                cors_allow_origins: vec![],
                cors_permissive: false,
                log_level: LogLevel::Info,
                metrics_addr: None,
                loki_url: None,
                runtime_base_path: None,
                reshare_interval_secs: 0,
                network_private_routes_only: false,
                network_bind_addr: None,
                node_controller_key: node_key.clone(),
                node_peer_id: None,
                node_whitelisted_policy_ids: vec![policy_id.clone()],
                node_whitelisted_ring_ids: vec![],
                grpc_concurrency_limit_per_connection: GRPC_CONCURRENCY_LIMIT_PER_CONNECTION,
                grpc_max_concurrent_streams: GRPC_MAX_CONCURRENT_STREAMS,
                network_ingress: NetworkIngressArgs::default(),
            },
            cors_policy: CorsPolicy::Disabled,
            identity: bulletin::startup::NodeIdentity {
                node_key: node_key.clone(),
                public_address: public_address.clone(),
            },
            backend_names: ("injected".into(), "injected".into()),
            network,
            local_storage,
            authz,
            bulletin,
            authorized_peers: None,
        };

        let node = init_node(config).await.expect("init_node");
        let app_state = node.app_state.clone();
        let (local_addr, task) = spawn_test_grpc_server(node);

        nodes.push(LiveNodeHandle {
            grpc_endpoint: format!("http://{local_addr}"),
            peer_addr,
            node_key: node_key.clone(),
            public_address,
            db_path,
            extra_cleanup_dir,
            app_state,
            task,
        });
    }

    let endpoints: Vec<&str> = nodes.iter().map(|h| h.grpc_endpoint.as_str()).collect();
    wait_for_nodes_ready(&endpoints, 30, Duration::from_millis(200)).await;

    LiveNodeNetwork {
        nodes,
        policy_id,
        node_keys,
        chain,
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
}

// =========================================================================
// Cosmos chain-only bootstrap
// =========================================================================

#[cfg(all(feature = "integration-test", feature = "cosmos"))]
pub struct Chain {
    pub chain_config: ChainConfig,
    container: VeraTestContainer,
}

#[cfg(all(feature = "integration-test", feature = "cosmos"))]
impl Chain {
    async fn start() -> Self {
        let container = VeraTestContainer::new();
        let chain_config = container.chain_config();
        Self {
            chain_config,
            container,
        }
    }

    async fn create_ring_policy(&self) -> String {
        test_support::admin::cosmos::create_orbis_ring_policy(&self.chain_config).await
    }

    #[allow(clippy::type_complexity)]
    async fn bootstrap_identity(
        &self,
        local_storage: &LocalStorageImpl,
        runtime_base_path: &Path,
        _node_index: usize,
    ) -> (
        Arc<dyn Bulletin + Send + Sync>,
        Arc<dyn Authz>,
        String,
        String,
        Option<std::path::PathBuf>,
    ) {
        let signer = create_and_store_node_key(
            local_storage.clone(),
            self.chain_config.clone(),
            runtime_base_path,
        )
        .expect("create node signing key");
        let public_address = signer.address();
        let node_key = signer.public_key_hex();

        cli_tool::fund(public_address.clone(), self.chain_config.clone())
            .await
            .expect("fund node account via faucet");

        let bulletin: Arc<dyn Bulletin + Send + Sync> = Arc::new(
            BulletinImpl::with_signer(
                self.container.chain_config_builder(),
                signer,
                Some(MIN_NODE_BALANCE),
            )
            .await
            .expect("BulletinImpl with signer"),
        );
        let authz: Arc<dyn Authz> = Arc::new(
            AuthzImpl::new(self.container.chain_config_builder())
                .await
                .expect("AuthzImpl"),
        );

        (bulletin, authz, node_key, public_address, None)
    }

    async fn create_ring(
        &self,
        node_keys: &[String],
        threshold: u32,
        policy_id: &str,
        nonce: Option<&str>,
    ) -> String {
        create_ring_on_chain(&self.chain_config, node_keys, threshold, policy_id, nonce).await
    }

    async fn create_ring_with_trusted_relays(
        &self,
        node_keys: &[String],
        threshold: u32,
        policy_id: &str,
        nonce: Option<&str>,
        trusted_relay_dids: Vec<String>,
    ) -> String {
        create_ring_on_chain_with_trusted_relays(
            &self.chain_config,
            node_keys,
            threshold,
            policy_id,
            nonce,
            trusted_relay_dids,
            false,
        )
        .await
    }

    async fn create_document_policy(&self) -> String {
        cli_tool::add_policy_to_chain_with_config(self.chain_config.clone())
            .await
            .expect("add document policy")
    }

    async fn register_object(&self, policy_id: &str, resource: &str, object_id: &str) {
        cli_tool::register_object_to_chain_with_config(
            policy_id.to_string(),
            object_id.to_string(),
            resource.to_string(),
            self.chain_config.clone(),
        )
        .await
        .expect("register object");
    }

    async fn grant(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
        did_seed: &str,
    ) {
        cli_tool::set_relationship_on_chain_with_config(
            policy_id.to_string(),
            object_id.to_string(),
            resource.to_string(),
            relation.to_string(),
            Some(did_seed.to_string()),
            self.chain_config.clone(),
        )
        .await
        .expect("grant relationship");
    }

    async fn read_node_demerits(&self, ring_id: &str, node_key: &str) -> u64 {
        let client = VeraClient::new(self.chain_config.clone())
            .await
            .expect("chain client for demerit read");
        client
            .orbis_read_node_demerits(ring_id, node_key)
            .await
            .expect("read node demerits")
    }

    async fn wait_for_ring_finalized(&self, ring_id: &str, timeout: Duration) -> String {
        test_support::admin::cosmos::wait_for_ring_finalized(&self.chain_config, ring_id, timeout)
            .await
    }
}

// =========================================================================
// Native chain-only bootstrap
// =========================================================================

#[cfg(all(feature = "integration-test", feature = "native"))]
const DEPLOYMENT: u64 = 9100;

/// Same policy YAML as `cli_tool::commands::admin::TEST_POLICY_YAML`
/// (private to that crate) — duplicated verbatim for native's direct
/// `native_create_policy` call, same "duplicate the deterministic test
/// constant" precedent used throughout this migration.
#[cfg(all(feature = "integration-test", feature = "native"))]
const DOCUMENT_POLICY_YAML: &str = r#"
name: test-policy
resources:
  - name: document
    relations:
      - name: creator
        types:
          - actor
      - name: reader
        types:
          - actor
    permissions:
      - name: read
        expr: creator + reader
      - name: write
        expr: creator
"#;

#[cfg(all(feature = "integration-test", feature = "native"))]
pub struct Chain {
    cluster: NativeTestNetwork,
    client: VeraClient,
    trusted: ConsensusPublicKey,
    root: [u8; 32],
    controller: k256::ecdsa::SigningKey,
    actor: String,
    worker: BlsSigner,
}

#[cfg(all(feature = "integration-test", feature = "native"))]
impl Chain {
    async fn start() -> Self {
        let cluster = NativeTestNetwork::start(DEPLOYMENT).await;
        let root: [u8; 32] = hex::decode(cluster.deployment_root_hex())
            .expect("deployment root is hex")
            .try_into()
            .expect("deployment root is 32 bytes");
        let trusted = ConsensusPublicKey::decode(alloy_primitives::bytes::Bytes::from(
            hex::decode(cluster.consensus_key_hex()).expect("consensus key is hex"),
        ))
        .expect("decode consensus public key");
        let controller = k256::ecdsa::SigningKey::from_slice(&[34; 32]).expect("controller key");
        let actor = vera_crypto::secp256k1::did_from_secp256k1_pubkey(
            controller.verifying_key().to_sec1_bytes().as_ref(),
        )
        .expect("controller did");
        let worker = BlsSigner::new(7u64.into(), DEPLOYMENT).expect("worker signer");
        let endpoint = cluster.node(0).rpc_url();
        let client = VeraClient::new(&endpoint);
        Self {
            cluster,
            client,
            trusted,
            root,
            controller,
            actor,
            worker,
        }
    }

    fn policy_bytes(policy_id_hex: &str) -> B256 {
        B256::from_slice(&hex::decode(policy_id_hex).expect("policy id is hex"))
    }

    /// Poll until a submitted native transaction is certified (or panic).
    /// Mirrors `bin/orbis-node/src/tests/e2e/native_confirmation.rs`'s own
    /// `confirmed`/`wait` helpers — duplicated here, parameterized on this
    /// cluster's client, rather than re-invented.
    async fn confirmed(&self, id: B256) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(proof) = self
                .client
                .read_receipt(id, &self.trusted)
                .await
                .expect("read native receipt")
            {
                assert!(
                    proof
                        .verify(id, &self.trusted)
                        .expect("verify native receipt")
                        .success(),
                    "native transaction {id} was rejected"
                );
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "native receipt {id} timed out after 30s"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn create_ring_policy(&self) -> String {
        let created = self
            .client
            .native_create_policy(
                &self.worker,
                super::report_scenario::STANDARD_RING_POLICY_YAML.as_bytes(),
                1,
            )
            .await
            .expect("create native ring policy");
        self.confirmed(created.transaction_hash).await;

        let policy_id = self
            .client
            .get_policy_ids()
            .await
            .expect("list policy ids")
            .pop()
            .expect("new policy id");
        let policy_bytes = Self::policy_bytes(&policy_id);

        let registered = self
            .client
            .native_register_object(&self.worker, policy_bytes, &policy_id, "ring_policy")
            .await
            .expect("register ring_policy object");
        self.confirmed(registered.transaction_hash).await;

        let granted = self
            .client
            .native_set_relationship(
                &self.worker,
                policy_bytes,
                "ring_policy",
                &policy_id,
                "creator",
                &self.actor,
            )
            .await
            .expect("grant ring creator relationship");
        self.confirmed(granted.transaction_hash).await;

        policy_id
    }

    #[allow(clippy::type_complexity)]
    async fn bootstrap_identity(
        &self,
        local_storage: &LocalStorageImpl,
        runtime_base_path: &Path,
        node_index: usize,
    ) -> (
        Arc<dyn Bulletin + Send + Sync>,
        Arc<dyn Authz>,
        String,
        String,
        Option<std::path::PathBuf>,
    ) {
        let node_dir = runtime_base_path.join(format!("node{node_index}"));
        let identity =
            initialize_identity(local_storage, &node_dir).expect("initialize native identity");

        let worker_dir = node_dir.join("native-vera").join(hex::encode(self.root));
        let endpoint = self.cluster.node(0).rpc_url();
        let writer = NativeVeraClient::open(
            VeraClient::new(&endpoint),
            self.trusted,
            self.root,
            DEPLOYMENT,
            &worker_dir,
            local_storage,
        )
        .expect("open native vera client");

        let bulletin: Arc<dyn Bulletin + Send + Sync> = Arc::new(
            NativeBulletin::connect(
                writer,
                VeraClient::new(&endpoint),
                30,
                Duration::from_secs(30),
            )
            .await
            .expect("NativeBulletin connect"),
        );
        let authz: Arc<dyn Authz> = Arc::new(
            NativeAuth::connect(VeraClient::new(&endpoint), self.trusted, self.root, 30)
                .await
                .expect("NativeAuth connect"),
        );

        (
            bulletin,
            authz,
            identity.node_key,
            identity.public_address,
            Some(node_dir),
        )
    }

    async fn create_ring(
        &self,
        node_keys: &[String],
        threshold: u32,
        policy_id: &str,
        nonce: Option<&str>,
    ) -> String {
        self.create_ring_inner(node_keys, threshold, policy_id, nonce, None)
            .await
    }

    async fn create_ring_with_trusted_relays(
        &self,
        node_keys: &[String],
        threshold: u32,
        policy_id: &str,
        nonce: Option<&str>,
        trusted_relay_dids: Vec<String>,
    ) -> String {
        self.create_ring_inner(
            node_keys,
            threshold,
            policy_id,
            nonce,
            Some(trusted_relay_dids),
        )
        .await
    }

    async fn create_ring_inner(
        &self,
        node_keys: &[String],
        threshold: u32,
        policy_id: &str,
        nonce: Option<&str>,
        trusted_relay_dids: Option<Vec<String>>,
    ) -> String {
        let mut members = node_keys.to_vec();
        members.sort();
        let nonce_bytes: [u8; 32] = match nonce {
            Some(seed) => {
                use sha2::{Digest, Sha256};
                Sha256::digest(seed.as_bytes()).into()
            }
            None => [2; 32],
        };
        let trusted_auth_relay_dids =
            trusted_relay_dids.filter(|dids: &Vec<String>| !dids.is_empty());
        let config = RingConfig {
            policy_id: policy_id.to_string(),
            peer_node_keys: members,
            threshold,
            pss_interval: 86_400,
            current_version: 0,
            requires_pet: false,
            nonce: nonce_bytes,
            trusted_auth_relay_dids,
            reporting: ReportingConfig::default(),
        };
        let ring_id = config.id(self.root, &self.actor).expect("derive ring id");

        let now = unix_now();
        let token = create_scoped_bearer_token(
            &self.controller,
            self.worker.did(),
            DEPLOYMENT,
            now,
            now + 300,
            DelegationScope::ManageRings,
        )
        .expect("create ring-management bearer token");
        let call =
            encode_ring_command(&RingCommand::Create(config), &token).expect("encode ring command");
        let wire = self
            .worker
            .sign_native_tx(vera_client::VERA_ADDRESS, call)
            .expect("sign native tx");
        let id = NativeTx::decode_wire(&wire)
            .expect("decode native tx")
            .tx_id()
            .0;
        assert_eq!(
            self.client
                .send_native_tx(&wire)
                .await
                .expect("submit ring creation"),
            id
        );
        self.confirmed(id).await;

        ring_id
    }

    async fn create_document_policy(&self) -> String {
        let created = self
            .client
            .native_create_policy(&self.worker, DOCUMENT_POLICY_YAML.as_bytes(), 1)
            .await
            .expect("create native document policy");
        self.confirmed(created.transaction_hash).await;
        self.client
            .get_policy_ids()
            .await
            .expect("list policy ids")
            .pop()
            .expect("new policy id")
    }

    async fn register_object(&self, policy_id: &str, resource: &str, object_id: &str) {
        let registered = self
            .client
            .native_register_object(
                &self.worker,
                Self::policy_bytes(policy_id),
                object_id,
                resource,
            )
            .await
            .expect("register native object");
        self.confirmed(registered.transaction_hash).await;
    }

    async fn grant(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
        did_seed: &str,
    ) {
        let did = cli_tool::reader_did_from_seed(did_seed);
        let granted = self
            .client
            .native_set_relationship(
                &self.worker,
                Self::policy_bytes(policy_id),
                resource,
                object_id,
                relation,
                &did,
            )
            .await
            .expect("grant native relationship");
        self.confirmed(granted.transaction_hash).await;
    }

    async fn read_node_demerits(&self, ring_id: &str, node_key: &str) -> u64 {
        self.client
            .read_threshold_node_demerits(ring_id, node_key, 1, &self.trusted)
            .await
            .expect("read native node demerits")
            .record
            .map(|demerits| demerits.points)
            .unwrap_or(0)
    }

    async fn wait_for_ring_finalized(&self, ring_id: &str, timeout: Duration) -> String {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let read = self
                .client
                .read_threshold_ring(ring_id, 1, &self.trusted)
                .await
                .expect("read threshold ring");
            if let Some(record) = read.record {
                if let RingState::Active { keys } = record.state {
                    return keys.public_key;
                }
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for ring {ring_id} to be finalized"
            );
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
}
