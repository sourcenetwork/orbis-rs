//! In-process test/benchmark harness.
//!
//! Spawns a real orbis-node instance as a tokio task (not a process or
//! container) against a caller-injected, shared mock bulletin instead of a
//! real chain — no Docker, no SourceHub, no external network dependency.
//! Real Iroh P2P networking and the real DKG/PRE/SIGN protocol code run
//! unmodified; only the chain/authz backends are swapped for in-memory mocks.
//!
//! Adapted from `tests::concurrent::setup_live_three_node_network`'s per-node
//! setup, which this mirrors closely — see that function for the equivalent
//! pattern against a real (Dockerized) SourceHub.
//!
//! Not used by the production binary; opt in via the `harness` feature.

use crate::constants;
use crate::dkg::v0::service::DkgServiceImpl;
use crate::helpers::launch::{
    build_node_info_from_args, create_and_store_node_key, Args, LogLevel,
};
use crate::info::InfoServiceImpl;
use crate::pre::v0::service::PreServiceImpl;
use crate::runtime::{init_node, NodeConfig};
use crate::sign::v0::service::SignServiceImpl;
use crate::store_secret::StoreSecretServiceImpl;
use authz::dummy::DummyAuthZ;
use authz::r#trait::Authz;
use bulletin::dummy::DummyBulletin;
use bulletin::r#trait::Bulletin;
use common::blockchain::ChainConfigBuilder;
use crypto::{DkgImpl, PreImpl, SignImpl};
use local_storage::{r#trait::LocalStorage, LocalStorageImpl};
use network::{Network, NetworkImpl};
use proto::info_service::info_service_server::InfoServiceServer;
use proto::v0::dkg::dkg_service_server::DkgServiceServer;
use proto::v0::pre::pre_service_server::PreServiceServer;
use proto::v0::sign::sign_service_server::SignServiceServer;
use proto::v0::store_secret::store_secret_service_server::StoreSecretServiceServer;
use std::path::Path;
use std::sync::Arc;

/// A single in-process orbis node, spawned as a tokio task.
///
/// Dropping this aborts the node's gRPC server task and removes its local
/// storage file.
pub struct HarnessNodeHandle {
    pub grpc_endpoint: String,
    pub peer_addr: String,
    pub node_key: String,
    pub public_address: String,
    task: tokio::task::JoinHandle<()>,
    db_path: String,
}

impl Drop for HarnessNodeHandle {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.db_path);
    }
}

/// Everything caller-specific needed to spawn one harness node. Everything
/// else (network, authz, gRPC service wiring) is fixed by this module.
pub struct HarnessNodeParams<'a> {
    /// `host:port` to bind this node's gRPC server to.
    pub grpc_addr: String,
    /// Local storage file path; must be unique per node.
    pub db_path: String,
    /// Local storage encryption password.
    pub password: String,
    /// Base directory for the node's signing key material.
    pub runtime_base_path: &'a Path,
    /// ACP policy this node whitelists on first boot.
    pub policy_id: String,
    /// Hex-encoded controller public key allowed to update this node's info.
    pub node_controller_key: String,
    /// Software delay/jitter/loss applied to this node's own outbound
    /// traffic — the in-process approximation of the Docker backend's
    /// per-container `tc netem` WAN shaping (see `network::shape`'s module
    /// docs for exactly what's approximated). `None` or a no-op profile
    /// skips wrapping entirely.
    pub network_shaping: Option<network::NetworkShapingProfile>,
}

/// Spawn one in-process orbis node against a caller-provided, shared
/// [`DummyBulletin`] (one instance cloned across every node in a harness
/// network, so they all see consistent ring/node-info state). Authorization
/// is always a permissive [`DummyAuthZ`] — this harness is for exercising
/// DKG/PRE/SIGN protocol and P2P networking behavior, not ACP policy
/// enforcement.
///
/// Takes the concrete `DummyBulletin` type (rather than `Arc<dyn Bulletin>`)
/// because NodeInfo registration goes directly through
/// [`DummyBulletin::set_node_info`] instead of `Bulletin::post` — the generic
/// `post` path (used by production nodes via `ensure_node_info`) doesn't
/// support `BulletinWriteKind::NodeInfo` on this backend, since a fresh-DKG
/// node can't derive a stable id for its own node-info post the way a real
/// chain assigns one.
pub async fn spawn_harness_node(
    params: HarnessNodeParams<'_>,
    bulletin: Arc<DummyBulletin>,
) -> anyhow::Result<HarnessNodeHandle> {
    let local_storage = LocalStorageImpl::new(params.password, params.db_path.clone())
        .map_err(|error| anyhow::anyhow!("local storage: {error}"))?;

    // The chain config here only carries denom/chain-id context for later
    // transaction signing — constructing a signer does not itself touch a
    // chain, and this harness never broadcasts a transaction at all.
    let chain_config = ChainConfigBuilder::default().build();
    let signer = create_and_store_node_key(
        local_storage.clone(),
        chain_config,
        params.runtime_base_path,
    )
    .map_err(|error| anyhow::anyhow!("create node signing key: {error}"))?;
    let public_address = signer.address();
    let node_key = signer.public_key_hex();

    let authz: Arc<dyn Authz> = Arc::new(
        DummyAuthZ::new()
            .await
            .map_err(|error| anyhow::anyhow!("DummyAuthZ: {error}"))?,
    );

    // Real Iroh P2P, bound explicitly to loopback. At small scale (the
    // 3-node Layer 2 test harness) `NetworkImpl::new()`'s bare defaults
    // (binds 0.0.0.0) work fine. At harness scale (dozens of real iroh
    // endpoints in one process) that default measurably degrades the whole
    // network: iroh's magicsock queues start dropping ping/pong packets
    // ("failed to queue pong", "queues full") under the aggregate relay/STUN
    // discovery load across that many endpoints, and a peer that loses path
    // validation stops accepting new DKG control connections entirely,
    // cascading into whole-ceremony aborts after ~2 minutes per attempt
    // (DKG_PREPARATION_TIMEOUT). Explicitly binding to loopback narrows what
    // magicsock needs to probe and clears this up in practice, even with
    // relay/discovery still nominally enabled.
    //
    // Tried and reverted: also passing `.private_routes_only()` (disables
    // relay + clears discovery) — that stops the degradation too, but
    // iroh's own `connect()` then fails immediately with "No addressing
    // information available" even though this harness always dials a fully
    // resolved `hex@127.0.0.1:port` peer address, never a bare node ID.
    // Worth revisiting if `bind_addr_v4` alone ever proves insufficient at
    // larger scale, but don't reintroduce it without re-diagnosing why
    // `with_ip_addr` addressing needs the default discovery.
    let unshaped_network = NetworkImpl::builder()
        .bind_addr_v4("127.0.0.1:0".parse().unwrap())
        .build()
        .await
        .map_err(|error| anyhow::anyhow!("network: {error}"))?;
    let network: Arc<dyn Network> = match params.network_shaping {
        Some(profile) if !profile.is_noop() => Arc::new(network::ShapedNetwork::new(
            Arc::new(unshaped_network),
            profile,
        )),
        _ => Arc::new(unshaped_network),
    };
    let local_address = network
        .local_address()
        .map_err(|error| anyhow::anyhow!("network local_address: {error}"))?;
    let p2p_socket = network
        .bound_addresses()
        .first()
        .copied()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|| "127.0.0.1:0".to_string());
    let peer_addr = format!("{local_address}@{p2p_socket}");

    let args = Args {
        addr: params.grpc_addr.clone(),
        log_level: LogLevel::Info,
        authz_grpc: None,
        bulletin_grpc: None,
        chain_rpc: None,
        chain_rest: None,
        denom: None,
        chain_gas_multiplier: None,
        metrics_addr: None,
        loki_url: None,
        runtime_base_path: None,
        reshare_interval_secs: 0,
        network_private_routes_only: false,
        node_controller_key: params.node_controller_key,
        node_peer_id: None,
        node_whitelisted_policy_ids: vec![params.policy_id],
        node_whitelisted_ring_ids: vec![],
        grpc_concurrency_limit_per_connection: constants::GRPC_CONCURRENCY_LIMIT_PER_CONNECTION,
        grpc_max_concurrent_streams: constants::GRPC_MAX_CONCURRENT_STREAMS,
    };

    // `local_address` is the same hex-encoded iroh node ID `ensure_node_info`
    // would derive itself (`hex::encode(network.local_peer_id().as_bytes())`)
    // — reused directly here since `DummyBulletin` needs a different write
    // path than the generic `Bulletin::post` one `ensure_node_info` uses.
    let node_info =
        build_node_info_from_args(local_address.clone(), &args.node_controller_key, &args);
    bulletin
        .set_node_info(node_key.clone(), node_info)
        .map_err(|error| anyhow::anyhow!("register NodeInfo: {error}"))?;

    let config = NodeConfig {
        args,
        node_key: node_key.clone(),
        network,
        local_storage,
        authz,
        bulletin: bulletin as Arc<dyn Bulletin + Send + Sync>,
    };
    let node = init_node(config)
        .await
        .map_err(|error| anyhow::anyhow!("init_node: {error}"))?;

    // Mirrors `spawn_test_grpc_server` in tests::concurrent — the same set of
    // gRPC services the production server registers.
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
    let grpc_addr = node.grpc_addr;
    let router = node.router;

    let task = tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(
                DkgServiceServer::new(dkg_service)
                    .max_decoding_message_size(constants::MAX_SMALL_GRPC_REQUEST_BYTES),
            )
            .add_service(
                PreServiceServer::new(pre_service)
                    .max_decoding_message_size(constants::MAX_SMALL_GRPC_REQUEST_BYTES),
            )
            .add_service(
                InfoServiceServer::new(info_service)
                    .max_decoding_message_size(constants::MAX_SMALL_GRPC_REQUEST_BYTES),
            )
            .add_service(
                StoreSecretServiceServer::new(store_secret_service)
                    .max_decoding_message_size(constants::MAX_STORE_SECRET_REQUEST_BYTES),
            )
            .add_service(
                SignServiceServer::new(sign_service)
                    .max_decoding_message_size(constants::MAX_SIGN_REQUEST_BYTES),
            )
            .serve(grpc_addr)
            .await;
        // Best-effort router cleanup when the server stops (e.g. on task abort).
        let _ = router.shutdown().await;
    });

    Ok(HarnessNodeHandle {
        grpc_endpoint: format!("http://{grpc_addr}"),
        peer_addr,
        node_key,
        public_address,
        task,
        db_path: params.db_path,
    })
}
