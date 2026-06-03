// Include the generated proto code
pub mod app_state;
pub mod constants;
pub mod dkg;
pub mod error;
pub mod helpers;
pub mod info;
pub mod metrics;
pub mod pre;
pub mod pss;
pub mod ring_state;
pub mod sign;
pub mod store_secret;

#[cfg(test)]
mod tests;

use crate::dkg::service::DkgServiceImpl;
use crate::helpers::create_routers::create_router_with_all_handlers;
use crate::helpers::launch::{
    create_and_store_node_key, db_path, derive_secret_key_bytes, ensure_node_info,
    get_network_key_secret, get_password, Args,
};
use crate::info::{BootstrapInfoServiceImpl, InfoServiceImpl};
use crate::pre::service::PreServiceImpl;
use crate::sign::service::SignServiceImpl;
use crate::store_secret::StoreSecretServiceImpl;
use app_state::AppState;
use authz::r#trait::Authz;
use authz::AuthzImpl;
use bulletin::{r#trait::Bulletin, BulletinImpl};
use clap::Parser;
use common::blockchain::ChainConfigBuilder;
use crypto::r#trait::{ThresholdDealer, ThresholdSigner};
use local_storage::{r#trait::LocalStorage, LocalStorageImpl};
use network::{Network, NetworkImpl, Router};
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicI32, Ordering},
        Arc,
    },
};
use tokio::{sync::oneshot, task::JoinHandle};
use tonic_web::GrpcWebLayer;
use tower_http::cors::CorsLayer;
// Concrete crypto implementations
use constants::MIN_NODE_BALANCE;
use crypto::{DkgImpl, PreImpl, SignImpl};
use tracing::Instrument;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use proto::dkg_service::dkg_service_server::DkgServiceServer;
use proto::info_service::{info_service_server::InfoServiceServer, NodeStatus};
use proto::pre_service::pre_service_server::PreServiceServer;
use proto::sign_service::sign_service_server::SignServiceServer;
use proto::store_secret_service::store_secret_service_server::StoreSecretServiceServer;

/// Configuration for running the node, allowing dependency injection for testing
pub struct NodeConfig {
    pub args: Args,
    pub node_key: String,
    pub network: Arc<dyn Network>,
    pub local_storage: LocalStorageImpl,
    pub authz: Arc<dyn Authz>,
    pub bulletin: Arc<dyn Bulletin + Send + Sync>,
}

/// Result of initializing the node (before starting the server)
pub struct InitializedNode {
    pub app_state: Arc<AppState<DkgImpl>>,
    pub router: Box<dyn Router>,
    pub grpc_addr: SocketAddr,
    pub local_address: String,
    pub metrics_addr: Option<SocketAddr>,
    /// Interval between PSS reshare ceremonies. Zero means disabled.
    pub reshare_interval: std::time::Duration,
}

/// Running info-only gRPC server used while the node waits for chain funding.
pub struct BootstrapInfoServer {
    local_addr: SocketAddr,
    status: Arc<AtomicI32>,
    shutdown_tx: oneshot::Sender<()>,
    task: JoinHandle<Result<(), tonic::transport::Error>>,
}

impl BootstrapInfoServer {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn set_status(&self, status: NodeStatus) {
        self.status.store(status as i32, Ordering::SeqCst);
    }

    pub async fn shutdown(self) -> Result<(), Box<dyn std::error::Error>> {
        let _ = self.shutdown_tx.send(());
        self.task.await??;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    run(args).await
}

/// Full run function that initializes and runs the server
pub async fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing with optional Loki support
    init_tracing(&args)?;

    let root_span = tracing::info_span!(
        "orbis_node",
        pre_impl = PreImpl::name(),
        sign_impl = SignImpl::name(),
        local_storage_impl = LocalStorageImpl::name(),
        authz_impl = AuthzImpl::name(),
        bulletin_impl = BulletinImpl::name(),
        network_impl = NetworkImpl::name(),
    );

    async move {
        // List implementations used for sanity
        tracing::info!("Crypto PRE implementation: {}", PreImpl::name());
        tracing::info!("Crypto Sign implementation: {}", SignImpl::name());
        tracing::info!("Local-storage implementation: {}", LocalStorageImpl::name());
        tracing::info!("Authz implementation: {}", AuthzImpl::name());
        tracing::info!("Bulletin implementation: {}", BulletinImpl::name());
        tracing::info!("Network implementation: {}", NetworkImpl::name());

        // Get password for encrypting ring key shares
        let password = get_password(None).map_err(|e| format!("Failed to get password: {}", e))?;
        let local_storage = LocalStorageImpl::new(Some(password), db_path("orbis"))
            .map_err(|e| format!("Failed to create local storage: {}", e))?;
        // Get node secret hex for netwokring
        let node_secret_hex = get_network_key_secret(None, local_storage.clone())
            .map_err(|e| format!("Failed to get node secret: {}", e))?;

        // Derive 32-byte key from input (supports hex or passphrase)
        let secret_key_bytes = derive_secret_key_bytes(&node_secret_hex)
            .map_err(|e| format!("Invalid node secret: {}", e))?;
        let secret_key = network::SecretKey::from_bytes(&secret_key_bytes);

        // Initialize network for node-to-node communication
        tracing::info!("Initializing network");
        let network: Arc<dyn Network> = Arc::new(
            network::NetworkImpl::builder()
                .secret_key(secret_key)
                .idle_timeout_ms(constants::NETWORK_IDLE_TIMEOUT_MS)
                .build()
                .await
                .map_err(|e| format!("Failed to initialize network: {}", e))?,
        );
        let authz_chain_config = ChainConfigBuilder::default()
            .grpc_url(args.authz_grpc.clone())
            .rpc_url(args.chain_rpc.clone())
            .rest_url(args.chain_rest.clone())
            .denom(args.denom.clone());

        let authz: Arc<dyn Authz> = Arc::new(
            AuthzImpl::new(authz_chain_config)
                .await
                .map_err(|e| format!("Failed to initialize authz: {}", e))?,
        );

        let bulletin_chain_config = ChainConfigBuilder::default()
            .grpc_url(args.bulletin_grpc.clone())
            .rpc_url(args.chain_rpc.clone())
            .rest_url(args.chain_rest.clone())
            .denom(args.denom.clone());
        let chain_config = bulletin_chain_config.clone().build();
        let signer = create_and_store_node_key(local_storage.clone(), chain_config)
            .map_err(|e| format!("Failed to create or store node key: {}", e))?;
        let node_key = signer.public_key_hex();

        let grpc_addr: SocketAddr = args.addr.parse()?;
        let bootstrap_info_server =
            start_bootstrap_info_server(grpc_addr, network.clone(), local_storage.clone())?;
        tracing::info!(
            grpc_addr = %bootstrap_info_server.local_addr(),
            "Bootstrap info service started while waiting for funding"
        );

        let init_result = async {
            bootstrap_info_server.set_status(NodeStatus::ConnectingToChain);

            // For integration tests, this funds the account, this is handled differently live
            // Only fund if both the feature is enabled AND we're in the integration test network
            #[cfg(feature = "integration-test")]
            {
                bootstrap_info_server.set_status(NodeStatus::WaitingForFunding);
                // Build chain config with the provided RPC/REST URLs
                let fund_config = ChainConfigBuilder::default()
                    .rpc_url(args.chain_rpc.clone())
                    .rest_url(args.chain_rest.clone())
                    .grpc_url(args.bulletin_grpc.clone())
                    .build();
                cli_tool::fund(signer.address(), fund_config)
                    .await
                    .map_err(|e| format!("Failed to fund node account: {}", e))?;
            }

            // TODO: consider checking that you have connected to the chain succefully and not break tests (here or in impl)
            bootstrap_info_server.set_status(NodeStatus::WaitingForFunding);
            let bulletin: Arc<BulletinImpl> = Arc::new(
                BulletinImpl::with_signer(bulletin_chain_config, signer, Some(MIN_NODE_BALANCE))
                    .await
                    .map_err(|e| format!("Failed to initialize bulletin: {}", e))?,
            );
            ensure_node_info(bulletin.as_ref(), &node_key, network.as_ref(), &args)
                .await
                .map_err(|e| format!("Failed to ensure node info: {}", e))?;
            bootstrap_info_server.set_status(NodeStatus::Funded);

            let config = NodeConfig {
                args,
                node_key,
                network,
                local_storage,
                authz,
                bulletin,
            };

            init_node(config).await
        };

        let init_result = init_result.await;
        let node = shutdown_bootstrap_after_init(bootstrap_info_server, init_result).await?;

        run_server(node).await
    }
    .instrument(root_span)
    .await
}

/// Start an info-only gRPC server before the full node is ready.
pub fn start_bootstrap_info_server(
    grpc_addr: SocketAddr,
    network: Arc<dyn Network>,
    local_storage: LocalStorageImpl,
) -> Result<BootstrapInfoServer, Box<dyn std::error::Error>> {
    let incoming = tonic::transport::server::TcpIncoming::bind(grpc_addr)?;
    let local_addr = incoming.local_addr()?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let status = Arc::new(AtomicI32::new(NodeStatus::Bootstrapping as i32));
    let info_service = BootstrapInfoServiceImpl::new(network, local_storage, status.clone());

    let task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .accept_http1(true)
            .layer(CorsLayer::permissive())
            .layer(GrpcWebLayer::new())
            .add_service(InfoServiceServer::new(info_service))
            .serve_with_incoming_shutdown(incoming, async {
                let _ = shutdown_rx.await;
            })
            .await
    });

    Ok(BootstrapInfoServer {
        local_addr,
        status,
        shutdown_tx,
        task,
    })
}

async fn shutdown_bootstrap_after_init(
    bootstrap_info_server: BootstrapInfoServer,
    init_result: Result<InitializedNode, Box<dyn std::error::Error>>,
) -> Result<InitializedNode, Box<dyn std::error::Error>> {
    if init_result.is_ok() {
        tracing::info!(
            "Funding and bulletin initialization complete; stopping bootstrap info service"
        );
    } else {
        tracing::info!("Node initialization failed; stopping bootstrap info service");
    }

    let shutdown_result = bootstrap_info_server.shutdown().await;

    match (init_result, shutdown_result) {
        (Ok(node), Ok(())) => Ok(node),
        (Err(init_err), Ok(())) => Err(init_err),
        (Ok(_), Err(shutdown_err)) => Err(shutdown_err),
        (Err(init_err), Err(shutdown_err)) => {
            tracing::error!(
                error = %shutdown_err,
                "Bootstrap info service shutdown failed while handling initialization error"
            );
            Err(init_err)
        }
    }
}

/// Initialize the node without starting the gRPC server
/// This is useful for testing the initialization logic
pub async fn init_node(config: NodeConfig) -> Result<InitializedNode, Box<dyn std::error::Error>> {
    let grpc_addr: SocketAddr = config.args.addr.parse()?;
    let metrics_addr: Option<SocketAddr> = config
        .args
        .metrics_addr
        .as_ref()
        .map(|s| s.parse())
        .transpose()?;

    // Get the local peer ID and address
    let local_peer_id = config.network.local_peer_id();
    let local_address = config
        .network
        .local_address()
        .map_err(|e| format!("Failed to get local address: {}", e))?;

    // Get the bound socket address (host:port) for the connection string
    let bound_addrs = config.network.bound_addresses();
    let socket_addr = bound_addrs
        .first()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|| "127.0.0.1:0".to_string());

    tracing::info!("Network initialized");
    let peer_id_hex = hex::encode(local_peer_id.as_bytes());
    let connection_string = format!("{}@{}", peer_id_hex, socket_addr);
    tracing::info!(connection = %connection_string, "Iroh connection string (peer_id@host:port)");

    // Create shared application state (needed for router)
    let app_state = AppState::<DkgImpl>::new(
        config.args.addr.clone(),
        config.node_key.clone(),
        config.network.clone(),
        config.local_storage,
        config.authz,
        config.bulletin,
    );
    let app_state_arc = Arc::new(app_state);

    // Start the router in the background with DKG, PRE, and Sign protocol handlers
    let router = create_router_with_all_handlers::<DkgImpl, PreImpl, SignImpl>(
        &config.network,
        app_state_arc.clone(),
    )
    .map_err(|e| format!("Failed to create router: {}", e))?;

    tracing::info!(
        "Router started with DKG, PRE, and Sign protocol handlers and ready to accept connections"
    );

    Ok(InitializedNode {
        app_state: app_state_arc,
        router,
        grpc_addr,
        local_address,
        metrics_addr,
        reshare_interval: std::time::Duration::from_secs(config.args.reshare_interval_secs),
    })
}

/// Run the gRPC server with the initialized node
pub async fn run_server(node: InitializedNode) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize metrics eagerly so registration panics surface here, not in a spawned task
    metrics::init();
    network::metrics::init();
    metrics::record_build_info(
        &PreImpl::name(),
        &SignImpl::name(),
        &LocalStorageImpl::name(),
        &AuthzImpl::name(),
        &BulletinImpl::name(),
        &NetworkImpl::name(),
    );

    // Start PSS reshare scheduler (no-op if interval is zero)
    pss::spawn_pss_scheduler(node.app_state.clone(), node.reshare_interval);

    tracing::info!("Server is ready to accept connections");
    tracing::info!(grpc_addr = %node.grpc_addr, "Starting gRPC server");
    tracing::info!(p2p_addr = %node.local_address, "P2P address for node-to-node communication");

    // Start metrics server if configured
    if let Some(metrics_addr) = node.metrics_addr {
        tokio::spawn(async move {
            if let Err(e) = metrics::start_metrics_server(metrics_addr).await {
                tracing::error!(error = %e, "Metrics server failed");
            }
        });
    }

    // Initialize services with shared state
    let dkg_service = DkgServiceImpl::<DkgImpl>::new((*node.app_state).clone());
    let pre_service = PreServiceImpl::<DkgImpl, PreImpl>::new((*node.app_state).clone());
    let info_service = InfoServiceImpl::<DkgImpl>::new((*node.app_state).clone());
    let store_secret_service =
        StoreSecretServiceImpl::<DkgImpl, SignImpl>::new((*node.app_state).clone());
    let sign_service = SignServiceImpl::<DkgImpl, SignImpl>::new((*node.app_state).clone());

    // Start gRPC server
    let grpc_server = tonic::transport::Server::builder()
        .accept_http1(true)
        .concurrency_limit_per_connection(constants::GRPC_CONCURRENCY_LIMIT_PER_CONNECTION)
        .max_concurrent_streams(Some(constants::GRPC_MAX_CONCURRENT_STREAMS))
        .layer(CorsLayer::permissive())
        .layer(GrpcWebLayer::new())
        .add_service(DkgServiceServer::new(dkg_service))
        .add_service(PreServiceServer::new(pre_service))
        .add_service(InfoServiceServer::new(info_service))
        .add_service(StoreSecretServiceServer::new(store_secret_service))
        .add_service(SignServiceServer::new(sign_service))
        .serve(node.grpc_addr);

    // Run gRPC server (router runs in background automatically)
    let result = tokio::select! {
        result = grpc_server => {
            result
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received shutdown signal");
            Ok(())
        }
    };

    // Clean shutdown of router
    tracing::info!("Shutting down router");
    node.router
        .shutdown()
        .await
        .map_err(|e| format!("Failed to shutdown router: {}", e))?;

    result?;

    Ok(())
}

/// Initialize the tracing subscriber with optional Loki log shipping
fn init_tracing(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let log_level = tracing::Level::from(args.log_level);
    let fmt_layer = tracing_subscriber::fmt::layer();
    let filter = tracing_subscriber::filter::LevelFilter::from_level(log_level);

    if let Some(loki_url) = &args.loki_url {
        let url: url::Url = loki_url.parse()?;

        let (loki_layer, loki_task) = tracing_loki::builder()
            .label("app", "orbis-node")?
            .build_url(url)?;

        // Spawn the background task that ships logs to Loki
        tokio::spawn(loki_task);

        tracing_subscriber::registry()
            .with(filter)
            .with(fmt_layer)
            .with(loki_layer)
            .init();

        // Can't use tracing here since it's not initialized until after init()
        println!("Loki log shipping enabled: {}", loki_url);
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt_layer)
            .init();
    }

    Ok(())
}
