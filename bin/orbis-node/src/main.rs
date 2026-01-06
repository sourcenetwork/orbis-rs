// Include the generated proto code
pub mod app_state;
pub mod constants;
pub mod dkg;
pub mod error;
pub mod helpers;
pub mod pre;

#[cfg(test)]
mod tests;

use crate::dkg::service::DkgServiceImpl;
use crate::helpers::launch::{derive_secret_key_bytes, get_network_key_secret, get_password, Args};
use crate::pre::service::PreServiceImpl;
use app_state::AppState;
use authz::r#trait::Authz;
use authz::sourcehub::SourceHubAuth;
use clap::Parser;
use common::blockchain::ChainConfigBuilder;
use local_storage::memory::MemoryStorage;
use local_storage::r#trait::LocalStorage;
use network::{Network, Router};
use std::{net::SocketAddr, sync::Arc};
// Concrete crypto implementations
use crypto::bls12_381::dkg::DKGNode;
use crypto::bls12_381::pre::ThresholdDealerNode;

// Type aliases for concrete implementations
pub type DkgImpl = DKGNode;
pub type PreImpl = ThresholdDealerNode;

use proto::dkg_service::dkg_service_server::DkgServiceServer;
use proto::pre_service::pre_service_server::PreServiceServer;

/// Configuration for running the node, allowing dependency injection for testing
pub struct NodeConfig {
    pub args: Args,
    pub network: Arc<dyn Network>,
    pub local_storage: MemoryStorage,
    pub authz: Arc<dyn Authz>,
}

/// Result of initializing the node (before starting the server)
pub struct InitializedNode {
    pub app_state: Arc<AppState<DkgImpl>>,
    pub router: Box<dyn Router>,
    pub grpc_addr: SocketAddr,
    pub local_address: String,
}

/// Initialize the node without starting the gRPC server
/// This is useful for testing the initialization logic
pub async fn init_node(config: NodeConfig) -> Result<InitializedNode, Box<dyn std::error::Error>> {
    let grpc_addr: SocketAddr = config.args.addr.parse()?;

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
        config.network.clone(),
        config.local_storage,
        config.authz,
    );
    let app_state_arc = Arc::new(app_state);

    // Start the router in the background with DKG and PRE protocol handlers
    let router = dkg::protocol_handler::create_router_with_handlers::<DkgImpl, PreImpl>(
        &config.network,
        app_state_arc.clone(),
    )
    .map_err(|e| format!("Failed to create router: {}", e))?;

    tracing::info!(
        "Router started with DKG and PRE protocol handlers and ready to accept connections"
    );

    Ok(InitializedNode {
        app_state: app_state_arc,
        router,
        grpc_addr,
        local_address,
    })
}

/// Run the gRPC server with the initialized node
pub async fn run_server(node: InitializedNode) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("Server is ready to accept connections");
    tracing::info!(grpc_addr = %node.grpc_addr, "Starting gRPC server");
    tracing::info!(p2p_addr = %node.local_address, "P2P address for node-to-node communication");

    // Initialize services with shared state
    let dkg_service = DkgServiceImpl::<DkgImpl>::new((*node.app_state).clone());
    let pre_service = PreServiceImpl::<DkgImpl, PreImpl>::new((*node.app_state).clone());

    // Start gRPC server with both DKG and PRE services
    let grpc_server = tonic::transport::Server::builder()
        .add_service(DkgServiceServer::new(dkg_service))
        .add_service(PreServiceServer::new(pre_service))
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

/// Full run function that initializes and runs the server
pub async fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::from(args.log_level))
        .init();

    // Get password for encrypting ring key shares
    let password = get_password(None).map_err(|e| format!("Failed to get password: {}", e))?;
    let local_storage = MemoryStorage::new(Some(password));
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
        network::IrohNetwork::builder()
            .secret_key(secret_key)
            .build()
            .await
            .map_err(|e| format!("Failed to initialize network: {}", e))?,
    );
    let chain_config_builder = ChainConfigBuilder::default().grpc_url(args.authz_grpc.clone());
    let authz: Arc<dyn Authz> = Arc::new(
        // TODO: consider checking that you have connected to the chain succefully and not break tests (here or in impl)
        SourceHubAuth::new(chain_config_builder)
            .await
            .map_err(|e| format!("Failed to initialize authz: {}", e))?,
    );

    let config = NodeConfig {
        args,
        network,
        local_storage,
        authz,
    };

    let node = init_node(config).await?;
    run_server(node).await
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    run(args).await
}
