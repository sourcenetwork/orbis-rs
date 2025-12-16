// Include the generated proto code
pub mod app_state;
pub mod dkg;
pub mod helpers;
pub mod pre;

use crate::dkg::service::CryptoServiceImpl;
use crate::pre::service::PreServiceImpl;
use app_state::AppState;
use clap::Parser;
use local_storage::memory::MemoryStorage as LocalStorage;
use network::Network;
use rand::Rng;
use std::{net::SocketAddr, sync::Arc};

pub mod crypto_service {
    tonic::include_proto!("crypto_service");
}

pub mod pre_service {
    tonic::include_proto!("pre_service");
}

use crypto_service::crypto_service_server::CryptoServiceServer;
use pre_service::pre_service_server::PreServiceServer;

#[derive(Parser, Debug)]
#[command(name = "orbis-node")]
#[command(about = "Orbis CryptoService gRPC server")]
struct Args {
    /// Address to bind the server to
    #[arg(short, long, default_value = "[::1]:50051")]
    addr: String,

    #[arg(short, long)]
    node_id: Option<u32>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let addr: SocketAddr = args.addr.parse()?;

    // Initialize iroh network for node-to-node communication
    println!("Initializing iroh network...");
    let network = network::IrohNetwork::new()
        .await
        .map_err(|e| format!("Failed to initialize iroh network: {}", e))?;
    let local_storage = LocalStorage::default();

    // Get the local peer ID and address before wrapping in Arc
    let local_peer_id = network.local_peer_id();
    let local_address = network
        .local_address()
        .map_err(|e| format!("Failed to get local address: {}", e))?;

    let network_arc = Arc::new(network);
    // TODO: node_id can be local_peer_id or local_address
    let node_id = args.node_id.unwrap_or_else(|| rand::thread_rng().gen());

    println!("Iroh network initialized:");
    println!("  Local Peer ID: {}", hex::encode(local_peer_id.as_bytes()));
    println!("  Local Address: {}", local_address);
    println!("  node_id: {}", node_id);

    // Create shared application state (needed for router)
    let app_state = AppState::new(
        node_id,
        args.addr.clone(),
        network_arc.clone(),
        local_storage,
    );
    // Wrap in Arc once, then clone Arc (cheap) for sharing
    let app_state_arc = Arc::new(app_state);

    // Start the iroh router in the background with DKG and PRE protocol handlers
    // The router will handle incoming connections automatically
    let endpoint = network_arc.endpoint().clone();
    let router =
        dkg::protocol_handler::create_router_with_handlers(endpoint, app_state_arc.clone());

    println!(
        "Iroh router started with DKG and PRE protocol handlers and ready to accept connections"
    );

    println!("Starting CryptoService gRPC server on {}", addr);
    println!("Server is ready to accept connections...");
    println!("  gRPC: {} (for user clients)", addr);
    println!("  Iroh: {} (for node-to-node communication)", local_address);

    // Initialize services with shared state (clone Arc, not AppState)
    let crypto_service = CryptoServiceImpl::new((*app_state_arc).clone());
    let pre_service = PreServiceImpl::new((*app_state_arc).clone());

    // Start gRPC server with both DKG and PRE services
    let grpc_server = tonic::transport::Server::builder()
        .add_service(CryptoServiceServer::new(crypto_service))
        .add_service(PreServiceServer::new(pre_service))
        .serve(addr);

    // Run gRPC server (router runs in background automatically)
    let result = tokio::select! {
        result = grpc_server => {
            result
        }
        _ = tokio::signal::ctrl_c() => {
            println!("Received shutdown signal...");
            Ok(())
        }
    };

    // Clean shutdown of router
    println!("Shutting down router...");
    router.shutdown().await?;

    result?;

    Ok(())
}
