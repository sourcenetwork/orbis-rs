// Include the generated proto code
pub mod app_state;
pub mod dkg;

use crate::dkg::service::CryptoServiceImpl;
use app_state::AppState;
use clap::Parser;
use std::net::SocketAddr;

pub mod crypto_service {
    tonic::include_proto!("crypto_service");
}

use crypto_service::crypto_service_server::CryptoServiceServer;

#[derive(Parser, Debug)]
#[command(name = "orbis-node")]
#[command(about = "Orbis CryptoService gRPC server")]
struct Args {
    /// Address to bind the server to
    #[arg(short, long, default_value = "[::1]:50051")]
    addr: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let addr: SocketAddr = args.addr.parse()?;

    // Create shared application state
    let app_state = AppState::new(
        "orbis-node-1".to_string(), // TODO: Generate or load from config
        args.addr.clone(),
    );

    println!("Starting CryptoService gRPC server on {}", addr);
    println!("Server is ready to accept connections...");

    // Initialize service with shared state
    let service = CryptoServiceImpl::new(app_state.clone());

    tonic::transport::Server::builder()
        .add_service(CryptoServiceServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
