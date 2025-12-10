// Include the generated proto code
pub mod server;

use clap::Parser;
use server::CryptoServiceImpl;
use std::net::SocketAddr;
use tonic::{Request, Response, Status};
pub mod crypto_service {
    tonic::include_proto!("crypto_service");
}
use crypto_service::{
    crypto_service_server::{CryptoService, CryptoServiceServer},
    EncryptionRequest, EncryptionResponse, StartDkgRequest, StartDkgResponse,
};

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

    println!("Starting CryptoService gRPC server on {}", addr);
    println!("Server is ready to accept connections...");

    let service = CryptoServiceImpl::default();

    tonic::transport::Server::builder()
        .add_service(CryptoServiceServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
