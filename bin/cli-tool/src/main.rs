use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use std::collections::HashMap;

pub mod dkg_service {
    tonic::include_proto!("dkg_service");
}

pub mod pre_service {
    tonic::include_proto!("pre_service");
}

use dkg_service::dkg_service_client::DkgServiceClient;
use pre_service::pre_service_client::PreServiceClient;

#[derive(Parser, Debug, Clone)]
#[clap(
    version,
    about = "CLI tool for interacting with an orbis network"
)]
pub struct Cli {
    #[clap(subcommand)]
    command: SubCommands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum SubCommands {
    /// Start a Distributed Key Generation session
    Dkg {
        /// gRPC endpoint of the node (e.g., http://localhost:50051)
        #[clap(short, long, default_value = "http://localhost:50051")]
        endpoint: String,

        /// Number of nodes required to reconstruct (threshold)
        #[clap(short, long)]
        threshold: u32,

        /// Optional session ID (generated if not provided)
        #[clap(short, long)]
        session_id: Option<String>,

        /// Peer IDs for P2P connections (required)
        #[clap(long, required = true, num_args = 1..)]
        peer_ids: Vec<String>,
    },

    /// Start a Proxy Re-Encryption session
    Pre {
        /// gRPC endpoint of the node to use
        #[clap(short, long, default_value = "http://localhost:50051")]
        endpoint: String,

        /// Ring public key (from DKG)
        #[clap(long)]
        ring_pk: String,

        /// Secret to encrypt
        #[clap(long)]
        secret: String,

        /// Reader's public key
        #[clap(long)]
        reader_pk: String,

        /// Peer IDs of nodes to participate (required)
        #[clap(long, required = true, num_args = 1..)]
        peer_ids: Vec<String>,
    },

    /// Query node info
    Info {
        /// gRPC endpoint of the node
        #[clap(short, long, default_value = "http://localhost:50051")]
        endpoint: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        SubCommands::Dkg {
            endpoint,
            threshold,
            session_id,
            peer_ids,
        } => {
            do_dkg(endpoint, threshold, session_id, peer_ids).await?;
        }
        SubCommands::Pre {
            endpoint,
            ring_pk,
            secret,
            reader_pk,
            peer_ids,
        } => {
            do_pre(endpoint, ring_pk, secret, reader_pk, peer_ids).await?;
        }
        SubCommands::Info { endpoint } => {
            println!("Querying node at: {}", endpoint);
            println!("(Info endpoint not yet implemented on server)");
        }
    }

    Ok(())
}

pub async fn do_dkg(
    endpoint: String,
    threshold: u32,
    session_id: Option<String>,
    peer_ids: Vec<String>,
) -> Result<()> {
    // Total nodes = peers + the node we're connecting to
    let total_nodes = (peer_ids.len() + 1) as u32;

    if threshold > total_nodes {
        return Err(anyhow!(
            "Threshold ({}) cannot be greater than total nodes ({})",
            threshold,
            total_nodes
        ));
    }

    let session_id = session_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    println!("Starting DKG session:");
    println!("  Endpoint: {}", endpoint);
    println!("  Session ID: {}", session_id);
    println!("  Threshold: {}/{}", threshold, total_nodes);
    println!("  Peer IDs: {:?}", peer_ids);
    println!();

    println!("Connecting to {}...", endpoint);

    let mut client = DkgServiceClient::connect(endpoint.clone())
        .await
        .map_err(|e| anyhow!("Failed to connect to {}: {}", endpoint, e))?;

    let request = tonic::Request::new(dkg_service::StartDkgRequest {
        session_id: session_id.clone(),
        threshold,
        total_participants: total_nodes,
        peer_ids,
        parameters: HashMap::new(),
    });

    let response = client
        .start_dkg(request)
        .await
        .map_err(|e| anyhow!("DKG request failed: {}", e))?;

    let response = response.into_inner();

    println!("DKG Result:");
    println!("{}", "=".repeat(60));
    println!("  Session ID: {}", response.session_id);
    println!("  Status: {}", response.status);
    println!("  Message: {}", response.message);

    Ok(())
}

pub async fn do_pre(
    endpoint: String,
    ring_pk: String,
    secret: String,
    reader_pk: String,
    peer_ids: Vec<String>,
) -> Result<()> {
    println!("Starting PRE session:");
    println!("  Endpoint: {}", endpoint);
    println!("  Ring PK: {}...", &ring_pk[..ring_pk.len().min(20)]);
    println!("  Reader PK: {}...", &reader_pk[..reader_pk.len().min(20)]);
    println!("  Peer IDs: {:?}", peer_ids);
    println!();

    let mut client = PreServiceClient::connect(endpoint.clone())
        .await
        .map_err(|e| anyhow!("Failed to connect to {}: {}", endpoint, e))?;

    let request = tonic::Request::new(pre_service::StartPreRequest {
        ring_pk,
        secret,
        rdr_pk: reader_pk,
        peer_ids,
    });

    let response = client
        .start_pre(request)
        .await
        .map_err(|e| anyhow!("PRE request failed: {}", e))?;

    let response = response.into_inner();

    println!("PRE Result:");
    println!("{}", "=".repeat(60));
    println!("  Status: {}", response.status);
    println!("  Message: {}", response.message);

    if !response.encrypted_secret.is_empty() {
        println!("  Encrypted Secret: {}", response.encrypted_secret);
    }

    Ok(())
}
