use anyhow::{anyhow, Result};
use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::Group;
use ark_std::UniformRand;
use clap::{Parser, Subcommand};
use crypto::bls12_381::pre::ThresholdDealerNode;
use crypto::r#trait::{Secret, ThresholdDealer};
use crypto::{CryptoDeserialize, CryptoSerialize};
use rand_core::OsRng;
use serde::Deserialize;

/// Response structure from PRE server
#[derive(Debug, Deserialize)]
struct PreResponse {
    /// Recovered reencrypted commitment (xnc_cmt) as hex string
    xnc_cmt: String,
    /// Original encrypted secret
    secret: Secret,
}

pub mod dkg_service {
    tonic::include_proto!("dkg_service");
}

pub mod pre_service {
    tonic::include_proto!("pre_service");
}

use dkg_service::dkg_service_client::DkgServiceClient;
use pre_service::pre_service_client::PreServiceClient;

#[derive(Parser, Debug, Clone)]
#[clap(version, about = "CLI tool for interacting with an orbis network")]
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

        /// Ring public key (from DKG) in hex format
        #[clap(long)]
        ring_pk: String,

        /// Plaintext secret to encrypt and re-encrypt
        #[clap(long)]
        secret: String,

        /// Reader's public key in hex format (from generate-reader-key)
        #[clap(long)]
        reader_pk: String,

        /// Reader's secret key in hex format (for decryption after PRE)
        #[clap(long)]
        reader_sk: String,

        /// Peer IDs of nodes to participate (required)
        #[clap(long, required = true, num_args = 1..)]
        peer_ids: Vec<String>,
    },
    /// Encrypts a secret to the ring public key (from DKG)
    EncryptSecret {
        /// Secret to encrypt
        #[clap(long)]
        secret: String,
        /// Ring public key (from DKG) in hex format
        #[clap(long)]
        ring_pk: String,
    },

    /// Generate a reader keypair for PRE decryption
    GenerateReaderKey,

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
            reader_sk,
            peer_ids,
        } => {
            do_pre(endpoint, ring_pk, secret, reader_pk, reader_sk, peer_ids).await?;
        }
        SubCommands::EncryptSecret { secret, ring_pk } => {
            do_encrypt_secret(ring_pk, secret).await?;
        }
        SubCommands::GenerateReaderKey => {
            do_generate_reader_key()?;
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
    let total_nodes = peer_ids.len() as u32;

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
        peer_ids,
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
    reader_sk: String,
    peer_ids: Vec<String>,
) -> Result<()> {
    println!("Starting PRE session:");
    println!("  Endpoint: {}", endpoint);
    println!("  Ring PK: {}...", &ring_pk[..ring_pk.len().min(20)]);
    println!("  Reader PK: {}...", &reader_pk[..reader_pk.len().min(20)]);
    println!("  Peer IDs: {:?}", peer_ids);
    println!();

    // Parse the ring public key
    let ring_pk_bytes =
        hex::decode(&ring_pk).map_err(|e| anyhow!("Failed to decode ring_pk hex: {}", e))?;
    let ring_pk_point = G1Affine::from_bytes(&ring_pk_bytes)
        .map_err(|e| anyhow!("Failed to deserialize ring_pk: {}", e))?;

    // Parse the reader keys
    let reader_pk_bytes =
        hex::decode(&reader_pk).map_err(|e| anyhow!("Failed to decode reader_pk hex: {}", e))?;
    let _reader_pk_point = G1Affine::from_bytes(&reader_pk_bytes)
        .map_err(|e| anyhow!("Failed to deserialize reader_pk: {}", e))?;

    let reader_sk_bytes =
        hex::decode(&reader_sk).map_err(|e| anyhow!("Failed to decode reader_sk hex: {}", e))?;
    let reader_sk_scalar = Fr::from_bytes(&reader_sk_bytes)
        .map_err(|e| anyhow!("Failed to deserialize reader_sk: {}", e))?;

    // Step 1: Encrypt the plaintext secret to the ring public key
    println!("Step 1: Encrypting secret to ring public key...");
    let (_enc_cmt, encrypted_secret) =
        ThresholdDealerNode::encrypt_secret(&ring_pk_point, secret.as_bytes())
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

    // Serialize the encrypted secret to JSON for the PRE request
    let encrypted_secret_json = serde_json::to_string(&encrypted_secret)
        .map_err(|e| anyhow!("Failed to serialize encrypted secret: {}", e))?;

    println!("  Encrypted secret created");
    println!();

    // Step 2: Send to PRE service for re-encryption
    println!("Step 2: Sending to PRE service for re-encryption...");
    let mut client = PreServiceClient::connect(endpoint.clone())
        .await
        .map_err(|e| anyhow!("Failed to connect to {}: {}", endpoint, e))?;

    let request = tonic::Request::new(pre_service::StartPreRequest {
        ring_pk: ring_pk.clone(),
        secret: encrypted_secret_json,
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

    // Step 3: If we got a re-encrypted commitment back, decrypt it
    if !response.encrypted_secret.is_empty() {
        println!();
        println!("Step 3: Decrypting with reader secret key...");

        // Parse the JSON response from server
        let pre_response: PreResponse = serde_json::from_str(&response.encrypted_secret)
            .map_err(|e| anyhow!("Failed to parse PRE response: {}", e))?;

        // Parse the re-encrypted commitment (xnc_cmt) from hex
        let xnc_cmt_bytes = hex::decode(&pre_response.xnc_cmt)
            .map_err(|e| anyhow!("Failed to decode xnc_cmt hex: {}", e))?;
        let xnc_cmt = G1Affine::from_bytes(&xnc_cmt_bytes)
            .map_err(|e| anyhow!("Failed to deserialize xnc_cmt: {}", e))?;

        // Decrypt using reader's secret key and the secret from the response
        let decrypted = ThresholdDealerNode::decrypt_secret(
            &ring_pk_point,
            &xnc_cmt,
            &reader_sk_scalar,
            &pre_response.secret,
        )
        .map_err(|e| anyhow!("Decryption failed: {}", e))?;

        let decrypted_str = String::from_utf8(decrypted)
            .map_err(|e| anyhow!("Decrypted data is not valid UTF-8: {}", e))?;

        println!("  Decrypted Secret: {}", decrypted_str);
    }

    Ok(())
}

pub async fn do_encrypt_secret(ring_pk: String, secret: String) -> Result<()> {
    println!("Encrypting secret to ring public key...");
    println!("  Ring PK: {}...", &ring_pk[..ring_pk.len().min(20)]);
    println!();

    // Parse the ring public key from hex
    let ring_pk_bytes =
        hex::decode(&ring_pk).map_err(|e| anyhow!("Failed to decode ring_pk hex: {}", e))?;

    let ring_pk_point = G1Affine::from_bytes(&ring_pk_bytes)
        .map_err(|e| anyhow!("Failed to deserialize ring_pk: {}", e))?;

    // Encrypt the secret
    let (_enc_cmt, encrypted_secret) =
        ThresholdDealerNode::encrypt_secret(&ring_pk_point, secret.as_bytes())
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

    // Output the full secret as JSON (this is what PRE expects)
    let secret_json = serde_json::to_string(&encrypted_secret)
        .map_err(|e| anyhow!("Failed to serialize secret: {}", e))?;

    println!("Encrypted Secret (JSON):");
    println!("{}", "=".repeat(60));
    println!("{}", secret_json);

    Ok(())
}

pub fn do_generate_reader_key() -> Result<()> {
    let mut rng = OsRng;

    // Generate random secret key (scalar)
    let sk = Fr::rand(&mut rng);

    // Derive public key: pk = sk * G
    let pk: G1Affine = (G1Projective::generator() * sk).into();

    // Serialize to bytes then hex
    let sk_bytes = sk
        .to_bytes()
        .map_err(|e| anyhow!("Failed to serialize secret key: {}", e))?;
    let pk_bytes = pk
        .to_bytes()
        .map_err(|e| anyhow!("Failed to serialize public key: {}", e))?;

    let sk_hex = hex::encode(&sk_bytes);
    let pk_hex = hex::encode(&pk_bytes);

    println!("Generated Reader Keypair:");
    println!("{}", "=".repeat(60));
    println!("Reader Secret Key (--reader-sk):");
    println!("{}", sk_hex);
    println!();
    println!("Reader Public Key (--reader-pk):");
    println!("{}", pk_hex);

    Ok(())
}
