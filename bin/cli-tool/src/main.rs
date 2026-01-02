mod commands;

use anyhow::Result;
use clap::{Parser, Subcommand};

pub use commands::{
    add_policy_to_chain, do_dkg, do_encrypt_secret, do_generate_reader_key, do_pre,
    register_object_to_chain, set_relationship_on_chain,
};

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
    /// Add a policy to the chain
    AddPolicyToChain,
    /// Register object to the chain
    RegisterObjectToChain {
        /// Policy to add object to
        #[clap(long)]
        policy_id: String,
        /// Id of object
        #[clap(long)]
        project_id: String,
        #[clap(long)]
        resource: String,
    },
    /// Set an object relationship on chain
    SetRelationshipOnChain {
        /// Policy to set relationship to
        #[clap(long)]
        policy_id: String,
        /// Id of object
        #[clap(long)]
        project_id: String,
        #[clap(long)]
        resource: String,
        #[clap(long)]
        relation: String,
        #[clap(long)]
        admin_id: String,
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
            peer_ids,
        } => {
            do_dkg(endpoint, threshold, peer_ids).await?;
        }
        SubCommands::Pre {
            endpoint,
            ring_pk,
            secret,
            reader_pk,
            reader_sk,
            peer_ids,
        } => {
            do_pre(
                endpoint,
                ring_pk,
                secret,
                reader_pk,
                reader_sk,
                peer_ids,
                "".to_string(),
                "".to_string(),
                "".to_string(),
                "".to_string(),
            )
            .await?;
        }
        SubCommands::EncryptSecret { secret, ring_pk } => {
            do_encrypt_secret(ring_pk, secret).await?;
        }
        SubCommands::GenerateReaderKey => {
            do_generate_reader_key()?;
        }
        SubCommands::AddPolicyToChain => {
            add_policy_to_chain().await?;
        }
        SubCommands::RegisterObjectToChain {
            policy_id,
            project_id,
            resource,
        } => {
            register_object_to_chain(policy_id, project_id, resource).await?;
        }
        SubCommands::SetRelationshipOnChain {
            policy_id,
            project_id,
            resource,
            relation,
            admin_id,
        } => {
            set_relationship_on_chain(policy_id, project_id, resource, relation, admin_id).await?;
        }
        SubCommands::Info { endpoint } => {
            println!("Querying node at: {}", endpoint);
            println!("(Info endpoint not yet implemented on server)");
        }
    }

    Ok(())
}
