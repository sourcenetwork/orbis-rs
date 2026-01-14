mod commands;

use anyhow::Result;
use clap::{Parser, Subcommand};
use hex;

pub use commands::{
    add_policy_to_chain, create_bulletin_post, do_dkg, do_encrypt_secret, do_generate_reader_key,
    do_pre, query_node_info, register_bulletin_namespace, register_object_to_chain,
    set_relationship_on_chain,
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

        /// Reader's public key in hex format (from generate-reader-key)
        #[clap(long)]
        reader_pk: String,

        /// Reader's secret key in hex format (for decryption after PRE)
        #[clap(long)]
        reader_sk: String,

        /// Id of object
        #[clap(long)]
        object_id: String,

        /// Id of object
        #[clap(long)]
        namespace: String,

        /// A private key to generate a reader did
        #[clap(long)]
        reader_did_pk: Option<String>,
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
        object_id: String,
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
        object_id: String,
        #[clap(long)]
        resource: String,
        #[clap(long)]
        relation: String,
        /// A private key to generate a reader did
        #[clap(long)]
        reader_did_pk: Option<String>,
    },
    /// Register a bulletin namespace
    RegisterBulletinNamespace {
        /// Namespace to register
        #[clap(long)]
        namespace: String,
    },
    /// Create a post on the bulletin
    CreateBulletinPost {
        /// Namespace to post to
        #[clap(long)]
        namespace: String,
        /// Payload as hex string
        #[clap(long)]
        payload: String,
        /// Proof as hex string
        #[clap(long)]
        proof: String,
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
            reader_pk,
            reader_sk,
            object_id,
            reader_did_pk,
            namespace,
        } => {
            do_pre(
                endpoint,
                ring_pk,
                reader_pk,
                reader_sk,
                object_id,
                reader_did_pk,
                namespace,
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
            object_id,
            resource,
        } => {
            register_object_to_chain(policy_id, object_id, resource).await?;
        }
        SubCommands::SetRelationshipOnChain {
            policy_id,
            object_id,
            resource,
            relation,
            reader_did_pk,
        } => {
            set_relationship_on_chain(policy_id, object_id, resource, relation, reader_did_pk)
                .await?;
        }
        SubCommands::RegisterBulletinNamespace { namespace } => {
            register_bulletin_namespace(namespace).await?;
        }
        SubCommands::CreateBulletinPost {
            namespace,
            payload,
            proof,
        } => {
            let payload_bytes = hex::decode(&payload).expect("Failed to decode payload hex");
            let proof_bytes = hex::decode(&proof).expect("Failed to decode proof hex");
            create_bulletin_post(namespace, payload_bytes, proof_bytes).await?;
        }
        SubCommands::Info { endpoint } => {
            query_node_info(endpoint).await?;
        }
    }

    Ok(())
}
