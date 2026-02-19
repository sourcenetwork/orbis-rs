mod commands;

use anyhow::Result;
use clap::{Parser, Subcommand};
pub use commands::{
    add_bulletin_collaborator, add_policy_to_chain, create_bulletin_post, derive_public_key,
    do_dkg, do_encrypt_secret, do_generate_reader_key, do_pre, do_sign, do_store_secret, fund,
    get_account_sequence, list_bulletin_posts, prepare_secret, query_node_info, read_bulletin_post,
    register_bulletin_namespace, register_object_to_chain, set_relationship_on_chain,
    store_prepared_secret, DerivePublicKeyResult, DkgResult, NodeInfoResult, PreparedSecret,
    SignResult, StoreSecretResult,
};
use common::blockchain::ChainConfig;
use hex;

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

        /// Optional derivation path (hex encoded)
        #[clap(long)]
        derivation: Option<String>,
    },
    /// Encrypts a secret to the ring public key (from DKG)
    EncryptSecret {
        /// Secret to encrypt
        #[clap(long)]
        secret: String,
        /// Ring public key (from DKG) in hex format
        #[clap(long)]
        ring_pk: String,
        /// Optional derivation path (hex encoded)
        #[clap(long)]
        derivation: Option<String>,
        /// Policy to attach to secret
        #[clap(long)]
        policy_id: String,
        /// Resource type of secret
        #[clap(long)]
        resource: String,
        /// Permission to read secret
        #[clap(long)]
        permission: String,
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
    /// Add a collaborator to a bulletin namespace
    AddBulletinCollaborator {
        /// Namespace to add collaborator to
        #[clap(long)]
        namespace: String,
        /// Collaborator address to add
        #[clap(long)]
        collaborator: String,
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
    /// Fund an account from the pre funded account
    Fund {
        /// Address to fund
        #[clap(long)]
        address: String,
    },
    /// Read an item from a bulletin
    ReadBulletinPost {
        /// Namespace to add collaborator to
        #[clap(long)]
        namespace: String,
        /// Collaborator address to add
        #[clap(long)]
        id: String,
    },
    /// List all bulletin posts on the namespace
    ListBulletinPost {
        /// Namespace to add collaborator to
        #[clap(long)]
        namespace: String,
    },
    /// Prepare a secret for storage (encrypt locally, output JSON for later use)
    PrepareSecret {
        /// Plaintext secret to encrypt
        #[clap(long)]
        secret: String,
        /// Ring public key (hex) - used for encryption
        #[clap(long)]
        ring_pk_hex: String,
        /// Optional derivation path (hex encoded)
        #[clap(long)]
        derivation: Option<String>,
        /// Policy to attach to secret
        #[clap(long)]
        policy_id: String,
        /// Resource type of secret
        #[clap(long)]
        resource: String,
        /// Permission to read secret
        #[clap(long)]
        permission: String,
    },
    /// Store a prepared (pre-encrypted) secret - idempotent, safe for retries
    StorePreparedSecret {
        /// gRPC endpoint of the node to use
        #[clap(long)]
        endpoint: String,
        /// Prepared secret JSON (from prepare-secret command)
        #[clap(long)]
        prepared_json: String,
        /// Ring id of ring to encrypt to
        #[clap(long)]
        ring_id: String,
        /// Namespace of board to store secret to
        #[clap(long)]
        namespace: String,
        /// Policy to attach to secret
        #[clap(long)]
        policy_id: String,
        /// Resource type of secret
        #[clap(long)]
        resource: String,
        /// Permission to read secret
        #[clap(long)]
        permission: String,
        /// A private key to generate a reader did
        #[clap(long)]
        reader_did_pk: Option<String>,
        /// Optional derived public key (hex encoded)
        #[clap(long)]
        derived_pk: Option<String>,
        /// Request a proof
        #[clap(long)]
        with_proof: bool,
    },
    /// Store secret by sending it to node (encrypts and stores in one step)
    StoreSecret {
        /// gRPC endpoint of the node to use
        #[clap(long)]
        endpoint: String,
        /// Plaintext secret encrypted locally before sending
        #[clap(long)]
        secret: String,
        /// Ring public key (hex) - used for encryption
        #[clap(long)]
        ring_pk_hex: String,
        /// Ring id of ring to encrypt to
        #[clap(long)]
        ring_id: String,
        /// Namespace of board to store secret to
        #[clap(long)]
        namespace: String,
        /// Policy to attach to secret
        #[clap(long)]
        policy_id: String,
        /// Resource type of secret
        #[clap(long)]
        resource: String,
        /// Permision to read secret
        #[clap(long)]
        permission: String,
        /// A private key to generate a reader did
        #[clap(long)]
        reader_did_pk: Option<String>,
        /// Optional derivation path (hex encoded)
        #[clap(long)]
        derivation: Option<String>,
        /// Request a proof
        #[clap(long)]
        with_proof: bool,
    },
    /// Query node info
    Info {
        /// gRPC endpoint of the node
        #[clap(short, long, default_value = "http://localhost:50051")]
        endpoint: String,
    },
    /// Derive a public key from a ring's master PK + label
    DerivePublicKey {
        /// gRPC endpoint of the node
        #[clap(short, long, default_value = "http://localhost:50051")]
        endpoint: String,
        /// Ring ID to derive from
        #[clap(long)]
        ring_id: String,
        /// Derivation label (hex encoded)
        #[clap(long)]
        derivation: String,
    },
    /// Perform threshold signing with a ring
    Sign {
        /// gRPC endpoint of the node
        #[clap(short, long, default_value = "http://localhost:50051")]
        endpoint: String,
        /// Ring ID to sign with
        #[clap(long)]
        ring_id: String,
        /// Message to sign (hex encoded)
        #[clap(long)]
        message: String,
        /// Optional derivation path (hex encoded)
        #[clap(long)]
        derivation: Option<String>,
        /// A private key to generate a signer did
        #[clap(long)]
        signer_did_pk: Option<String>,
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
            derivation,
        } => {
            let derivation_bytes =
                derivation.map(|d| hex::decode(&d).expect("Failed to decode derivation hex"));
            do_pre(
                endpoint,
                ring_pk,
                reader_pk,
                reader_sk,
                object_id,
                reader_did_pk,
                namespace,
                derivation_bytes,
            )
            .await?;
        }
        SubCommands::EncryptSecret {
            secret,
            ring_pk,
            derivation,
            policy_id,
            resource,
            permission,
        } => {
            let derivation_bytes =
                derivation.map(|d| hex::decode(&d).expect("Failed to decode derivation hex"));
            do_encrypt_secret(
                ring_pk,
                secret,
                derivation_bytes,
                policy_id,
                resource,
                permission,
            )
            .await?;
        }
        SubCommands::GenerateReaderKey => {
            do_generate_reader_key()?;
        }
        SubCommands::AddPolicyToChain => {
            add_policy_to_chain(ChainConfig::local()).await?;
        }
        SubCommands::RegisterObjectToChain {
            policy_id,
            object_id,
            resource,
        } => {
            register_object_to_chain(policy_id, object_id, resource, ChainConfig::local()).await?;
        }
        SubCommands::SetRelationshipOnChain {
            policy_id,
            object_id,
            resource,
            relation,
            reader_did_pk,
        } => {
            set_relationship_on_chain(policy_id, object_id, resource, relation, reader_did_pk, ChainConfig::local())
                .await?;
        }
        SubCommands::RegisterBulletinNamespace { namespace } => {
            register_bulletin_namespace(namespace, ChainConfig::local()).await?;
        }
        SubCommands::AddBulletinCollaborator {
            namespace,
            collaborator,
        } => {
            add_bulletin_collaborator(namespace, collaborator, ChainConfig::local()).await?;
        }
        SubCommands::CreateBulletinPost {
            namespace,
            payload,
            proof,
        } => {
            let payload_bytes = hex::decode(&payload).expect("Failed to decode payload hex");
            let proof_bytes = hex::decode(&proof).expect("Failed to decode proof hex");
            create_bulletin_post(namespace, payload_bytes, proof_bytes, ChainConfig::local()).await?;
        }
        SubCommands::Fund { address } => {
            fund(address, ChainConfig::local()).await?;
        }
        SubCommands::ReadBulletinPost { namespace, id } => {
            read_bulletin_post(namespace, id, ChainConfig::local()).await?;
        }
        SubCommands::ListBulletinPost { namespace } => {
            list_bulletin_posts(namespace, ChainConfig::local()).await?;
        }
        SubCommands::PrepareSecret {
            secret,
            ring_pk_hex,
            derivation,
            policy_id,
            resource,
            permission,
        } => {
            let derivation_bytes =
                derivation.map(|d| hex::decode(&d).expect("Failed to decode derivation hex"));
            let prepared = prepare_secret(
                secret.as_bytes(),
                &ring_pk_hex,
                derivation_bytes,
                policy_id,
                resource,
                permission,
            )?;
            let json = serde_json::to_string_pretty(&prepared)?;
            println!("Prepared Secret (save this for store-prepared-secret):");
            println!("{}", "=".repeat(60));
            println!("{}", json);
        }
        SubCommands::StorePreparedSecret {
            endpoint,
            prepared_json,
            ring_id,
            namespace,
            policy_id,
            resource,
            permission,
            reader_did_pk,
            derived_pk,
            with_proof,
        } => {
            let derived_pk_bytes =
                derived_pk.map(|d| hex::decode(&d).expect("Failed to decode derived_pk hex"));
            let prepared: PreparedSecret = serde_json::from_str(&prepared_json)
                .map_err(|e| anyhow::anyhow!("Invalid prepared_json: {}", e))?;
            store_prepared_secret(
                endpoint,
                &prepared,
                ring_id,
                namespace,
                policy_id,
                resource,
                permission,
                reader_did_pk,
                derived_pk_bytes,
                with_proof,
            )
            .await?;
        }
        SubCommands::StoreSecret {
            endpoint,
            secret,
            ring_pk_hex,
            ring_id,
            namespace,
            policy_id,
            resource,
            permission,
            reader_did_pk,
            derivation,
            with_proof,
        } => {
            let derivation_bytes =
                derivation.map(|d| hex::decode(&d).expect("Failed to decode derivation hex"));
            do_store_secret(
                endpoint,
                secret.as_bytes(),
                ring_pk_hex,
                ring_id,
                namespace,
                policy_id,
                resource,
                permission,
                reader_did_pk,
                derivation_bytes,
                with_proof,
            )
            .await?;
        }
        SubCommands::Info { endpoint } => {
            query_node_info(endpoint).await?;
        }
        SubCommands::DerivePublicKey {
            endpoint,
            ring_id,
            derivation,
        } => {
            let derivation_bytes =
                hex::decode(&derivation).expect("Failed to decode derivation hex");
            derive_public_key(endpoint, ring_id, derivation_bytes).await?;
        }
        SubCommands::Sign {
            endpoint,
            ring_id,
            message,
            derivation,
            signer_did_pk,
        } => {
            let message_bytes = hex::decode(&message).expect("Failed to decode message hex");
            let derivation_bytes =
                derivation.map(|d| hex::decode(&d).expect("Failed to decode derivation hex"));
            do_sign(endpoint, ring_id, message_bytes, derivation_bytes, signer_did_pk, None).await?;
        }
    }

    Ok(())
}
