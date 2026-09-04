mod commands;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
pub use commands::{
    add_bulletin_collaborator, add_policy_to_chain, create_bulletin_post, derive_public_key,
    do_dkg, do_encrypt_secret, do_generate_reader_key, do_pre, do_sign, do_store_secret,
    do_utility_sign, fund, get_account_sequence, get_latest_ring, list_bulletin_posts,
    post_key_derivation, prepare_secret, query_node_info, read_bulletin_post,
    register_bulletin_namespace, register_object_to_chain, set_relationship_on_chain,
    signer_did_for_pk, store_prepared_secret, DerivePublicKeyResult, PreparedSecret, SignAcpFields,
    SignResult, UtilitySignResult,
};
use common::blockchain::ChainConfig;
use hex;

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Parser, Debug, Clone)]
#[clap(version, about = "CLI tool for interacting with an orbis network")]
pub struct Cli {
    /// Output format (text or json)
    #[clap(long, value_enum, default_value = "text", global = true)]
    output: OutputFormat,

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

        /// Reader's secret key in hex format (for decryption after PRE).
        /// Not required when --xnc-only is set.
        #[clap(long)]
        reader_sk: Option<String>,

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
        /// Optional salt
        #[clap(long)]
        salt: Option<String>,

        /// Start of the validity window (Unix timestamp, inclusive). Requires --valid-window-end.
        #[clap(long)]
        valid_window_start: Option<u64>,

        /// End of the validity window (Unix timestamp, inclusive). Requires --valid-window-start.
        #[clap(long)]
        valid_window_end: Option<u64>,

        /// Print only the re-encrypted commitment (xnc_cmt) without decrypting.
        #[clap(long)]
        xnc_only: bool,
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
        /// Optional tier
        #[clap(long)]
        tier: Option<String>,
        /// Optional timestamp
        #[clap(long)]
        timestamp: Option<u64>,
        /// Optional salt
        #[clap(long)]
        salt: Option<String>,
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
        /// Optional tier
        #[clap(long)]
        tier: Option<String>,
        /// Optional timestamp
        #[clap(long)]
        timestamp: Option<u64>,
        /// Optional salt
        #[clap(long)]
        salt: Option<String>,
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
        /// Optional tier
        #[clap(long)]
        tier: Option<String>,
        /// Optional timestamp
        #[clap(long)]
        timestamp: Option<u64>,
        /// Optional metadata hash
        #[clap(long)]
        metadata_hash: Option<String>,
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
        /// Optional tier
        #[clap(long)]
        tier: Option<String>,
        /// Optional timestamp
        #[clap(long)]
        timestamp: Option<u64>,
        /// Optional salt
        #[clap(long)]
        salt: Option<String>,
    },
    /// Query node info
    Info {
        /// gRPC endpoint of the node
        #[clap(short, long, default_value = "http://localhost:50051")]
        endpoint: String,
    },
    /// Get latest ring from bulletin (after DKG). Prints RING_ID and RING_PK for sourcing in scripts.
    GetLatestRing {
        /// Bulletin namespace for ring payloads [default: orbis]
        #[clap(long)]
        namespace: Option<String>,
    },
    /// Post a KeyDerivation to the bulletin (registers a sign key derivation config)
    PostKeyDerivation {
        /// Bulletin namespace to post to
        #[clap(long)]
        namespace: String,
        /// Ring ID from DKG (used to fetch the ring public key from the bulletin)
        #[clap(long)]
        ring_id: String,
        /// Derivation path string
        #[clap(long)]
        derivation: String,
        /// Policy ID for authz check
        #[clap(long)]
        policy_id: String,
        /// Resource type on the policy
        #[clap(long)]
        resource: String,
        /// Permission required on the policy
        #[clap(long)]
        permission: String,
        /// Proof bytes (hex encoded)
        #[clap(long)]
        proof: String,
    },
    /// Start a threshold Sign session (Policy pathway via SignService)
    Sign {
        /// gRPC endpoint of the node to use
        #[clap(short, long, default_value = "http://localhost:50051")]
        endpoint: String,
        /// Message to sign (hex encoded)
        #[clap(long)]
        message: String,
        /// Bulletin namespace that holds the KeyDerivation
        #[clap(long)]
        namespace: String,
        /// Derivation ID (post ID returned by post-key-derivation)
        #[clap(long)]
        derivation_id: String,
        /// A private key to generate a reader DID for JWT
        #[clap(long)]
        reader_did_pk: Option<String>,
        /// Start of the validity window (Unix timestamp, inclusive). Requires --valid-window-end.
        #[clap(long)]
        valid_window_start: Option<u64>,
        /// End of the validity window (Unix timestamp, inclusive). Requires --valid-window-start.
        #[clap(long)]
        valid_window_end: Option<u64>,
    },
    /// Start a threshold Sign session (UtilityService pathway, direct ring_id)
    UtilitySign {
        /// gRPC endpoint of the node to use
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
        /// Signer DID private key (hex) for JWT authentication
        #[clap(long)]
        signer_did_pk: Option<String>,
        /// ACP policy ID (optional)
        #[clap(long)]
        policy_id: Option<String>,
        /// ACP resource type (optional)
        #[clap(long)]
        resource: Option<String>,
        /// ACP object ID (optional)
        #[clap(long)]
        object_id: Option<String>,
        /// ACP permission (optional)
        #[clap(long)]
        permission: Option<String>,
    },
    /// Derive a public key from a ring's master key and derivation path
    DerivePublicKey {
        /// gRPC endpoint of the node to use
        #[clap(short, long, default_value = "http://localhost:50051")]
        endpoint: String,
        /// Ring ID
        #[clap(long)]
        ring_id: String,
        /// Derivation path (hex encoded)
        #[clap(long)]
        derivation: String,
    },
    /// Print the DID URI for a given signer private key (hex)
    SignerDid {
        /// Signer private key (hex encoded, 32 bytes)
        #[clap(long)]
        signer_did_pk: String,
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
            salt,
            valid_window_start,
            valid_window_end,
            xnc_only,
        } => {
            if !xnc_only && reader_sk.is_none() {
                anyhow::bail!("--reader-sk is required unless --xnc-only is set");
            }
            match (valid_window_start, valid_window_end) {
                (Some(_), None) | (None, Some(_)) => {
                    anyhow::bail!(
                        "--valid-window-start and --valid-window-end must both be provided"
                    );
                }
                _ => {}
            }
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
                salt,
                valid_window_start,
                valid_window_end,
                xnc_only,
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
            tier,
            timestamp,
            salt,
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
                tier,
                timestamp,
                salt,
            )
            .await?;
        }
        SubCommands::GenerateReaderKey => {
            do_generate_reader_key()?;
        }
        SubCommands::AddPolicyToChain => {
            let policy_id = add_policy_to_chain().await?;
            println!("POLICY_ID={}", policy_id);
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
        SubCommands::AddBulletinCollaborator {
            namespace,
            collaborator,
        } => {
            add_bulletin_collaborator(namespace, collaborator).await?;
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
        SubCommands::Fund { address } => {
            fund(address, ChainConfig::local()).await?;
        }
        SubCommands::ReadBulletinPost { namespace, id } => {
            read_bulletin_post(namespace, id).await?;
        }
        SubCommands::ListBulletinPost { namespace } => {
            list_bulletin_posts(namespace).await?;
        }
        SubCommands::PrepareSecret {
            secret,
            ring_pk_hex,
            derivation,
            policy_id,
            resource,
            permission,
            tier,
            timestamp,
            salt,
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
                tier,
                timestamp,
                salt,
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
            tier,
            timestamp,
            metadata_hash,
        } => {
            let derived_pk_bytes =
                derived_pk.map(|d| hex::decode(&d).expect("Failed to decode derived_pk hex"));
            let metadata_hash_bytes =
                metadata_hash.map(|d| hex::decode(&d).expect("Failed to decode metadata_hash hex"));
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
                tier,
                timestamp,
                metadata_hash_bytes,
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
            tier,
            timestamp,
            salt,
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
                tier,
                timestamp,
                salt,
                reader_did_pk,
                derivation_bytes,
                with_proof,
            )
            .await?;
        }
        SubCommands::Info { endpoint } => {
            query_node_info(endpoint).await?;
        }
        SubCommands::GetLatestRing { namespace } => {
            let (ring_id, ring_pk) = get_latest_ring(namespace).await?;
            println!("RING_ID={}", ring_id);
            println!("RING_PK={}", ring_pk);
        }
        SubCommands::PostKeyDerivation {
            namespace,
            ring_id,
            derivation,
            policy_id,
            resource,
            permission,
            proof,
        } => {
            let proof_bytes = hex::decode(&proof)
                .map_err(|e| anyhow::anyhow!("Failed to decode proof hex: {}", e))?;
            let (derivation_id, derived_pk_hex) = post_key_derivation(
                namespace,
                ring_id,
                derivation,
                policy_id,
                resource,
                permission,
                proof_bytes,
            )
            .await?;
            println!("DERIVATION_ID={}", derivation_id);
            println!("DERIVED_PK={}", derived_pk_hex);
        }
        SubCommands::Sign {
            endpoint,
            message,
            namespace,
            derivation_id,
            reader_did_pk,
            valid_window_start,
            valid_window_end,
        } => {
            match (valid_window_start, valid_window_end) {
                (Some(_), None) | (None, Some(_)) => {
                    anyhow::bail!(
                        "--valid-window-start and --valid-window-end must both be provided"
                    );
                }
                _ => {}
            }
            let message_bytes = hex::decode(&message)
                .map_err(|e| anyhow::anyhow!("Failed to decode message hex: {}", e))?;
            let result = do_sign(
                endpoint,
                message_bytes,
                namespace,
                derivation_id,
                reader_did_pk,
                valid_window_start,
                valid_window_end,
            )
            .await?;
            if matches!(cli.output, OutputFormat::Json) {
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
        }
        SubCommands::UtilitySign {
            endpoint,
            ring_id,
            message,
            derivation,
            signer_did_pk,
            policy_id,
            resource,
            object_id,
            permission,
        } => {
            let message_bytes = hex::decode(&message)
                .map_err(|e| anyhow::anyhow!("Failed to decode message hex: {}", e))?;
            let derivation_bytes =
                derivation.map(|d| hex::decode(&d).expect("Failed to decode derivation hex"));
            let acp = if policy_id.is_some()
                || resource.is_some()
                || object_id.is_some()
                || permission.is_some()
            {
                Some(SignAcpFields {
                    policy_id: policy_id.unwrap_or_default(),
                    resource: resource.unwrap_or_default(),
                    object_id: object_id.unwrap_or_default(),
                    permission: permission.unwrap_or_default(),
                })
            } else {
                None
            };
            let result = do_utility_sign(
                endpoint,
                ring_id,
                message_bytes,
                derivation_bytes,
                signer_did_pk,
                acp,
            )
            .await?;
            if matches!(cli.output, OutputFormat::Json) {
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
        }
        SubCommands::DerivePublicKey {
            endpoint,
            ring_id,
            derivation,
        } => {
            let derivation_bytes = hex::decode(&derivation)
                .map_err(|e| anyhow::anyhow!("Failed to decode derivation hex: {}", e))?;
            let result = derive_public_key(endpoint, ring_id, derivation_bytes).await?;
            if matches!(cli.output, OutputFormat::Json) {
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
        }
        SubCommands::SignerDid { signer_did_pk } => {
            let did = signer_did_for_pk(&signer_did_pk);
            if matches!(cli.output, OutputFormat::Json) {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({"did": did}))?
                );
            } else {
                println!("{}", did);
            }
        }
    }

    Ok(())
}
