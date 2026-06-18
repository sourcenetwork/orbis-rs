mod commands;

use anyhow::Result;
use bulletin::r#trait::BulletinKind;
use clap::{Parser, Subcommand};
pub use commands::{
    add_bulletin_collaborator, add_node_to_whitelist, add_policy_to_chain,
    cancel_ring_upgrade_by_acp, create_bulletin_post, do_dkg, do_encrypt_secret,
    do_generate_reader_key, do_pre, do_sign, do_store_secret, fund, get_account_sequence,
    get_latest_ring, list_bulletin_posts, post_key_derivation, prepare_secret, query_node_info,
    query_ring_state, read_bulletin_post, register_bulletin_namespace, register_object_to_chain,
    remove_node_from_whitelist, schedule_ring_upgrade_by_acp, set_relationship_on_chain,
    set_ring_pss_interval_by_acp, start_ring_reshare_by_acp, store_prepared_secret,
    transfer_node_controller, update_node_peer_id, PreparedSecret, SignResult,
};
use common::blockchain::{orbis::WhitelistTarget, ChainConfig};

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

        /// Pre-created blank ring entry targeted by this DKG
        #[clap(long)]
        ring_id: String,
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
    /// Initiate a committee/threshold reshare for a ring via ACP authorization
    StartRingReshare {
        #[clap(long)]
        ring_id: String,
        /// New committee peer node keys (comma-separated)
        #[clap(long, value_delimiter = ',')]
        new_peer_node_keys: Vec<String>,
        /// New threshold (absent means keep current)
        #[clap(long)]
        new_threshold: Option<u32>,
    },
    /// Set the PSS refresh interval for a ring via ACP authorization
    SetRingPssInterval {
        #[clap(long)]
        ring_id: String,
        /// Seconds between automatic PSS refresh ceremonies
        #[clap(long)]
        pss_interval: u64,
    },
    /// Schedule a protocol version upgrade for a ring via ACP authorization
    ScheduleRingUpgrade {
        #[clap(long)]
        ring_id: String,
        /// Protocol version to activate
        #[clap(long)]
        next_version: u64,
        /// Unix timestamp (seconds) at which the upgrade activates; must be at least 10 minutes in the future
        #[clap(long)]
        activation_time: u64,
    },
    /// Cancel a pending protocol version upgrade for a ring via ACP authorization
    CancelRingUpgrade {
        #[clap(long)]
        ring_id: String,
    },
    /// Update the peer ID of a registered node
    UpdateNodePeerId {
        #[clap(long)]
        node_key: String,
        #[clap(long)]
        peer_id: String,
    },
    /// Transfer the controller key of a registered node
    TransferNodeController {
        #[clap(long)]
        node_key: String,
        #[clap(long)]
        controller_key: String,
    },
    /// Add a policy or ring to a node's whitelist
    AddNodeToWhitelist {
        #[clap(long)]
        node_key: String,
        /// Policy ID to whitelist (mutually exclusive with --ring-id)
        #[clap(long, conflicts_with = "ring_id")]
        policy_id: Option<String>,
        /// Ring ID to whitelist (mutually exclusive with --policy-id)
        #[clap(long, conflicts_with = "policy_id")]
        ring_id: Option<String>,
    },
    /// Remove a policy or ring from a node's whitelist
    RemoveNodeFromWhitelist {
        #[clap(long)]
        node_key: String,
        /// Policy ID to remove (mutually exclusive with --ring-id)
        #[clap(long, conflicts_with = "ring_id")]
        policy_id: Option<String>,
        /// Ring ID to remove (mutually exclusive with --policy-id)
        #[clap(long, conflicts_with = "policy_id")]
        ring_id: Option<String>,
    },
    /// Fund an account from the pre funded account
    Fund {
        /// Address to fund
        #[clap(long)]
        address: String,
    },
    /// Read an item from a bulletin
    ReadBulletinPost {
        /// Post ID to read
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
        /// Request a proof
        #[clap(long)]
        with_proof: bool,
        /// Optional tier
        #[clap(long)]
        tier: Option<String>,
        /// Optional timestamp
        #[clap(long)]
        timestamp: Option<u64>,
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
    /// Query the local ring state (public polynomial + last refresh timestamp) from a node
    RingState {
        /// gRPC endpoint of the node
        #[clap(short, long, default_value = "http://localhost:50051")]
        endpoint: String,
        /// Ring public key hex (from DKG)
        #[clap(long)]
        ring_pk_hex: String,
    },
    /// Fetch a ring from the orbis module by ring_id. Prints RING_ID and RING_PK for sourcing in scripts.
    GetLatestRing {
        /// Ring ID to look up
        #[clap(long)]
        ring_id: String,
    },
    /// Post a KeyDerivation to the bulletin (registers a sign key derivation config)
    PostKeyDerivation {
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
    },
    /// Start a threshold Sign session (Policy pathway)
    Sign {
        /// gRPC endpoint of the node to use
        #[clap(short, long, default_value = "http://localhost:50051")]
        endpoint: String,
        /// Message to sign (hex encoded)
        #[clap(long)]
        message: String,
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        SubCommands::Dkg { endpoint, ring_id } => {
            do_dkg(endpoint, ring_id).await?;
        }
        SubCommands::Pre {
            endpoint,
            ring_pk,
            reader_pk,
            reader_sk,
            object_id,
            reader_did_pk,
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
        SubCommands::StartRingReshare {
            ring_id,
            new_peer_node_keys,
            new_threshold,
        } => {
            start_ring_reshare_by_acp(ring_id, new_peer_node_keys, new_threshold).await?;
        }
        SubCommands::SetRingPssInterval {
            ring_id,
            pss_interval,
        } => {
            set_ring_pss_interval_by_acp(ring_id, pss_interval).await?;
        }
        SubCommands::ScheduleRingUpgrade {
            ring_id,
            next_version,
            activation_time,
        } => {
            schedule_ring_upgrade_by_acp(ring_id, next_version, activation_time).await?;
        }
        SubCommands::CancelRingUpgrade { ring_id } => {
            cancel_ring_upgrade_by_acp(ring_id).await?;
        }
        SubCommands::UpdateNodePeerId { node_key, peer_id } => {
            update_node_peer_id(node_key, peer_id).await?;
        }
        SubCommands::TransferNodeController {
            node_key,
            controller_key,
        } => {
            transfer_node_controller(node_key, controller_key).await?;
        }
        SubCommands::AddNodeToWhitelist {
            node_key,
            policy_id,
            ring_id,
        } => {
            let target = match (policy_id, ring_id) {
                (Some(id), _) => WhitelistTarget::PolicyId(id),
                (_, Some(id)) => WhitelistTarget::RingId(id),
                _ => return Err(anyhow::anyhow!("Must provide --policy-id or --ring-id")),
            };
            add_node_to_whitelist(node_key, target).await?;
        }
        SubCommands::RemoveNodeFromWhitelist {
            node_key,
            policy_id,
            ring_id,
        } => {
            let target = match (policy_id, ring_id) {
                (Some(id), _) => WhitelistTarget::PolicyId(id),
                (_, Some(id)) => WhitelistTarget::RingId(id),
                _ => return Err(anyhow::anyhow!("Must provide --policy-id or --ring-id")),
            };
            remove_node_from_whitelist(node_key, target).await?;
        }
        SubCommands::Fund { address } => {
            fund(address, ChainConfig::local()).await?;
        }
        SubCommands::ReadBulletinPost { id } => {
            read_bulletin_post(id, BulletinKind::Ring).await?;
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
            policy_id,
            resource,
            permission,
            reader_did_pk,
            with_proof,
            tier,
            timestamp,
        } => {
            let prepared: PreparedSecret = serde_json::from_str(&prepared_json)
                .map_err(|e| anyhow::anyhow!("Invalid prepared_json: {}", e))?;
            store_prepared_secret(
                endpoint,
                &prepared,
                ring_id,
                policy_id,
                resource,
                permission,
                reader_did_pk,
                with_proof,
                tier,
                timestamp,
            )
            .await?;
        }
        SubCommands::StoreSecret {
            endpoint,
            secret,
            ring_pk_hex,
            ring_id,
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
        SubCommands::RingState {
            endpoint,
            ring_pk_hex,
        } => {
            let (poly, last_pss) = query_ring_state(endpoint, ring_pk_hex).await?;
            println!("PUBLIC_POLYNOMIAL={}", poly);
            println!("LAST_PSS={}", last_pss);
        }
        SubCommands::GetLatestRing { ring_id } => {
            let (ring_id, ring_pk) = get_latest_ring(ring_id).await?;
            println!("RING_ID={}", ring_id);
            println!("RING_PK={}", ring_pk);
        }
        SubCommands::PostKeyDerivation {
            ring_id,
            derivation,
            policy_id,
            resource,
            permission,
        } => {
            let (derivation_id, derived_pk_hex) =
                post_key_derivation(ring_id, derivation, policy_id, resource, permission).await?;
            println!("DERIVATION_ID={}", derivation_id);
            println!("DERIVED_PK={}", derived_pk_hex);
        }
        SubCommands::Sign {
            endpoint,
            message,
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
            do_sign(
                endpoint,
                message_bytes,
                derivation_id,
                reader_did_pk,
                valid_window_start,
                valid_window_end,
            )
            .await?;
        }
    }

    Ok(())
}
