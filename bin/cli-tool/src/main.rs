mod commands;

use anyhow::Result;
use bulletin::r#trait::BulletinKind;
use clap::{Args, Parser, Subcommand};
pub use commands::{
    add_bulletin_collaborator, add_node_to_whitelist, add_policy_to_chain,
    cancel_ring_reshare_by_acp, cancel_ring_upgrade_by_acp, create_bulletin_post, create_ring,
    derive_signer_did, do_dkg, do_encrypt_secret, do_generate_reader_key, do_pre, do_sign,
    do_store_secret, fund_with_signer, get_account_sequence, get_latest_ring, list_bulletin_posts,
    post_key_derivation, prepare_secret, query_node_info, query_ring_state,
    read_bulletin_post_with_config, register_bulletin_namespace, register_object_to_chain,
    remove_node_from_whitelist, schedule_ring_upgrade_by_acp, set_relationship_on_chain,
    set_ring_pss_interval_by_acp, start_ring_reshare_by_acp, store_prepared_secret,
    transfer_node_controller, update_node_peer_id, PreparedSecret, SignResult,
};
use commands::{reader_did_from_seed, secp256k1_pubkey_to_did};
use common::blockchain::{orbis::WhitelistTarget, ChainConfig};

/// Network and signing configuration, shared across every subcommand.
#[derive(Args, Debug, Clone)]
struct NetworkArgs {
    /// gRPC endpoint of the orbis node (e.g., http://localhost:50051)
    #[arg(
        short,
        long,
        env = "ORBIS_ENDPOINT",
        default_value = "http://localhost:50051",
        global = true
    )]
    endpoint: String,

    /// Chain ID of the target SourceHub network
    #[arg(
        long,
        env = "ORBIS_CHAIN_ID",
        default_value = "sourcehub-localnet",
        global = true
    )]
    chain_id: String,

    /// Tendermint RPC URL of the target chain
    #[arg(
        long,
        env = "ORBIS_RPC_URL",
        default_value = "http://localhost:26657",
        global = true
    )]
    rpc_url: String,

    /// Cosmos REST API URL of the target chain
    #[arg(
        long,
        env = "ORBIS_REST_URL",
        default_value = "http://localhost:1317",
        global = true
    )]
    rest_url: String,

    /// gRPC URL of the target chain (distinct from --endpoint, which is the orbis node)
    #[arg(
        long,
        env = "ORBIS_CHAIN_GRPC_URL",
        default_value = "http://localhost:9090",
        global = true
    )]
    chain_grpc_url: String,

    /// Bech32 account address prefix of the target chain
    #[arg(
        long,
        env = "ORBIS_ACCOUNT_PREFIX",
        default_value = "source",
        global = true
    )]
    account_prefix: String,

    /// Hex-encoded secp256k1 private key used to sign chain transactions.
    /// Required for any command that writes to chain. For local devnet
    /// testing only, see README.md for the well-known local test key —
    /// never use it against a real network.
    #[arg(long, env = "ORBIS_SIGNING_KEY", global = true, hide_env_values = true)]
    signing_key: Option<String>,
}

impl NetworkArgs {
    fn chain_config(&self) -> ChainConfig {
        ChainConfig::builder()
            .chain_id(Some(self.chain_id.clone()))
            .rpc_url(Some(self.rpc_url.clone()))
            .rest_url(Some(self.rest_url.clone()))
            .grpc_url(Some(self.chain_grpc_url.clone()))
            .account_prefix(Some(self.account_prefix.clone()))
            .build()
    }

    fn require_signing_key(&self) -> Result<String> {
        self.signing_key.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "No signing key configured. Pass --signing-key <hex> or set ORBIS_SIGNING_KEY.\n\
                 For local devnet testing only, you may use the well-known SourceHub localnet \
                 test key documented in README.md — never use it against a real network."
            )
        })
    }
}

#[derive(Parser, Debug, Clone)]
#[clap(version, about = "CLI tool for interacting with an orbis network")]
pub struct Cli {
    #[clap(flatten)]
    network: NetworkArgs,

    #[clap(subcommand)]
    command: SubCommands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum SubCommands {
    /// Create a blank ring on-chain, to be targeted by a subsequent `dkg` session
    CreateRing {
        /// Peer node keys for the ring's initial committee (comma-separated, secp256k1 hex)
        #[clap(long, value_delimiter = ',')]
        peer_node_keys: Vec<String>,
        /// Signing/reconstruction threshold
        #[clap(long)]
        threshold: u32,
        /// Seconds between automatic PSS refresh ceremonies (the chain enforces a minimum)
        #[clap(long, default_value_t = 86400)]
        pss_interval: u64,
        /// ACP policy ID authorizing this ring
        #[clap(long)]
        policy_id: String,
        /// Optional nonce to avoid ring_id collisions when creating multiple rings in one block
        #[clap(long)]
        nonce: Option<String>,
        /// Protocol version this ring starts on
        #[clap(long, default_value_t = 0)]
        current_version: u64,
        /// Trusted auth-relay DIDs allowed to relay requests on this ring's behalf (comma-separated)
        #[clap(long, value_delimiter = ',')]
        trusted_auth_relay_dids: Vec<String>,
    },
    /// Start a Distributed Key Generation session
    Dkg {
        /// Blank ring entry targeted by this DKG (create one with `create-ring`)
        #[clap(long)]
        ring_id: String,
    },

    /// Start a Proxy Re-Encryption session
    Pre {
        /// Ring public key (from DKG) in hex format
        #[clap(long)]
        ring_pk: String,

        /// Reader's public key in hex format (from generate-reader-key)
        #[clap(long)]
        reader_pk: String,

        /// Reader's secret key in hex format (for decryption after PRE).
        /// Not required when --xnc-only is set.
        #[clap(long, env = "ORBIS_READER_SK", hide_env_values = true)]
        reader_sk: Option<String>,

        /// Id of object
        #[clap(long)]
        object_id: String,

        /// A private key to generate a reader did
        #[clap(long, env = "ORBIS_READER_DID_PK", hide_env_values = true)]
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
        /// Secret to encrypt. If omitted, you'll be prompted for it (hidden input).
        #[clap(long)]
        secret: Option<String>,
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
    /// Derive the secp256k1 public key and did:key for --signing-key. Pure local
    /// computation, no network calls. SourceHub resolves ACP actor identity for
    /// signed transactions (e.g. create-ring's `create_ring` permission check)
    /// from this same derivation -- use this to find out, ahead of time, which
    /// DID needs a relation granted (via `set-relationship-on-chain --actor-pubkey`)
    /// before such a transaction will be authorized.
    DeriveSignerDid,
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
        #[clap(
            long,
            env = "ORBIS_READER_DID_PK",
            hide_env_values = true,
            conflicts_with = "actor_pubkey"
        )]
        reader_did_pk: Option<String>,
        /// Grant this relation to the DID derived from a secp256k1 public key
        /// instead of --reader-did-pk -- matches the identity SourceHub resolves
        /// for ACP checks on signed transactions (see `derive-signer-did`).
        #[clap(long, conflicts_with = "reader_did_pk")]
        actor_pubkey: Option<String>,
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
    /// Cancel a pending reshare for a ring via ACP authorization
    CancelRingReshare {
        #[clap(long)]
        ring_id: String,
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
        /// Plaintext secret to encrypt. If omitted, you'll be prompted for it (hidden input).
        #[clap(long)]
        secret: Option<String>,
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
        #[clap(long, env = "ORBIS_READER_DID_PK", hide_env_values = true)]
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
        /// Plaintext secret encrypted locally before sending. If omitted, you'll be prompted for it (hidden input).
        #[clap(long)]
        secret: Option<String>,
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
        #[clap(long, env = "ORBIS_READER_DID_PK", hide_env_values = true)]
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
    Info,
    /// Query the local ring state (public polynomial + last refresh timestamp) from a node
    RingState {
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
        /// Message to sign (hex encoded)
        #[clap(long)]
        message: String,
        /// Derivation ID (post ID returned by post-key-derivation)
        #[clap(long)]
        derivation_id: String,
        /// A private key to generate a reader DID for JWT
        #[clap(long, env = "ORBIS_READER_DID_PK", hide_env_values = true)]
        reader_did_pk: Option<String>,
        /// Start of the validity window (Unix timestamp, inclusive). Requires --valid-window-end.
        #[clap(long)]
        valid_window_start: Option<u64>,
        /// End of the validity window (Unix timestamp, inclusive). Requires --valid-window-start.
        #[clap(long)]
        valid_window_end: Option<u64>,
    },
}

/// Returns `secret` if given, otherwise prompts for it interactively with hidden input.
fn resolve_secret(secret: Option<String>, prompt: &str) -> Result<String> {
    match secret {
        Some(s) => Ok(s),
        None => rpassword::prompt_password(prompt)
            .map_err(|e| anyhow::anyhow!("Failed to read secret from prompt: {}", e)),
    }
}

/// Every user must supply their own value here (via `--reader-did-pk` or `ORBIS_READER_DID_PK`) —
/// there is no shared default, since one would silently collapse every unspecified user onto the
/// same on-chain DID identity.
fn require_reader_did_pk(reader_did_pk: Option<String>) -> Result<String> {
    reader_did_pk.ok_or_else(|| {
        anyhow::anyhow!(
            "No reader DID identity configured. Pass --reader-did-pk <value> or set ORBIS_READER_DID_PK.\n\
             Each user needs their own value — a shared default would collapse everyone onto the same DID."
        )
    })
}

/// Resolve the DID to grant a relationship to: either the Ed25519 DID derived
/// from --reader-did-pk's seed, or the secp256k1 DID derived from
/// --actor-pubkey (matching SourceHub's ACP actor identity for signed
/// transactions -- see `derive-signer-did`). Clap's `conflicts_with` already
/// rejects both being given; this handles neither being given.
fn resolve_relationship_actor_did(
    reader_did_pk: Option<String>,
    actor_pubkey: Option<String>,
) -> Result<String> {
    if let Some(seed) = reader_did_pk {
        return Ok(reader_did_from_seed(&seed));
    }
    if let Some(pubkey_hex) = actor_pubkey {
        return secp256k1_pubkey_to_did(&pubkey_hex);
    }
    Err(anyhow::anyhow!(
        "Must provide --reader-did-pk or --actor-pubkey"
    ))
}

/// `--valid-window-start`/`--valid-window-end` must be given together or not at all.
fn require_valid_window_pair(start: Option<u64>, end: Option<u64>) -> Result<()> {
    match (start, end) {
        (Some(_), None) | (None, Some(_)) => {
            anyhow::bail!("--valid-window-start and --valid-window-end must both be provided");
        }
        _ => Ok(()),
    }
}

/// Resolve `--policy-id`/`--ring-id` into a single whitelist target. Clap's `conflicts_with`
/// already rejects both being given; this handles neither being given.
fn resolve_whitelist_target(
    policy_id: Option<String>,
    ring_id: Option<String>,
) -> Result<WhitelistTarget> {
    match (policy_id, ring_id) {
        (Some(id), _) => Ok(WhitelistTarget::PolicyId(id)),
        (_, Some(id)) => Ok(WhitelistTarget::RingId(id)),
        _ => Err(anyhow::anyhow!("Must provide --policy-id or --ring-id")),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let network = cli.network.clone();

    match cli.command {
        SubCommands::CreateRing {
            peer_node_keys,
            threshold,
            pss_interval,
            policy_id,
            nonce,
            current_version,
            trusted_auth_relay_dids,
        } => {
            let signing_key = network.require_signing_key()?;
            let ring_id = create_ring(
                peer_node_keys,
                threshold,
                pss_interval,
                policy_id,
                nonce,
                current_version,
                trusted_auth_relay_dids,
                network.chain_config(),
                &signing_key,
            )
            .await?;
            println!("RING_ID={}", ring_id);
        }
        SubCommands::Dkg { ring_id } => {
            do_dkg(network.endpoint.clone(), ring_id).await?;
        }
        SubCommands::Pre {
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
            require_valid_window_pair(valid_window_start, valid_window_end)?;
            let reader_did_pk = require_reader_did_pk(reader_did_pk)?;
            let derivation_bytes =
                derivation.map(|d| hex::decode(&d).expect("Failed to decode derivation hex"));
            do_pre(
                network.endpoint.clone(),
                ring_pk,
                reader_pk,
                reader_sk,
                object_id,
                Some(reader_did_pk),
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
            let secret = resolve_secret(secret, "Secret to encrypt: ")?;
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
        SubCommands::DeriveSignerDid => {
            let signing_key = network.require_signing_key()?;
            let (public_key, did) = derive_signer_did(&signing_key, network.chain_config())?;
            println!("PUBLIC_KEY={}", public_key);
            println!("DID={}", did);
        }
        SubCommands::AddPolicyToChain => {
            let signing_key = network.require_signing_key()?;
            let policy_id = add_policy_to_chain(network.chain_config(), &signing_key).await?;
            println!("POLICY_ID={}", policy_id);
        }
        SubCommands::RegisterObjectToChain {
            policy_id,
            object_id,
            resource,
        } => {
            let signing_key = network.require_signing_key()?;
            register_object_to_chain(
                policy_id,
                object_id,
                resource,
                network.chain_config(),
                &signing_key,
            )
            .await?;
        }
        SubCommands::SetRelationshipOnChain {
            policy_id,
            object_id,
            resource,
            relation,
            reader_did_pk,
            actor_pubkey,
        } => {
            let signing_key = network.require_signing_key()?;
            let did_uri = resolve_relationship_actor_did(reader_did_pk, actor_pubkey)?;
            set_relationship_on_chain(
                policy_id,
                object_id,
                resource,
                relation,
                did_uri,
                network.chain_config(),
                &signing_key,
            )
            .await?;
        }
        SubCommands::RegisterBulletinNamespace { namespace } => {
            let signing_key = network.require_signing_key()?;
            register_bulletin_namespace(namespace, network.chain_config(), &signing_key).await?;
        }
        SubCommands::AddBulletinCollaborator {
            namespace,
            collaborator,
        } => {
            let signing_key = network.require_signing_key()?;
            add_bulletin_collaborator(
                namespace,
                collaborator,
                network.chain_config(),
                &signing_key,
            )
            .await?;
        }
        SubCommands::StartRingReshare {
            ring_id,
            new_peer_node_keys,
            new_threshold,
        } => {
            let signing_key = network.require_signing_key()?;
            start_ring_reshare_by_acp(
                ring_id,
                new_peer_node_keys,
                new_threshold,
                network.chain_config(),
                &signing_key,
            )
            .await?;
        }
        SubCommands::CancelRingReshare { ring_id } => {
            let signing_key = network.require_signing_key()?;
            cancel_ring_reshare_by_acp(ring_id, network.chain_config(), &signing_key).await?;
        }
        SubCommands::SetRingPssInterval {
            ring_id,
            pss_interval,
        } => {
            let signing_key = network.require_signing_key()?;
            set_ring_pss_interval_by_acp(
                ring_id,
                pss_interval,
                network.chain_config(),
                &signing_key,
            )
            .await?;
        }
        SubCommands::ScheduleRingUpgrade {
            ring_id,
            next_version,
            activation_time,
        } => {
            let signing_key = network.require_signing_key()?;
            schedule_ring_upgrade_by_acp(
                ring_id,
                next_version,
                activation_time,
                network.chain_config(),
                &signing_key,
            )
            .await?;
        }
        SubCommands::CancelRingUpgrade { ring_id } => {
            let signing_key = network.require_signing_key()?;
            cancel_ring_upgrade_by_acp(ring_id, network.chain_config(), &signing_key).await?;
        }
        SubCommands::UpdateNodePeerId { node_key, peer_id } => {
            let signing_key = network.require_signing_key()?;
            update_node_peer_id(node_key, peer_id, network.chain_config(), &signing_key).await?;
        }
        SubCommands::TransferNodeController {
            node_key,
            controller_key,
        } => {
            let signing_key = network.require_signing_key()?;
            transfer_node_controller(
                node_key,
                controller_key,
                network.chain_config(),
                &signing_key,
            )
            .await?;
        }
        SubCommands::AddNodeToWhitelist {
            node_key,
            policy_id,
            ring_id,
        } => {
            let target = resolve_whitelist_target(policy_id, ring_id)?;
            let signing_key = network.require_signing_key()?;
            add_node_to_whitelist(node_key, target, network.chain_config(), &signing_key).await?;
        }
        SubCommands::RemoveNodeFromWhitelist {
            node_key,
            policy_id,
            ring_id,
        } => {
            let target = resolve_whitelist_target(policy_id, ring_id)?;
            let signing_key = network.require_signing_key()?;
            remove_node_from_whitelist(node_key, target, network.chain_config(), &signing_key)
                .await?;
        }
        SubCommands::Fund { address } => {
            let signing_key = network.require_signing_key()?;
            fund_with_signer(address, network.chain_config(), &signing_key).await?;
        }
        SubCommands::ReadBulletinPost { id } => {
            read_bulletin_post_with_config(id, BulletinKind::Ring, network.chain_config()).await?;
        }
        SubCommands::ListBulletinPost { namespace } => {
            list_bulletin_posts(namespace, network.chain_config()).await?;
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
            let secret = resolve_secret(secret, "Secret to encrypt: ")?;
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
            let reader_did_pk = require_reader_did_pk(reader_did_pk)?;
            let prepared: PreparedSecret = serde_json::from_str(&prepared_json)
                .map_err(|e| anyhow::anyhow!("Invalid prepared_json: {}", e))?;
            store_prepared_secret(
                network.endpoint.clone(),
                &prepared,
                ring_id,
                policy_id,
                resource,
                permission,
                Some(reader_did_pk),
                with_proof,
                tier,
                timestamp,
            )
            .await?;
        }
        SubCommands::StoreSecret {
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
            let secret = resolve_secret(secret, "Plaintext secret to store: ")?;
            let reader_did_pk = require_reader_did_pk(reader_did_pk)?;
            let derivation_bytes =
                derivation.map(|d| hex::decode(&d).expect("Failed to decode derivation hex"));
            do_store_secret(
                network.endpoint.clone(),
                secret.as_bytes(),
                ring_pk_hex,
                ring_id,
                policy_id,
                resource,
                permission,
                tier,
                timestamp,
                salt,
                Some(reader_did_pk),
                derivation_bytes,
                with_proof,
            )
            .await?;
        }
        SubCommands::Info => {
            query_node_info(network.endpoint.clone()).await?;
        }
        SubCommands::RingState { ring_pk_hex } => {
            let (poly, last_pss) = query_ring_state(network.endpoint.clone(), ring_pk_hex).await?;
            println!("PUBLIC_POLYNOMIAL={}", poly);
            println!("LAST_PSS={}", last_pss);
        }
        SubCommands::GetLatestRing { ring_id } => {
            let (ring_id, ring_pk) = get_latest_ring(ring_id, network.chain_config()).await?;
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
            let signing_key = network.require_signing_key()?;
            let (derivation_id, derived_pk_hex) = post_key_derivation(
                ring_id,
                derivation,
                policy_id,
                resource,
                permission,
                network.chain_config(),
                &signing_key,
            )
            .await?;
            println!("DERIVATION_ID={}", derivation_id);
            println!("DERIVED_PK={}", derived_pk_hex);
        }
        SubCommands::Sign {
            message,
            derivation_id,
            reader_did_pk,
            valid_window_start,
            valid_window_end,
        } => {
            require_valid_window_pair(valid_window_start, valid_window_end)?;
            let reader_did_pk = require_reader_did_pk(reader_did_pk)?;
            let message_bytes = hex::decode(&message)
                .map_err(|e| anyhow::anyhow!("Failed to decode message hex: {}", e))?;
            do_sign(
                network.endpoint.clone(),
                message_bytes,
                derivation_id,
                Some(reader_did_pk),
                valid_window_start,
                valid_window_end,
            )
            .await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests;
