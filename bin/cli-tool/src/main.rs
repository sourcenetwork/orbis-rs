mod commands;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
pub use commands::{
    derive_signer_did, do_dkg, do_encrypt_secret, do_pre, do_pre_and_save, do_retrieve_pre,
    do_sign, do_store_secret, prepare_secret, query_node_info, query_pet_ring_state,
    query_ring_state, reader_did_from_seed, store_prepared_secret, PendingPreRetrieval,
    PreparedSecret, SignResult,
};

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

    /// Chain ID of the target Vera network
    #[arg(
        long,
        env = "ORBIS_CHAIN_ID",
        default_value = "vera-localnet",
        global = true
    )]
    chain_id: String,

    /// Hex-encoded secp256k1 private key whose public key and did:key
    /// `derive-signer-did` prints.
    #[arg(long, env = "ORBIS_SIGNING_KEY", global = true, hide_env_values = true)]
    signing_key: Option<String>,
}

impl NetworkArgs {
    fn require_signing_key(&self) -> Result<String> {
        self.signing_key.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "No signing key configured. Pass --signing-key <hex> or set ORBIS_SIGNING_KEY."
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
    /// Start a Distributed Key Generation session
    Dkg {
        /// Blank ring entry targeted by this DKG (create one with `vera-admin ring`)
        #[clap(long)]
        ring_id: String,
    },

    /// Start a Proxy Re-Encryption session
    Pre {
        /// Ring public key (from DKG) in hex format
        #[clap(long)]
        ring_pk: String,

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

        /// Don't decrypt now — print a JSON blob (reader key + raw response)
        /// that `retrieve-pre` can decrypt later, independently of this process.
        #[clap(long)]
        save_only: bool,
    },
    /// Decrypt a PRE response saved earlier via `pre --save-only`
    RetrievePre {
        /// The JSON printed by `pre --save-only`
        #[clap(long)]
        pending_json: String,
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

    /// Derive the secp256k1 public key and did:key for --signing-key. Pure local
    /// computation, no network calls. Vera resolves the ACP actor of a request
    /// signed with this key from this same derivation, so this names the DID
    /// that needs a relation granted before such a request is authorized.
    DeriveSignerDid,
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
        /// Prepared secret JSON (from prepare-secret command). Carries the policy
        /// fields the encryption proof is bound to.
        #[clap(long)]
        prepared_json: String,
        /// Ring id of ring to encrypt to
        #[clap(long)]
        ring_id: String,
        /// A private key to generate a reader did
        #[clap(long, env = "ORBIS_READER_DID_PK", hide_env_values = true)]
        reader_did_pk: Option<String>,
        /// Request a proof
        #[clap(long)]
        with_proof: bool,
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
    /// Query the local PET checking-key ring state (public polynomial + last
    /// RefreshPet/ResharePet timestamp) from a node
    PetRingState {
        /// Ring ID (the PET key has no public key of its own to query by)
        #[clap(long)]
        ring_id: String,
    },
    /// Start a threshold Sign session (Policy pathway)
    Sign {
        /// Message to sign (hex encoded)
        #[clap(long)]
        message: String,
        /// Derivation ID of a key derivation registered with Vera
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

/// Decode an optional `--derivation` hex string into bytes.
fn parse_derivation_hex(derivation: Option<String>) -> Result<Option<Vec<u8>>> {
    derivation
        .map(|d| hex::decode(&d).context("--derivation must be valid hex"))
        .transpose()
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

/// `--valid-window-start`/`--valid-window-end` must be given together or not at all.
fn require_valid_window_pair(start: Option<u64>, end: Option<u64>) -> Result<()> {
    match (start, end) {
        (Some(_), None) | (None, Some(_)) => {
            anyhow::bail!("--valid-window-start and --valid-window-end must both be provided");
        }
        _ => Ok(()),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let network = cli.network.clone();

    match cli.command {
        SubCommands::Dkg { ring_id } => {
            do_dkg(network.endpoint.clone(), ring_id).await?;
        }
        SubCommands::Pre {
            ring_pk,
            object_id,
            reader_did_pk,
            derivation,
            salt,
            valid_window_start,
            valid_window_end,
            save_only,
        } => {
            require_valid_window_pair(valid_window_start, valid_window_end)?;
            let reader_did_pk = require_reader_did_pk(reader_did_pk)?;
            let derivation_bytes = parse_derivation_hex(derivation)?;
            if save_only {
                let pending = do_pre_and_save(
                    network.endpoint.clone(),
                    network.chain_id.clone(),
                    ring_pk,
                    object_id,
                    Some(reader_did_pk),
                    derivation_bytes,
                    salt,
                    valid_window_start,
                    valid_window_end,
                )
                .await?;
                println!(
                    "PENDING_PRE_RETRIEVAL={}",
                    serde_json::to_string(&pending).map_err(|e| anyhow::anyhow!(
                        "Failed to serialize pending retrieval: {}",
                        e
                    ))?
                );
            } else {
                do_pre(
                    network.endpoint.clone(),
                    network.chain_id.clone(),
                    ring_pk,
                    object_id,
                    Some(reader_did_pk),
                    derivation_bytes,
                    salt,
                    valid_window_start,
                    valid_window_end,
                )
                .await?;
            }
        }
        SubCommands::RetrievePre { pending_json } => {
            do_retrieve_pre(pending_json).await?;
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
            let derivation_bytes = parse_derivation_hex(derivation)?;
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
        SubCommands::DeriveSignerDid => {
            let signing_key = network.require_signing_key()?;
            let (public_key, did) = derive_signer_did(&signing_key)?;
            println!("PUBLIC_KEY={}", public_key);
            println!("DID={}", did);
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
            let derivation_bytes = parse_derivation_hex(derivation)?;
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
                None,
            )?;
            let json = serde_json::to_string_pretty(&prepared)?;
            println!("Prepared Secret (save this for store-prepared-secret):");
            println!("{}", "=".repeat(60));
            println!("{}", json);
        }
        SubCommands::StorePreparedSecret {
            prepared_json,
            ring_id,
            reader_did_pk,
            with_proof,
        } => {
            let reader_did_pk = require_reader_did_pk(reader_did_pk)?;
            let prepared: PreparedSecret = serde_json::from_str(&prepared_json)
                .map_err(|e| anyhow::anyhow!("Invalid prepared_json: {}", e))?;
            store_prepared_secret(
                network.endpoint.clone(),
                &prepared,
                ring_id,
                Some(reader_did_pk),
                with_proof,
                None,
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
            let derivation_bytes = parse_derivation_hex(derivation)?;
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
        SubCommands::PetRingState { ring_id } => {
            let (poly, last_pss) = query_pet_ring_state(network.endpoint.clone(), ring_id).await?;
            println!("PUBLIC_POLYNOMIAL={}", poly);
            println!("LAST_PSS={}", last_pss);
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
