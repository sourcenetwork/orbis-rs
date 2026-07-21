use crate::constants::{
    PASSWORD_ENV_VAR, PASSWORD_FILE_NAME, SECRET_KEY_ENV_VAR, SECRET_KEY_FILE_NAME,
};
use crate::error::PasswordError;
use bulletin::{
    error::BulletinError,
    r#trait::{Bulletin, BulletinKind, BulletinWriteKind, NodeInfo},
};
use clap::{Parser, ValueEnum};
use common::blockchain::{ChainConfig, TxSigner};
use local_storage::{
    r#trait::{LocalStorage, LocalStorageKeys},
    LocalStorageImpl,
};
use network::Network;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::{env, fs};
use zeroize::Zeroizing;

#[derive(Parser, Debug, Clone)]
#[command(name = "orbis-node")]
#[command(about = "Orbis DkgService gRPC server")]
pub struct Args {
    /// Address to bind the server to
    #[arg(short, long, default_value = "[::1]:50051")]
    pub addr: String,
    /// Log level for tracing
    #[arg(short, long, default_value = "info")]
    pub log_level: LogLevel,
    /// AuthZ GRPC (chain GRPC endpoint probably)
    #[arg(short = 'z', long, default_value = "http://localhost:9090")]
    pub authz_grpc: Option<String>,
    /// Bulletin GRPC (chain GRPC endpoint probably)
    #[arg(short = 'b', long, default_value = "http://localhost:9090")]
    pub bulletin_grpc: Option<String>,
    /// Chain RPC URL (Tendermint RPC endpoint)
    #[arg(long, default_value = "http://localhost:26657")]
    pub chain_rpc: Option<String>,
    /// Chain REST URL (Cosmos REST API endpoint)
    #[arg(long, default_value = "http://localhost:1317")]
    pub chain_rest: Option<String>,
    /// denomination of chain gas tokens
    #[arg(long)]
    pub denom: Option<String>,
    /// Safety multiplier applied to simulated chain gas before broadcasting transactions.
    /// Increase this when concurrent writers can change state between simulation and delivery.
    #[arg(long)]
    pub chain_gas_multiplier: Option<f64>,
    /// Address for Prometheus metrics HTTP server (e.g., "0.0.0.0:9090")
    #[arg(short = 'm', long)]
    pub metrics_addr: Option<String>,
    /// Loki server URL for log aggregation (e.g., "http://localhost:3100")
    #[arg(long)]
    pub loki_url: Option<String>,
    /// Base directory for runtime files such as databases and the public key
    #[arg(long)]
    pub runtime_base_path: Option<PathBuf>,
    /// Interval between when node will check if PSS ceremony is needed.
    /// Set to 0 to disable automatic resharing. Defaults to 86400 (24 hours).
    #[arg(long, default_value_t = crate::constants::DEFAULT_RESHARE_INTERVAL_SECS)]
    pub reshare_interval_secs: u64,
    /// Hex-encoded public key of the external controller allowed to update node info.
    #[arg(long)]
    pub node_controller_key: String,
    /// Override the peer ID registered in node info. Defaults to this node's local iroh peer ID.
    #[arg(long)]
    pub node_peer_id: Option<String>,
    /// Policy ID this node initially allows. Ignored if node info already exists.
    #[arg(long = "node-whitelisted-policy-id")]
    pub node_whitelisted_policy_ids: Vec<String>,
    /// Ring ID this node initially allows. Ignored if node info already exists.
    #[arg(long = "node-whitelisted-ring-id")]
    pub node_whitelisted_ring_ids: Vec<String>,
    /// Maximum in-flight gRPC requests per client connection.
    #[arg(
        long,
        default_value_t = crate::constants::GRPC_CONCURRENCY_LIMIT_PER_CONNECTION
    )]
    pub grpc_concurrency_limit_per_connection: usize,
    /// Maximum concurrent HTTP/2 streams per gRPC client connection.
    #[arg(
        long,
        default_value_t = crate::constants::GRPC_MAX_CONCURRENT_STREAMS
    )]
    pub grpc_max_concurrent_streams: u32,
}

/// Ensure the node has a matching x/orbis NodeInfo record before serving traffic.
pub async fn ensure_node_info(
    bulletin: &(dyn Bulletin + Send + Sync),
    node_key: &str,
    network: &dyn Network,
    args: &Args,
) -> Result<(), Box<dyn std::error::Error>> {
    let controller_key = args.node_controller_key.trim();
    if controller_key.is_empty() {
        return Err("--node-controller-key is required to create or verify node info".into());
    }

    let derived_peer_id = hex::encode(network.local_peer_id().as_bytes());
    let peer_id = args
        .node_peer_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&derived_peer_id)
        .to_string();

    let existing = match bulletin
        .read(node_key.to_string(), BulletinKind::NodeInfo)
        .await
    {
        Ok(post) => Some(NodeInfo::try_from(post)?),
        Err(BulletinError::NotFound { .. }) => None,
        Err(err) => return Err(err.into()),
    };

    if let Some(existing) = existing {
        if existing.peer_id != peer_id {
            return Err(format!(
                "existing node info for node_key {} has peer_id {}, expected {}",
                node_key, existing.peer_id, peer_id
            )
            .into());
        }
        if existing.controller_key != controller_key {
            return Err(format!(
                "existing node info for node_key {} has controller_key {}, expected {}",
                node_key, existing.controller_key, controller_key
            )
            .into());
        }

        if !args.node_whitelisted_policy_ids.is_empty()
            || !args.node_whitelisted_ring_ids.is_empty()
        {
            tracing::warn!(
                node_key = %node_key,
                policy_id_count = args.node_whitelisted_policy_ids.len(),
                ring_id_count = args.node_whitelisted_ring_ids.len(),
                "Existing node info found; ignoring startup whitelist flags because controller-owned updates must use UpdateNodeInfo"
            );
        }
        tracing::info!(
            node_key = %node_key,
            peer_id = %peer_id,
            "Existing node info matches local identity"
        );
        return Ok(());
    }

    let node_info = build_node_info_from_args(peer_id.clone(), controller_key, args);
    let payload: Vec<u8> = node_info.try_into()?;
    let created_node_key = bulletin.post(BulletinWriteKind::NodeInfo, payload).await?;
    if created_node_key != node_key {
        return Err(format!(
            "bulletin created node info under key {}, expected {}",
            created_node_key, node_key
        )
        .into());
    }
    tracing::info!(
        node_key = %node_key,
        peer_id = %peer_id,
        "Created node info"
    );
    Ok(())
}

pub fn build_node_info_from_args(peer_id: String, controller_key: &str, args: &Args) -> NodeInfo {
    NodeInfo {
        peer_id,
        controller_key: controller_key.to_string(),
        whitelisted_policy_ids: args
            .node_whitelisted_policy_ids
            .iter()
            .map(|policy_id| policy_id.trim().to_string())
            .filter(|policy_id| !policy_id.is_empty())
            .collect(),
        whitelisted_ring_ids: args
            .node_whitelisted_ring_ids
            .iter()
            .map(|ring_id| ring_id.trim().to_string())
            .filter(|ring_id| !ring_id.is_empty())
            .collect(),
    }
}

// ============================================================================
// Network key Retrieval Functions
// ============================================================================

/// Minimum length for passphrase-based secrets (non-hex input)
const MIN_SECRET_LENGTH: usize = 16;

/// Derive a 32-byte secret key from any string input.
///
/// If the input is exactly 64 hex characters (32 bytes), it's decoded directly.
/// Otherwise, the input is hashed with SHA-256 to derive the key.
/// This allows users to use either raw hex keys or passphrases.
///
/// # Errors
/// Returns an error if non-hex input is shorter than 16 characters.
pub fn derive_secret_key_bytes(input: &str) -> Result<[u8; 32], String> {
    let trimmed = input.trim();

    // Check if it's valid 64-char hex (32 bytes)
    if trimmed.len() == 64 {
        if let Ok(bytes) = hex::decode(trimmed) {
            if let Ok(arr) = bytes.try_into() {
                return Ok(arr);
            }
        }
    }

    // For non-hex input, enforce minimum length
    if trimmed.len() < MIN_SECRET_LENGTH {
        return Err(format!(
            "Secret must be at least {} characters (got {}). Use a longer passphrase or a 64-character hex string.",
            MIN_SECRET_LENGTH,
            trimmed.len()
        ));
    }

    // Hash the input with SHA-256
    let hash = Sha256::digest(trimmed.as_bytes());
    Ok(hash.into())
}

pub fn get_network_key_secret(
    custom_file_path: Option<PathBuf>,
    local_storage: LocalStorageImpl,
) -> Result<String, PasswordError> {
    // Check secret_node_key file first
    let file_path =
        custom_file_path.unwrap_or_else(|| get_file_path(SECRET_KEY_FILE_NAME.to_string()));
    if file_path.exists() {
        if let Ok(content) = fs::read_to_string(&file_path).inspect_err(|error| {
            tracing::warn!(
                path = %file_path.display(),
                error = %error,
                "Could not read password file"
            );
        }) {
            let secret = content.trim().to_string();
            if secret.is_empty() {
                tracing::warn!("secret file exists but is empty, checking environment variable");
            } else {
                tracing::info!(path = %file_path.display(), "secret network key loaded from file");
                return Ok(secret);
            }
        }
    }
    // SECURITY: env vars are readable by same-uid processes via /proc/<pid>/environ
    // and by privileged users via `ps auxe`. Prefer the key file or local storage.
    // See SECRET_KEY_ENV_VAR doc comment for safe alternatives.
    if let Ok(secret_node_key) = env::var(SECRET_KEY_ENV_VAR) {
        let secret_node_key = secret_node_key.trim().to_string();
        if !secret_node_key.is_empty() {
            tracing::info!(
                env_var = SECRET_KEY_ENV_VAR,
                "secret loaded from environment variable"
            );
            return Ok(secret_node_key);
        }
        tracing::warn!(
            env_var = SECRET_KEY_ENV_VAR,
            "Environment variable is set but empty, prompting for password"
        );
    }

    // Get secret from local storage
    if let Some(secret_node_key) = local_storage
        .get_encrypted(LocalStorageKeys::NodeSecretKey)
        .inspect_err(|error| {
            tracing::warn!(
                error = %error,
                "Could not get secret from local storage creating new one"
            );
        })
        .ok()
        .flatten()
    {
        tracing::info!("secret network key loaded from local storage");
        return String::from_utf8(secret_node_key.to_vec()).map_err(PasswordError::Utf8Error);
    }
    // None exist - generate new secret key
    let mut key_bytes = [0u8; 32];
    getrandom::getrandom(&mut key_bytes)
        .map_err(|e| PasswordError::RandomGenerationError(e.to_string()))?;
    let secret_hex = hex::encode(key_bytes);

    // Store in local storage for future use
    local_storage
        .set_encrypted(
            LocalStorageKeys::NodeSecretKey,
            Zeroizing::new(secret_hex.as_bytes().to_vec()),
        )
        .map_err(|e| PasswordError::StorageError(e.to_string()))?;

    Ok(secret_hex)
}

// ============================================================================
// Password Retrieval Functions
// ============================================================================

/// Get the default password file path
///
/// Returns the path to the password file in the user's home directory.
/// Falls back to current directory if home directory cannot be determined.
pub fn get_file_path(file_name: String) -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(file_name)
}

/// Retrieve the encryption password following precedence order:
/// 1. Password file (highest priority)
/// 2. Environment variable
/// 3. Interactive prompt (lowest priority)
///
/// This is used for encrypting ring key shares in local storage.
///
/// # Arguments
/// * `custom_file_path` - Optional custom path to password file. If None, uses default location.
///
/// # Returns
/// A string of password on success, or an error
pub fn get_password(custom_file_path: Option<PathBuf>) -> Result<String, PasswordError> {
    // 1. Check password file first
    let file_path =
        custom_file_path.unwrap_or_else(|| get_file_path(PASSWORD_FILE_NAME.to_string()));
    if file_path.exists() {
        if let Ok(content) = fs::read_to_string(&file_path).inspect_err(|error| {
            tracing::warn!(
                path = %file_path.display(),
                error = %error,
                "Could not read password file"
            );
        }) {
            let password = content.trim().to_string();
            if password.is_empty() {
                tracing::warn!("Password file exists but is empty, checking environment variable");
            } else {
                tracing::info!(path = %file_path.display(), "Password loaded from file");
                return Ok(password);
            }
        }
    }

    // 2. Check environment variable.
    // SECURITY: env vars are readable by same-uid processes via /proc/<pid>/environ
    // and by privileged users via `ps auxe`. Prefer the password file (0600).
    // See PASSWORD_ENV_VAR doc comment for safe alternatives.
    if let Ok(password) = env::var(PASSWORD_ENV_VAR) {
        let password = password.trim().to_string();
        if !password.is_empty() {
            tracing::info!(
                env_var = PASSWORD_ENV_VAR,
                "Password loaded from environment variable"
            );
            return Ok(password);
        }
        tracing::warn!(
            env_var = PASSWORD_ENV_VAR,
            "Environment variable is set but empty, prompting for password"
        );
    }

    // 3. Prompt for password interactively
    prompt_for_password()
}

/// Prompt the user for a password interactively
///
/// This function reads a password from stdin with echo disabled for security.
///
/// # Returns
/// A string of password on success
fn prompt_for_password() -> Result<String, PasswordError> {
    let password = rpassword::prompt_password("Enter encryption password for ring key share: ")
        .map_err(PasswordError::StdinError)?;

    let password = password.trim().to_string();

    if password.is_empty() {
        return Err(PasswordError::EmptyPassword);
    }

    tracing::info!("Password entered interactively");
    Ok(password)
}

// ============================================================================
// Log Level Configuration
// ============================================================================

/// Log level for tracing subscriber configuration
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

impl From<LogLevel> for tracing::Level {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Trace => tracing::Level::TRACE,
            LogLevel::Debug => tracing::Level::DEBUG,
            LogLevel::Info => tracing::Level::INFO,
            LogLevel::Warn => tracing::Level::WARN,
            LogLevel::Error => tracing::Level::ERROR,
        }
    }
}

pub fn resolve_runtime_base_path(configured_path: Option<&Path>) -> PathBuf {
    configured_path.map(Path::to_path_buf).unwrap_or_else(|| {
        project_root::get_project_root().unwrap_or_else(|_| {
            let data_dir = PathBuf::from("/data");
            if data_dir.exists() {
                data_dir
            } else {
                env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
            }
        })
    })
}

fn local_storage_backend_name() -> String {
    let storage_name = LocalStorageImpl::name();
    storage_name
        .rsplit('/')
        .next()
        .unwrap_or(&storage_name)
        .to_string()
}

pub fn db_path(runtime_base_path: &Path, name: &str) -> String {
    let db_dir = runtime_base_path.join("dbs");
    // Create the dbs directory if it doesn't exist
    let _ = std::fs::create_dir_all(&db_dir).inspect_err(|error| {
        tracing::warn!(
            path = %db_dir.display(),
            error = %error,
            "Could not create database directory"
        );
    });
    let backend = local_storage_backend_name();
    db_dir
        .join(format!("{}.{}", name, backend))
        .display()
        .to_string()
}

pub fn create_and_store_node_key(
    local_storage: LocalStorageImpl,
    config: ChainConfig,
    runtime_base_path: &Path,
) -> Result<TxSigner, String> {
    fs::create_dir_all(runtime_base_path).map_err(|error| {
        format!(
            "Failed to create runtime base directory {}: {}",
            runtime_base_path.display(),
            error
        )
    })?;
    let public_key_path = runtime_base_path.join("public_key.txt");

    // Check if a signing key exists in DB
    let hex_key = match local_storage.get_encrypted(LocalStorageKeys::NodeSigningKey) {
        Ok(Some(key_bytes)) => {
            // Key exists, use it
            let hex_key = String::from_utf8(key_bytes.to_vec())
                .map_err(|e| format!("Failed to parse stored key as UTF-8: {}", e))?;
            tracing::info!("Existing signing key loaded from storage");
            hex_key
        }
        Ok(None) => {
            // No key exists, create one.
            //
            // In integration-test builds, ORBIS_SIGNING_KEY may supply a deterministic
            // private key hex so the public key is known before the chain starts (needed
            // for genesis injection).  The env var is absent in production.
            #[cfg(feature = "integration-test")]
            if let Ok(env_hex) = std::env::var("ORBIS_SIGNING_KEY") {
                let env_hex = env_hex.trim().to_string();
                if !env_hex.is_empty() {
                    tracing::info!("Using ORBIS_SIGNING_KEY for deterministic signing key");
                    local_storage
                        .set_encrypted(
                            LocalStorageKeys::NodeSigningKey,
                            Zeroizing::new(env_hex.as_bytes().to_vec()),
                        )
                        .map_err(|e| format!("Failed to store signing key: {}", e))?;
                    let signer = TxSigner::from_hex_key(&env_hex, config).map_err(|e| {
                        format!("Failed to create signer from ORBIS_SIGNING_KEY: {}", e)
                    })?;
                    let public_address = signer.address();
                    tracing::info!(address = %public_address, "Signing key ready");
                    fs::write(&public_key_path, &public_address)
                        .map_err(|e| format!("Failed to write public key to file: {}", e))?;
                    return Ok(signer);
                }
            }

            tracing::info!("No signing key found, generating new one");
            let mut key_bytes = [0u8; 32];
            getrandom::getrandom(&mut key_bytes)
                .map_err(|e| format!("Failed to generate random bytes: {}", e))?;
            let hex_key = hex::encode(key_bytes);

            // Store the key encrypted
            local_storage
                .set_encrypted(
                    LocalStorageKeys::NodeSigningKey,
                    Zeroizing::new(hex_key.as_bytes().to_vec()),
                )
                .map_err(|e| format!("Failed to store signing key: {}", e))?;
            hex_key
        }
        Err(e) => {
            return Err(format!(
                "Failed to read signing key from storage: {}. \
                 Refusing to generate a new key to avoid overwriting an existing identity. \
                 Check storage health and retry.",
                e
            ));
        }
    };

    let signer = TxSigner::from_hex_key(&hex_key, config)
        .map_err(|e| format!("Failed to create signer: {}", e))?;

    let public_address = signer.address();
    tracing::info!(address = %public_address, "Signing key ready");

    fs::write(&public_key_path, &public_address)
        .map_err(|e| format!("Failed to write public key to file: {}", e))?;

    tracing::info!(path = %public_key_path.display(), "Public key written to file");

    Ok(signer)
}

/// Retrieve the node signing key from storage and create a TxSigner.
///
/// This function loads the stored secp256k1 signing key and returns a TxSigner
/// that can be used with `SourceHubBulletin::with_signer`.
///
/// # Arguments
/// * `local_storage` - The local storage implementation to read from
/// * `config` - The chain configuration for the signer
///
/// # Returns
/// A TxSigner on success, or an error if the key doesn't exist or is invalid
pub fn get_node_signer(
    local_storage: LocalStorageImpl,
    config: ChainConfig,
) -> Result<TxSigner, String> {
    let key_bytes = local_storage
        .get_encrypted(LocalStorageKeys::NodeSigningKey)
        .map_err(|e| format!("Failed to read signing key from storage: {}", e))?
        .ok_or_else(|| {
            "No signing key found in storage. Run create_and_store_node_key first.".to_string()
        })?;

    let hex_key = String::from_utf8(key_bytes.to_vec())
        .map_err(|e| format!("Failed to parse stored key as UTF-8: {}", e))?;

    TxSigner::from_hex_key(&hex_key, config).map_err(|e| format!("Failed to create signer: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_runtime_base_path_argument() {
        let args = Args::try_parse_from([
            "orbis-node",
            "--node-controller-key",
            "controller-key",
            "--runtime-base-path",
            "custom/runtime",
        ])
        .expect("parse arguments");

        assert_eq!(
            args.runtime_base_path,
            Some(PathBuf::from("custom/runtime"))
        );
    }

    #[test]
    fn configured_runtime_base_path_overrides_fallback_detection() {
        let configured_path = PathBuf::from("custom/runtime");

        assert_eq!(
            resolve_runtime_base_path(Some(&configured_path)),
            configured_path
        );
    }

    #[test]
    fn db_path_uses_runtime_base_path_and_creates_database_directory() {
        let temp_dir = tempfile::tempdir().expect("create temporary directory");
        let runtime_base_path = temp_dir.path().join("runtime");

        let path = db_path(&runtime_base_path, "orbis");

        assert_eq!(
            PathBuf::from(path),
            runtime_base_path.join("dbs").join("orbis.redb")
        );
        assert_eq!(local_storage_backend_name(), "redb");
        assert!(runtime_base_path.join("dbs").is_dir());
    }
}
