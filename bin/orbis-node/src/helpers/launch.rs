use crate::constants::{
    PASSWORD_ENV_VAR, PASSWORD_FILE_NAME, SECRET_KEY_ENV_VAR, SECRET_KEY_FILE_NAME,
};
use crate::error::PasswordError;
use clap::{Parser, ValueEnum};
use common::blockchain::{ChainConfig, TxSigner};
use local_storage::{
    r#trait::{LocalStorage, LocalStorageKeys},
    LocalStorageImpl,
};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::{env, fs};

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
        match fs::read_to_string(&file_path) {
            Ok(content) => {
                let secret = content.trim().to_string();
                if secret.is_empty() {
                    // File exists but is empty, continue to next source
                    tracing::warn!(
                        "secret file exists but is empty, checking environment variable"
                    );
                } else {
                    tracing::info!(path = %file_path.display(), "secret network key loaded from file");
                    return Ok(secret);
                }
            }
            Err(e) => {
                // Log warning but continue to next source
                tracing::warn!(
                    path = %file_path.display(),
                    error = %e,
                    "Could not read password file"
                );
            }
        }
    }
    // Check environment variable
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
    match local_storage.get_encrypted(LocalStorageKeys::NodeSecretKey) {
        Ok(secret_node_key_option) => {
            if let Some(secret_node_key) = secret_node_key_option {
                tracing::info!("secret network key loaded from local storage");
                return String::from_utf8(secret_node_key).map_err(PasswordError::Utf8Error);
            }
        }
        Err(e) => {
            // Log warning but continue to next source
            tracing::warn!(
                error = %e,
                "Could not get secret from local storage creating new one"
            );
        }
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
            secret_hex.as_bytes().to_vec(),
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
        match fs::read_to_string(&file_path) {
            Ok(content) => {
                let password = content.trim().to_string();
                if password.is_empty() {
                    // File exists but is empty, continue to next source
                    tracing::warn!(
                        "Password file exists but is empty, checking environment variable"
                    );
                } else {
                    tracing::info!(path = %file_path.display(), "Password loaded from file");
                    return Ok(password);
                }
            }
            Err(e) => {
                // Log warning but continue to next source
                tracing::warn!(
                    path = %file_path.display(),
                    error = %e,
                    "Could not read password file"
                );
            }
        }
    }

    // 2. Check environment variable
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

pub fn db_path(name: &str) -> String {
    // Try to get project root (works in dev environment), fall back to /data for Docker
    let base_path = match project_root::get_project_root() {
        Ok(root) => root,
        Err(_) => {
            // In Docker or other environments without Cargo.toml, use /data or current dir
            let data_dir = std::path::PathBuf::from("/data");
            if data_dir.exists() {
                data_dir
            } else {
                std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
            }
        }
    };
    let db_dir = base_path.join("dbs");
    // Create the dbs directory if it doesn't exist
    std::fs::create_dir_all(&db_dir).ok();
    format!("{}/{}.redb", db_dir.display(), name)
}

pub fn create_and_store_node_key(
    local_storage: LocalStorageImpl,
    config: ChainConfig,
) -> Result<TxSigner, String> {
    // Write public key to file - try project root first, fall back to /data or current dir
    let base_path = match project_root::get_project_root() {
        Ok(root) => root,
        Err(_) => {
            // In Docker or other environments without Cargo.toml, use /data or current dir
            let data_dir = std::path::PathBuf::from("/data");
            if data_dir.exists() {
                data_dir
            } else {
                std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
            }
        }
    };
    let public_key_path = base_path.join("public_key.txt");

    // Check if a signing key exists in DB
    let hex_key = match local_storage.get_encrypted(LocalStorageKeys::NodeSigningKey) {
        Ok(Some(key_bytes)) => {
            // Key exists, use it
            let hex_key = String::from_utf8(key_bytes)
                .map_err(|e| format!("Failed to parse stored key as UTF-8: {}", e))?;
            tracing::info!("Existing signing key loaded from storage");
            hex_key
        }
        Ok(None) => {
            // No key exists, create one
            tracing::info!("No signing key found, generating new one");
            let mut key_bytes = [0u8; 32];
            getrandom::getrandom(&mut key_bytes)
                .map_err(|e| format!("Failed to generate random bytes: {}", e))?;
            let hex_key = hex::encode(key_bytes);

            // Store the key encrypted
            local_storage
                .set_encrypted(
                    LocalStorageKeys::NodeSigningKey,
                    hex_key.as_bytes().to_vec(),
                )
                .map_err(|e| format!("Failed to store signing key: {}", e))?;
            hex_key
        }
        Err(e) => {
            tracing::warn!(error = %e, "Error reading signing key from storage, generating new one");
            let mut key_bytes = [0u8; 32];
            getrandom::getrandom(&mut key_bytes)
                .map_err(|e| format!("Failed to generate random bytes: {}", e))?;
            let hex_key = hex::encode(key_bytes);

            // Store the key encrypted
            local_storage
                .set_encrypted(
                    LocalStorageKeys::NodeSigningKey,
                    hex_key.as_bytes().to_vec(),
                )
                .map_err(|e| format!("Failed to store signing key: {}", e))?;
            hex_key
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

    let hex_key = String::from_utf8(key_bytes)
        .map_err(|e| format!("Failed to parse stored key as UTF-8: {}", e))?;

    TxSigner::from_hex_key(&hex_key, config).map_err(|e| format!("Failed to create signer: {}", e))
}
