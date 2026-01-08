use crate::constants::{
    PASSWORD_ENV_VAR, PASSWORD_FILE_NAME, SECRET_KEY_ENV_VAR, SECRET_KEY_FILE_NAME,
};
use crate::error::PasswordError;
use clap::{Parser, ValueEnum};
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
                return Ok(String::from_utf8(secret_node_key)
                    .expect("Issue stringifying secret key from local storage"));
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
    getrandom::getrandom(&mut key_bytes).expect("Failed to generate random bytes");
    let secret_hex = hex::encode(key_bytes);

    // Store in local storage for future use
    local_storage
        .set_encrypted(
            LocalStorageKeys::NodeSecretKey,
            secret_hex.as_bytes().to_vec(),
        )
        .expect("Issue storing secret key in local storage");

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
    let project_root = project_root::get_project_root().unwrap();
    format!("{}/dbs/{}.redb", project_root.display(), name)
}
