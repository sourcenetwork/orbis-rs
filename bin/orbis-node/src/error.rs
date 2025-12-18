//! Error types for orbis-node
//!
//! This module centralizes error types used throughout the codebase.

use std::io;
use std::path::PathBuf;

// ============================================================================
// Peer ID Validation Errors
// ============================================================================

/// Error type for peer ID validation
#[derive(Debug, Clone)]
pub enum PeerIdValidationError {
    /// Peer ID string is empty
    Empty,
    /// Peer ID string exceeds maximum length
    TooLong { length: usize, max: usize },
    /// Invalid format - missing or malformed node ID
    InvalidFormat(String),
    /// Invalid socket address in peer ID
    InvalidSocketAddr(String),
    /// Node ID part has incorrect length
    InvalidNodeIdLength { length: usize, expected: usize },
    /// Node ID contains invalid characters
    InvalidCharacters(String),
}

impl std::fmt::Display for PeerIdValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerIdValidationError::Empty => write!(f, "Peer ID cannot be empty"),
            PeerIdValidationError::TooLong { length, max } => {
                write!(f, "Peer ID too long: {} bytes, maximum is {}", length, max)
            }
            PeerIdValidationError::InvalidFormat(msg) => {
                write!(f, "Invalid peer ID format: {}", msg)
            }
            PeerIdValidationError::InvalidSocketAddr(msg) => {
                write!(f, "Invalid socket address in peer ID: {}", msg)
            }
            PeerIdValidationError::InvalidNodeIdLength { length, expected } => {
                write!(
                    f,
                    "Invalid node ID length: {} chars, expected {}",
                    length, expected
                )
            }
            PeerIdValidationError::InvalidCharacters(msg) => {
                write!(f, "Node ID contains invalid characters: {}", msg)
            }
        }
    }
}

impl std::error::Error for PeerIdValidationError {}

// ============================================================================
// Password Errors
// ============================================================================

/// Error type for password retrieval
#[derive(Debug)]
pub enum PasswordError {
    /// Failed to read password file
    FileReadError(io::Error),
    /// Failed to read from stdin
    StdinError(io::Error),
    /// Password is empty
    EmptyPassword,
    /// User cancelled the password prompt
    UserCancelled,
}

impl std::fmt::Display for PasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasswordError::FileReadError(e) => write!(f, "Failed to read password file: {}", e),
            PasswordError::StdinError(e) => write!(f, "Failed to read password from stdin: {}", e),
            PasswordError::EmptyPassword => write!(f, "Password cannot be empty"),
            PasswordError::UserCancelled => write!(f, "Password entry cancelled by user"),
        }
    }
}

impl std::error::Error for PasswordError {}

// ============================================================================
// Password Source
// ============================================================================

/// Source of the retrieved password
#[derive(Debug, Clone, PartialEq)]
pub enum PasswordSource {
    /// Password was read from a file
    File(PathBuf),
    /// Password was read from environment variable
    Environment,
    /// Password was entered interactively by the user
    Interactive,
}
