//! Error types for orbis-node
//!
//! This module centralizes error types used throughout the codebase.

use std::io;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GrpcErrorClassification {
    pub(crate) code: tonic::Code,
    pub(crate) level: tracing::Level,
    pub(crate) record_failure: bool,
}

impl GrpcErrorClassification {
    pub(crate) const fn new(
        code: tonic::Code,
        level: tracing::Level,
        record_failure: bool,
    ) -> Self {
        Self {
            code,
            level,
            record_failure,
        }
    }
}

pub(crate) trait GrpcServiceError: std::fmt::Display {
    const SERVICE: &'static str;

    fn classification(&self) -> GrpcErrorClassification;

    fn record_failure_metric(&self) {}

    fn into_status(self) -> tonic::Status
    where
        Self: Sized,
    {
        let classification = self.classification();
        let message = self.to_string();

        log_grpc_error(
            classification.level,
            Self::SERVICE,
            classification.code,
            &message,
        );

        if classification.record_failure {
            self.record_failure_metric();
        }

        tonic::Status::new(classification.code, message)
    }
}

fn log_grpc_error(level: tracing::Level, service: &str, code: tonic::Code, error: &str) {
    match level {
        tracing::Level::TRACE => {
            tracing::trace!(
                service = service,
                grpc_code = ?code,
                error = error,
                "gRPC request failed"
            );
        }
        tracing::Level::DEBUG => {
            tracing::debug!(
                service = service,
                grpc_code = ?code,
                error = error,
                "gRPC request failed"
            );
        }
        tracing::Level::INFO => {
            tracing::info!(
                service = service,
                grpc_code = ?code,
                error = error,
                "gRPC request failed"
            );
        }
        tracing::Level::WARN => {
            tracing::warn!(
                service = service,
                grpc_code = ?code,
                error = error,
                "gRPC request failed"
            );
        }
        tracing::Level::ERROR => {
            tracing::error!(
                service = service,
                grpc_code = ?code,
                error = error,
                "gRPC request failed"
            );
        }
    }
}

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
    /// Failed to read from stdin
    StdinError(io::Error),
    /// Password is empty
    EmptyPassword,
    /// Failed to convert bytes to UTF-8 string
    Utf8Error(std::string::FromUtf8Error),
    /// Failed to generate random bytes
    RandomGenerationError(String),
    /// Failed to store or retrieve from local storage
    StorageError(String),
}

impl std::fmt::Display for PasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasswordError::StdinError(e) => write!(f, "Failed to read password from stdin: {}", e),
            PasswordError::EmptyPassword => write!(f, "Password cannot be empty"),
            PasswordError::Utf8Error(e) => write!(f, "Failed to convert to UTF-8: {}", e),
            PasswordError::RandomGenerationError(e) => {
                write!(f, "Failed to generate random bytes: {}", e)
            }
            PasswordError::StorageError(e) => write!(f, "Storage error: {}", e),
        }
    }
}

impl std::error::Error for PasswordError {}
