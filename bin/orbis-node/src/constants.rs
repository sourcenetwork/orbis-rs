//! Constants used throughout the orbis-node codebase
//!
//! This module centralizes all configuration constants to make them easier to
//! maintain and understand. Constants are organized by category.

use std::time::Duration;

// ============================================================================
// Cryptographic Constants
// ============================================================================

/// Maximum number of coefficients allowed in a polynomial commitment
///
/// This sets an upper bound on the degree of polynomials used in DKG sessions.
/// A polynomial commitment consists of G1 points, one for each coefficient.
/// This limit prevents DoS attacks via extremely large commitments and ensures
/// reasonable memory usage. The value of 256 is a reasonable upper bound that
/// allows for very large threshold values while still being practical.
pub const MAX_COMMITMENT_COEFFICIENTS: usize = 256;

// ============================================================================
// DKG Session Management Constants
// ============================================================================

/// Maximum number of concurrent DKG sessions allowed per node
///
/// This limit prevents unbounded memory growth and resource exhaustion. Each
/// DKG session maintains state including polynomial commitments, shares, and
/// cryptographic material. The value of 100 allows for substantial concurrent
/// activity while maintaining reasonable resource usage.
pub const MAX_DKG_SESSIONS: usize = 100;

/// Time-to-live for DKG sessions before they are eligible for cleanup
///
/// Sessions older than this duration are automatically cleaned up to prevent
/// memory leaks. This is set to 1 hour (3600 seconds), which provides ample
/// time for DKG protocols to complete while ensuring stale sessions don't
/// accumulate indefinitely.
pub const SESSION_TTL: Duration = Duration::from_secs(3600);

// ============================================================================
// PRE (Proxy Re-Encryption) Constants
// ============================================================================

/// Maximum number of pending PRE responses
///
/// PRE responses are collected asynchronously from multiple nodes. This limit
/// prevents unbounded growth of response storage. The value of 1000 allows for
/// many concurrent PRE operations while maintaining reasonable memory usage.
pub const MAX_PRE_RESPONSES: usize = 1000;

/// Time-to-live for PRE responses before they are cleaned up
///
/// PRE responses older than this duration are automatically cleaned up. This
/// is set to 5 minutes (300 seconds), which provides time for responses to
/// arrive while ensuring stale responses don't accumulate.
pub const PRE_RESPONSE_TTL: Duration = Duration::from_secs(300);

// ============================================================================
// Peer ID Validation Constants
// ============================================================================

/// Maximum allowed length for peer ID strings in bytes
///
/// Peer IDs are used to identify nodes in the network. This limit prevents
/// DoS attacks via oversized peer ID strings. The value of 256 bytes provides
/// ample space for peer IDs (which are typically hex-encoded Ed25519 public
/// keys plus optional socket addresses) while preventing abuse.
pub const MAX_PEER_ID_LENGTH: usize = 256;

/// Minimum length for a valid node ID (hex-encoded Ed25519 public key)
///
/// Ed25519 public keys are 32 bytes, which when hex-encoded become 64
/// characters. This constant is used for validation to ensure node IDs have
/// the correct format. Note: This is the same as EXPECTED_HEX_NODE_ID_LENGTH
/// but kept for clarity in validation logic.
pub const MIN_NODE_ID_LENGTH: usize = 64;

/// Expected length for hex-encoded Ed25519 public key (node ID)
///
/// Ed25519 public keys are 32 bytes, which when hex-encoded become 64
/// characters. This is the standard format for node IDs in the iroh network.
/// This constant is used to validate that peer IDs contain properly formatted
/// node IDs.
pub const EXPECTED_HEX_NODE_ID_LENGTH: usize = 64;

// ============================================================================
// Password Configuration Constants
// ============================================================================

/// Default filename for the password file
///
/// The password file stores the encryption password used for encrypting
/// ring key shares in local storage. This file should have restricted
/// permissions (0600) and be located in a secure directory.
pub const PASSWORD_FILE_NAME: &str = ".orbis_password";

/// Environment variable name for the encryption password
///
/// If set, this environment variable takes precedence over password file
/// but not over the password file (file has highest priority).
/// This allows for secure password injection in containerized environments.
pub const PASSWORD_ENV_VAR: &str = "ORBIS_PASSWORD";
