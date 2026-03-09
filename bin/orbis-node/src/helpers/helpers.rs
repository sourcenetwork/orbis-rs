//! General helper functions for orbis-node
//!
//! This module provides utility functions used across the codebase.
use crate::constants::{EXPECTED_HEX_NODE_ID_LENGTH, MAX_PEER_ID_LENGTH};
use crate::error::PeerIdValidationError;
use network::{Network, PeerId};
use sha2::{Digest, Sha256};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::Arc;

/// Check if a string is a valid address (either ip:port or hostname:port)
fn is_valid_address(addr_str: &str) -> bool {
    // First, try to parse as a socket address (ip:port)
    if addr_str.parse::<SocketAddr>().is_ok() {
        return true;
    }

    // Otherwise, check if it's a valid hostname:port format
    // Find the last colon to split host and port
    if let Some(colon_pos) = addr_str.rfind(':') {
        let host = &addr_str[..colon_pos];
        let port_str = &addr_str[colon_pos + 1..];

        // Port must be a valid number between 1 and 65535
        if let Ok(port) = port_str.parse::<u16>() {
            if port == 0 {
                return false;
            }

            // Host must be a valid hostname (alphanumeric, hyphens, dots)
            // and must not be empty
            if !host.is_empty()
                && host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
                && !host.starts_with('-')
                && !host.ends_with('-')
            {
                return true;
            }
        }
    }

    false
}

/// Validate a peer ID string
///
/// Valid formats:
/// - `node_id` - Just the iroh public key (hex-encoded, 64 chars for Ed25519)
/// - `node_id@ip:port` - Node ID with IP socket address
/// - `node_id@hostname:port` - Node ID with hostname address (for Docker/DNS)
///
/// # Arguments
/// * `peer_id` - The peer ID string to validate
///
/// # Returns
/// * `Ok(())` if valid
/// * `Err(PeerIdValidationError)` if invalid
pub fn validate_peer_id(peer_id: &str) -> Result<(), PeerIdValidationError> {
    // Check for empty string
    if peer_id.is_empty() {
        return Err(PeerIdValidationError::Empty);
    }

    // Check maximum length
    if peer_id.len() > MAX_PEER_ID_LENGTH {
        return Err(PeerIdValidationError::TooLong {
            length: peer_id.len(),
            max: MAX_PEER_ID_LENGTH,
        });
    }

    // Split by '@' to separate node_id from optional socket address
    let parts: Vec<&str> = peer_id.splitn(2, '@').collect();
    let node_id = parts[0];

    // Validate node_id part - should be hex-encoded Ed25519 public key (64 chars)
    if node_id.len() != EXPECTED_HEX_NODE_ID_LENGTH {
        return Err(PeerIdValidationError::InvalidNodeIdLength {
            length: node_id.len(),
            expected: EXPECTED_HEX_NODE_ID_LENGTH,
        });
    }

    // Check that node_id contains only valid hex characters
    if !node_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(PeerIdValidationError::InvalidCharacters(format!(
            "Node ID must contain only hexadecimal characters (0-9, a-f, A-F), got: {}",
            &node_id[..node_id.len().min(20)]
        )));
    }

    // If there's a socket address part, validate it
    if parts.len() == 2 {
        let addr_str = parts[1];
        if addr_str.is_empty() {
            return Err(PeerIdValidationError::InvalidFormat(
                "Socket address after '@' cannot be empty".to_string(),
            ));
        }

        // Try to parse as a socket address (ip:port) or hostname:port
        if !is_valid_address(addr_str) {
            return Err(PeerIdValidationError::InvalidSocketAddr(format!(
                "Cannot parse '{}' as a valid address (expected ip:port or hostname:port)",
                addr_str
            )));
        }
    }

    Ok(())
}

/// Validate multiple peer IDs and return detailed results
///
/// # Returns
/// A vector of (peer_id, Result) pairs
pub fn validate_peer_ids(peer_ids: &[String]) -> Vec<(&String, Result<(), PeerIdValidationError>)> {
    peer_ids
        .iter()
        .map(|id| (id, validate_peer_id(id)))
        .collect()
}

/// Validate all peer IDs and return an error if any are invalid
///
/// # Returns
/// * `Ok(())` if all peer IDs are valid
/// * `Err` with details about the first invalid peer ID
pub fn validate_all_peer_ids(peer_ids: &[String]) -> Result<(), (String, PeerIdValidationError)> {
    for peer_id in peer_ids {
        if let Err(e) = validate_peer_id(peer_id) {
            return Err((peer_id.clone(), e));
        }
    }
    Ok(())
}

/// Result of connecting to a peer
#[derive(Debug, Clone)]
pub struct PeerConnectionResult {
    /// The peer ID that was attempted
    pub peer_id: String,
    /// Whether the connection was successful
    pub success: bool,
    /// Error message if connection failed
    pub error: Option<String>,
}

/// Summary of peer connection attempts
#[derive(Debug)]
pub struct PeerConnectionSummary {
    /// Total number of peers attempted
    pub total: usize,
    /// Number of successful connections
    pub successful: usize,
    /// Number of failed connections
    pub failed: usize,
    /// Detailed results for each peer
    pub results: Vec<PeerConnectionResult>,
}

/// Connect to multiple peer nodes using the iroh network
///
/// This function attempts to connect to all provided peer IDs using the specified protocol.
/// It will attempt to connect to all peers even if some fail, and returns a summary of
/// the connection attempts.
///
/// # Arguments
/// * `network` - The iroh network instance to use for connections
/// * `peer_ids` - Vector of peer ID strings to connect to. Peer IDs should be in iroh
///   PublicKey format: either "node_id" or "node_id@ip:port" where node_id is the
///   iroh public key string representation
/// * `protocol` - The protocol to use for the connection (e.g., b"orbis/dkg/0")
///
/// # Returns
/// A `PeerConnectionSummary` containing details about all connection attempts
///
/// # Example
/// ```rust
/// use network::Network;
/// use crate::helpers::helpers::connect_to_peers;
///
/// let summary = connect_to_peers(
///     &app_state.network,
///     vec!["peer1".to_string(), "peer2".to_string()],
///     b"orbis/dkg/0"
/// ).await;
///
/// println!("Connected to {}/{} peers", summary.successful, summary.total);
/// ```
pub async fn connect_to_peers(
    network: &Arc<dyn Network>,
    peer_ids: Vec<String>,
    protocol: &[u8],
) -> PeerConnectionSummary {
    let total = peer_ids.len();
    let mut successful = 0;
    let mut failed = 0;
    let mut results = Vec::new();

    if peer_ids.is_empty() {
        return PeerConnectionSummary {
            total: 0,
            successful: 0,
            failed: 0,
            results: Vec::new(),
        };
    }

    let protocol_str = std::str::from_utf8(protocol).unwrap_or("<invalid-utf8>");
    tracing::info!(
        peer_count = total,
        protocol = protocol_str,
        "Connecting to peer nodes"
    );

    // Get our local peer ID to skip self-connections
    let our_peer_id_hex = hex::encode(network.local_peer_id().as_bytes());
    let mut skipped_self = 0;

    for peer_id_str in peer_ids {
        // Skip connecting to ourselves
        if extract_node_part(&peer_id_str) == our_peer_id_hex {
            tracing::debug!(peer_id = %peer_id_str, "Skipping self-connection");
            skipped_self += 1;
            continue;
        }

        // Clone once for result storage (used in both success and error cases)
        let peer_id_for_result = peer_id_str.clone();

        // Convert peer ID string to PeerId
        // The network.connect() method will parse this as UTF-8 and then as iroh PublicKey
        let peer_id = PeerId::new(peer_id_str.as_bytes().to_vec());

        // Connect to the peer using the specified protocol
        match network.connect(&peer_id, protocol).await {
            Ok(_connection) => {
                tracing::info!(peer_id = %peer_id_str, "Connected to peer");
                successful += 1;
                results.push(PeerConnectionResult {
                    peer_id: peer_id_for_result,
                    success: true,
                    error: None,
                });
            }
            Err(e) => {
                let error_msg = format!("{}", e);
                tracing::error!(
                    peer_id = %peer_id_str,
                    error = %error_msg,
                    "Failed to connect to peer"
                );
                failed += 1;
                results.push(PeerConnectionResult {
                    peer_id: peer_id_for_result,
                    success: false,
                    error: Some(error_msg),
                });
            }
        }
    }

    // Adjust total to exclude self-connections
    let actual_total = total - skipped_self;

    tracing::info!(
        successful = successful,
        failed = failed,
        total = actual_total,
        skipped_self = skipped_self,
        "Connection summary"
    );

    PeerConnectionSummary {
        total: actual_total,
        successful,
        failed,
        results,
    }
}

/// Connect to a single peer node
///
/// Convenience function for connecting to a single peer. Returns the connection result
/// directly instead of a summary.
///
/// # Arguments
/// * `network` - The iroh network instance to use for connections
/// * `peer_id` - Peer ID string to connect to
/// * `protocol` - The protocol to use for the connection (e.g., b"orbis/dkg/0")
///
/// # Returns
/// `Ok(Box<dyn Connection>)` if successful, `Err(NetworkError)` if failed
///
/// # Example
/// ```rust
/// use network::Network;
/// use crate::helpers::helpers::connect_to_peer;
///
/// match connect_to_peer(&app_state.network, "peer1".to_string(), b"orbis/dkg/0").await {
///     Ok(connection) => {
///         // Use connection for communication
///     }
///     Err(e) => {
///         eprintln!("Failed to connect: {}", e);
///     }
/// }
/// ```
pub async fn connect_to_peer(
    network: &Arc<dyn Network>,
    peer_id: String,
    protocol: &[u8],
) -> Result<Box<dyn network::Connection>, network::error::NetworkError> {
    let peer_id_obj = PeerId::new(peer_id.as_bytes().to_vec());
    network.connect(&peer_id_obj, protocol).await
}

/// Derive a stable u32 identifier from a peer ID
///
/// This function hashes the peer ID bytes to produce a deterministic u32.
/// The peer ID should be the iroh PublicKey (hex-encoded or raw bytes).
///
/// # Arguments
/// * `peer_id_bytes` - The peer ID bytes (iroh PublicKey)
///
/// # Returns
/// A u32 hash of the peer ID
pub fn derive_node_id_from_peer_id_bytes(peer_id_bytes: &[u8]) -> u32 {
    let mut hasher = DefaultHasher::new();
    peer_id_bytes.hash(&mut hasher);
    hasher.finish() as u32
}

/// Derive a stable u32 identifier from a peer ID string
///
/// This function hashes the peer ID string to produce a deterministic u32.
pub fn derive_node_id_from_peer_id(peer_id: &str) -> u32 {
    let mut hasher = DefaultHasher::new();
    peer_id.hash(&mut hasher);
    hasher.finish() as u32
}

/// Extract just the node_id part (before @) from a peer_id string
///
/// This handles both "hex_string" and "hex_string@address" formats.
///
/// # Arguments
/// * `peer_id` - The peer ID string (may include @address suffix)
///
/// # Returns
/// The node_id part (hex string without @address suffix)
pub fn extract_node_part(peer_id: &str) -> String {
    peer_id.split('@').next().unwrap_or(peer_id).to_string()
}

/// Check if a peer_id string matches our local peer_id
///
/// This handles both "hex_string" and "hex_string@address" formats by
/// comparing just the node_id part (before @).
///
/// # Arguments
/// * `network` - The network instance to get our local peer_id from
/// * `peer_id_str` - The peer ID string to check
///
/// # Returns
/// `true` if the peer_id matches our local peer_id, `false` otherwise
pub fn is_self_peer_id(network: &Arc<dyn Network>, peer_id_str: &str) -> bool {
    let our_peer_id = network.local_peer_id();
    let our_peer_id_hex = hex::encode(our_peer_id.as_bytes());
    let peer_node_part = extract_node_part(peer_id_str);
    our_peer_id_hex == peer_node_part
}

/// Determine node_id for a DKG session based on sorted peer_ids
///
/// In a DKG session, node_id must be between 1 and total_nodes.
/// This function sorts all peer_ids and returns the 1-indexed position
/// of the given peer_id in that sorted list.
///
/// # Arguments
/// * `our_peer_id` - Our own peer ID (hex-encoded, may include @address)
/// * `all_peer_ids` - All peer IDs participating in the session (including ours)
///
/// # Returns
/// The node_id (1-indexed) for this peer in the session, or None if peer_id not found
pub fn determine_session_node_id(our_peer_id: &str, all_peer_ids: &[String]) -> Option<u32> {
    // Normalize all peer_ids to just the hex part for comparison
    let our_node_part = extract_node_part(our_peer_id);

    // Sort peer_ids by their node_id part (hex string comparison)
    let mut sorted_peer_ids: Vec<String> = all_peer_ids
        .iter()
        .map(|pid| extract_node_part(pid))
        .collect();
    sorted_peer_ids.sort();
    sorted_peer_ids.dedup(); // Remove duplicates if any

    // Find our position (1-indexed)
    sorted_peer_ids
        .iter()
        .position(|pid| *pid == our_node_part)
        .map(|idx| (idx + 1) as u32)
}

/// Ring configuration fetched from the bulletin.
///
/// Groups the five bulletin-derived fields that always travel together through
/// both the PRE and Sign coordinator call chains. Constructed in the service
/// layer from a `RingPayload` after validation, then passed into the coordinator.
#[derive(Debug, Clone)]
pub struct RingConfig {
    /// Decoded ring public key bytes (compressed G1Affine)
    pub ring_pk_bytes: Vec<u8>,
    /// Network addresses of all ring participants
    pub peer_ids: Vec<String>,
    /// Minimum shares required to reconstruct
    pub threshold: usize,
    /// Total number of nodes in the ring
    pub total_participants: usize,
    /// Hex-encoded public polynomial (for share verification)
    pub public_polynomial_hex: String,
}

/// Convert session_id string to u64 using SHA-256 (cryptographic hash)
///
/// This function allows string session IDs from the proto while DKGNode uses u64.
/// Using SHA-256 prevents collision attacks that would be possible with DefaultHasher.
///
/// # Arguments
/// * `session_id_str` - The session ID string to convert
///
/// # Returns
/// * `Ok(u64)` - The session ID as a u64
/// * `Err(std::array::TryFromSliceError)` - If the hash conversion fails
///
/// # Example
/// ```rust
/// use crate::helpers::helpers::session_id_string_to_u64;
///
/// let session_id = session_id_string_to_u64("test-session-123")?;
/// ```
pub fn session_id_string_to_u64(
    session_id_str: &str,
) -> Result<u64, std::array::TryFromSliceError> {
    let hash = Sha256::digest(session_id_str.as_bytes());
    Ok(u64::from_le_bytes(hash[..8].try_into()?))
}
