//! General helper functions for orbis-node
//!
//! This module provides utility functions used across the codebase.

use network::{Network, PeerId};
use std::sync::Arc;

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
pub async fn connect_to_peers<N: Network>(
    network: &Arc<N>,
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
    println!(
        "Connecting to {} peer nodes using protocol '{}'...",
        total, protocol_str
    );

    for peer_id_str in peer_ids {
        // Convert peer ID string to PeerId
        // The network.connect() method will parse this as UTF-8 and then as iroh PublicKey
        let peer_id = PeerId::new(peer_id_str.as_bytes().to_vec());

        // Connect to the peer using the specified protocol
        match network.connect(&peer_id, protocol).await {
            Ok(mut connection) => {
                println!("  ✓ Connected to peer: {}", peer_id_str);
                successful += 1;
                results.push(PeerConnectionResult {
                    peer_id: peer_id_str.clone(),
                    success: true,
                    error: None,
                });
            }
            Err(e) => {
                let error_msg = format!("{}", e);
                eprintln!(
                    "  ✗ Failed to connect to peer {}: {}",
                    peer_id_str, error_msg
                );
                failed += 1;
                results.push(PeerConnectionResult {
                    peer_id: peer_id_str.clone(),
                    success: false,
                    error: Some(error_msg),
                });
            }
        }
    }

    println!(
        "Connection summary: {}/{} successful, {}/{} failed",
        successful, total, failed, total
    );

    PeerConnectionSummary {
        total,
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
pub async fn connect_to_peer<N: Network>(
    network: &Arc<N>,
    peer_id: String,
    protocol: &[u8],
) -> Result<Box<dyn network::Connection>, network::error::NetworkError> {
    let peer_id_obj = PeerId::new(peer_id.as_bytes().to_vec());
    network.connect(&peer_id_obj, protocol).await
}
