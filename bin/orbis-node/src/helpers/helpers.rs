//! General helper functions for orbis-node
//!
//! This module provides utility functions used across the codebase.
use crate::constants::{EXPECTED_HEX_NODE_ID_LENGTH, MAX_PEER_ID_LENGTH};
use crate::dkg::session_state::SessionStateManager;
use crate::error::PeerIdValidationError;
use crate::helpers::auth::current_unix_time;
use crate::ring_state::RingShareBundle;
use crypto::r#trait::{CryptoDeserialize, Dkg};
use crypto::GroupAffine as G1Affine;
use local_storage::r#trait::LocalStorage;
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
    peer_ids
        .iter()
        .try_for_each(|peer_id| validate_peer_id(peer_id).map_err(|e| (peer_id.clone(), e)))
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
) -> Result<Box<dyn network::PeerConnection>, network::error::NetworkError> {
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

/// Determine node_id for a DKG session based on sorted participant identities.
///
/// In a DKG session, node_id must be between 1 and total_nodes.
/// This function sorts all identities and returns the 1-indexed position
/// of the given identity in that sorted list. For current ring logic those
/// identities are chain node keys; older route-oriented tests may still pass
/// peer IDs, which are normalized by stripping any `@address` suffix.
///
/// # Arguments
/// * `our_peer_id` - Our own identity or peer ID (peer IDs may include @address)
/// * `all_peer_ids` - All identities participating in the session (including ours)
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

pub fn determine_ring_node_id_from_peer_id(peer_id: &str, ring: &RingConfig) -> Option<u32> {
    if ring.peer_node_keys.len() != ring.peer_ids.len() {
        return None;
    }

    let peer_node_part = extract_node_part(peer_id);
    let node_key = ring
        .peer_node_keys
        .iter()
        .zip(ring.peer_ids.iter())
        .find(|(_, route_peer_id)| extract_node_part(route_peer_id) == peer_node_part)
        .map(|(node_key, _)| node_key.as_str())?;

    determine_session_node_id(node_key, &ring.peer_node_keys)
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
    /// Chain node keys of all ring participants, in the same order as `peer_ids`.
    pub peer_node_keys: Vec<String>,
    /// Minimum shares required to reconstruct
    pub threshold: usize,
    /// Total number of nodes in the ring
    pub total_participants: usize,
    /// Hex-encoded public polynomial (for share verification)
    pub public_polynomial_hex: String,
}

/// Convert a session_id string to u128 using SHA-256 (cryptographic hash)
///
/// This function allows string session IDs from the proto while DKGNode uses u128.
/// Using SHA-256 prevents collision attacks that would be possible with DefaultHasher.
///
/// # Arguments
/// * `session_id_str` - The session ID string to convert
///
/// # Returns
/// * `Ok(u128)` - The session ID as a u128
/// * `Err(std::array::TryFromSliceError)` - If the hash conversion fails
///
/// # Example
/// ```rust
/// use crate::helpers::helpers::session_id_string_to_u128;
///
/// let session_id = session_id_string_to_u128("test-session-123")?;
/// ```
pub fn session_id_string_to_u128(
    session_id_str: &str,
) -> Result<u128, std::array::TryFromSliceError> {
    let hash = Sha256::digest(session_id_str.as_bytes());
    Ok(u128::from_le_bytes(hash[..16].try_into()?))
}

/// Returns `true` when a PSS reshare is currently in progress for the ring
/// identified by `ring_pk_bytes`.
///
/// Uses the `rings_pss` flag from `SessionStateManager`, which is
/// exclusively set/cleared by the PSS scheduler (not initial DKG), so there
/// are no false positives immediately after DKG completion.
pub async fn is_ring_reshare_in_progress<D: Dkg + 'static>(
    ring_pk_bytes: &[u8],
    session_state: &SessionStateManager<D>,
) -> bool {
    let Ok(ring_pk) = G1Affine::from_bytes(ring_pk_bytes) else {
        return false;
    };
    session_state.is_ring_pss_active(&ring_pk.to_string()).await
}

/// Load the public polynomial and (when `self_in_list`) the local `RingShareBundle`
/// from a single atomic storage read.
///
/// When `self_in_list` is true, loads the `RingShareBundle` for the ring. On success,
/// derives the public polynomial from the bundle, guaranteeing that the poly and share
/// are from the same PSS generation. On bundle load failure, falls back to
/// `ring.public_polynomial_hex`.
///
/// When `self_in_list` is false, always deserializes from `ring.public_polynomial_hex`.
///
/// Returns `(pub_poly, Option<RingShareBundle>)`. The caller extracts whatever it needs
/// from the bundle (PRE keeps the full bundle; Sign extracts a `DistKeyShare`).
pub fn load_ring_pub_poly_and_bundle<D>(
    storage: &impl LocalStorage,
    ring: &RingConfig,
    self_in_list: bool,
) -> Result<(D::PubPoly, Option<RingShareBundle>), String>
where
    D: Dkg<PublicKey = G1Affine>,
{
    if !self_in_list {
        let poly = decode_pub_poly_hex::<D>(&ring.public_polynomial_hex)?;
        return Ok((poly, None));
    }

    let ring_pk = G1Affine::from_bytes(&ring.ring_pk_bytes)
        .map_err(|error| format!("Failed to deserialize ring public key: {}", error))?;

    let Some(bundle) = RingShareBundle::load(storage, &ring_pk)
        .inspect_err(|error| {
            tracing::warn!(
                error = %error,
                "local bundle missing, falling back to ring config polynomial"
            );
        })
        .ok()
    else {
        let poly = decode_pub_poly_hex::<D>(&ring.public_polynomial_hex)?;
        return Ok((poly, None));
    };

    let poly = decode_pub_poly_hex::<D>(&bundle.public_polynomial)
        .map_err(|error| format!("bundle polynomial: {}", error))?;
    Ok((poly, Some(bundle)))
}

/// Resolve the ring protocol epoch at a captured Unix timestamp.
pub fn effective_protocol_version(
    upgrade_info: &bulletin::r#trait::UpgradeInfo,
    current_time: u64,
) -> Result<u64, String> {
    match (upgrade_info.next_version, upgrade_info.activation_time) {
        (None, None) => Ok(upgrade_info.current_version),
        (Some(next_version), Some(activation_time)) => {
            if next_version <= upgrade_info.current_version {
                return Err(format!(
                    "next_version {} must be greater than current_version {}",
                    next_version, upgrade_info.current_version
                ));
            }
            if activation_time == 0 {
                return Err("activation_time must be positive".to_string());
            }
            if current_time >= activation_time {
                Ok(next_version)
            } else {
                Ok(upgrade_info.current_version)
            }
        }
        _ => Err("next_version and activation_time must both be set or both be absent".to_string()),
    }
}

fn activation_time_label(upgrade_info: &bulletin::r#trait::UpgradeInfo) -> String {
    upgrade_info
        .activation_time
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_string())
}

/// Capture local Unix time and fail closed unless this binary serves the ring.
pub fn ensure_ring_protocol_version(
    ring_id: &str,
    ring_payload: &bulletin::r#trait::RingPayload,
) -> Result<u64, String> {
    let node_version = crate::constants::PROTOCOL_VERSION;
    let activation_time = activation_time_label(&ring_payload.upgrade_info);
    let current_time = current_unix_time().map_err(|error| {
        format!(
            "failed to read system clock for ring {}: node_version={} effective_version=unknown current_time=unknown activation_time={}: {}",
            ring_id, node_version, activation_time, error
        )
    })?;
    let effective_version = effective_protocol_version(&ring_payload.upgrade_info, current_time)
        .map_err(|error| {
            format!(
                "malformed protocol upgrade state for ring {}: node_version={} effective_version=invalid current_time={} activation_time={}: {}",
                ring_id, node_version, current_time, activation_time, error
            )
        })?;

    if effective_version != node_version {
        return Err(format!(
            "protocol version mismatch for ring {}: node_version={} effective_version={} current_time={} activation_time={}",
            ring_id, node_version, effective_version, current_time, activation_time
        ));
    }

    Ok(effective_version)
}

/// Read a ring and validate it against one captured local Unix timestamp.
pub async fn read_ring_for_protocol(
    bulletin: &(dyn bulletin::r#trait::Bulletin + Send + Sync),
    ring_id: &str,
) -> Result<bulletin::r#trait::RingPayload, String> {
    let ring_post = bulletin
        .read(
            ring_id.to_string(),
            bulletin::r#trait::BulletinKind::Ring,
        )
        .await
        .map_err(|error| {
            format!(
                "failed to read protocol state for ring {}: node_version={} effective_version=unknown current_time=unknown activation_time=unknown: {}",
                ring_id,
                crate::constants::PROTOCOL_VERSION,
                error
            )
        })?;
    let ring_payload =
        bulletin::r#trait::RingPayload::try_from(ring_post).map_err(|error| {
            format!(
                "malformed ring payload for ring {}: node_version={} effective_version=invalid current_time=unknown activation_time=unknown: {}",
                ring_id,
                crate::constants::PROTOCOL_VERSION,
                error
            )
        })?;
    ensure_ring_protocol_version(ring_id, &ring_payload)?;
    Ok(ring_payload)
}

fn decode_pub_poly_hex<D: Dkg>(hex_str: &str) -> Result<D::PubPoly, String> {
    let bytes =
        hex::decode(hex_str).map_err(|e| format!("Failed to decode polynomial hex: {}", e))?;
    <D::PubPoly>::from_bytes(&bytes)
        .map_err(|e| format!("Failed to deserialize public polynomial: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring_config(peer_node_keys: Vec<String>, peer_ids: Vec<String>) -> RingConfig {
        RingConfig {
            ring_pk_bytes: vec![],
            peer_ids,
            peer_node_keys,
            threshold: 1,
            total_participants: 1,
            public_polynomial_hex: String::new(),
        }
    }

    #[test]
    fn determine_ring_node_id_from_peer_id_fails_closed_on_length_mismatch() {
        let ring = ring_config(
            vec!["node-a".to_string(), "node-b".to_string()],
            vec!["peer-a".to_string()],
        );

        assert_eq!(determine_ring_node_id_from_peer_id("peer-a", &ring), None);
    }

    #[test]
    fn determine_ring_node_id_from_peer_id_maps_peer_to_node_key_position() {
        let ring = ring_config(
            vec!["node-b".to_string(), "node-a".to_string()],
            vec!["peer-b".to_string(), "peer-a".to_string()],
        );

        assert_eq!(
            determine_ring_node_id_from_peer_id("peer-a", &ring),
            Some(1)
        );
        assert_eq!(
            determine_ring_node_id_from_peer_id("peer-b", &ring),
            Some(2)
        );
    }

    #[test]
    fn effective_protocol_version_returns_next_at_activation() {
        let info = bulletin::r#trait::UpgradeInfo {
            current_version: 0,
            next_version: Some(1),
            activation_time: Some(50),
        };
        assert_eq!(effective_protocol_version(&info, 49), Ok(0));
        assert_eq!(effective_protocol_version(&info, 50), Ok(1));
        assert_eq!(effective_protocol_version(&info, 51), Ok(1));
    }

    #[test]
    fn effective_protocol_version_rejects_malformed_pending_fields() {
        let missing_time = bulletin::r#trait::UpgradeInfo {
            current_version: 0,
            next_version: Some(1),
            activation_time: None,
        };
        assert!(effective_protocol_version(&missing_time, 50).is_err());

        let non_monotonic = bulletin::r#trait::UpgradeInfo {
            current_version: 1,
            next_version: Some(1),
            activation_time: Some(50),
        };
        assert!(effective_protocol_version(&non_monotonic, 50).is_err());

        let zero_activation_time = bulletin::r#trait::UpgradeInfo {
            current_version: 0,
            next_version: Some(1),
            activation_time: Some(0),
        };
        assert!(effective_protocol_version(&zero_activation_time, 50).is_err());
    }

    #[test]
    fn protocol_mismatch_error_includes_decision_context() {
        let payload = bulletin::r#trait::RingPayload {
            upgrade_info: bulletin::r#trait::UpgradeInfo {
                current_version: crate::constants::PROTOCOL_VERSION + 1,
                next_version: None,
                activation_time: None,
            },
            ..Default::default()
        };
        let error = ensure_ring_protocol_version("ring-1", &payload).unwrap_err();
        assert!(error.contains("ring-1"));
        assert!(error.contains("node_version=0"));
        assert!(error.contains("effective_version=1"));
        assert!(error.contains("current_time="));
        assert!(error.contains("activation_time=none"));
    }
}
