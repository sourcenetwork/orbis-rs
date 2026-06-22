use crate::constants::{EXPECTED_HEX_NODE_ID_LENGTH, MAX_PEER_ID_LENGTH};
use crate::error::PeerIdValidationError;
use crate::helpers::ring::RingConfig;
use network::Network;
use std::net::SocketAddr;
use std::sync::Arc;

fn is_valid_address(addr_str: &str) -> bool {
    if addr_str.parse::<SocketAddr>().is_ok() {
        return true;
    }
    let Some(colon_pos) = addr_str.rfind(':') else {
        return false;
    };
    let host = &addr_str[..colon_pos];
    let port = &addr_str[colon_pos + 1..];
    port.parse::<u16>().is_ok_and(|port| port != 0)
        && !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && !host.starts_with('-')
        && !host.ends_with('-')
}

pub fn validate_peer_id(peer_id: &str) -> Result<(), PeerIdValidationError> {
    if peer_id.is_empty() {
        return Err(PeerIdValidationError::Empty);
    }
    if peer_id.len() > MAX_PEER_ID_LENGTH {
        return Err(PeerIdValidationError::TooLong {
            length: peer_id.len(),
            max: MAX_PEER_ID_LENGTH,
        });
    }

    let mut parts = peer_id.splitn(2, '@');
    let node_id = parts.next().unwrap_or_default();
    if node_id.len() != EXPECTED_HEX_NODE_ID_LENGTH {
        return Err(PeerIdValidationError::InvalidNodeIdLength {
            length: node_id.len(),
            expected: EXPECTED_HEX_NODE_ID_LENGTH,
        });
    }
    if !node_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(PeerIdValidationError::InvalidCharacters(format!(
            "Node ID must contain only hexadecimal characters (0-9, a-f, A-F), got: {}",
            &node_id[..node_id.len().min(20)]
        )));
    }

    if let Some(addr) = parts.next() {
        if addr.is_empty() {
            return Err(PeerIdValidationError::InvalidFormat(
                "Socket address after '@' cannot be empty".to_string(),
            ));
        }
        if !is_valid_address(addr) {
            return Err(PeerIdValidationError::InvalidSocketAddr(format!(
                "Cannot parse '{addr}' as a valid address (expected ip:port or hostname:port)"
            )));
        }
    }
    Ok(())
}

pub fn validate_all_peer_ids(peer_ids: &[String]) -> Result<(), (String, PeerIdValidationError)> {
    peer_ids
        .iter()
        .try_for_each(|peer_id| validate_peer_id(peer_id).map_err(|e| (peer_id.clone(), e)))
}

pub fn extract_node_part(peer_id: &str) -> String {
    peer_id.split('@').next().unwrap_or(peer_id).to_string()
}

pub fn is_self_peer_id(network: &Arc<dyn Network>, peer_id_str: &str) -> bool {
    let our_peer_id_hex = hex::encode(network.local_peer_id().as_bytes());
    our_peer_id_hex == extract_node_part(peer_id_str)
}

pub fn determine_session_node_id(our_peer_id: &str, all_peer_ids: &[String]) -> Option<u32> {
    let our_node_part = extract_node_part(our_peer_id);
    let mut sorted_peer_ids: Vec<String> = all_peer_ids
        .iter()
        .map(|peer_id| extract_node_part(peer_id))
        .collect();
    sorted_peer_ids.sort();
    sorted_peer_ids.dedup();
    sorted_peer_ids
        .iter()
        .position(|peer_id| *peer_id == our_node_part)
        .map(|index| (index + 1) as u32)
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
        .find(|(_, route)| extract_node_part(route) == peer_node_part)
        .map(|(node_key, _)| node_key.as_str())?;
    determine_session_node_id(node_key, &ring.peer_node_keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring(peer_node_keys: &[&str], peer_ids: &[&str]) -> RingConfig {
        RingConfig {
            ring_pk_bytes: vec![],
            peer_ids: peer_ids.iter().map(|value| (*value).to_string()).collect(),
            peer_node_keys: peer_node_keys
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            threshold: 1,
            total_participants: peer_ids.len(),
            public_polynomial_hex: String::new(),
        }
    }

    #[test]
    fn ring_node_id_fails_closed_on_route_length_mismatch() {
        assert_eq!(
            determine_ring_node_id_from_peer_id(
                "peer-a",
                &ring(&["node-a", "node-b"], &["peer-a"])
            ),
            None
        );
    }

    #[test]
    fn ring_node_id_uses_canonical_node_key_order() {
        let ring = ring(&["node-b", "node-a"], &["peer-b", "peer-a"]);
        assert_eq!(
            determine_ring_node_id_from_peer_id("peer-a", &ring),
            Some(1)
        );
        assert_eq!(
            determine_ring_node_id_from_peer_id("peer-b", &ring),
            Some(2)
        );
    }
}
