use crate::error::PeerIdValidationError;
use crate::helpers::ring::RingConfig;
pub use common::peer_id::{canonicalize_peer_id, validate_peer_id};
use network::Network;
use std::sync::Arc;

pub fn validate_all_peer_ids(peer_ids: &[String]) -> Result<(), (String, PeerIdValidationError)> {
    peer_ids
        .iter()
        .try_for_each(|peer_id| validate_peer_id(peer_id).map_err(|e| (peer_id.clone(), e)))
}

/// Validate `peer_id` and lowercase its hex node part, leaving any `@address`
/// suffix untouched.
///
/// Iroh's node-ID parser and `hex::encode` (used for authenticated sender
/// identities) both only ever produce/accept lowercase hex, while route
/// comparisons throughout the codebase are a mix of case-sensitive and
/// `.to_lowercase()`-normalized. Canonicalizing at the point a peer ID enters
/// the system (chain-sourced `NodeInfo.peer_id`, or a locally derived/operator
/// -supplied ID) keeps every downstream comparison and dial consistent
/// regardless of the casing an operator originally typed or pasted.
pub fn extract_node_part(peer_id: &str) -> String {
    common::peer_id::node_part(peer_id).to_string()
}

pub fn is_self_peer_id(network: &Arc<dyn Network>, peer_id_str: &str) -> bool {
    let our_peer_id_hex = hex::encode(network.local_peer_id().as_bytes());
    our_peer_id_hex == extract_node_part(peer_id_str).to_lowercase()
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

/// Inverse of [`determine_session_node_id`]: given a 1-based node id, find
/// the identity key at that position in `all_peer_ids`'s canonical sort
/// order. Used to verify a signed attestation actually came from the
/// committee member it claims to be — a node that mislabels its own
/// `from_node_id` cannot borrow another member's identity this way, since
/// the caller checks the returned key against the signature itself.
pub fn node_key_for_id(node_id: u32, all_peer_ids: &[String]) -> Option<String> {
    let mut sorted_peer_ids: Vec<String> = all_peer_ids
        .iter()
        .map(|peer_id| extract_node_part(peer_id))
        .collect();
    sorted_peer_ids.sort();
    sorted_peer_ids.dedup();
    let index = (node_id as usize).checked_sub(1)?;
    sorted_peer_ids.get(index).cloned()
}

pub fn determine_ring_node_id_from_peer_id(peer_id: &str, ring: &RingConfig) -> Option<u32> {
    if ring.peer_node_keys.len() != ring.peer_ids.len() {
        return None;
    }
    let peer_node_part = extract_node_part(peer_id).to_lowercase();
    let node_key = ring
        .peer_node_keys
        .iter()
        .zip(ring.peer_ids.iter())
        .find(|(_, route)| extract_node_part(route).to_lowercase() == peer_node_part)
        .map(|(node_key, _)| node_key.as_str())?;
    determine_session_node_id(node_key, &ring.peer_node_keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_lowercases_node_part_only() {
        let upper_node = "A".repeat(64);
        let lower_node = "a".repeat(64);

        assert_eq!(
            canonicalize_peer_id(&upper_node).expect("valid peer id"),
            lower_node
        );

        let with_addr = format!("{upper_node}@Host.Example.com:4000");
        assert_eq!(
            canonicalize_peer_id(&with_addr).expect("valid peer id"),
            format!("{lower_node}@Host.Example.com:4000")
        );
    }

    #[test]
    fn canonicalize_rejects_invalid_peer_id() {
        assert!(canonicalize_peer_id("not-a-peer-id").is_err());
    }

    fn ring(peer_node_keys: &[&str], peer_ids: &[&str]) -> RingConfig {
        RingConfig {
            ring_id: "ring".to_string(),
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

    #[test]
    fn node_key_for_id_is_the_inverse_of_determine_session_node_id() {
        let peer_node_keys = vec![
            "node-c".to_string(),
            "node-a".to_string(),
            "node-b".to_string(),
        ];
        for key in &peer_node_keys {
            let id = determine_session_node_id(key, &peer_node_keys).unwrap();
            assert_eq!(
                node_key_for_id(id, &peer_node_keys).as_deref(),
                Some(key.as_str())
            );
        }
    }

    #[test]
    fn node_key_for_id_rejects_zero_and_out_of_range() {
        let peer_node_keys = vec!["node-a".to_string(), "node-b".to_string()];
        assert_eq!(node_key_for_id(0, &peer_node_keys), None);
        assert_eq!(node_key_for_id(3, &peer_node_keys), None);
    }
}
