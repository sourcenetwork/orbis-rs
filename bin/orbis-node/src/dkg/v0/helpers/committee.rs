//! Committee membership, node indexing, and key-matching utilities.

use crate::dkg::v0::error::{DkgError, Result};
use bulletin::r#trait::RingPayload;
use crypto::r#trait::CryptoDeserialize;
use crypto::GroupAffine as G1Affine;
use std::collections::HashMap;

/// Build the forward and reverse node_id <-> peer_id lookup maps from one mapping.
pub fn bidirectional_node_peer_maps(
    node_id_to_peer_id: HashMap<u32, String>,
) -> (HashMap<u32, String>, HashMap<String, u32>) {
    let mut node_to_peer = HashMap::with_capacity(node_id_to_peer_id.len());
    let mut peer_to_node = HashMap::with_capacity(node_id_to_peer_id.len());
    for (node_id, peer_id) in node_id_to_peer_id {
        node_to_peer.insert(node_id, peer_id.clone());
        peer_to_node.insert(peer_id, node_id);
    }
    (node_to_peer, peer_to_node)
}

pub(crate) fn ring_payload_matches_ring_key(ring_pk_key: &str, ring_pk_payload: &str) -> bool {
    if let Ok(bytes) = hex::decode(ring_pk_payload) {
        if let Ok(ring_pk) = G1Affine::from_bytes(&bytes) {
            return ring_pk.to_string() == ring_pk_key;
        }
    }
    ring_pk_payload == ring_pk_key
}

pub(crate) fn public_key_matches_storage_key(public_key: &G1Affine, storage_key: &str) -> bool {
    public_key.to_string() == storage_key
}

/// Returns `true` if `our_node_key` appears in
/// `committee` (sorted or unsorted — membership check is order-independent).
///
/// Used during reshare `SessionInit` handling to decide whether this node is in the
/// old committee, the new committee, or both.
pub fn in_committee(committee: &[String], our_node_key: &str) -> bool {
    committee.iter().any(|node_key| node_key == our_node_key)
}

/// Returns the 1-based node index of `our_node_key` in `sorted_committee`.
///
/// `sorted_committee` must already be sorted so that all nodes derive the same
/// index for the same node key.  Panics if not found — callers must confirm membership
/// with `in_committee` before calling this.
pub fn node_index_in(sorted_committee: &[String], our_node_key: &str) -> Result<u32> {
    sorted_committee
        .iter()
        .position(|node_key| node_key == our_node_key)
        .map(|i| (i + 1) as u32)
        .ok_or_else(|| {
            DkgError::InvalidInput(format!(
                "node '{}' not found in sorted committee",
                our_node_key
            ))
        })
}

/// Returns the effective new committee from a ring payload.
///
/// Uses `new_peer_node_keys` when present (a reshare has been announced),
/// otherwise falls back to the current `peer_node_keys`.
pub fn effective_new_peer_node_keys(ring_payload: &RingPayload) -> &[String] {
    ring_payload
        .new_peer_node_keys
        .as_deref()
        .unwrap_or(&ring_payload.peer_node_keys)
}

/// Returns `true` if two peer-node-key slices represent the same committee
/// regardless of ordering.
pub fn peer_node_keys_match(a: &[String], b: &[String]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut sa: Vec<&str> = a.iter().map(String::as_str).collect();
    let mut sb: Vec<&str> = b.iter().map(String::as_str).collect();
    sa.sort_unstable();
    sb.sort_unstable();
    sa == sb
}
