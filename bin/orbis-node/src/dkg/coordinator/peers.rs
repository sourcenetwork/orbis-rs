use std::collections::HashMap;

use crate::dkg::messages::SessionKind;

pub(in crate::dkg::coordinator) fn same_peer_set(left: &[String], right: &[String]) -> bool {
    let mut left_sorted = left.to_vec();
    let mut right_sorted = right.to_vec();
    left_sorted.sort();
    right_sorted.sort();
    left_sorted == right_sorted
}

pub(in crate::dkg::coordinator) fn session_peer_ids(
    kind: &SessionKind,
    peer_ids: &[String],
) -> Vec<String> {
    if let SessionKind::Reshare { next_peer_ids, .. } = kind {
        let mut new_peers = next_peer_ids.clone();
        new_peers.sort();
        new_peers
    } else {
        peer_ids.to_vec()
    }
}

pub(in crate::dkg::coordinator) fn old_committee_node_peer_mappings(
    peer_ids: &[String],
    node_id_assignments: &HashMap<String, u32>,
) -> HashMap<u32, String> {
    node_id_assignments
        .iter()
        .map(|(peer_id_key, node_id)| {
            let full_peer_id = peer_ids
                .iter()
                .find(|pid| pid.split('@').next().unwrap_or(pid) == peer_id_key)
                .cloned()
                .unwrap_or_else(|| peer_id_key.clone());
            (*node_id, full_peer_id)
        })
        .collect()
}

pub(in crate::dkg::coordinator) fn node_peer_mappings(peer_ids: &[String]) -> HashMap<u32, String> {
    peer_ids
        .iter()
        .enumerate()
        .map(|(idx, peer_id)| ((idx + 1) as u32, peer_id.clone()))
        .collect()
}
