use std::collections::HashMap;

use crate::dkg::error::{DkgError, Result};
use crate::dkg::messages::SessionKind;
use crate::helpers::helpers::extract_node_part;

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
    if let SessionKind::Reshare { new_peer_ids, .. } = kind {
        let mut new_peers = new_peer_ids.clone();
        new_peers.sort();
        new_peers
    } else {
        peer_ids.to_vec()
    }
}

pub(in crate::dkg::coordinator) fn canonical_node_id_assignments(
    peer_ids: &[String],
) -> Result<HashMap<String, u32>> {
    let mut sorted_peer_ids = peer_ids.to_vec();
    sorted_peer_ids.sort();

    let mut assignments = HashMap::new();
    for (idx, peer_id) in sorted_peer_ids.iter().enumerate() {
        let peer_key = extract_node_part(peer_id);
        if assignments
            .insert(peer_key.clone(), (idx + 1) as u32)
            .is_some()
        {
            return Err(DkgError::InvalidInput(format!(
                "Duplicate peer node ID in SessionInit peer_ids: {}",
                peer_key
            )));
        }
    }

    Ok(assignments)
}

pub(in crate::dkg::coordinator) fn validate_node_id_assignments(
    peer_ids: &[String],
    node_id_assignments: &HashMap<String, u32>,
) -> Result<HashMap<String, u32>> {
    let canonical = canonical_node_id_assignments(peer_ids)?;
    if node_id_assignments.len() != canonical.len() {
        return Err(DkgError::Unauthorized(format!(
            "SessionInit node_id_assignments has {} entries, expected {}",
            node_id_assignments.len(),
            canonical.len()
        )));
    }

    for (peer_key, expected_node_id) in &canonical {
        match node_id_assignments.get(peer_key) {
            Some(actual_node_id) if actual_node_id == expected_node_id => {}
            Some(actual_node_id) => {
                return Err(DkgError::Unauthorized(format!(
                    "SessionInit node_id_assignments maps peer {} to node_id {}, expected {}",
                    peer_key, actual_node_id, expected_node_id
                )));
            }
            None => {
                return Err(DkgError::Unauthorized(format!(
                    "SessionInit node_id_assignments missing peer {}",
                    peer_key
                )));
            }
        }
    }

    Ok(canonical)
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
                .find(|pid| extract_node_part(pid) == *peer_id_key)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_assignments_use_sorted_peer_order() {
        let assignments =
            canonical_node_id_assignments(&["bbbb".to_string(), "aaaa@127.0.0.1:1".to_string()])
                .expect("canonical assignments");

        assert_eq!(assignments.get("aaaa"), Some(&1));
        assert_eq!(assignments.get("bbbb"), Some(&2));
    }

    #[test]
    fn validate_assignments_rejects_non_canonical_map() {
        let peer_ids = vec!["bbbb".to_string(), "aaaa".to_string()];
        let supplied = HashMap::from([("aaaa".to_string(), 2), ("bbbb".to_string(), 1)]);

        let result = validate_node_id_assignments(&peer_ids, &supplied);

        assert!(matches!(result, Err(DkgError::Unauthorized(_))));
    }
}
