use std::collections::HashMap;

use crate::dkg::error::{DkgError, Result};
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
    let _ = kind;
    peer_ids.to_vec()
}

pub(in crate::dkg::coordinator) fn canonical_node_id_assignments(
    peer_node_keys: &[String],
) -> Result<HashMap<String, u32>> {
    let mut sorted_node_keys = peer_node_keys.to_vec();
    sorted_node_keys.sort();

    let mut assignments = HashMap::new();
    for (idx, node_key) in sorted_node_keys.iter().enumerate() {
        if assignments
            .insert(node_key.clone(), (idx + 1) as u32)
            .is_some()
        {
            return Err(DkgError::InvalidInput(format!(
                "Duplicate peer_node_key in SessionInit: {}",
                node_key
            )));
        }
    }

    Ok(assignments)
}

pub(in crate::dkg::coordinator) fn validate_node_id_assignments(
    peer_node_keys: &[String],
    node_id_assignments: &HashMap<String, u32>,
) -> Result<HashMap<String, u32>> {
    let canonical = canonical_node_id_assignments(peer_node_keys)?;
    if node_id_assignments.len() != canonical.len() {
        return Err(DkgError::Unauthorized(format!(
            "SessionInit node_id_assignments has {} entries, expected {}",
            node_id_assignments.len(),
            canonical.len()
        )));
    }

    for (node_key, expected_node_id) in &canonical {
        match node_id_assignments.get(node_key) {
            Some(actual_node_id) if actual_node_id == expected_node_id => {}
            Some(actual_node_id) => {
                return Err(DkgError::Unauthorized(format!(
                    "SessionInit node_id_assignments maps node_key {} to node_id {}, expected {}",
                    node_key, actual_node_id, expected_node_id
                )));
            }
            None => {
                return Err(DkgError::Unauthorized(format!(
                    "SessionInit node_id_assignments missing node_key {}",
                    node_key
                )));
            }
        }
    }

    Ok(canonical)
}

pub(in crate::dkg::coordinator) fn old_committee_node_peer_mappings(
    peer_node_keys: &[String],
    peer_ids: &[String],
    node_id_assignments: &HashMap<String, u32>,
) -> HashMap<u32, String> {
    peer_node_keys
        .iter()
        .zip(peer_ids.iter())
        .filter_map(|(node_key, peer_id)| {
            node_id_assignments
                .get(node_key)
                .map(|node_id| (*node_id, peer_id.clone()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_assignments_use_sorted_peer_order() {
        let assignments =
            canonical_node_id_assignments(&["node-b".to_string(), "node-a".to_string()])
                .expect("canonical assignments");

        assert_eq!(assignments.get("node-a"), Some(&1));
        assert_eq!(assignments.get("node-b"), Some(&2));
    }

    #[test]
    fn validate_assignments_rejects_non_canonical_map() {
        let peer_node_keys = vec!["node-b".to_string(), "node-a".to_string()];
        let supplied = HashMap::from([("node-a".to_string(), 2), ("node-b".to_string(), 1)]);

        let result = validate_node_id_assignments(&peer_node_keys, &supplied);

        assert!(matches!(result, Err(DkgError::Unauthorized(_))));
    }
}
