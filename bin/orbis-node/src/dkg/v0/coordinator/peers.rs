use std::collections::HashMap;

use crate::dkg::v0::error::{DkgError, Result};
use crate::helpers::node_routes::{canonical_node_id_assignments_from_node_keys, NodeRoute};

pub(in crate::dkg::v0::coordinator) fn same_peer_set(left: &[String], right: &[String]) -> bool {
    let mut left_sorted = left.to_vec();
    let mut right_sorted = right.to_vec();
    left_sorted.sort();
    right_sorted.sort();
    left_sorted == right_sorted
}

pub(in crate::dkg::v0::coordinator) fn validate_node_id_assignments(
    peer_node_keys: &[String],
    node_id_assignments: &HashMap<String, u32>,
) -> Result<HashMap<String, u32>> {
    let canonical = canonical_node_id_assignments_from_node_keys(peer_node_keys)
        .map_err(DkgError::InvalidInput)?;
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

pub(in crate::dkg::v0::coordinator) fn old_committee_node_peer_mappings(
    peer_node_keys: &[String],
    routes: &[NodeRoute],
    node_id_assignments: &HashMap<String, u32>,
) -> Result<HashMap<u32, String>> {
    if routes.len() != peer_node_keys.len() {
        return Err(DkgError::InvalidInput(format!(
            "old committee route count {} does not match peer_node_keys count {}",
            routes.len(),
            peer_node_keys.len()
        )));
    }

    let mut peer_id_by_node_key = HashMap::with_capacity(routes.len());
    for route in routes {
        if peer_id_by_node_key
            .insert(route.node_key.as_str(), route.peer_id.as_str())
            .is_some()
        {
            return Err(DkgError::InvalidInput(format!(
                "duplicate route for old committee node_key {}",
                route.node_key
            )));
        }
    }

    let mut mappings = HashMap::with_capacity(peer_node_keys.len());
    for node_key in peer_node_keys {
        let node_id = *node_id_assignments.get(node_key).ok_or_else(|| {
            DkgError::InvalidInput(format!(
                "missing node_id assignment for old committee node_key {}",
                node_key
            ))
        })?;
        let peer_id = peer_id_by_node_key.get(node_key.as_str()).ok_or_else(|| {
            DkgError::InvalidInput(format!(
                "missing peer_id route for old committee node_key {}",
                node_key
            ))
        })?;
        if mappings.insert(node_id, (*peer_id).to_string()).is_some() {
            return Err(DkgError::InvalidInput(format!(
                "duplicate node_id assignment {} for old committee",
                node_id
            )));
        }
    }

    Ok(mappings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::node_routes::canonical_node_id_assignments_from_node_keys;

    #[test]
    fn canonical_assignments_use_sorted_peer_order() {
        let assignments = canonical_node_id_assignments_from_node_keys(&[
            "node-b".to_string(),
            "node-a".to_string(),
        ])
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

    #[test]
    fn old_committee_mappings_resolve_peer_ids_by_node_key() {
        let peer_node_keys = vec!["node-b".to_string(), "node-a".to_string()];
        let routes = vec![
            NodeRoute {
                node_key: "node-a".to_string(),
                peer_id: "peer-a".to_string(),
            },
            NodeRoute {
                node_key: "node-b".to_string(),
                peer_id: "peer-b".to_string(),
            },
        ];
        let assignments =
            canonical_node_id_assignments_from_node_keys(&peer_node_keys).expect("assignments");

        let result =
            old_committee_node_peer_mappings(&peer_node_keys, &routes, &assignments).unwrap();

        assert_eq!(result.get(&1), Some(&"peer-a".to_string()));
        assert_eq!(result.get(&2), Some(&"peer-b".to_string()));
    }

    #[test]
    fn old_committee_mappings_reject_missing_route() {
        let peer_node_keys = vec!["node-b".to_string(), "node-a".to_string()];
        let routes = vec![NodeRoute {
            node_key: "node-a".to_string(),
            peer_id: "peer-a".to_string(),
        }];
        let assignments =
            canonical_node_id_assignments_from_node_keys(&peer_node_keys).expect("assignments");

        let result = old_committee_node_peer_mappings(&peer_node_keys, &routes, &assignments);

        assert!(matches!(result, Err(DkgError::InvalidInput(_))));
    }
}
