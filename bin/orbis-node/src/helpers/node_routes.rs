use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use bulletin::r#trait::{Bulletin, BulletinKind, NodeInfo};

use crate::helpers::identity::{extract_node_part, validate_peer_id};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRoute {
    pub node_key: String,
    pub peer_id: String,
}

pub async fn resolve_node_routes(
    bulletin: &Arc<dyn Bulletin + Send + Sync>,
    peer_node_keys: &[String],
) -> Result<Vec<NodeRoute>, String> {
    let mut seen_node_keys = HashSet::new();
    let mut seen_peer_parts = HashSet::new();
    let mut routes = Vec::with_capacity(peer_node_keys.len());

    for node_key in peer_node_keys {
        if node_key.trim().is_empty() {
            return Err("peer_node_keys contains an empty node key".to_string());
        }
        if !seen_node_keys.insert(node_key.clone()) {
            return Err(format!("duplicate peer_node_key: {node_key}"));
        }

        let post = bulletin
            .read(node_key.clone(), BulletinKind::NodeInfo)
            .await
            .map_err(|e| format!("NodeInfo for node {node_key} not found: {e}"))?;
        let node_info = NodeInfo::try_from(post)
            .map_err(|e| format!("NodeInfo for node {node_key} is malformed: {e}"))?;
        let peer_id = node_info.peer_id.trim().to_string();
        if peer_id.is_empty() {
            return Err(format!("NodeInfo for node {node_key} has an empty peer_id"));
        }
        validate_peer_id(&peer_id)
            .map_err(|e| format!("NodeInfo for node {node_key} has invalid peer_id: {e}"))?;

        let peer_part = extract_node_part(&peer_id);
        if !seen_peer_parts.insert(peer_part.clone()) {
            return Err(format!(
                "duplicate resolved peer_id node part for peer_node_key {node_key}: {peer_part}"
            ));
        }

        routes.push(NodeRoute {
            node_key: node_key.clone(),
            peer_id,
        });
    }

    Ok(routes)
}

pub fn peer_ids_from_routes(routes: &[NodeRoute]) -> Vec<String> {
    routes.iter().map(|route| route.peer_id.clone()).collect()
}

/// Validate the exact `node_key -> peer route` bindings supplied on the wire
/// against routes independently resolved from Vera `NodeInfo` records.
/// Vector ordering may differ, but a route may not be reassigned to another
/// node key and the full authoritative route (including direct addresses) must
/// match.
pub fn validate_node_route_bindings(
    node_keys: &[String],
    peer_routes: &[String],
    resolved_routes: &[NodeRoute],
) -> Result<(), String> {
    if node_keys.len() != peer_routes.len() {
        return Err(format!(
            "supplied node-key count {} does not match route count {}",
            node_keys.len(),
            peer_routes.len()
        ));
    }

    let mut expected = HashMap::with_capacity(resolved_routes.len());
    for route in resolved_routes {
        if expected
            .insert(route.node_key.as_str(), route.peer_id.as_str())
            .is_some()
        {
            return Err(format!(
                "resolved Vera routes contain duplicate node key {}",
                route.node_key
            ));
        }
    }

    let mut supplied_keys = HashSet::with_capacity(node_keys.len());
    for (node_key, peer_route) in node_keys.iter().zip(peer_routes) {
        if !supplied_keys.insert(node_key.as_str()) {
            return Err(format!(
                "supplied transport routes contain duplicate node key {node_key}"
            ));
        }
        let Some(expected_route) = expected.get(node_key.as_str()) else {
            return Err(format!(
                "supplied transport route names unexpected node key {node_key}"
            ));
        };
        if peer_route != expected_route {
            return Err(format!(
                "supplied transport route for node key {node_key} does not match Vera NodeInfo"
            ));
        }
    }

    if supplied_keys.len() != expected.len()
        || expected
            .keys()
            .any(|node_key| !supplied_keys.contains(node_key))
    {
        return Err("supplied transport routes do not cover the resolved committee".to_string());
    }

    Ok(())
}

pub fn canonical_node_id_assignments_from_node_keys(
    peer_node_keys: &[String],
) -> Result<HashMap<String, u32>, String> {
    let mut sorted = peer_node_keys.to_vec();
    sorted.sort();

    let mut assignments = HashMap::with_capacity(sorted.len());
    for (idx, node_key) in sorted.iter().enumerate() {
        if assignments
            .insert(node_key.clone(), (idx + 1) as u32)
            .is_some()
        {
            return Err(format!("duplicate peer_node_key: {node_key}"));
        }
    }

    Ok(assignments)
}

pub fn node_key_for_canonical_node_id(node_id: u32, peer_node_keys: &[String]) -> Option<String> {
    if node_id == 0 {
        return None;
    }
    canonical_node_id_assignments_from_node_keys(peer_node_keys)
        .ok()?
        .into_iter()
        .find(|(_, assigned_node_id)| *assigned_node_id == node_id)
        .map(|(node_key, _)| node_key)
}

pub fn node_id_to_peer_id_from_routes(
    routes: &[NodeRoute],
    node_id_assignments: &HashMap<String, u32>,
) -> Result<HashMap<u32, String>, String> {
    let mut map = HashMap::with_capacity(routes.len());
    for route in routes {
        let node_id = node_id_assignments
            .get(&route.node_key)
            .ok_or_else(|| format!("missing node_id assignment for {}", route.node_key))?;
        map.insert(*node_id, route.peer_id.clone());
    }
    Ok(map)
}

pub fn node_key_for_peer<'a>(routes: &'a [NodeRoute], sender_peer_hex: &str) -> Option<&'a str> {
    routes
        .iter()
        .find(|route| extract_node_part(&route.peer_id) == sender_peer_hex)
        .map(|route| route.node_key.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulletin::dummy::DummyBulletin;

    fn node_info(peer_id: String) -> NodeInfo {
        NodeInfo {
            peer_id,
            controller_key: "controller".to_string(),
            whitelisted_policy_ids: vec![],
            whitelisted_ring_ids: vec![],
        }
    }

    async fn bulletin_with_nodes(nodes: &[(&str, String)]) -> Arc<dyn Bulletin + Send + Sync> {
        let dummy = Arc::new(DummyBulletin::new().await.expect("dummy bulletin"));
        for (node_key, peer_id) in nodes {
            dummy
                .set_node_info((*node_key).to_string(), node_info(peer_id.clone()))
                .expect("seed node info");
        }
        dummy
    }

    #[tokio::test]
    async fn resolves_node_keys_to_routes_in_input_order() {
        let peer_a = "a".repeat(64);
        let peer_b = format!("{}@127.0.0.1:4000", "b".repeat(64));
        let bulletin =
            bulletin_with_nodes(&[("node-a", peer_a.clone()), ("node-b", peer_b.clone())]).await;

        let routes = resolve_node_routes(&bulletin, &["node-b".to_string(), "node-a".to_string()])
            .await
            .expect("routes");

        assert_eq!(
            routes,
            vec![
                NodeRoute {
                    node_key: "node-b".to_string(),
                    peer_id: peer_b,
                },
                NodeRoute {
                    node_key: "node-a".to_string(),
                    peer_id: peer_a,
                },
            ]
        );
    }

    #[tokio::test]
    async fn rejects_missing_node_info() {
        let bulletin = bulletin_with_nodes(&[]).await;

        let err = resolve_node_routes(&bulletin, &["missing-node".to_string()])
            .await
            .expect_err("missing node info should fail");

        assert!(err.contains("not found"));
    }

    #[tokio::test]
    async fn rejects_invalid_peer_id() {
        let bulletin = bulletin_with_nodes(&[("node-a", "not-a-peer-id".to_string())]).await;

        let err = resolve_node_routes(&bulletin, &["node-a".to_string()])
            .await
            .expect_err("invalid peer id should fail");

        assert!(err.contains("invalid peer_id"));
    }

    #[tokio::test]
    async fn rejects_duplicate_node_keys() {
        let bulletin = bulletin_with_nodes(&[("node-a", "a".repeat(64))]).await;

        let err = resolve_node_routes(&bulletin, &["node-a".to_string(), "node-a".to_string()])
            .await
            .expect_err("duplicate node key should fail");

        assert!(err.contains("duplicate peer_node_key"));
    }

    #[tokio::test]
    async fn rejects_duplicate_resolved_peer_ids() {
        let peer = "a".repeat(64);
        let bulletin = bulletin_with_nodes(&[
            ("node-a", peer.clone()),
            ("node-b", format!("{peer}@127.0.0.1:4000")),
        ])
        .await;

        let err = resolve_node_routes(&bulletin, &["node-a".to_string(), "node-b".to_string()])
            .await
            .expect_err("duplicate peer route should fail");

        assert!(err.contains("duplicate resolved peer_id"));
    }

    #[test]
    fn canonical_assignments_sort_node_keys() {
        let assignments = canonical_node_id_assignments_from_node_keys(&[
            "node-c".to_string(),
            "node-a".to_string(),
            "node-b".to_string(),
        ])
        .expect("assignments");

        assert_eq!(assignments["node-a"], 1);
        assert_eq!(assignments["node-b"], 2);
        assert_eq!(assignments["node-c"], 3);
    }

    #[test]
    fn route_bindings_accept_reordered_exact_pairs() {
        let resolved = vec![
            NodeRoute {
                node_key: "node-a".to_string(),
                peer_id: "route-a@127.0.0.1:9001".to_string(),
            },
            NodeRoute {
                node_key: "node-b".to_string(),
                peer_id: "route-b@127.0.0.1:9002".to_string(),
            },
        ];

        validate_node_route_bindings(
            &["node-b".to_string(), "node-a".to_string()],
            &[
                "route-b@127.0.0.1:9002".to_string(),
                "route-a@127.0.0.1:9001".to_string(),
            ],
            &resolved,
        )
        .expect("paired reordering must preserve exact route bindings");
    }

    #[test]
    fn route_bindings_reject_swapped_routes_and_altered_direct_addresses() {
        let resolved = vec![
            NodeRoute {
                node_key: "node-a".to_string(),
                peer_id: "route-a@127.0.0.1:9001".to_string(),
            },
            NodeRoute {
                node_key: "node-b".to_string(),
                peer_id: "route-b@127.0.0.1:9002".to_string(),
            },
        ];
        let node_keys = ["node-a".to_string(), "node-b".to_string()];

        let swapped = validate_node_route_bindings(
            &node_keys,
            &[
                "route-b@127.0.0.1:9002".to_string(),
                "route-a@127.0.0.1:9001".to_string(),
            ],
            &resolved,
        )
        .expect_err("an unchanged route set with swapped key bindings must fail");
        assert!(swapped.contains("node key node-a"));

        let altered = validate_node_route_bindings(
            &node_keys,
            &[
                "route-a@127.0.0.1:9999".to_string(),
                "route-b@127.0.0.1:9002".to_string(),
            ],
            &resolved,
        )
        .expect_err("a changed direct address must fail exact binding validation");
        assert!(altered.contains("node key node-a"));
    }

    #[test]
    fn node_key_for_canonical_node_id_uses_sorted_node_keys() {
        let peer_node_keys = vec![
            "node-c".to_string(),
            "node-a".to_string(),
            "node-b".to_string(),
        ];

        assert_eq!(
            node_key_for_canonical_node_id(1, &peer_node_keys).as_deref(),
            Some("node-a")
        );
        assert_eq!(
            node_key_for_canonical_node_id(3, &peer_node_keys).as_deref(),
            Some("node-c")
        );
        assert_eq!(node_key_for_canonical_node_id(0, &peer_node_keys), None);
    }
}
