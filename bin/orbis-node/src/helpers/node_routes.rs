use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use bulletin::r#trait::{Bulletin, BulletinKind, NodeInfo};

use crate::helpers::helpers::{extract_node_part, validate_peer_id};

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

pub fn peer_id_for_node_key<'a>(routes: &'a [NodeRoute], node_key: &str) -> Option<&'a str> {
    routes
        .iter()
        .find(|route| route.node_key == node_key)
        .map(|route| route.peer_id.as_str())
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
}
