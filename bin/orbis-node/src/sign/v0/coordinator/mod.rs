//! Sign Coordinator
//!
//! This module implements the threshold signing protocol coordinator for each node.
//! Each node has its own instance that manages its participation in signing sessions.
//!
//! **Architecture: Decentralized (Peer-to-Peer)**
//!
//! This is NOT a central coordinator. Each node has its own coordinator that:
//! - Initiates sign requests to other nodes
//! - Responds to incoming sign requests from other nodes
//! - Manages signature share collection and recovery
//!
//! Supports both non-interactive (BLS) and interactive (FROST) signing via
//! the `ThresholdSigner::INTERACTIVE` flag. For FROST, an additional nonce
//! commitment round is performed before the signing round.

mod handlers;
mod network;
mod rounds;
mod verification;

use crate::app_state::AppState;
use crypto::r#trait::{Dkg, ThresholdSigner};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;

/// Response structure containing the recovered signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResponse {
    /// Recovered signature as hex string
    pub signature: String,
}

#[derive(Debug, Clone, Default)]
pub struct SigningOptions {
    pub excluded_node_keys: HashSet<String>,
}

impl SigningOptions {
    pub(crate) fn excludes_peer(
        &self,
        peer_id: &str,
        ring: &crate::helpers::ring::RingConfig,
    ) -> bool {
        ring.peer_node_keys
            .iter()
            .zip(ring.peer_ids.iter())
            .find(|(_, route)| {
                crate::helpers::identity::extract_node_part(route)
                    == crate::helpers::identity::extract_node_part(peer_id)
            })
            .map(|(node_key, _)| self.excluded_node_keys.contains(node_key))
            .unwrap_or(false)
    }
}

/// Sign Coordinator
///
/// Each node has its own instance that manages this node's participation
/// in threshold signing sessions. This is NOT a central coordinator - the protocol is
/// decentralized with each node managing its own state.
///
/// Type parameters:
/// - D: DKG implementation (must use Fr and G1Affine)
/// - S: ThresholdSigner implementation (must use compatible types)
pub struct SignCoordinator<D, S>
where
    D: Dkg + Clone + 'static,
    S: ThresholdSigner,
{
    pub app_state: Arc<AppState<D>>,
    pub routes: &'static ::network::ProtocolRoutes,
    _phantom: std::marker::PhantomData<S>,
}

impl<D, S> SignCoordinator<D, S>
where
    D: Dkg + Clone + 'static,
    S: ThresholdSigner,
{
    pub fn with_routes(
        app_state: Arc<AppState<D>>,
        routes: &'static ::network::ProtocolRoutes,
    ) -> Self {
        Self {
            app_state,
            routes,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[cfg(test)]
mod signing_options_tests {
    use super::SigningOptions;
    use crate::helpers::ring::RingConfig;
    use std::collections::HashSet;

    #[test]
    fn exclusion_maps_peer_route_to_node_key() {
        let ring = RingConfig {
            ring_id: "ring".to_string(),
            ring_pk_bytes: vec![],
            peer_ids: vec!["aa".repeat(32), "bb".repeat(32)],
            peer_node_keys: vec!["node-a".to_string(), "node-b".to_string()],
            threshold: 1,
            total_participants: 2,
            public_polynomial_hex: String::new(),
        };
        let options = SigningOptions {
            excluded_node_keys: HashSet::from(["node-b".to_string()]),
        };
        assert!(!options.excludes_peer(&ring.peer_ids[0], &ring));
        assert!(options.excludes_peer(&ring.peer_ids[1], &ring));
    }
}
