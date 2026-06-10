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
use std::sync::Arc;

/// Response structure containing the recovered signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResponse {
    /// Recovered signature as hex string
    pub signature: String,
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
    /// Create a new Sign coordinator for this node
    pub fn new(app_state: Arc<AppState<D>>) -> Self {
        Self::with_routes(app_state, &::network::V0)
    }

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
