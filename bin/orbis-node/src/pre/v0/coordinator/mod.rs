//! PRE Coordinator
//!
//! This module implements the PRE protocol coordinator for each node.
//! Each node has its own instance that manages its participation in PRE sessions.
//!
//! **Architecture: Decentralized (Peer-to-Peer)**
//!
//! This is NOT a central coordinator. Each node has its own coordinator that:
//! - Initiates PRE requests to other nodes
//! - Responds to incoming PRE requests from other nodes
//! - Manages reencryption share collection and recovery

mod handlers;
mod initiator;
mod network;
mod verification;

pub(crate) use initiator::PreReportBinding;

use crate::app_state::AppState;
use crypto::context::CiphertextContext;
use crypto::r#trait::{Dkg, Secret, ThresholdDealer};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Response structure containing reencrypted commitment and original secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreResponse {
    /// Recovered reencrypted commitment (xnc_cmt) as hex string
    pub xnc_cmt: String,
    /// Original encrypted secret (for Bob to decrypt) as JSON
    pub secret: Secret,
    /// Ciphertext-binding context the requesting node verified the encryption
    /// proof against. Echoed so the reader can rebuild the AES-GCM AAD for
    /// `decrypt_secret` without a bulletin read. `None` when the initiating node
    /// did not attach it (e.g. legacy in-process callers).
    #[serde(default)]
    pub context: Option<CiphertextContext>,
}

/// PRE Coordinator
///
/// Each node has its own instance that manages this node's participation
/// in PRE sessions. This is NOT a central coordinator - the protocol is
/// decentralized with each node managing its own state.
///
/// Type parameters:
/// - D: DKG implementation (must use Fr and G1Affine)
/// - T: ThresholdDealer implementation (must use compatible types)
pub struct PreCoordinator<D, T>
where
    D: Dkg + Clone + 'static,
    T: ThresholdDealer,
{
    pub app_state: Arc<AppState<D>>,
    pub routes: &'static ::network::ProtocolRoutes,
    _phantom: std::marker::PhantomData<T>,
}

impl<D, T> PreCoordinator<D, T>
where
    D: Dkg + Clone + 'static,
    T: ThresholdDealer,
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
