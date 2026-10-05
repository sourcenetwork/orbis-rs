//! PET Coordinator
//!
//! Threshold ownership-tag check coordinator, mirroring
//! `pre::v0::coordinator::PreCoordinator`'s decentralized (peer-to-peer)
//! shape: each node has its own instance, both initiating checks (as the
//! node that received the PRE request) and responding to incoming checks
//! initiated by other nodes. There is no separate "leader" concept, exactly
//! like PRE's own reencryption: whichever node received the external
//! request drives the check, fanning out directly to the whole ring
//! committee.

mod handlers;
mod initiator;
mod network;
mod verification;

use crate::app_state::AppState;
use crypto::r#trait::{Dkg, Pet};
use std::sync::Arc;

/// PET Coordinator.
///
/// Type parameters:
/// - `D`: DKG implementation (must use the workspace's configured `Fr`/`G1Affine`).
/// - `P`: `Pet` implementation (must use compatible types — see `Pet`'s own
///   doc comment on why its associated types mirror `ThresholdDealer`'s).
pub struct PetCoordinator<D, P>
where
    D: Dkg + Clone + 'static,
    P: Pet,
{
    pub app_state: Arc<AppState<D>>,
    pub routes: &'static ::network::ProtocolRoutes,
    _phantom: std::marker::PhantomData<P>,
}

impl<D, P> PetCoordinator<D, P>
where
    D: Dkg + Clone + 'static,
    P: Pet,
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
