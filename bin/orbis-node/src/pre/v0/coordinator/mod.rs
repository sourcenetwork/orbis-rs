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
mod stored_delivery;
mod verification;

pub(crate) use initiator::PreReportBinding;

use crate::app_state::AppState;
use crypto::context::CiphertextContext;
use crypto::r#trait::{Dkg, Secret, ThresholdDealer};
use pre_share::{PreShareManifestEntry, PreShareRetrievalManifest};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Internal coordinator output. The requesting node's service layer wraps this into a
/// [`PreReencryptResponse`] before returning it to the caller.
///
/// `Direct` is today's recovered-commitment path, unchanged. `Stored` is the
/// `pre_share_endpoints` delivery mode's result, assembled by
/// `initiator::finalize_stored_reencryption`. Mirrors `Direct`'s own split from
/// `PreReencryptResponse::Direct`: everything the coordinator itself resolved, minus
/// the ciphertext-binding context, which only the *service* layer (not the
/// coordinator) has — `encode_pre_response` completes the full
/// `PreShareRetrievalManifest` from this plus its own `ciphertext_context`, exactly
/// how it completes `DirectPreReencryptResponse` from `Direct` today.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PreResponse {
    Direct {
        /// Recovered reencrypted commitment (xnc_cmt) as hex string
        xnc_cmt: String,
        /// Original encrypted secret (for the reader to decrypt) as JSON
        secret: Secret,
    },
    // Boxed per clippy's `large_enum_variant` (same reasoning as `PreReencryptResponse`).
    Stored(Box<StoredPreResponse>),
}

/// Every [`PreShareRetrievalManifest`] field except `context` — see `PreResponse::Stored`'s
/// doc comment for why.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPreResponse {
    pub request_id: String,
    pub ring_id: String,
    pub ring_pk: String,
    pub threshold: usize,
    pub total_participants: usize,
    pub pinned_public_polynomial: String,
    pub rdr_pk_bytes: Vec<u8>,
    pub object_id: String,
    pub secret: Secret,
    pub pre_share_endpoints: Vec<String>,
    pub entries: Vec<PreShareManifestEntry>,
}

/// The `start_pre` wire payload (JSON inside `StartPreResponse.encrypted_secret`).
///
/// `Direct` carries the ciphertext-binding [`CiphertextContext`] the requesting node verified
/// the encryption proof against, so the reader rebuilds the AES-GCM AAD for `decrypt_secret`
/// without a bulletin read. `Stored` carries the same context inside the completed
/// `PreShareRetrievalManifest` instead, for the same reason but checked once at retrieval
/// time rather than now — the reader fetches and decrypts later, independently of this
/// response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PreReencryptResponse {
    // Boxed (as a newtype variant, which serializes identically to the equivalent struct
    // variant) since `Direct`'s fields are much larger than `Stored`'s boxed manifest, which
    // clippy's `large_enum_variant` flags otherwise.
    Direct(Box<DirectPreReencryptResponse>),
    Stored {
        manifest: Box<PreShareRetrievalManifest>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectPreReencryptResponse {
    /// Recovered reencrypted commitment (xnc_cmt) as hex string
    pub xnc_cmt: String,
    /// Original encrypted secret (for the reader to decrypt) as JSON
    pub secret: Secret,
    /// Context the encryption proof was bound to.
    pub context: CiphertextContext,
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
