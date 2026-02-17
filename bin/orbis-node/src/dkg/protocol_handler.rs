//! DKG Protocol Handler
//!
//! This module implements the protocol handler for DKG (Distributed Key Generation)
//! communication between nodes over the iroh network.
//!
//! The handler acts as the network layer:
//! - Accepts connections (authentication via iroh)
//! - Reads/writes messages
//! - Routes messages to the DKG session manager
//!
//! The actual DKG protocol logic is handled by the DKG session manager.
//!
//! **Architecture Note**: Each node has its own session manager instance.
//! The DKG protocol is decentralized - there is no central coordinator.
//! All nodes participate equally in the peer-to-peer protocol.

use crate::app_state::AppState;
use crate::dkg::coordinator::DkgCoordinator;
use crate::dkg::messages::DkgMessage;
use async_trait::async_trait;
use network::error::Result as NetworkResult;
use network::{Connection, Message, ProtocolHandler};
use std::sync::Arc;

/// DKG Protocol Handler
///
/// Network layer handler that accepts connections and routes messages
/// to this node's DKG session manager for processing.
///
/// Each node has its own handler instance that manages connections
/// for this node's participation in the decentralized DKG protocol.
pub struct DkgProtocolHandler<D>
where
    D: crypto::r#trait::Dkg + Clone + 'static,
{
    coordinator: Arc<DkgCoordinator<D>>,
}

impl<D> DkgProtocolHandler<D>
where
    D: crypto::r#trait::Dkg<
            ShareValue = crypto::ScalarField,
            PublicKey = crypto::GroupAffine,
            PolynomialCommitment = crypto::PolynomialCommitmentImpl,
        > + Clone,
{
    /// Create a new DKG protocol handler with access to app state
    pub fn new(app_state: Arc<AppState<D>>) -> Self {
        let coordinator = Arc::new(DkgCoordinator::new(app_state));
        Self { coordinator }
    }
}

#[async_trait]
impl<D> ProtocolHandler for DkgProtocolHandler<D>
where
    D: crypto::r#trait::Dkg<
            ShareValue = crypto::ScalarField,
            PublicKey = crypto::GroupAffine,
            PolynomialCommitment = crypto::PolynomialCommitmentImpl,
        > + Clone
        + Send
        + Sync
        + 'static,
{
    async fn handle(&self, connection: Box<dyn Connection>) -> NetworkResult<()> {
        let peer_id = connection.peer_id().clone();
        tracing::info!(peer_id = ?peer_id, "DKG Protocol: Accepted connection from peer");

        // Read messages from the connection and route them to the coordinator
        loop {
            // Receive a message from the connection
            let network_message = match connection.recv().await {
                Ok(msg) => msg,
                Err(e) => {
                    // Connection closed or error
                    tracing::debug!(
                        peer_id = ?peer_id,
                        error = %e,
                        "DKG Protocol: Connection closed or error from peer"
                    );
                    break;
                }
            };

            // Deserialize the DKG message
            let dkg_message: DkgMessage = match serde_json::from_slice(&network_message.data) {
                Ok(msg) => msg,
                Err(e) => {
                    tracing::error!(
                        peer_id = ?peer_id,
                        error = %e,
                        "DKG Protocol: Failed to deserialize message from peer"
                    );
                    // Send error response
                    let error_msg = DkgMessage::Error {
                        session_id: 0, // Unknown session
                        error: format!("Failed to deserialize message: {}", e),
                    };
                    if let Ok(error_data) = serde_json::to_vec(&error_msg) {
                        let _ = connection
                            .send(Message::new(error_data, network_message.protocol))
                            .await;
                    }
                    continue;
                }
            };

            tracing::debug!(
                message_type = ?std::mem::discriminant(&dkg_message),
                session_id = dkg_message.session_id(),
                peer_id = ?peer_id,
                "DKG Protocol: Received message"
            );

            // Route message to coordinator with authenticated peer identity
            match self.coordinator.handle_message(dkg_message, &peer_id).await {
                Ok(Some(response)) => {
                    // Send response back
                    if let Ok(response_data) = serde_json::to_vec(&response) {
                        if let Err(e) = connection
                            .send(Message::new(response_data, network_message.protocol))
                            .await
                        {
                            tracing::error!(
                                peer_id = ?peer_id,
                                error = %e,
                                "DKG Protocol: Failed to send response to peer"
                            );
                        }
                    }
                }
                Ok(None) => {
                    // No response needed
                }
                Err(e) => {
                    tracing::error!(
                        peer_id = ?peer_id,
                        error = %e,
                        "DKG Protocol: Coordinator error"
                    );
                    // Send error response
                    let error_msg = DkgMessage::Error {
                        session_id: 0, // Could extract from failed message if needed
                        error: e.to_string(),
                    };
                    if let Ok(error_data) = serde_json::to_vec(&error_msg) {
                        let _ = connection
                            .send(Message::new(error_data, network_message.protocol))
                            .await;
                    }
                }
            }
        }

        tracing::debug!(peer_id = ?peer_id, "DKG Protocol: Connection closed with peer");
        Ok(())
    }
}
