//! Sign Protocol Handler
//!
//! This module implements the protocol handler for threshold BLS signing
//! communication between nodes over the network.
//!
//! The handler acts as the network layer:
//! - Accepts connections (authentication via iroh)
//! - Reads/writes messages
//! - Routes messages to the Sign coordinator
//!
//! The actual signing protocol logic is handled by the Sign coordinator.

use crate::app_state::AppState;
use crate::sign::coordinator::SignCoordinator;
use crate::sign::messages::SignMessage;
use async_trait::async_trait;
use network::error::Result as NetworkResult;
use network::{Connection, Message, ProtocolHandler};
use std::sync::Arc;

/// Sign Protocol Handler
///
/// Network layer handler that accepts connections and routes messages
/// to this node's Sign coordinator for processing.
pub struct SignProtocolHandler<D, S>
where
    D: crypto::r#trait::Dkg + Clone + 'static,
    S: crypto::r#trait::ThresholdSigner,
{
    coordinator: Arc<SignCoordinator<D, S>>,
}

impl<D, S> SignProtocolHandler<D, S>
where
    D: crypto::r#trait::Dkg<ShareValue = crypto::ScalarField, PublicKey = crypto::GroupAffine>
        + Clone
        + Send
        + Sync
        + 'static,
    S: crypto::r#trait::ThresholdSigner<
            ShareValue = crypto::ScalarField,
            PublicKey = crypto::GroupAffine,
            DistKeyShare = crypto::r#trait::DistKeyShare<crypto::ScalarField>,
            PubPoly = D::PubPoly,
            Signature = crypto::SignaturePoint,
            SigShare = crypto::r#trait::PubShare<crypto::SignaturePoint>,
        > + Send
        + Sync
        + 'static,
{
    /// Create a new Sign protocol handler with access to app state
    pub fn new(app_state: Arc<AppState<D>>) -> Self {
        let coordinator = Arc::new(SignCoordinator::new(app_state));
        Self { coordinator }
    }
}

#[async_trait]
impl<D, S> ProtocolHandler for SignProtocolHandler<D, S>
where
    D: crypto::r#trait::Dkg<ShareValue = crypto::ScalarField, PublicKey = crypto::GroupAffine>
        + Clone
        + Send
        + Sync
        + 'static,
    S: crypto::r#trait::ThresholdSigner<
            ShareValue = crypto::ScalarField,
            PublicKey = crypto::GroupAffine,
            DistKeyShare = crypto::r#trait::DistKeyShare<crypto::ScalarField>,
            PubPoly = D::PubPoly,
            Signature = crypto::SignaturePoint,
            SigShare = crypto::r#trait::PubShare<crypto::SignaturePoint>,
        > + Send
        + Sync
        + 'static,
{
    async fn handle(&self, connection: Box<dyn Connection>) -> NetworkResult<()> {
        let peer_id = connection.peer_id().clone();
        tracing::info!(peer_id = ?peer_id, "Sign Protocol: Accepted connection from peer");

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
                        "Sign Protocol: Connection closed or error from peer"
                    );
                    break;
                }
            };

            // Deserialize the Sign message
            let sign_message: SignMessage = match serde_json::from_slice(&network_message.data) {
                Ok(msg) => msg,
                Err(e) => {
                    tracing::error!(
                        peer_id = ?peer_id,
                        error = %e,
                        "Sign Protocol: Failed to deserialize message from peer"
                    );
                    // Send error response
                    let error_msg = SignMessage::Error {
                        request_id: String::from("unknown"),
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
                message_type = ?std::mem::discriminant(&sign_message),
                request_id = %sign_message.request_id(),
                peer_id = ?peer_id,
                "Sign Protocol: Received message"
            );

            // Special handling for responses - store them for the initiator
            if let SignMessage::SignResponse { .. } = &sign_message {
                self.coordinator.store_response(sign_message).await;
                continue;
            }

            // Route message to coordinator
            match self.coordinator.handle_message(sign_message).await {
                Ok(Some(response)) => {
                    // Send response back
                    if let Ok(response_data) = serde_json::to_vec(&response) {
                        if let Err(e) = connection
                            .send(Message::new(response_data, network_message.protocol))
                            .await
                        {
                            tracing::error!(error = %e, "Sign Protocol: Failed to send response");
                        }
                    }
                }
                Ok(None) => {
                    // No response needed
                }
                Err(e) => {
                    tracing::error!(error = %e, "Sign Protocol: Error handling message");
                    // Send error response
                    let error_msg = SignMessage::Error {
                        request_id: String::from("unknown"),
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

        tracing::debug!(peer_id = ?peer_id, "Sign Protocol: Connection handler finished for peer");
        Ok(())
    }
}
