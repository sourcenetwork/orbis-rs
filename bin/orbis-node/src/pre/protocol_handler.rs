//! PRE Protocol Handler
//!
//! This module implements the protocol handler for PRE (Proxy Re-Encryption)
//! communication between nodes over the iroh network.
//!
//! The handler acts as the network layer:
//! - Accepts connections (authentication via iroh)
//! - Reads/writes messages
//! - Routes messages to the PRE coordinator
//!
//! The actual PRE protocol logic is handled by the PRE coordinator.

use crate::app_state::AppState;
use crate::pre::coordinator::PreCoordinator;
use crate::pre::messages::PreMessage;
use async_trait::async_trait;
use network::error::Result as NetworkResult;
use network::{Connection, Message, ProtocolHandler, Router, REENCRYPT};
use std::sync::Arc;

/// PRE Protocol Handler
///
/// Network layer handler that accepts connections and routes messages
/// to this node's PRE coordinator for processing.
pub struct PreProtocolHandler {
    coordinator: Arc<PreCoordinator>,
}

impl PreProtocolHandler {
    /// Create a new PRE protocol handler with access to app state
    pub fn new(app_state: Arc<AppState>) -> Self {
        let coordinator = Arc::new(PreCoordinator::new(app_state));
        Self { coordinator }
    }
}

#[async_trait]
impl ProtocolHandler for PreProtocolHandler {
    async fn handle(&self, connection: Box<dyn Connection>) -> NetworkResult<()> {
        let peer_id = connection.peer_id().clone();
        println!("PRE Protocol: Accepted connection from peer: {:?}", peer_id);

        // Read messages from the connection and route them to the coordinator
        loop {
            // Receive a message from the connection
            let network_message = match connection.recv().await {
                Ok(msg) => msg,
                Err(e) => {
                    // Connection closed or error
                    println!(
                        "PRE Protocol: Connection closed or error from peer {:?}: {}",
                        peer_id, e
                    );
                    break;
                }
            };

            // Deserialize the PRE message
            let pre_message: PreMessage = match serde_json::from_slice(&network_message.data) {
                Ok(msg) => msg,
                Err(e) => {
                    eprintln!(
                        "PRE Protocol: Failed to deserialize message from peer {:?}: {}",
                        peer_id, e
                    );
                    // Send error response
                    let error_msg = PreMessage::Error {
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

            println!(
                "PRE Protocol: Received message type {:?} for request {} from peer {:?}",
                std::mem::discriminant(&pre_message),
                pre_message.request_id(),
                peer_id
            );

            // Special handling for responses - store them for the initiator
            if let PreMessage::ReencryptResponse { .. } = &pre_message {
                self.coordinator.store_response(pre_message).await;
                continue;
            }

            // Route message to coordinator
            match self.coordinator.handle_message(pre_message).await {
                Ok(Some(response)) => {
                    // Send response back
                    if let Ok(response_data) = serde_json::to_vec(&response) {
                        if let Err(e) = connection
                            .send(Message::new(response_data, network_message.protocol))
                            .await
                        {
                            eprintln!("PRE Protocol: Failed to send response: {}", e);
                        }
                    }
                }
                Ok(None) => {
                    // No response needed
                }
                Err(e) => {
                    eprintln!("PRE Protocol: Error handling message: {}", e);
                    // Send error response
                    let error_msg = PreMessage::Error {
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

        println!(
            "PRE Protocol: Connection handler finished for peer: {:?}",
            peer_id
        );
        Ok(())
    }
}

/// Create a router with PRE protocol handler
pub fn create_router_with_pre_handler(
    network: &Arc<dyn network::Network>,
    app_state: Arc<AppState>,
) -> NetworkResult<Box<dyn Router>> {
    let pre_handler = Arc::new(PreProtocolHandler::new(app_state));
    let mut router_builder = network.create_router_builder()?;
    router_builder = router_builder.accept(REENCRYPT.to_vec(), pre_handler);
    router_builder.spawn()
}
