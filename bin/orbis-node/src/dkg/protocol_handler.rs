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
use crate::pre::protocol_handler::PreProtocolHandler;
use async_trait::async_trait;
use network::error::Result as NetworkResult;
use network::{Connection, Message, ProtocolHandler, Router, DKG, REENCRYPT};
use std::sync::Arc;

/// DKG Protocol Handler
///
/// Network layer handler that accepts connections and routes messages
/// to this node's DKG session manager for processing.
///
/// Each node has its own handler instance that manages connections
/// for this node's participation in the decentralized DKG protocol.
pub struct DkgProtocolHandler {
    coordinator: Arc<DkgCoordinator>,
}

impl DkgProtocolHandler {
    /// Create a new DKG protocol handler with access to app state
    pub fn new(app_state: Arc<AppState>) -> Self {
        let coordinator = Arc::new(DkgCoordinator::new(app_state));
        Self { coordinator }
    }
}

#[async_trait]
impl ProtocolHandler for DkgProtocolHandler {
    async fn handle(&self, connection: Box<dyn Connection>) -> NetworkResult<()> {
        let peer_id = connection.peer_id().clone();
        // TODO: Authentic nodes?
        println!("DKG Protocol: Accepted connection from peer: {:?}", peer_id);

        // Read messages from the connection and route them to the coordinator
        loop {
            // Receive a message from the connection
            let network_message = match connection.recv().await {
                Ok(msg) => msg,
                Err(e) => {
                    // Connection closed or error
                    println!(
                        "DKG Protocol: Connection closed or error from peer {:?}: {}",
                        peer_id, e
                    );
                    break;
                }
            };

            // Deserialize the DKG message
            let dkg_message: DkgMessage = match serde_json::from_slice(&network_message.data) {
                Ok(msg) => msg,
                Err(e) => {
                    eprintln!(
                        "DKG Protocol: Failed to deserialize message from peer {:?}: {}",
                        peer_id, e
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

            println!(
                "DKG Protocol: Received message type {:?} for session {} from peer {:?}",
                std::mem::discriminant(&dkg_message),
                dkg_message.session_id(),
                peer_id
            );

            // Route message to coordinator
            match self.coordinator.handle_message(dkg_message).await {
                Ok(Some(response)) => {
                    // Send response back
                    if let Ok(response_data) = serde_json::to_vec(&response) {
                        if let Err(e) = connection
                            .send(Message::new(response_data, network_message.protocol))
                            .await
                        {
                            eprintln!(
                                "DKG Protocol: Failed to send response to peer {:?}: {}",
                                peer_id, e
                            );
                        }
                    }
                }
                Ok(None) => {
                    // No response needed
                }
                Err(e) => {
                    eprintln!(
                        "DKG Protocol: Coordinator error for peer {:?}: {}",
                        peer_id, e
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

        println!("DKG Protocol: Connection closed with peer: {:?}", peer_id);
        Ok(())
    }
}

/// Create a router with DKG protocol handler registered
///
/// This is a helper function that sets up a router with the DKG protocol handler.
/// It's used both in production (main.rs) and in tests.
///
/// # Arguments
/// * `network` - The network instance to create router for
/// * `app_state` - The application state (needed for DKG coordinator)
pub fn create_router_with_dkg_handler(
    network: &Arc<dyn network::Network>,
    app_state: Arc<AppState>,
) -> NetworkResult<Box<dyn Router>> {
    let dkg_handler = Arc::new(DkgProtocolHandler::new(app_state));
    let mut router_builder = network.create_router_builder()?;
    router_builder = router_builder.accept(DKG.to_vec(), dkg_handler);
    router_builder.spawn()
}

/// Create a router with both DKG and PRE protocol handlers
///
/// This is the recommended function for setting up a full node that supports
/// both DKG and PRE protocols.
///
/// # Arguments
/// * `network` - The network instance to create router for
/// * `app_state` - The application state (needed for coordinators)
pub fn create_router_with_handlers(
    network: &Arc<dyn network::Network>,
    app_state: Arc<AppState>,
) -> NetworkResult<Box<dyn Router>> {
    let dkg_handler = Arc::new(DkgProtocolHandler::new(app_state.clone()));
    let pre_handler = Arc::new(PreProtocolHandler::new(app_state));

    let mut router_builder = network.create_router_builder()?;
    router_builder = router_builder.accept(DKG.to_vec(), dkg_handler);
    router_builder = router_builder.accept(REENCRYPT.to_vec(), pre_handler);
    router_builder.spawn()
}
