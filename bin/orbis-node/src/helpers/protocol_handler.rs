//! Generic protocol handler loop for MPC network protocols.
//!
//! All three protocols (DKG, PRE, Sign) share the same connection loop:
//! recv → deserialize → maybe store response → route to coordinator → send reply.
//!
//! This module provides:
//! - `MessageCoordinator` — a trait that each coordinator implements to plug
//!   into the generic loop (how to make an error message, how to decide if a
//!   message is a "stored response", how to route a request).
//! - `GenericProtocolHandler<C>` — the single `ProtocolHandler` impl that
//!   drives the loop for any `C: MessageCoordinator`.

use async_trait::async_trait;
use network::error::Result as NetworkResult;
use network::{Connection, Message, PeerId, ProtocolHandler};
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;

/// Coordinator behaviour needed by the generic network handler loop.
#[async_trait]
pub trait MessageCoordinator: Send + Sync + 'static {
    /// The protocol-level message type (e.g. `DkgMessage`, `PreMessage`).
    type Msg: DeserializeOwned + Serialize + Send + Sync + 'static;

    /// Short protocol name used in tracing output (e.g. `"DKG"`, `"PRE"`, `"Sign"`).
    fn protocol_name(&self) -> &'static str;

    /// Extract a printable ID from a message for log context and error replies.
    fn message_id(msg: &Self::Msg) -> String;

    /// Build an error message to send back to the peer.
    ///
    /// `id` is the request/session ID extracted from the failing message
    /// (or `"unknown"` when deserialization failed before we could read it).
    fn make_error(&self, id: &str, error: String) -> Self::Msg;

    /// Handle a message that is a peer response (e.g. `ReencryptResponse`,
    /// `SignResponse`, `NonceResponse`) by storing it for the initiator.
    ///
    /// Returns `None` if the message was consumed (caller should `continue`),
    /// or `Some(msg)` if it is not a response and should proceed to
    /// `route_message`.
    async fn try_store_response(&self, msg: Self::Msg, peer_id: &PeerId) -> Option<Self::Msg>;

    /// Handle a protocol request and return an optional reply.
    async fn route_message(
        &self,
        msg: Self::Msg,
        peer_id: &PeerId,
    ) -> anyhow::Result<Option<Self::Msg>>;
}

/// Generic `ProtocolHandler` that runs the shared recv/deserialize/route loop.
pub struct GenericProtocolHandler<C: MessageCoordinator> {
    coordinator: Arc<C>,
}

impl<C: MessageCoordinator> GenericProtocolHandler<C> {
    pub fn new(coordinator: Arc<C>) -> Self {
        Self { coordinator }
    }
}

#[async_trait]
impl<C: MessageCoordinator> ProtocolHandler for GenericProtocolHandler<C> {
    async fn handle(&self, connection: Box<dyn Connection>) -> NetworkResult<()> {
        let peer_id = connection.peer_id().clone();
        let proto = self.coordinator.protocol_name();
        tracing::info!(peer_id = ?peer_id, "{}: Accepted connection from peer", proto);

        loop {
            let Ok(network_message) = connection.recv().await.inspect_err(|error| {
                tracing::debug!(
                    peer_id = ?peer_id,
                    error = %error,
                    "{}: Connection closed or error from peer", proto
                );
            }) else {
                break;
            };

            let message: C::Msg = match serde_json::from_slice(&network_message.data) {
                Ok(msg) => msg,
                Err(e) => {
                    tracing::error!(
                        peer_id = ?peer_id,
                        error = %e,
                        "{}: Failed to deserialize message from peer", proto
                    );
                    let err_msg = self
                        .coordinator
                        .make_error("unknown", format!("Failed to deserialize message: {}", e));
                    if let Ok(data) = serde_json::to_vec(&err_msg) {
                        let _ = connection
                            .send(Message::new(data, network_message.protocol))
                            .await;
                    }
                    continue;
                }
            };

            let msg_id = C::message_id(&message);
            tracing::debug!(
                message_type = ?std::mem::discriminant(&message),
                id = %msg_id,
                peer_id = ?peer_id,
                "{}: Received message", proto
            );

            // Short-circuit if this is a peer response to be stored
            let message = match self.coordinator.try_store_response(message, &peer_id).await {
                None => continue, // consumed
                Some(msg) => msg, // proceed to routing
            };

            match self.coordinator.route_message(message, &peer_id).await {
                Ok(Some(response)) => {
                    if let Ok(data) = serde_json::to_vec(&response) {
                        if let Err(e) = connection
                            .send(Message::new(data, network_message.protocol))
                            .await
                        {
                            tracing::error!(
                                error = %e,
                                "{}: Failed to send response to peer", proto
                            );
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::error!(error = %e, "{}: Coordinator error", proto);
                    let err_msg = self.coordinator.make_error(&msg_id, e.to_string());
                    if let Ok(data) = serde_json::to_vec(&err_msg) {
                        let _ = connection
                            .send(Message::new(data, network_message.protocol))
                            .await;
                    }
                }
            }
        }

        tracing::debug!(peer_id = ?peer_id, "{}: Connection closed with peer", proto);
        Ok(())
    }
}
