//! Iroh Router for ALPN-based protocol routing
//!
//! This module provides a router that can compose multiple protocols
//! using iroh's ALPN (Application-Layer Protocol Negotiation) support.

use async_trait::async_trait;
use iroh::protocol::Router as IrohRouter;
use iroh::Endpoint;
use std::sync::Arc;

use crate::error::{NetworkError, Result};
use crate::ingress::IngressController;
use crate::iroh::base::IrohStreamWrapper;
use crate::metrics;
use crate::r#trait::{PeerId, ProtocolHandler};
use crate::r#trait::{Router as RouterTrait, RouterBuilder as RouterBuilderTrait};

/// Router for composing multiple protocols over a single iroh endpoint
///
/// This router uses iroh's Router builder to handle multiple protocols
/// via ALPN negotiation. Each protocol can have its own handler.
pub struct IrohRouterWrapper {
    router: IrohRouter,
}

#[async_trait]
impl RouterTrait for IrohRouterWrapper {
    async fn shutdown(self: Box<Self>) -> Result<()> {
        self.router
            .shutdown()
            .await
            .map_err(|e| NetworkError::Protocol(format!("Failed to shutdown router: {}", e)))?;
        Ok(())
    }
}

/// Builder for creating a router with multiple protocol handlers
pub struct IrohRouterBuilder {
    endpoint: Endpoint,
    gossip: Option<iroh_gossip::net::Gossip>,
    handlers: Vec<(Vec<u8>, Arc<dyn ProtocolHandler>)>,
    max_message_size: usize,
    ingress: Arc<IngressController>,
}

impl RouterBuilderTrait for IrohRouterBuilder {
    fn accept(
        mut self: Box<Self>,
        protocol: Vec<u8>,
        handler: Arc<dyn ProtocolHandler>,
    ) -> Box<dyn RouterBuilderTrait> {
        self.handlers.push((protocol, handler));
        Box::new(*self)
    }

    fn max_message_size(mut self: Box<Self>, size: usize) -> Box<dyn RouterBuilderTrait> {
        self.max_message_size = size;
        Box::new(*self)
    }

    fn spawn(self: Box<Self>) -> Result<Box<dyn RouterTrait>> {
        let mut builder = IrohRouter::builder(self.endpoint.clone());
        if let Some(gossip) = self.gossip.clone() {
            // Gossip owns long-lived mesh connections, so its raw ALPN handler
            // cannot use the per-application-work wrapper below. Authenticated
            // PubSub frames use the same ingress controller in IrohTopic::recv.
            builder = builder.accept(iroh_gossip::ALPN, gossip);
        }
        let max_message_size = self.max_message_size;

        for (alpn, handler) in self.handlers {
            let handler_wrapper = IrohProtocolHandlerWrapper {
                handler,
                max_message_size,
                ingress: Arc::clone(&self.ingress),
            };
            builder = builder.accept(alpn, Arc::new(handler_wrapper));
        }

        let router = builder.spawn();
        Ok(Box::new(IrohRouterWrapper { router }))
    }
}

impl IrohRouterBuilder {
    /// Create a new router builder from an endpoint
    pub(crate) fn new(
        endpoint: Endpoint,
        gossip: Option<iroh_gossip::net::Gossip>,
        max_message_size: usize,
        ingress: Arc<IngressController>,
    ) -> Self {
        Self {
            endpoint,
            gossip,
            handlers: Vec::new(),
            max_message_size,
            ingress,
        }
    }
}

/// Wrapper to adapt our ProtocolHandler to iroh's ProtocolHandler
struct IrohProtocolHandlerWrapper {
    handler: Arc<dyn ProtocolHandler>,
    max_message_size: usize,
    ingress: Arc<IngressController>,
}

impl std::fmt::Debug for IrohProtocolHandlerWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrohProtocolHandlerWrapper")
            .field("handler", &"<ProtocolHandler>")
            .field("max_message_size", &self.max_message_size)
            .finish()
    }
}

#[async_trait::async_trait]
impl iroh::protocol::ProtocolHandler for IrohProtocolHandlerWrapper {
    fn accept(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> impl std::future::Future<Output = std::result::Result<(), iroh::protocol::AcceptError>> + Send
    {
        let handler = Arc::clone(&self.handler);
        let max_message_size = self.max_message_size;
        let ingress = Arc::clone(&self.ingress);
        async move {
            let peer_id = PeerId::from_bytes(connection.remote_id().as_bytes());
            let protocol: Arc<[u8]> = Arc::from(connection.alpn());

            // Loop: accept one QUIC stream per request/session, spawn a handler task per stream.
            // This lets concurrent sessions to the same peer run on independent streams
            // with no head-of-line blocking between them.
            while let Ok((send, recv)) = connection.accept_bi().await {
                let lease = match ingress.try_admit(&peer_id).await {
                    Ok(lease) => lease,
                    Err(reason) => {
                        metrics::record_ingress_dropped(protocol.as_ref(), reason.as_str());
                        drop(send);
                        drop(recv);
                        continue;
                    }
                };

                let stream = IrohStreamWrapper::new(
                    send,
                    recv,
                    peer_id.clone(),
                    Arc::clone(&protocol),
                    max_message_size,
                );
                let h = Arc::clone(&handler);
                let handler_peer_id = peer_id.clone();
                let handler_protocol = Arc::clone(&protocol);
                tokio::spawn(async move {
                    let _lease = lease;
                    let _ = h.handle(Box::new(stream)).await.inspect_err(|error| {
                        tracing::error!(
                            peer_id = ?handler_peer_id,
                            protocol = %String::from_utf8_lossy(handler_protocol.as_ref()),
                            error = %error,
                            "Network protocol handler failed"
                        );
                    });
                });
            }

            Ok(())
        }
    }
}
