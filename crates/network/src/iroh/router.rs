//! Iroh Router for ALPN-based protocol routing
//!
//! This module provides a router that can compose multiple protocols
//! using iroh's ALPN (Application-Layer Protocol Negotiation) support.

use async_trait::async_trait;
use iroh::protocol::Router as IrohRouter;
use iroh::Endpoint;
use std::sync::Arc;

use crate::error::Result;
use crate::iroh::base::IrohStreamWrapper;
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
        self.router.shutdown().await.map_err(|e| {
            crate::error::NetworkError::Protocol(format!("Failed to shutdown router: {}", e))
        })?;
        Ok(())
    }
}

/// Builder for creating a router with multiple protocol handlers
pub struct IrohRouterBuilder {
    endpoint: Endpoint,
    handlers: Vec<(Vec<u8>, Arc<dyn ProtocolHandler>)>,
    max_message_size: usize,
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
        let max_message_size = self.max_message_size;

        for (alpn, handler) in self.handlers {
            let handler_wrapper = IrohProtocolHandlerWrapper {
                handler,
                max_message_size,
            };
            builder = builder.accept(alpn, Arc::new(handler_wrapper));
        }

        let router = builder.spawn();
        Ok(Box::new(IrohRouterWrapper { router }))
    }
}

impl IrohRouterBuilder {
    /// Create a new router builder from an endpoint
    pub fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            handlers: Vec::new(),
            max_message_size: 1024 * 1024, // 1MB default
        }
    }
}

/// Wrapper to adapt our ProtocolHandler to iroh's ProtocolHandler
struct IrohProtocolHandlerWrapper {
    handler: Arc<dyn ProtocolHandler>,
    max_message_size: usize,
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
        async move {
            let peer_id = PeerId::from_bytes(connection.remote_id().as_bytes());
            let protocol: Arc<[u8]> = Arc::from(connection.alpn());

            // Loop: accept one QUIC stream per request/session, spawn a handler task per stream.
            // This lets concurrent sessions to the same peer run on independent streams
            // with no head-of-line blocking between them.
            loop {
                match connection.accept_bi().await {
                    Ok((send, recv)) => {
                        let stream = IrohStreamWrapper::new(
                            send,
                            recv,
                            peer_id.clone(),
                            Arc::clone(&protocol),
                            max_message_size,
                        );
                        let h = Arc::clone(&handler);
                        tokio::spawn(async move {
                            let _ = h.handle(Box::new(stream)).await;
                        });
                    }
                    Err(_) => {
                        break;
                    }
                }
            }

            Ok(())
        }
    }
}
