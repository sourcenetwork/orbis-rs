//! Iroh Router for ALPN-based protocol routing
//!
//! This module provides a router that can compose multiple protocols
//! using iroh's ALPN (Application-Layer Protocol Negotiation) support.

use anyhow::Error as AnyError;
use iroh::protocol::Router as IrohRouter;
use iroh::Endpoint;
use std::sync::Arc;

use crate::error::Result;
use crate::iroh::base::IrohConnectionWrapper;
use crate::r#trait::ProtocolHandler;

/// ALPN protocol identifiers for Orbis
pub mod alpn {
    /// DKG protocol between ring nodes
    pub const DKG: &[u8] = b"orbis/dkg/0";

    /// Re-encryption requests (Bob → Ring nodes)
    pub const REENCRYPT: &[u8] = b"orbis/reencrypt/0";

    /// Ring node coordination
    pub const COORD: &[u8] = b"orbis/coord/0";
}

/// Router for composing multiple protocols over a single iroh endpoint
///
/// This router uses iroh's Router builder to handle multiple protocols
/// via ALPN negotiation. Each protocol can have its own handler.
pub struct Router {
    router: IrohRouter,
}

impl Router {
    /// Create a new router builder from an endpoint
    pub fn builder(endpoint: Endpoint) -> RouterBuilder {
        RouterBuilder {
            endpoint,
            handlers: Vec::new(),
        }
    }

    /// Shutdown the router
    pub async fn shutdown(self) -> Result<()> {
        self.router.shutdown().await.map_err(|e| {
            crate::error::NetworkError::Protocol(format!("Failed to shutdown router: {}", e))
        })?;
        Ok(())
    }
}

/// Builder for creating a router with multiple protocol handlers
pub struct RouterBuilder {
    endpoint: Endpoint,
    handlers: Vec<(Vec<u8>, Arc<dyn ProtocolHandler>)>,
}

impl RouterBuilder {
    /// Register a protocol handler for a specific ALPN
    pub fn accept(mut self, alpn: Vec<u8>, handler: Arc<dyn ProtocolHandler>) -> Self {
        self.handlers.push((alpn, handler));
        self
    }

    /// Spawn the router with all registered handlers
    pub fn spawn(self) -> Router {
        let mut builder = IrohRouter::builder(self.endpoint.clone());

        for (alpn, handler) in self.handlers {
            let handler_wrapper = IrohProtocolHandlerWrapper { handler };
            builder = builder.accept(alpn, Arc::new(handler_wrapper));
        }

        let router = builder.spawn();
        Router { router }
    }
}

/// Wrapper to adapt our ProtocolHandler to iroh's ProtocolHandler
struct IrohProtocolHandlerWrapper {
    handler: Arc<dyn ProtocolHandler>,
}

impl std::fmt::Debug for IrohProtocolHandlerWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrohProtocolHandlerWrapper")
            .field("handler", &"<ProtocolHandler>")
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
        async move {
            // Convert iroh connection to our Connection trait
            let conn = IrohConnectionWrapper::new(connection);

            // Call our handler
            handler.handle(Box::new(conn)).await.map_err(|e| {
                // Convert NetworkError to AcceptError
                // NetworkError implements std::error::Error via thiserror
                // Use the Display implementation to create a string error
                iroh::protocol::AcceptError::from_err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ))
            })?;

            Ok(())
        }
    }
}
