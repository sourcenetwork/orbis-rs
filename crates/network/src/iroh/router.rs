//! Iroh Router for ALPN-based protocol routing
//!
//! This module provides a router that can compose multiple protocols
//! using iroh's ALPN (Application-Layer Protocol Negotiation) support.

use async_trait::async_trait;
use iroh::protocol::Router as IrohRouter;
use iroh::Endpoint;
use std::sync::Arc;
use std::time::Duration;

use crate::error::{NetworkError, Result};
use crate::ingress::IngressController;
use crate::iroh::base::IrohStreamWrapper;
use crate::metrics;
use crate::r#trait::{PeerId, ProtocolHandler};
use crate::r#trait::{Router as RouterTrait, RouterBuilder as RouterBuilderTrait};

/// Consecutive stream-admission refusals on one QUIC connection before it is
/// closed. A peer that keeps opening streams while pinned at its per-peer cap or
/// stream rate limit is otherwise an unbounded accept/drop loop.
const MAX_CONSECUTIVE_STREAM_REFUSALS: u32 = 128;

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
    read_timeout: Duration,
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
        let read_timeout = self.read_timeout;

        for (alpn, handler) in self.handlers {
            let handler_wrapper = IrohProtocolHandlerWrapper {
                handler,
                max_message_size,
                read_timeout,
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
        read_timeout: Duration,
        ingress: Arc<IngressController>,
    ) -> Self {
        Self {
            endpoint,
            gossip,
            handlers: Vec::new(),
            max_message_size,
            read_timeout,
            ingress,
        }
    }
}

/// Wrapper to adapt our ProtocolHandler to iroh's ProtocolHandler
struct IrohProtocolHandlerWrapper {
    handler: Arc<dyn ProtocolHandler>,
    max_message_size: usize,
    read_timeout: Duration,
    ingress: Arc<IngressController>,
}

impl std::fmt::Debug for IrohProtocolHandlerWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrohProtocolHandlerWrapper")
            .field("handler", &"<ProtocolHandler>")
            .field("max_message_size", &self.max_message_size)
            .field("read_timeout", &self.read_timeout)
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
        let read_timeout = self.read_timeout;
        let ingress = Arc::clone(&self.ingress);
        async move {
            let peer_id = PeerId::from_bytes(connection.remote_id().as_bytes());
            let protocol: Arc<[u8]> = Arc::from(connection.alpn());
            let mut consecutive_refusals: u32 = 0;

            // Loop: accept one QUIC stream per request/session, spawn a handler task per stream.
            // This lets concurrent sessions to the same peer run on independent streams
            // with no head-of-line blocking between them.
            while let Ok((send, recv)) = connection.accept_bi().await {
                // One slot per accepted stream, held for the stream's lifetime
                // and bounded per peer; one peer-rate tick for the open itself.
                // Frame-level work and receive-byte admission are charged
                // separately, inside `IrohStreamWrapper::recv`.
                let stream_lease = match ingress.try_admit_stream(&peer_id).await {
                    Ok(lease) => {
                        consecutive_refusals = 0;
                        lease
                    }
                    Err(reason) => {
                        metrics::record_ingress_dropped(protocol.as_ref(), reason.as_str());
                        drop(send);
                        drop(recv);
                        consecutive_refusals += 1;
                        if consecutive_refusals >= MAX_CONSECUTIVE_STREAM_REFUSALS {
                            metrics::record_ingress_dropped(
                                protocol.as_ref(),
                                "connection_terminated",
                            );
                            connection
                                .close(1u32.into(), b"ingress: repeated stream admission failures");
                            break;
                        }
                        continue;
                    }
                };

                let stream = IrohStreamWrapper::new(
                    send,
                    recv,
                    peer_id.clone(),
                    Arc::clone(&protocol),
                    max_message_size,
                    read_timeout,
                    Some(Arc::clone(&ingress)),
                );
                let h = Arc::clone(&handler);
                let handler_peer_id = peer_id.clone();
                let handler_protocol = Arc::clone(&protocol);
                tokio::spawn(async move {
                    let _stream_lease = stream_lease;
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
