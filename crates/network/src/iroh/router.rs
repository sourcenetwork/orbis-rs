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
use crate::ingress::{IngressController, StreamAdmitReason};
use crate::iroh::base::IrohStreamWrapper;
use crate::metrics;
use crate::r#trait::{PeerId, ProtocolHandler};
use crate::r#trait::{Router as RouterTrait, RouterBuilder as RouterBuilderTrait};

/// Consecutive *concurrency* stream-admission refusals (global / per-peer cap)
/// on one QUIC connection before it is closed. Those refusals are transient —
/// a slot frees and the next open succeeds — so a moderate streak is tolerated.
/// A stream-open *rate* refusal is not transient (the peer is over its
/// per-second budget), so it closes the connection immediately instead.
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
        // A route-level `max_message_size` override (via `RouterBuilder::
        // max_message_size`) can raise the accepted inbound frame size after the
        // network was built. Re-check it here: an inbound-request frame the
        // request receive-byte pool can never reserve would always fail
        // mid-`recv()`.
        let body_budget = self.ingress.max_inbound_request_body_bytes();
        if self.max_message_size > body_budget {
            return Err(NetworkError::InvalidConfig(format!(
                "router max_message_size ({}) exceeds the inbound-request receive-byte pool ({})",
                self.max_message_size, body_budget
            )));
        }

        let mut builder = IrohRouter::builder(self.endpoint.clone());
        if let Some(gossip) = self.gossip.clone() {
            // Gossip owns long-lived mesh connections, so its raw ALPN handler
            // cannot use the per-application-work wrapper below. It is wrapped
            // only for connection-level admission; authenticated PubSub frames
            // use the same ingress controller in IrohTopic::recv.
            builder = builder.accept(
                iroh_gossip::ALPN,
                Arc::new(GossipIngressGuard {
                    gossip,
                    ingress: Arc::clone(&self.ingress),
                }),
            );
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

            // One connection lease for this whole accept future — i.e. for the
            // connection's lifetime, since the `accept_bi()` loop below exits
            // only when the connection closes. Bounds identities that keep
            // connections alive with transport traffic but open no streams.
            let _connection_lease = match ingress.try_admit_connection(&peer_id).await {
                Ok(lease) => lease,
                Err(reason) => {
                    metrics::record_ingress_dropped(protocol.as_ref(), reason.as_str());
                    connection.close(1u32.into(), b"ingress: connection admission refused");
                    return Ok(());
                }
            };

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
                        // A stream-open rate refusal means the peer is over its
                        // per-second budget and reconnecting would only reset the
                        // per-connection streak, not the peer-level limiter — so
                        // close now, bounding wasted accept work to ~one refusal
                        // per connection attempt.
                        let terminate = matches!(reason, StreamAdmitReason::Rate) || {
                            consecutive_refusals += 1;
                            consecutive_refusals >= MAX_CONSECUTIVE_STREAM_REFUSALS
                        };
                        if terminate {
                            metrics::record_ingress_dropped(
                                protocol.as_ref(),
                                "connection_terminated",
                            );
                            connection.close(1u32.into(), b"ingress: stream admission refused");
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
                    Arc::clone(&ingress),
                    true,
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

/// Wraps the native Gossip ALPN handler so an inbound Gossip connection is
/// admission-controlled like any other. `Gossip::accept` hands the connection to
/// its actor and returns immediately, so the connection lease is held by a
/// side task that lives exactly as long as the connection.
struct GossipIngressGuard {
    gossip: iroh_gossip::net::Gossip,
    ingress: Arc<IngressController>,
}

impl std::fmt::Debug for GossipIngressGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GossipIngressGuard").finish()
    }
}

impl iroh::protocol::ProtocolHandler for GossipIngressGuard {
    async fn accept(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> std::result::Result<(), iroh::protocol::AcceptError> {
        let peer_id = PeerId::from_bytes(connection.remote_id().as_bytes());
        let lease = match self.ingress.try_admit_connection(&peer_id).await {
            Ok(lease) => lease,
            Err(reason) => {
                metrics::record_ingress_dropped(iroh_gossip::ALPN, reason.as_str());
                connection.close(1u32.into(), b"ingress: gossip connection refused");
                return Ok(());
            }
        };
        let watch = connection.clone();
        tokio::spawn(async move {
            let _lease = lease;
            watch.closed().await;
        });
        self.gossip.accept(connection).await
    }

    async fn shutdown(&self) {
        if let Err(error) = self.gossip.shutdown().await {
            tracing::warn!(%error, "error while shutting down gossip");
        }
    }
}
