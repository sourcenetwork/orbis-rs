//! Iroh Router for ALPN-based protocol routing
//!
//! This module provides a router that can compose multiple protocols
//! using iroh's ALPN (Application-Layer Protocol Negotiation) support.

use async_trait::async_trait;
use iroh::protocol::Router as IrohRouter;
use iroh::Endpoint;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

use crate::error::{NetworkError, Result};
use crate::iroh::base::IrohStreamWrapper;
use crate::metrics;
use crate::r#trait::{PeerId, ProtocolHandler, RouterIngressLimits};
use crate::r#trait::{Router as RouterTrait, RouterBuilder as RouterBuilderTrait};

const MAX_TRACKED_RATE_LIMIT_PEERS: usize = 8192;
const RATE_LIMIT_PEER_IDLE_TTL: Duration = Duration::from_secs(60);

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
    ingress_limits: RouterIngressLimits,
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

    fn max_concurrent_streams(mut self: Box<Self>, limit: usize) -> Box<dyn RouterBuilderTrait> {
        self.ingress_limits.max_concurrent_streams = limit;
        Box::new(*self)
    }

    fn max_streams_per_peer_per_second(
        mut self: Box<Self>,
        limit: usize,
    ) -> Box<dyn RouterBuilderTrait> {
        self.ingress_limits.max_streams_per_peer_per_second = limit;
        Box::new(*self)
    }

    fn spawn(self: Box<Self>) -> Result<Box<dyn RouterTrait>> {
        let mut builder = IrohRouter::builder(self.endpoint.clone());
        if let Some(gossip) = self.gossip.clone() {
            // Native Gossip intentionally bypasses IrohProtocolHandlerWrapper.
            // The limits configured in create_routers.rs therefore apply only
            // to wrapped ALPN handlers, not this raw Gossip handler.
            builder = builder.accept(iroh_gossip::ALPN, gossip);
        }
        let max_message_size = self.max_message_size;
        let ingress_limits = self.ingress_limits;
        // One semaphore and one rate-limiter table shared across every ALPN so
        // the limits are global rather than per-protocol.
        let concurrent_streams = Arc::new(Semaphore::new(ingress_limits.max_concurrent_streams));
        let peer_rate_limiters: Arc<Mutex<HashMap<PeerId, FixedWindowRateLimiter>>> =
            Arc::new(Mutex::new(HashMap::new()));

        for (alpn, handler) in self.handlers {
            let handler_wrapper = IrohProtocolHandlerWrapper {
                handler,
                max_message_size,
                ingress_limits,
                concurrent_streams: Arc::clone(&concurrent_streams),
                peer_rate_limiters: Arc::clone(&peer_rate_limiters),
            };
            builder = builder.accept(alpn, Arc::new(handler_wrapper));
        }

        let router = builder.spawn();
        Ok(Box::new(IrohRouterWrapper { router }))
    }
}

impl IrohRouterBuilder {
    /// Create a new router builder from an endpoint
    pub fn new(endpoint: Endpoint, gossip: Option<iroh_gossip::net::Gossip>) -> Self {
        Self {
            endpoint,
            gossip,
            handlers: Vec::new(),
            max_message_size: 1024 * 1024, // 1MB default
            ingress_limits: RouterIngressLimits::default(),
        }
    }
}

struct FixedWindowRateLimiter {
    max_events: usize,
    window: Duration,
    window_start: Instant,
    last_seen: Instant,
    events: usize,
}

impl FixedWindowRateLimiter {
    fn new(max_events: usize, window: Duration) -> Self {
        let now = Instant::now();
        Self {
            max_events,
            window,
            window_start: now,
            last_seen: now,
            events: 0,
        }
    }

    fn allow(&mut self) -> bool {
        let now = Instant::now();
        self.last_seen = now;

        if now.duration_since(self.window_start) >= self.window {
            self.window_start = now;
            self.events = 0;
        }

        if self.events >= self.max_events {
            return false;
        }

        self.events += 1;
        true
    }

    fn is_idle(&self, now: Instant, idle_ttl: Duration) -> bool {
        now.duration_since(self.last_seen) >= idle_ttl
    }
}

/// Wrapper to adapt our ProtocolHandler to iroh's ProtocolHandler
struct IrohProtocolHandlerWrapper {
    handler: Arc<dyn ProtocolHandler>,
    max_message_size: usize,
    ingress_limits: RouterIngressLimits,
    concurrent_streams: Arc<Semaphore>,
    peer_rate_limiters: Arc<Mutex<HashMap<PeerId, FixedWindowRateLimiter>>>,
}

impl std::fmt::Debug for IrohProtocolHandlerWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrohProtocolHandlerWrapper")
            .field("handler", &"<ProtocolHandler>")
            .field("max_message_size", &self.max_message_size)
            .field("ingress_limits", &self.ingress_limits)
            .finish()
    }
}

fn try_acquire_stream_permit(permits: &Arc<Semaphore>) -> Option<OwnedSemaphorePermit> {
    Arc::clone(permits).try_acquire_owned().ok()
}

async fn allow_peer_stream(
    peer_rate_limiters: &Arc<Mutex<HashMap<PeerId, FixedWindowRateLimiter>>>,
    peer_id: &PeerId,
    max_streams_per_second: usize,
) -> bool {
    let mut limiters = peer_rate_limiters.lock().await;
    if !limiters.contains_key(peer_id) && limiters.len() >= MAX_TRACKED_RATE_LIMIT_PEERS {
        let now = Instant::now();
        limiters.retain(|_, limiter| !limiter.is_idle(now, RATE_LIMIT_PEER_IDLE_TTL));

        if limiters.len() >= MAX_TRACKED_RATE_LIMIT_PEERS {
            // Evict the least-recently-seen peer so the new peer gets a slot
            // rather than being hard-rejected due to map capacity alone.
            let lrs_key = limiters
                .iter()
                .min_by_key(|(_, limiter)| limiter.last_seen)
                .map(|(k, _)| k.clone());
            if let Some(key) = lrs_key {
                limiters.remove(&key);
            }
        }
    }

    let limiter = limiters.entry(peer_id.clone()).or_insert_with(|| {
        FixedWindowRateLimiter::new(max_streams_per_second, Duration::from_secs(1))
    });

    limiter.allow()
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
        let ingress_limits = self.ingress_limits;
        let concurrent_streams = Arc::clone(&self.concurrent_streams);
        let peer_rate_limiters = Arc::clone(&self.peer_rate_limiters);
        async move {
            let peer_id = PeerId::from_bytes(connection.remote_id().as_bytes());
            let protocol: Arc<[u8]> = Arc::from(connection.alpn());

            // Loop: accept one QUIC stream per request/session, spawn a handler task per stream.
            // This lets concurrent sessions to the same peer run on independent streams
            // with no head-of-line blocking between them.
            while let Ok((send, recv)) = connection.accept_bi().await {
                if !allow_peer_stream(
                    &peer_rate_limiters,
                    &peer_id,
                    ingress_limits.max_streams_per_peer_per_second,
                )
                .await
                {
                    metrics::record_ingress_dropped(protocol.as_ref(), "rate_limit");
                    drop(send);
                    drop(recv);
                    continue;
                }

                let Some(permit) = try_acquire_stream_permit(&concurrent_streams) else {
                    metrics::record_ingress_dropped(protocol.as_ref(), "concurrency_limit");
                    drop(send);
                    drop(recv);
                    continue;
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
                    let _permit = permit;
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

#[cfg(test)]
mod tests {
    use super::FixedWindowRateLimiter;
    use std::time::Duration;

    #[test]
    fn fixed_window_rate_limiter_rejects_after_limit() {
        let mut limiter = FixedWindowRateLimiter::new(2, Duration::from_secs(60));

        assert!(limiter.allow());
        assert!(limiter.allow());
        assert!(!limiter.allow());
    }

    #[test]
    fn fixed_window_rate_limiter_zero_limit_rejects_all() {
        let mut limiter = FixedWindowRateLimiter::new(0, Duration::from_secs(60));

        assert!(!limiter.allow());
    }
}
