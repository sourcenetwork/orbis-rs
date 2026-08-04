//! Software network shaping — approximates WAN delay, jitter, and packet
//! loss for in-process (no-container) networks, where there is no per-node
//! network namespace to apply real `tc netem`-style shaping to (unlike
//! `orbis-bench`'s Docker backend, which applies `tc netem` to each
//! container's own egress interface).
//!
//! `ShapedNetwork` wraps a node's own `Arc<dyn Network>` and applies the
//! configured delay/jitter/loss to every outbound send *this node* makes —
//! symmetrically, whether the send happens on a connection this node opened
//! (`connect`/`open_stream`) or one it accepted (`create_router_builder`).
//! That symmetry matches Docker's per-container egress-only `tc netem`
//! semantics: every node shapes its own outbound traffic, in both roles.
//!
//! Loss here is a hard per-message send/receive failure, not (real QUIC's)
//! transparent per-UDP-packet retransmission — a coarser approximation than
//! `tc netem`, whose loss operates below QUIC's own recovery. Treat
//! shaped-network loss numbers as directional, not calibrated against real
//! WAN QUIC behavior.
//!
//! Only compiled when the `shaping` feature is enabled.

use crate::error::{NetworkError, Result};
use crate::pubsub::{AuthenticatedMessage, PubSub, PubSubEvent, SignedPayload, Topic, TopicId};
use crate::r#trait::{
    Connection, Message, Network, PeerConnection, PeerId, ProtocolHandler, Router, RouterBuilder,
};
use async_trait::async_trait;
use bytes::Bytes;
use rand::Rng;
use std::sync::Arc;
use std::time::Duration;

/// Delay/jitter/loss applied to every outbound send this node makes. Fixed
/// for the lifetime of the [`ShapedNetwork`] it's attached to — unlike
/// `FaultNetwork`'s fault injection, there's no runtime controller to change
/// it mid-run.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NetworkShapingProfile {
    pub delay_ms: f64,
    pub jitter_ms: f64,
    pub loss_percent: f64,
}

impl NetworkShapingProfile {
    /// No delay, no jitter, no loss.
    pub const NONE: Self = Self {
        delay_ms: 0.0,
        jitter_ms: 0.0,
        loss_percent: 0.0,
    };

    /// True when this profile would not alter traffic at all — callers may
    /// use this to skip wrapping a network entirely rather than pay for a
    /// passthrough wrapper.
    pub fn is_noop(&self) -> bool {
        self.delay_ms <= 0.0 && self.jitter_ms <= 0.0 && self.loss_percent <= 0.0
    }

    async fn delay(&self) {
        if self.delay_ms <= 0.0 && self.jitter_ms <= 0.0 {
            return;
        }
        let jittered = if self.jitter_ms > 0.0 {
            let offset = rand::thread_rng().gen_range(-self.jitter_ms..=self.jitter_ms);
            (self.delay_ms + offset).max(0.0)
        } else {
            self.delay_ms
        };
        tokio::time::sleep(Duration::from_secs_f64(jittered / 1000.0)).await;
    }

    fn should_drop(&self) -> bool {
        self.loss_percent > 0.0 && rand::thread_rng().gen_range(0.0..100.0) < self.loss_percent
    }
}

/// Wraps a node's own network with [`NetworkShapingProfile`]-based delay,
/// jitter, and loss. See module docs for the approximation this makes.
pub struct ShapedNetwork {
    inner: Arc<dyn Network>,
    profile: NetworkShapingProfile,
}

impl ShapedNetwork {
    /// Wrap `inner` with `profile`. A no-op (`NetworkShapingProfile::NONE`,
    /// or all-zero fields) still wraps but every method becomes a thin,
    /// zero-delay passthrough.
    pub fn new(inner: Arc<dyn Network>, profile: NetworkShapingProfile) -> Self {
        Self { inner, profile }
    }
}

struct ShapedConnection {
    inner: Box<dyn Connection>,
    profile: NetworkShapingProfile,
}

#[async_trait]
impl Connection for ShapedConnection {
    async fn send(&self, message: Message) -> Result<()> {
        self.profile.delay().await;
        if self.profile.should_drop() {
            return Err(NetworkError::Connection(
                "ShapedNetwork: simulated WAN packet loss on send".to_string(),
            ));
        }
        self.inner.send(message).await
    }

    async fn recv(&self) -> Result<Message> {
        let message = self.inner.recv().await?;
        self.profile.delay().await;
        if self.profile.should_drop() {
            return Err(NetworkError::Connection(
                "ShapedNetwork: simulated WAN packet loss on recv".to_string(),
            ));
        }
        Ok(message)
    }

    fn peer_id(&self) -> &PeerId {
        self.inner.peer_id()
    }
}

struct ShapedPeerConnection {
    inner: Box<dyn PeerConnection>,
    profile: NetworkShapingProfile,
}

#[async_trait]
impl PeerConnection for ShapedPeerConnection {
    async fn open_stream(&self) -> Result<Box<dyn Connection>> {
        let inner = self.inner.open_stream().await?;
        Ok(Box::new(ShapedConnection {
            inner,
            profile: self.profile,
        }))
    }

    fn peer_id(&self) -> &PeerId {
        self.inner.peer_id()
    }

    async fn close(&self) -> Result<()> {
        self.inner.close().await
    }
}

struct ShapedProtocolHandler {
    inner: Arc<dyn ProtocolHandler>,
    profile: NetworkShapingProfile,
}

#[async_trait]
impl ProtocolHandler for ShapedProtocolHandler {
    async fn handle(&self, connection: Box<dyn Connection>) -> Result<()> {
        let shaped = Box::new(ShapedConnection {
            inner: connection,
            profile: self.profile,
        });
        self.inner.handle(shaped).await
    }
}

struct ShapedRouterBuilder {
    inner: Box<dyn RouterBuilder>,
    profile: NetworkShapingProfile,
}

impl RouterBuilder for ShapedRouterBuilder {
    fn accept(
        self: Box<Self>,
        protocol: Vec<u8>,
        handler: Arc<dyn ProtocolHandler>,
    ) -> Box<dyn RouterBuilder> {
        let profile = self.profile;
        let wrapped: Arc<dyn ProtocolHandler> = Arc::new(ShapedProtocolHandler {
            inner: handler,
            profile,
        });
        let inner = self.inner.accept(protocol, wrapped);
        Box::new(ShapedRouterBuilder { inner, profile })
    }

    fn max_message_size(self: Box<Self>, size: usize) -> Box<dyn RouterBuilder> {
        let profile = self.profile;
        let inner = self.inner.max_message_size(size);
        Box::new(ShapedRouterBuilder { inner, profile })
    }

    fn spawn(self: Box<Self>) -> Result<Box<dyn Router>> {
        self.inner.spawn()
    }
}

struct ShapedPubSub {
    inner: Arc<dyn PubSub>,
    profile: NetworkShapingProfile,
}

struct ShapedTopic {
    inner: Arc<dyn Topic>,
    profile: NetworkShapingProfile,
}

#[async_trait]
impl PubSub for ShapedPubSub {
    async fn sign(&self, domain: &[u8], data: Bytes) -> Result<SignedPayload> {
        self.inner.sign(domain, data).await
    }

    async fn verify(&self, domain: &[u8], payload: &SignedPayload) -> Result<AuthenticatedMessage> {
        self.inner.verify(domain, payload).await
    }

    async fn subscribe(&self, topic: TopicId, bootstrap: Vec<PeerId>) -> Result<Arc<dyn Topic>> {
        let inner = self.inner.subscribe(topic, bootstrap).await?;
        Ok(Arc::new(ShapedTopic {
            inner,
            profile: self.profile,
        }))
    }
}

#[async_trait]
impl Topic for ShapedTopic {
    fn id(&self) -> TopicId {
        self.inner.id()
    }

    async fn broadcast(&self, data: Bytes) -> Result<()> {
        self.profile.delay().await;
        if self.profile.should_drop() {
            // Matches real Gossip fire-and-forget semantics (and
            // `FaultTopic`'s precedent): a dropped broadcast is invisible to
            // the publisher, not a reported error.
            return Ok(());
        }
        self.inner.broadcast(data).await
    }

    async fn recv(&self) -> Result<PubSubEvent> {
        let event = self.inner.recv().await?;
        if matches!(event, PubSubEvent::Received(_)) {
            self.profile.delay().await;
            if self.profile.should_drop() {
                return Ok(PubSubEvent::Lagged);
            }
        }
        Ok(event)
    }
}

#[async_trait]
impl Network for ShapedNetwork {
    async fn connect(&self, peer_id: &PeerId, protocol: &[u8]) -> Result<Box<dyn PeerConnection>> {
        let inner = self.inner.connect(peer_id, protocol).await?;
        Ok(Box::new(ShapedPeerConnection {
            inner,
            profile: self.profile,
        }))
    }

    /// Not used — `ShapedNetwork` is always started via `create_router_builder`.
    async fn listen(&mut self, _protocol: &[u8], _handler: Box<dyn ProtocolHandler>) -> Result<()> {
        Err(NetworkError::Protocol(
            "ShapedNetwork: use create_router_builder".to_string(),
        ))
    }

    fn local_peer_id(&self) -> PeerId {
        self.inner.local_peer_id()
    }

    fn local_address(&self) -> Result<String> {
        self.inner.local_address()
    }

    fn bound_addresses(&self) -> Vec<std::net::SocketAddr> {
        self.inner.bound_addresses()
    }

    fn pubsub(&self) -> Option<Arc<dyn PubSub>> {
        self.inner.pubsub().map(|inner| {
            Arc::new(ShapedPubSub {
                inner,
                profile: self.profile,
            }) as Arc<dyn PubSub>
        })
    }

    fn create_router_builder(&self) -> Result<Box<dyn RouterBuilder>> {
        let inner = self.inner.create_router_builder()?;
        Ok(Box::new(ShapedRouterBuilder {
            inner,
            profile: self.profile,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::NetworkShapingProfile;

    #[test]
    fn zero_profile_is_a_noop() {
        assert!(NetworkShapingProfile::NONE.is_noop());
        assert!(!NetworkShapingProfile {
            delay_ms: 25.0,
            jitter_ms: 5.0,
            loss_percent: 0.1,
        }
        .is_noop());
    }

    #[test]
    fn loss_rolls_are_bounded_by_the_configured_percent() {
        let never = NetworkShapingProfile {
            delay_ms: 0.0,
            jitter_ms: 0.0,
            loss_percent: 0.0,
        };
        let always = NetworkShapingProfile {
            delay_ms: 0.0,
            jitter_ms: 0.0,
            loss_percent: 100.0,
        };
        assert!((0..1000).all(|_| !never.should_drop()));
        assert!((0..1000).all(|_| always.should_drop()));
    }
}
