//! Authenticated topic-based broadcast abstractions.
//!
//! This API transports only opaque bytes. Protocol crates should wrap it in a
//! type-safe publisher that accepts public message variants only.

use crate::{IngressDropReason, PeerId, Result};
use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;

use crate::ingress::IngressLease;

/// A 32-byte topic identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TopicId([u8; 32]);

impl TopicId {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for TopicId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TopicId({})", hex::encode(self.0))
    }
}

/// A pub-sub message whose endpoint-identity signature has already been verified.
#[derive(Debug, Clone)]
pub struct AuthenticatedMessage {
    pub origin: PeerId,
    /// For a message received over an actual topic subscription, the
    /// immediate Gossip relay — not an attributable publisher, so this must
    /// not be used as protocol evidence (see [`PubSubEvent::Rejected`] and
    /// [`PubSubEvent::IngressDropped`], which document the same caveat).
    ///
    /// For a message produced by [`PubSub::verify`] on a standalone
    /// [`SignedPayload`] (no topic delivery involved, so no relay exists),
    /// this is simply set equal to `origin` rather than left meaningless;
    /// consumers must not read that as relay attribution either.
    pub delivered_from: PeerId,
    pub data: Bytes,
    /// Holds shared ingress capacity until the application finishes processing
    /// a message received from the network. Embedded-signature verification does
    /// not attach a lease.
    pub(crate) ingress_lease: Option<Arc<IngressLease>>,
}

/// Endpoint-identity-signed opaque payload suitable for embedding in a relayed
/// or batched protocol message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPayload {
    pub origin: Vec<u8>,
    pub signature: Vec<u8>,
    pub data: Vec<u8>,
}

impl SignedPayload {
    pub fn origin_peer_id(&self) -> PeerId {
        PeerId::from_bytes(&self.origin)
    }
}

/// Events emitted by a topic subscription.
#[derive(Debug, Clone)]
pub enum PubSubEvent {
    NeighborUp(PeerId),
    NeighborDown(PeerId),
    Received(AuthenticatedMessage),
    /// A Gossip frame reached the local subscriber but could not be
    /// authenticated. The subscription itself remains healthy.
    ///
    /// `delivered_from` identifies the immediate Gossip relay, not an
    /// attributable publisher, and must not be used as protocol evidence.
    Rejected {
        delivered_from: PeerId,
        reason: PubSubRejectReason,
    },
    /// An application frame was dropped by configured ingress admission.
    /// This is an availability event, not failed authentication or evidence of
    /// publisher misconduct. Consumers must keep the subscription and use their
    /// ordinary completeness-repair policy.
    IngressDropped {
        delivered_from: PeerId,
        reason: IngressDropReason,
    },
    /// The local subscriber stopped consuming quickly enough. Protocols must
    /// rejoin and repair their expected-message set before advancing.
    Lagged,
}

/// Bounded reasons for rejecting an unauthenticated Gossip frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PubSubRejectReason {
    MalformedEnvelope,
    InvalidAuthentication,
}

impl PubSubRejectReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedEnvelope => "malformed_envelope",
            Self::InvalidAuthentication => "invalid_authentication",
        }
    }
}

impl fmt::Display for PubSubRejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A live topic subscription.
#[async_trait]
pub trait Topic: Send + Sync {
    fn id(&self) -> TopicId;

    /// Sign with the local endpoint identity and broadcast to the topic.
    async fn broadcast(&self, data: Bytes) -> Result<()>;

    /// Receive the next topic event. An invalid application frame is returned
    /// as [`PubSubEvent::Rejected`]; only receiver/transport failure returns an
    /// error.
    async fn recv(&self) -> Result<PubSubEvent>;
}

/// Optional topic broadcast capability supplied by a network backend.
#[async_trait]
pub trait PubSub: Send + Sync {
    /// Sign a payload using the network endpoint identity. `domain` must bind the
    /// protocol, wire version, and semantic context in which the payload is valid.
    async fn sign(&self, domain: &[u8], data: Bytes) -> Result<SignedPayload>;

    /// Verify an embedded endpoint-identity signature.
    async fn verify(&self, domain: &[u8], payload: &SignedPayload) -> Result<AuthenticatedMessage>;

    /// Join a topic using authenticated endpoint identities as bootstrap peers.
    async fn subscribe(&self, topic: TopicId, bootstrap: Vec<PeerId>) -> Result<Arc<dyn Topic>>;
}
