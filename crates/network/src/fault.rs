//! Fault-injection network wrapper for testing network partition scenarios.
//!
//! `FaultNetwork` wraps any `Arc<dyn Network>` and can intercept both direct
//! connections and authenticated pub-sub traffic. This simulates node dropout,
//! network partitions, and Gossip loss in in-process integration tests without
//! adding test branches to production protocol code.
//!
//! Only compiled when the `fault-injection` feature is enabled.

use crate::error::{NetworkError, Result};
use crate::pubsub::{AuthenticatedMessage, PubSub, PubSubEvent, SignedPayload, Topic, TopicId};
use crate::r#trait::{
    Connection, Message, Network, PeerConnection, PeerId, ProtocolHandler, RouterBuilder,
};
use async_trait::async_trait;
use bytes::Bytes;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};

#[derive(Debug, Default)]
struct DropRule {
    pass_through: usize,
    remaining: usize,
    observed: usize,
}

impl DropRule {
    fn configure(&mut self, pass_through: usize, count: usize) {
        *self = Self {
            pass_through,
            remaining: count,
            observed: 0,
        };
    }

    fn clear(&mut self) {
        *self = Self::default();
    }

    fn should_drop(&mut self) -> bool {
        let observed = self.observed;
        self.observed = self.observed.saturating_add(1);
        if observed < self.pass_through || self.remaining == 0 {
            return false;
        }
        self.remaining -= 1;
        true
    }
}

struct FaultState {
    blocked_peers: RwLock<HashSet<String>>,
    gossip_deliveries: RwLock<DropRule>,
    gossip_broadcasts: RwLock<DropRule>,
    gossip_neighbor_flaps: RwLock<usize>,
    protocol_stream_failures: RwLock<HashMap<Vec<u8>, DropRule>>,
    protocol_response_failures: RwLock<HashMap<Vec<u8>, DropRule>>,
    protocol_response_stalls: RwLock<HashMap<Vec<u8>, (DropRule, Duration)>>,
    protocol_response_corruptions: RwLock<HashMap<Vec<u8>, DropRule>>,
    protocol_messages: RwLock<HashMap<Vec<u8>, VecDeque<Bytes>>>,
}

/// A network wrapper that can block outbound connections to specific peers.
///
/// Create via [`FaultNetwork::new`], which returns both the network and a
/// [`FaultNetworkController`] for controlling which peers are blocked.
pub struct FaultNetwork {
    inner: Arc<dyn Network>,
    state: Arc<FaultState>,
}

impl FaultNetwork {
    /// Wrap an existing network with fault-injection capabilities.
    ///
    /// Returns the wrapped network and a controller for blocking/unblocking peers.
    pub fn new(inner: Arc<dyn Network>) -> (Self, FaultNetworkController) {
        let state = Arc::new(FaultState {
            blocked_peers: RwLock::new(HashSet::new()),
            gossip_deliveries: RwLock::new(DropRule::default()),
            gossip_broadcasts: RwLock::new(DropRule::default()),
            gossip_neighbor_flaps: RwLock::new(0),
            protocol_stream_failures: RwLock::new(HashMap::new()),
            protocol_response_failures: RwLock::new(HashMap::new()),
            protocol_response_stalls: RwLock::new(HashMap::new()),
            protocol_response_corruptions: RwLock::new(HashMap::new()),
            protocol_messages: RwLock::new(HashMap::new()),
        });
        let controller = FaultNetworkController {
            state: state.clone(),
        };
        (Self { inner, state }, controller)
    }
}

/// Controller for a [`FaultNetwork`] that can block/unblock specific peers.
///
/// Cheaply cloneable — all clones share the same underlying fault state.
#[derive(Clone)]
pub struct FaultNetworkController {
    state: Arc<FaultState>,
}

impl FaultNetworkController {
    /// Block outbound connections to `hex` (64-char hex node ID).
    pub async fn block_peer(&self, hex: &str) {
        self.state
            .blocked_peers
            .write()
            .await
            .insert(hex.to_string());
    }

    /// Unblock outbound connections to `hex`.
    pub async fn unblock_peer(&self, hex: &str) {
        self.state.blocked_peers.write().await.remove(hex);
    }

    /// Return the set of currently blocked peer hex IDs.
    pub async fn blocked_peers(&self) -> Vec<String> {
        self.state
            .blocked_peers
            .read()
            .await
            .iter()
            .cloned()
            .collect()
    }

    /// Drop `count` authenticated Gossip deliveries after allowing
    /// `pass_through` deliveries. A dropped delivery is surfaced to the
    /// subscriber as [`PubSubEvent::Lagged`] so normal rejoin and completeness
    /// repair logic is exercised.
    pub async fn drop_gossip_deliveries_after(&self, pass_through: usize, count: usize) {
        self.state
            .gossip_deliveries
            .write()
            .await
            .configure(pass_through, count);
    }

    /// Silently drop `count` local Gossip broadcasts after allowing
    /// `pass_through` broadcasts. The publisher still sees success, matching a
    /// packet-loss or relay-omission fault rather than an application error.
    pub async fn drop_gossip_broadcasts_after(&self, pass_through: usize, count: usize) {
        self.state
            .gossip_broadcasts
            .write()
            .await
            .configure(pass_through, count);
    }

    /// Remove all configured Gossip delivery and broadcast faults.
    pub async fn clear_gossip_faults(&self) {
        self.state.gossip_deliveries.write().await.clear();
        self.state.gossip_broadcasts.write().await.clear();
        *self.state.gossip_neighbor_flaps.write().await = 0;
    }

    /// After the next `count` real neighbor-up events, enqueue an immediate
    /// down/up pair for the same authenticated peer. This models normal Gossip
    /// mesh optimization without disconnecting the underlying transport.
    pub async fn inject_gossip_neighbor_flaps(&self, count: usize) {
        *self.state.gossip_neighbor_flaps.write().await = count;
    }

    /// Fail `count` stream opens for one ALPN after allowing `pass_through`
    /// opens. Because the check lives on the cached peer connection, this also
    /// exercises reconnect/retry behavior after the initial QUIC connection
    /// has been established.
    pub async fn fail_protocol_streams_after(
        &self,
        protocol: &[u8],
        pass_through: usize,
        count: usize,
    ) {
        let mut failures = self.state.protocol_stream_failures.write().await;
        failures
            .entry(protocol.to_vec())
            .or_default()
            .configure(pass_through, count);
    }

    /// Clear all configured protocol faults: stream-open failures, response
    /// failures, response stalls, and response corruptions.
    pub async fn clear_protocol_faults(&self) {
        self.state.protocol_stream_failures.write().await.clear();
        self.state.protocol_response_failures.write().await.clear();
        self.state.protocol_response_stalls.write().await.clear();
        self.state
            .protocol_response_corruptions
            .write()
            .await
            .clear();
    }

    /// Fail `count` response receives for streams on `protocol` after allowing
    /// `pass_through` responses. The request bytes reach the remote handler, so
    /// protocol retries must resend an idempotent, byte-identical request.
    pub async fn fail_protocol_responses_after(
        &self,
        protocol: &[u8],
        pass_through: usize,
        count: usize,
    ) {
        self.state
            .protocol_response_failures
            .write()
            .await
            .entry(protocol.to_vec())
            .or_default()
            .configure(pass_through, count);
    }

    /// Stall `count` response receives for streams on `protocol` after
    /// allowing `pass_through` responses. This models a silent QUIC stream or
    /// peer that remains connected but never produces a response.
    pub async fn stall_protocol_responses_after(
        &self,
        protocol: &[u8],
        pass_through: usize,
        count: usize,
        duration: Duration,
    ) {
        let mut stalls = self.state.protocol_response_stalls.write().await;
        let (rule, configured_duration) = stalls
            .entry(protocol.to_vec())
            .or_insert_with(|| (DropRule::default(), duration));
        rule.configure(pass_through, count);
        *configured_duration = duration;
    }

    /// Replace `count` received response payloads with malformed bytes after
    /// allowing `pass_through` responses. This proves a forwarded caller sees
    /// the leader's semantic preparation error instead of waiting on its outer
    /// response timeout.
    pub async fn corrupt_protocol_responses_after(
        &self,
        protocol: &[u8],
        pass_through: usize,
        count: usize,
    ) {
        self.state
            .protocol_response_corruptions
            .write()
            .await
            .entry(protocol.to_vec())
            .or_default()
            .configure(pass_through, count);
    }

    /// Return the bounded sequence of outbound message payloads observed for
    /// `protocol`. This lets fault tests prove retry bytes are identical.
    pub async fn sent_protocol_messages(&self, protocol: &[u8]) -> Vec<Bytes> {
        self.state
            .protocol_messages
            .read()
            .await
            .get(protocol)
            .map(|messages| messages.iter().cloned().collect())
            .unwrap_or_default()
    }
}

struct FaultConnection {
    inner: Box<dyn Connection>,
    state: Arc<FaultState>,
    protocol: Vec<u8>,
}

#[async_trait]
impl Connection for FaultConnection {
    async fn send(&self, message: Message) -> Result<()> {
        const MAX_RECORDED_MESSAGES_PER_PROTOCOL: usize = 4096;
        {
            let mut observed = self.state.protocol_messages.write().await;
            let messages = observed.entry(self.protocol.clone()).or_default();
            if messages.len() == MAX_RECORDED_MESSAGES_PER_PROTOCOL {
                messages.pop_front();
            }
            messages.push_back(message.data.clone());
        }
        self.inner.send(message).await
    }

    async fn recv(&self) -> Result<Message> {
        let stall = {
            let mut stalls = self.state.protocol_response_stalls.write().await;
            stalls
                .get_mut(&self.protocol)
                .and_then(|(rule, duration)| rule.should_drop().then_some(*duration))
        };
        if let Some(duration) = stall {
            tokio::time::sleep(duration).await;
        }
        let should_fail = self
            .state
            .protocol_response_failures
            .write()
            .await
            .get_mut(&self.protocol)
            .is_some_and(DropRule::should_drop);
        if should_fail {
            return Err(NetworkError::Connection(format!(
                "FaultNetwork: injected response loss on protocol {}",
                String::from_utf8_lossy(&self.protocol)
            )));
        }
        let mut response = self.inner.recv().await?;
        let should_corrupt = self
            .state
            .protocol_response_corruptions
            .write()
            .await
            .get_mut(&self.protocol)
            .is_some_and(DropRule::should_drop);
        if should_corrupt {
            response.data = Bytes::from_static(b"FaultNetwork: malformed response");
        }
        Ok(response)
    }

    fn peer_id(&self) -> &PeerId {
        self.inner.peer_id()
    }
}

struct FaultPeerConnection {
    inner: Box<dyn PeerConnection>,
    state: Arc<FaultState>,
    peer_hex: String,
    protocol: Vec<u8>,
}

#[async_trait]
impl PeerConnection for FaultPeerConnection {
    async fn open_stream(&self) -> Result<Box<dyn crate::Connection>> {
        if self
            .state
            .blocked_peers
            .read()
            .await
            .contains(&self.peer_hex)
        {
            return Err(NetworkError::Connection(format!(
                "FaultNetwork: peer {} blocked",
                self.peer_hex
            )));
        }
        let should_fail = self
            .state
            .protocol_stream_failures
            .write()
            .await
            .get_mut(&self.protocol)
            .is_some_and(DropRule::should_drop);
        if should_fail {
            return Err(NetworkError::Connection(format!(
                "FaultNetwork: injected stream reset for peer {} on protocol {}",
                self.peer_hex,
                String::from_utf8_lossy(&self.protocol)
            )));
        }
        let inner = self.inner.open_stream().await?;
        Ok(Box::new(FaultConnection {
            inner,
            state: self.state.clone(),
            protocol: self.protocol.clone(),
        }))
    }

    fn peer_id(&self) -> &PeerId {
        self.inner.peer_id()
    }

    async fn close(&self) -> Result<()> {
        self.inner.close().await
    }
}

struct FaultPubSub {
    inner: Arc<dyn PubSub>,
    state: Arc<FaultState>,
}

struct FaultTopic {
    inner: Arc<dyn Topic>,
    state: Arc<FaultState>,
    pending_events: Mutex<VecDeque<PubSubEvent>>,
}

#[async_trait]
impl PubSub for FaultPubSub {
    async fn sign(&self, domain: &[u8], data: Bytes) -> Result<SignedPayload> {
        self.inner.sign(domain, data).await
    }

    async fn verify(&self, domain: &[u8], payload: &SignedPayload) -> Result<AuthenticatedMessage> {
        self.inner.verify(domain, payload).await
    }

    async fn subscribe(&self, topic: TopicId, bootstrap: Vec<PeerId>) -> Result<Arc<dyn Topic>> {
        let inner = self.inner.subscribe(topic, bootstrap).await?;
        Ok(Arc::new(FaultTopic {
            inner,
            state: self.state.clone(),
            pending_events: Mutex::new(VecDeque::new()),
        }))
    }
}

#[async_trait]
impl Topic for FaultTopic {
    fn id(&self) -> TopicId {
        self.inner.id()
    }

    async fn broadcast(&self, data: Bytes) -> Result<()> {
        if self.state.gossip_broadcasts.write().await.should_drop() {
            return Ok(());
        }
        self.inner.broadcast(data).await
    }

    async fn recv(&self) -> Result<PubSubEvent> {
        if let Some(event) = self.pending_events.lock().await.pop_front() {
            return Ok(event);
        }
        let event = self.inner.recv().await?;
        if matches!(event, PubSubEvent::Received(_))
            && self.state.gossip_deliveries.write().await.should_drop()
        {
            return Ok(PubSubEvent::Lagged);
        }
        if let PubSubEvent::NeighborUp(peer) = &event {
            let mut flaps = self.state.gossip_neighbor_flaps.write().await;
            if *flaps > 0 {
                *flaps -= 1;
                let mut pending = self.pending_events.lock().await;
                pending.push_back(PubSubEvent::NeighborDown(peer.clone()));
                pending.push_back(PubSubEvent::NeighborUp(peer.clone()));
            }
        }
        Ok(event)
    }
}

#[async_trait]
impl Network for FaultNetwork {
    /// Connect to a peer, returning an immediate error if the peer is blocked.
    ///
    /// Peer IDs in this codebase are the ASCII bytes of `"hex64@ip:port"` or
    /// just `"hex64"`. We extract the 64-char hex prefix and check the blocked set.
    async fn connect(&self, peer_id: &PeerId, protocol: &[u8]) -> Result<Box<dyn PeerConnection>> {
        let mut peer_hex = String::new();
        if let Ok(peer_str) = std::str::from_utf8(peer_id.as_bytes()) {
            let hex_id = peer_str.split('@').next().unwrap_or(peer_str);
            peer_hex = hex_id.to_string();
            if self.state.blocked_peers.read().await.contains(hex_id) {
                return Err(NetworkError::Connection(format!(
                    "FaultNetwork: peer {} blocked",
                    hex_id
                )));
            }
        }
        let inner = self.inner.connect(peer_id, protocol).await?;
        Ok(Box::new(FaultPeerConnection {
            inner,
            state: self.state.clone(),
            peer_hex,
            protocol: protocol.to_vec(),
        }))
    }

    /// Not used — FaultNetwork is always started via `create_router_builder`.
    async fn listen(&mut self, _protocol: &[u8], _handler: Box<dyn ProtocolHandler>) -> Result<()> {
        Err(NetworkError::Protocol(
            "FaultNetwork: use create_router_builder".to_string(),
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
            Arc::new(FaultPubSub {
                inner,
                state: self.state.clone(),
            }) as Arc<dyn PubSub>
        })
    }

    fn create_router_builder(&self) -> Result<Box<dyn RouterBuilder>> {
        self.inner.create_router_builder()
    }
}

#[cfg(test)]
mod tests {
    use super::DropRule;

    #[test]
    fn drop_rule_is_deterministic_and_bounded() {
        let mut rule = DropRule::default();
        rule.configure(1, 2);
        assert!(!rule.should_drop());
        assert!(rule.should_drop());
        assert!(rule.should_drop());
        assert!(!rule.should_drop());

        rule.clear();
        assert!(!rule.should_drop());
    }
}
