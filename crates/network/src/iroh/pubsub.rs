//! Authenticated Iroh Gossip adapter.

use async_trait::async_trait;
use bincode::Options;
use bytes::Bytes;
use futures::StreamExt;
use iroh::discovery::static_provider::StaticProvider;
use iroh::{Endpoint, EndpointAddr, PublicKey, Signature};
use iroh_gossip::api::{Event, GossipReceiver, GossipSender};
use iroh_gossip::net::Gossip;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Instant;
use tokio::sync::Mutex;

use crate::error::{NetworkError, Result};
use crate::ingress::IngressController;
use crate::metrics;
use crate::pubsub::{
    AuthenticatedMessage, PubSub, PubSubEvent, PubSubRejectReason, SignedPayload, Topic, TopicId,
};
use crate::{IngressDropReason, PeerId};

const SIGNING_DOMAIN: &[u8] = b"orbis-authenticated-pubsub-v1";

fn signed_bytes(domain: &[u8], data: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(SIGNING_DOMAIN.len() + 8 + domain.len() + 8 + data.len());
    bytes.extend_from_slice(SIGNING_DOMAIN);
    bytes.extend_from_slice(&(domain.len() as u64).to_be_bytes());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&(data.len() as u64).to_be_bytes());
    bytes.extend_from_slice(data);
    bytes
}

fn topic_domain(topic: TopicId) -> Vec<u8> {
    let mut domain = b"orbis-gossip-topic-v1".to_vec();
    domain.extend_from_slice(topic.as_bytes());
    domain
}

#[derive(Debug, Serialize, Deserialize)]
struct TopicWireMessage {
    delivery_id: [u8; 16],
    payload: SignedPayload,
}

fn topic_delivery_domain(topic: TopicId, delivery_id: &[u8; 16]) -> Vec<u8> {
    let mut domain = topic_domain(topic);
    domain.extend_from_slice(b"/delivery/");
    domain.extend_from_slice(delivery_id);
    domain
}

fn encode_topic_wire(message: &TopicWireMessage) -> Result<Vec<u8>> {
    codec()
        .serialize(message)
        .map_err(|error| NetworkError::Serialization(error.to_string()))
}

#[cfg(test)]
pub(crate) fn encode_topic_frame_for_test(
    endpoint: &Endpoint,
    topic: TopicId,
    data: &[u8],
) -> Vec<u8> {
    let delivery_id = [17; 16];
    let signature = endpoint.secret_key().sign(&signed_bytes(
        &topic_delivery_domain(topic, &delivery_id),
        data,
    ));
    encode_topic_wire(&TopicWireMessage {
        delivery_id,
        payload: SignedPayload {
            origin: endpoint.id().as_bytes().to_vec(),
            signature: signature.to_bytes().to_vec(),
            data: data.to_vec(),
        },
    })
    .expect("test topic frame must encode")
}

fn decode_topic_wire(bytes: &[u8]) -> Result<TopicWireMessage> {
    codec()
        .with_limit(bytes.len() as u64)
        .deserialize(bytes)
        .map_err(|error| NetworkError::Serialization(error.to_string()))
}

fn verify_signed(domain: &[u8], payload: &SignedPayload) -> Result<AuthenticatedMessage> {
    let origin: [u8; PublicKey::LENGTH] = payload.origin.as_slice().try_into().map_err(|_| {
        NetworkError::Protocol("authenticated payload origin must be 32 bytes".to_string())
    })?;
    let signature: [u8; Signature::LENGTH] =
        payload.signature.as_slice().try_into().map_err(|_| {
            NetworkError::Protocol("authenticated payload signature must be 64 bytes".to_string())
        })?;
    let origin = PublicKey::from_bytes(&origin)
        .map_err(|error| NetworkError::Protocol(error.to_string()))?;
    origin
        .verify(
            &signed_bytes(domain, &payload.data),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| NetworkError::Protocol("invalid endpoint signature".to_string()))?;
    Ok(AuthenticatedMessage {
        origin: PeerId::from_bytes(origin.as_bytes()),
        delivered_from: PeerId::from_bytes(origin.as_bytes()),
        data: payload.data.clone().into(),
        signature: payload.signature.clone(),
        delivery_id: None,
        ingress_lease: None,
    })
}

fn authenticate_topic_frame(
    topic: TopicId,
    delivered_from: PeerId,
    bytes: &[u8],
) -> std::result::Result<AuthenticatedMessage, PubSubRejectReason> {
    let wire = decode_topic_wire(bytes).map_err(|_| PubSubRejectReason::MalformedEnvelope)?;
    let mut authenticated = verify_signed(
        &topic_delivery_domain(topic, &wire.delivery_id),
        &wire.payload,
    )
    .map_err(|_| PubSubRejectReason::InvalidAuthentication)?;
    authenticated.delivered_from = delivered_from;
    authenticated.delivery_id = Some(wire.delivery_id);
    Ok(authenticated)
}

fn codec() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
}

fn endpoint_id(peer: &PeerId) -> Result<PublicKey> {
    if let Ok(raw) = <&[u8; 32]>::try_from(peer.as_bytes()) {
        return PublicKey::from_bytes(raw)
            .map_err(|error| NetworkError::InvalidAddress(error.to_string()));
    }

    let text = std::str::from_utf8(peer.as_bytes())
        .map_err(|_| NetworkError::InvalidAddress("peer ID is not UTF-8".to_string()))?;
    let node_part = text.split_once('@').map_or(text, |(node, _)| node);
    PublicKey::from_str(node_part).map_err(|error| NetworkError::InvalidAddress(error.to_string()))
}

/// Iroh Gossip implementation of authenticated pub-sub.
#[derive(Clone)]
pub struct IrohPubSub {
    endpoint: Endpoint,
    gossip: Gossip,
    static_provider: StaticProvider,
    ingress: Arc<IngressController>,
}

impl IrohPubSub {
    pub(crate) fn new(
        endpoint: Endpoint,
        gossip: Gossip,
        static_provider: StaticProvider,
        ingress: Arc<IngressController>,
    ) -> Self {
        Self {
            endpoint,
            gossip,
            static_provider,
            ingress,
        }
    }
}

async fn endpoint_addr(peer: &PeerId) -> Result<EndpointAddr> {
    let public_key = endpoint_id(peer)?;
    let Ok(text) = std::str::from_utf8(peer.as_bytes()) else {
        return Ok(EndpointAddr::new(public_key));
    };
    let Some((_, address)) = text.split_once('@') else {
        return Ok(EndpointAddr::new(public_key));
    };
    let socket = if let Ok(socket) = address.parse::<std::net::SocketAddr>() {
        socket
    } else {
        tokio::net::lookup_host(address)
            .await
            .map_err(|error| NetworkError::InvalidAddress(error.to_string()))?
            .next()
            .ok_or_else(|| {
                NetworkError::InvalidAddress(format!("no addresses found for {address}"))
            })?
    };
    Ok(EndpointAddr::new(public_key).with_ip_addr(socket))
}

struct IrohTopic {
    id: TopicId,
    endpoint: Endpoint,
    sender: GossipSender,
    receiver: Mutex<GossipReceiver>,
    neighbors: StdMutex<HashSet<PublicKey>>,
    ingress: Arc<IngressController>,
    rate_limited_frames: AtomicU64,
    concurrency_limited_frames: AtomicU64,
}

impl IrohTopic {
    fn record_ingress_drop(&self, delivered_from: &PeerId, reason: IngressDropReason) {
        metrics::record_ingress_dropped(iroh_gossip::ALPN, reason.as_str());
        let counter = match reason {
            IngressDropReason::RateLimit => &self.rate_limited_frames,
            IngressDropReason::ConcurrencyLimit => &self.concurrency_limited_frames,
        };
        let dropped = counter.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        if dropped == 1 || dropped.is_power_of_two() {
            tracing::warn!(
                topic = %hex::encode(self.id.as_bytes()),
                delivered_from = %hex::encode(delivered_from.as_bytes()),
                reason = reason.as_str(),
                dropped_frames = dropped,
                "dropping Gossip frame at network ingress"
            );
        }
    }
}

impl Drop for IrohTopic {
    fn drop(&mut self) {
        let count = self
            .neighbors
            .lock()
            .map(|neighbors| neighbors.len())
            .unwrap_or_default();
        if count > 0 {
            metrics::P2P_GOSSIP_NEIGHBORS
                .with_label_values(&[metrics::protocol_label(iroh_gossip::ALPN).as_str()])
                .sub(count as f64);
        }
    }
}

#[async_trait]
impl Topic for IrohTopic {
    fn id(&self) -> TopicId {
        self.id
    }

    async fn broadcast(&self, data: Bytes) -> Result<()> {
        let start = Instant::now();
        // Iroh Gossip derives its message ID from the full wire content. A
        // fresh authenticated delivery ID lets an application deliberately
        // retransmit identical semantic bytes after a mesh change without the
        // prior delivery being suppressed as a duplicate.
        let delivery_id: [u8; 16] = rand::random();
        let domain = topic_delivery_domain(self.id, &delivery_id);
        let signature = self
            .endpoint
            .secret_key()
            .sign(&signed_bytes(&domain, &data));
        let message = TopicWireMessage {
            delivery_id,
            payload: SignedPayload {
                origin: self.endpoint.id().as_bytes().to_vec(),
                signature: signature.to_bytes().to_vec(),
                data: data.to_vec(),
            },
        };
        let encoded = encode_topic_wire(&message)?;
        let encoded_len = encoded.len();
        let result = self
            .sender
            .broadcast(encoded.into())
            .await
            .map_err(|error| NetworkError::Protocol(error.to_string()));
        match &result {
            Ok(()) => metrics::record_message_sent(
                iroh_gossip::ALPN,
                encoded_len,
                start.elapsed().as_secs_f64(),
            ),
            Err(_) => metrics::record_send_error(iroh_gossip::ALPN),
        }
        result
    }

    async fn recv(&self) -> Result<PubSubEvent> {
        let start = Instant::now();
        let event = self
            .receiver
            .lock()
            .await
            .next()
            .await
            .ok_or_else(|| NetworkError::Connection("gossip topic closed".to_string()))?
            .map_err(|error| NetworkError::Protocol(error.to_string()))?;

        let event = match event {
            Event::NeighborUp(peer) => {
                if self
                    .neighbors
                    .lock()
                    .map(|mut neighbors| neighbors.insert(peer))
                    .unwrap_or(false)
                {
                    metrics::P2P_GOSSIP_NEIGHBORS
                        .with_label_values(&[metrics::protocol_label(iroh_gossip::ALPN).as_str()])
                        .inc();
                }
                PubSubEvent::NeighborUp(PeerId::from_bytes(peer.as_bytes()))
            }
            Event::NeighborDown(peer) => {
                if self
                    .neighbors
                    .lock()
                    .map(|mut neighbors| neighbors.remove(&peer))
                    .unwrap_or(false)
                {
                    metrics::P2P_GOSSIP_NEIGHBORS
                        .with_label_values(&[metrics::protocol_label(iroh_gossip::ALPN).as_str()])
                        .dec();
                }
                PubSubEvent::NeighborDown(PeerId::from_bytes(peer.as_bytes()))
            }
            Event::Lagged => PubSubEvent::Lagged,
            Event::Received(message) => {
                metrics::record_message_received(
                    iroh_gossip::ALPN,
                    message.content.len(),
                    start.elapsed().as_secs_f64(),
                );
                let delivered_from = PeerId::from_bytes(message.delivered_from.as_bytes());
                let lease = match self.ingress.try_admit(&delivered_from).await {
                    Ok(lease) => lease,
                    Err(reason) => {
                        self.record_ingress_drop(&delivered_from, reason);
                        return Ok(PubSubEvent::IngressDropped {
                            delivered_from,
                            reason,
                        });
                    }
                };
                match authenticate_topic_frame(self.id, delivered_from.clone(), &message.content) {
                    Ok(mut authenticated) => {
                        authenticated.ingress_lease = Some(Arc::new(lease));
                        PubSubEvent::Received(authenticated)
                    }
                    Err(reason) => {
                        metrics::record_gossip_frame_rejected(iroh_gossip::ALPN, reason.as_str());
                        PubSubEvent::Rejected {
                            delivered_from,
                            reason,
                        }
                    }
                }
            }
        };
        Ok(event)
    }
}

#[async_trait]
impl PubSub for IrohPubSub {
    async fn sign(&self, domain: &[u8], data: Bytes) -> Result<SignedPayload> {
        let signature = self
            .endpoint
            .secret_key()
            .sign(&signed_bytes(domain, &data));
        Ok(SignedPayload {
            origin: self.endpoint.id().as_bytes().to_vec(),
            signature: signature.to_bytes().to_vec(),
            data: data.to_vec(),
        })
    }

    async fn verify(&self, domain: &[u8], payload: &SignedPayload) -> Result<AuthenticatedMessage> {
        verify_signed(domain, payload)
    }

    async fn verify_topic_delivery(
        &self,
        topic: TopicId,
        delivery_id: [u8; 16],
        payload: &SignedPayload,
    ) -> Result<AuthenticatedMessage> {
        verify_signed(&topic_delivery_domain(topic, &delivery_id), payload)
    }

    async fn subscribe(&self, topic: TopicId, bootstrap: Vec<PeerId>) -> Result<Arc<dyn Topic>> {
        let mut bootstrap_ids = Vec::with_capacity(bootstrap.len());
        for peer in &bootstrap {
            let address = endpoint_addr(peer).await?;
            bootstrap_ids.push(address.id);
            self.static_provider.add_endpoint_info(address);
        }
        let topic_id = iroh_gossip::TopicId::from_bytes(*topic.as_bytes());
        let subscription = if bootstrap_ids.is_empty() {
            self.gossip
                .subscribe(topic_id, bootstrap_ids)
                .await
                .map_err(|error| NetworkError::Protocol(error.to_string()))?
        } else {
            self.gossip
                .subscribe_and_join(topic_id, bootstrap_ids)
                .await
                .map_err(|error| NetworkError::Protocol(error.to_string()))?
        };
        let (sender, receiver) = subscription.split();
        Ok(Arc::new(IrohTopic {
            id: topic,
            endpoint: self.endpoint.clone(),
            sender,
            receiver: Mutex::new(receiver),
            neighbors: StdMutex::new(HashSet::new()),
            ingress: Arc::clone(&self.ingress),
            rate_limited_frames: AtomicU64::new(0),
            concurrency_limited_frames: AtomicU64::new(0),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_id_parser_accepts_raw_and_routable_ids() {
        let key = iroh::SecretKey::from_bytes(&[7; 32]).public();
        assert_eq!(
            endpoint_id(&PeerId::from_bytes(key.as_bytes())).unwrap(),
            key
        );
        let routable = format!("{}@127.0.0.1:1234", key);
        assert_eq!(
            endpoint_id(&PeerId::from_bytes(routable.as_bytes())).unwrap(),
            key
        );
    }

    #[test]
    fn signed_payload_rejects_tampering_and_wrong_domain() {
        let secret = iroh::SecretKey::from_bytes(&[11; 32]);
        let domain = b"test-domain";
        let data = b"authenticated contribution";
        let signature = secret.sign(&signed_bytes(domain, data));
        let mut payload = SignedPayload {
            origin: secret.public().as_bytes().to_vec(),
            signature: signature.to_bytes().to_vec(),
            data: data.to_vec(),
        };

        assert!(verify_signed(domain, &payload).is_ok());
        assert!(verify_signed(b"other-domain", &payload).is_err());
        payload.data[0] ^= 1;
        assert!(verify_signed(domain, &payload).is_err());
    }

    fn signed_topic_wire(secret: &iroh::SecretKey, topic: TopicId) -> Vec<u8> {
        let delivery_id = [13; 16];
        let data = b"authenticated topic payload";
        let signature = secret.sign(&signed_bytes(
            &topic_delivery_domain(topic, &delivery_id),
            data,
        ));
        encode_topic_wire(&TopicWireMessage {
            delivery_id,
            payload: SignedPayload {
                origin: secret.public().as_bytes().to_vec(),
                signature: signature.to_bytes().to_vec(),
                data: data.to_vec(),
            },
        })
        .unwrap()
    }

    #[test]
    fn malformed_topic_envelope_is_a_nonfatal_rejection() {
        let result = authenticate_topic_frame(
            TopicId::new([3; 32]),
            PeerId::from_bytes(&[4; 32]),
            b"not a bincode topic envelope",
        );

        assert!(matches!(result, Err(PubSubRejectReason::MalformedEnvelope)));
    }

    #[test]
    fn invalid_topic_authentication_is_a_nonfatal_rejection() {
        let topic = TopicId::new([3; 32]);
        let secret = iroh::SecretKey::from_bytes(&[11; 32]);
        let mut encoded = signed_topic_wire(&secret, topic);
        let mut wire = decode_topic_wire(&encoded).unwrap();
        wire.payload.data[0] ^= 1;
        encoded = encode_topic_wire(&wire).unwrap();

        let result = authenticate_topic_frame(topic, PeerId::from_bytes(&[4; 32]), &encoded);

        assert!(matches!(
            result,
            Err(PubSubRejectReason::InvalidAuthentication)
        ));
    }

    #[test]
    fn valid_topic_frame_preserves_origin_and_immediate_relay() {
        let topic = TopicId::new([3; 32]);
        let secret = iroh::SecretKey::from_bytes(&[11; 32]);
        let delivered_from = PeerId::from_bytes(&[4; 32]);
        let encoded = signed_topic_wire(&secret, topic);

        let authenticated =
            authenticate_topic_frame(topic, delivered_from.clone(), &encoded).unwrap();

        assert_eq!(
            authenticated.origin,
            PeerId::from_bytes(secret.public().as_bytes())
        );
        assert_eq!(authenticated.delivered_from, delivered_from);
        assert_eq!(&authenticated.data[..], b"authenticated topic payload");
    }
}
