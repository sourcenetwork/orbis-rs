//! Iroh-specific tests for the network crate
//!
//! This module runs the generic trait tests against the IrohNetwork implementation
//! and includes iroh-specific test cases.

use super::IrohNetwork;
use crate::r#trait::{Connection, Message, Network, ProtocolHandler};
use crate::tests as trait_tests;
use crate::{AuthenticatedMessage, PeerId, Result, SecretKey, Topic};
use crate::{PubSubEvent, TopicId};
use async_trait::async_trait;
use std::net::SocketAddrV4;
use std::sync::Arc;
use tokio::sync::{mpsc, Notify};

fn loopback() -> SocketAddrV4 {
    "127.0.0.1:0".parse().unwrap()
}

fn peer_addr(network: &IrohNetwork) -> PeerId {
    let node_id_str = network.local_address().expect("Should get local address");
    let bound_addrs = network.bound_addresses();

    if let Some(addr) = bound_addrs.first() {
        PeerId::from_bytes(format!("{}@{}", node_id_str, addr).as_bytes())
    } else {
        PeerId::from_bytes(node_id_str.as_bytes())
    }
}

async fn new_test_network() -> IrohNetwork {
    IrohNetwork::builder()
        .bind_addr_v4(loopback())
        .private_routes_only()
        .build()
        .await
        .expect("Should create network")
}

async fn wait_for_neighbor(topic: &Arc<dyn Topic>) {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let PubSubEvent::NeighborUp(_) = topic.recv().await.expect("topic event") {
                return;
            }
        }
    })
    .await
    .expect("topic should gain a neighbor");
}

async fn receive_authenticated(topic: &Arc<dyn Topic>) -> AuthenticatedMessage {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let PubSubEvent::Received(message) = topic.recv().await.expect("topic event") {
                return message;
            }
        }
    })
    .await
    .expect("topic should receive an authenticated message")
}

fn ingress_drop_count(reason: &'static str) -> f64 {
    let protocol = std::str::from_utf8(iroh_gossip::ALPN).expect("Gossip ALPN is UTF-8");
    crate::metrics::P2P_INGRESS_DROPPED_TOTAL
        .with_label_values(&[protocol, reason])
        .get()
}

async fn wait_for_ingress_drop(reason: &'static str, previous: f64) {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if ingress_drop_count(reason) > previous {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Gossip ingress drop should be recorded");
}
// ============================================================================
// Run Generic Trait Tests Against IrohNetwork
// ============================================================================

#[test]
fn test_name() {
    assert_eq!(IrohNetwork::name(), "network/iroh");
}

#[tokio::test]
#[serial_test::serial]
async fn iroh_network_creation() {
    let network = new_test_network().await;
    trait_tests::test_network_creation(&network).await;
}

#[tokio::test]
#[serial_test::serial]
async fn iroh_connection_establishment() {
    let net1 = new_test_network().await;
    let net2 = new_test_network().await;
    trait_tests::test_connection_establishment(&net1, &net2).await;
}

#[tokio::test]
#[serial_test::serial]
async fn iroh_single_message_roundtrip() {
    let net1 = new_test_network().await;
    let net2 = new_test_network().await;
    trait_tests::test_single_message_roundtrip(&net1, &net2).await;
}

#[tokio::test]
#[serial_test::serial]
async fn iroh_multiple_messages() {
    let net1 = new_test_network().await;
    let net2 = new_test_network().await;
    trait_tests::test_multiple_messages(&net1, &net2).await;
}

#[tokio::test]
#[serial_test::serial]
async fn iroh_large_message() {
    let net1 = new_test_network().await;
    let net2 = new_test_network().await;
    trait_tests::test_large_message(&net1, &net2).await;
}

#[tokio::test]
#[serial_test::serial]
async fn iroh_router_multiple_protocols() {
    let net1 = new_test_network().await;
    let net2 = new_test_network().await;
    trait_tests::test_router_multiple_protocols(&net1, &net2).await;
}

#[tokio::test]
#[serial_test::serial]
async fn iroh_connection_peer_id() {
    let net1 = new_test_network().await;
    let net2 = new_test_network().await;
    trait_tests::test_connection_peer_id(&net1, &net2).await;
}

#[tokio::test]
#[serial_test::serial]
async fn iroh_concurrent_connections() {
    let net1 = new_test_network().await;
    let net2 = new_test_network().await;
    let net3 = new_test_network().await;
    trait_tests::test_concurrent_connections(&net1, &net2, &net3).await;
}

#[tokio::test]
#[serial_test::serial]
async fn iroh_authenticated_pubsub_roundtrip() {
    let net1 = new_test_network().await;
    let net2 = new_test_network().await;
    let router1 = net1
        .create_router_builder()
        .unwrap()
        .spawn()
        .expect("spawn first gossip router");
    let router2 = net2
        .create_router_builder()
        .unwrap()
        .spawn()
        .expect("spawn second gossip router");

    let topic_id = TopicId::new([7u8; 32]);
    let topic1 = net1
        .pubsub()
        .expect("pubsub enabled")
        .subscribe(topic_id, vec![])
        .await
        .expect("open topic");
    let topic2 = net2
        .pubsub()
        .expect("pubsub enabled")
        .subscribe(topic_id, vec![peer_addr(&net1)])
        .await
        .expect("join topic");

    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let PubSubEvent::NeighborUp(_) = topic1.recv().await.expect("topic event") {
                break;
            }
        }
    })
    .await
    .expect("publisher should see the subscriber as a neighbor");

    for _ in 0..2 {
        topic1
            .broadcast(bytes::Bytes::from_static(b"signed payload"))
            .await
            .expect("broadcast identical semantic bytes");
    }

    let received = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut received = Vec::new();
        while received.len() < 2 {
            if let PubSubEvent::Received(message) = topic2.recv().await.expect("topic event") {
                received.push(message);
            }
        }
        received
    })
    .await
    .expect("receive both authenticated retransmissions");
    assert_eq!(received.len(), 2);
    for message in received {
        assert_eq!(message.origin, net1.local_peer_id());
        assert_eq!(&message.data[..], b"signed payload");
    }

    router1.shutdown().await.unwrap();
    router2.shutdown().await.unwrap();
}

#[tokio::test]
#[serial_test::serial]
async fn iroh_pubsub_applies_configured_concurrency_limit_and_recovers() {
    let publisher = new_test_network().await;
    let subscriber = IrohNetwork::builder()
        .bind_addr_v4(loopback())
        .private_routes_only()
        .max_concurrent_ingress_work(1)
        .build()
        .await
        .expect("create concurrency-limited subscriber");
    let publisher_router = publisher
        .create_router_builder()
        .unwrap()
        .spawn()
        .expect("spawn publisher router");
    let subscriber_router = subscriber
        .create_router_builder()
        .unwrap()
        .spawn()
        .expect("spawn subscriber router");

    let topic_id = TopicId::new([27; 32]);
    let publisher_topic = publisher
        .pubsub()
        .expect("pubsub enabled")
        .subscribe(topic_id, vec![])
        .await
        .expect("open publisher topic");
    let subscriber_topic = subscriber
        .pubsub()
        .expect("pubsub enabled")
        .subscribe(topic_id, vec![peer_addr(&publisher)])
        .await
        .expect("join subscriber topic");
    wait_for_neighbor(&publisher_topic).await;

    publisher_topic
        .broadcast(bytes::Bytes::from_static(b"first holds the permit"))
        .await
        .expect("broadcast first frame");
    let first = receive_authenticated(&subscriber_topic).await;
    assert_eq!(&first.data[..], b"first holds the permit");

    let drops_before = ingress_drop_count("concurrency_limit");
    let receive_task = tokio::spawn({
        let topic = Arc::clone(&subscriber_topic);
        async move { receive_authenticated(&topic).await }
    });
    publisher_topic
        .broadcast(bytes::Bytes::from_static(b"second must be dropped"))
        .await
        .expect("broadcast over-capacity frame");
    wait_for_ingress_drop("concurrency_limit", drops_before).await;

    drop(first);
    publisher_topic
        .broadcast(bytes::Bytes::from_static(b"third after release"))
        .await
        .expect("broadcast after permit release");
    let third = tokio::time::timeout(std::time::Duration::from_secs(10), receive_task)
        .await
        .expect("receive task should complete")
        .expect("receive task should not panic");
    assert_eq!(&third.data[..], b"third after release");

    publisher_router.shutdown().await.unwrap();
    subscriber_router.shutdown().await.unwrap();
}

#[tokio::test]
#[serial_test::serial]
async fn iroh_pubsub_applies_configured_peer_rate_limit_and_recovers() {
    let publisher = new_test_network().await;
    let subscriber = IrohNetwork::builder()
        .bind_addr_v4(loopback())
        .private_routes_only()
        .max_ingress_events_per_peer_per_second(1)
        .build()
        .await
        .expect("create rate-limited subscriber");
    let publisher_router = publisher
        .create_router_builder()
        .unwrap()
        .spawn()
        .expect("spawn publisher router");
    let subscriber_router = subscriber
        .create_router_builder()
        .unwrap()
        .spawn()
        .expect("spawn subscriber router");

    let topic_id = TopicId::new([28; 32]);
    let publisher_topic = publisher
        .pubsub()
        .expect("pubsub enabled")
        .subscribe(topic_id, vec![])
        .await
        .expect("open publisher topic");
    let subscriber_topic = subscriber
        .pubsub()
        .expect("pubsub enabled")
        .subscribe(topic_id, vec![peer_addr(&publisher)])
        .await
        .expect("join subscriber topic");
    wait_for_neighbor(&publisher_topic).await;

    publisher_topic
        .broadcast(bytes::Bytes::from_static(b"first in rate window"))
        .await
        .expect("broadcast first frame");
    let first = receive_authenticated(&subscriber_topic).await;
    assert_eq!(&first.data[..], b"first in rate window");
    drop(first);

    let drops_before = ingress_drop_count("rate_limit");
    let receive_task = tokio::spawn({
        let topic = Arc::clone(&subscriber_topic);
        async move { receive_authenticated(&topic).await }
    });
    publisher_topic
        .broadcast(bytes::Bytes::from_static(b"second must be rate limited"))
        .await
        .expect("broadcast over-rate frame");
    wait_for_ingress_drop("rate_limit", drops_before).await;

    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    publisher_topic
        .broadcast(bytes::Bytes::from_static(b"third in next window"))
        .await
        .expect("broadcast in next rate window");
    let third = tokio::time::timeout(std::time::Duration::from_secs(10), receive_task)
        .await
        .expect("receive task should complete")
        .expect("receive task should not panic");
    assert_eq!(&third.data[..], b"third in next window");

    publisher_router.shutdown().await.unwrap();
    subscriber_router.shutdown().await.unwrap();
}

#[tokio::test]
#[serial_test::serial]
async fn iroh_direct_stream_and_pubsub_share_the_concurrency_budget() {
    struct HoldingHandler {
        started: mpsc::Sender<()>,
        release: Arc<Notify>,
    }

    #[async_trait]
    impl ProtocolHandler for HoldingHandler {
        async fn handle(&self, connection: Box<dyn Connection>) -> Result<()> {
            // Retain the message so its frame-admission lease (the single work
            // permit) stays held while this handler blocks on `release`.
            let _held = connection.recv().await?;
            let _ = self.started.send(()).await;
            self.release.notified().await;
            Ok(())
        }
    }

    const SHARED_PROTOCOL: &[u8] = b"test/shared-ingress";
    let publisher = new_test_network().await;
    let subscriber = IrohNetwork::builder()
        .bind_addr_v4(loopback())
        .private_routes_only()
        .max_concurrent_ingress_work(1)
        .build()
        .await
        .expect("create concurrency-limited subscriber");
    let (started_tx, mut started_rx) = mpsc::channel(1);
    let release = Arc::new(Notify::new());
    let publisher_router = publisher
        .create_router_builder()
        .unwrap()
        .spawn()
        .expect("spawn publisher router");
    let subscriber_router = subscriber
        .create_router_builder()
        .unwrap()
        .accept(
            SHARED_PROTOCOL.to_vec(),
            Arc::new(HoldingHandler {
                started: started_tx,
                release: Arc::clone(&release),
            }),
        )
        .spawn()
        .expect("spawn subscriber router");

    let topic_id = TopicId::new([29; 32]);
    let publisher_topic = publisher
        .pubsub()
        .expect("pubsub enabled")
        .subscribe(topic_id, vec![])
        .await
        .expect("open publisher topic");
    let subscriber_topic = subscriber
        .pubsub()
        .expect("pubsub enabled")
        .subscribe(topic_id, vec![peer_addr(&publisher)])
        .await
        .expect("join subscriber topic");
    wait_for_neighbor(&publisher_topic).await;

    let connection = publisher
        .connect(&peer_addr(&subscriber), SHARED_PROTOCOL)
        .await
        .expect("connect direct protocol");
    let stream = connection.open_stream().await.expect("open direct stream");
    stream
        .send(Message::new(
            bytes::Bytes::from_static(b"hold shared permit"),
            SHARED_PROTOCOL,
        ))
        .await
        .expect("send direct request");
    tokio::time::timeout(std::time::Duration::from_secs(10), started_rx.recv())
        .await
        .expect("direct handler should start")
        .expect("direct handler signal");

    let drops_before = ingress_drop_count("concurrency_limit");
    let receive_task = tokio::spawn({
        let topic = Arc::clone(&subscriber_topic);
        async move { receive_authenticated(&topic).await }
    });
    publisher_topic
        .broadcast(bytes::Bytes::from_static(b"dropped while direct is busy"))
        .await
        .expect("broadcast while direct handler holds permit");
    wait_for_ingress_drop("concurrency_limit", drops_before).await;

    release.notify_waiters();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    publisher_topic
        .broadcast(bytes::Bytes::from_static(b"accepted after direct finishes"))
        .await
        .expect("broadcast after direct handler releases permit");
    let received = tokio::time::timeout(std::time::Duration::from_secs(10), receive_task)
        .await
        .expect("receive task should complete")
        .expect("receive task should not panic");
    assert_eq!(&received.data[..], b"accepted after direct finishes");

    connection.close().await.unwrap();
    publisher_router.shutdown().await.unwrap();
    subscriber_router.shutdown().await.unwrap();
}

#[tokio::test]
#[serial_test::serial]
async fn malformed_gossip_frame_does_not_end_the_subscription() {
    let net1 = new_test_network().await;
    let net2 = new_test_network().await;
    let router1 = net1
        .create_router_builder()
        .unwrap()
        .spawn()
        .expect("spawn raw gossip publisher router");
    let router2 = net2
        .create_router_builder()
        .unwrap()
        .spawn()
        .expect("spawn authenticated subscriber router");

    let topic_id = TopicId::new([19u8; 32]);
    let raw_topic = net1
        .gossip_for_tests()
        .subscribe(
            iroh_gossip::TopicId::from_bytes(*topic_id.as_bytes()),
            vec![],
        )
        .await
        .expect("open raw Gossip topic");
    let (raw_sender, _raw_receiver) = raw_topic.split();
    let authenticated_topic = net2
        .pubsub()
        .expect("pubsub enabled")
        .subscribe(topic_id, vec![peer_addr(&net1)])
        .await
        .expect("join authenticated topic");

    raw_sender
        .broadcast(bytes::Bytes::from_static(b"malformed outer envelope"))
        .await
        .expect("broadcast malformed frame");

    let rejection = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let PubSubEvent::Rejected {
                delivered_from,
                reason,
            } = authenticated_topic.recv().await.expect("topic event")
            {
                return (delivered_from, reason);
            }
        }
    })
    .await
    .expect("malformed frame should be surfaced without ending the stream");
    assert_eq!(rejection.0, net1.local_peer_id());
    assert_eq!(rejection.1, crate::PubSubRejectReason::MalformedEnvelope);

    let valid_frame = super::pubsub::encode_topic_frame_for_test(
        net1.endpoint(),
        topic_id,
        b"valid frame after rejection",
    );
    raw_sender
        .broadcast(valid_frame.into())
        .await
        .expect("broadcast valid frame");

    let received = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let PubSubEvent::Received(message) =
                authenticated_topic.recv().await.expect("topic event")
            {
                return message;
            }
        }
    })
    .await
    .expect("the same subscription should receive a later valid frame");
    assert_eq!(received.origin, net1.local_peer_id());
    assert_eq!(&received.data[..], b"valid frame after rejection");

    router1.shutdown().await.unwrap();
    router2.shutdown().await.unwrap();
}

#[tokio::test]
#[serial_test::serial]
async fn iroh_pubsub_sign_and_verify_roundtrip() {
    let net1 = new_test_network().await;
    let pubsub = net1.pubsub().expect("pubsub enabled");

    let domain = b"test-sign-verify-domain";
    let data = bytes::Bytes::from_static(b"authenticated payload");
    let payload = pubsub
        .sign(domain, data.clone())
        .await
        .expect("sign with local endpoint identity");

    let authenticated = pubsub
        .verify(domain, &payload)
        .await
        .expect("verify a correctly signed payload");
    assert_eq!(authenticated.origin, net1.local_peer_id());
    assert_eq!(authenticated.delivered_from, net1.local_peer_id());
    assert_eq!(&authenticated.data[..], &data[..]);

    // Wrong domain must be rejected — the signature binds the domain.
    assert!(pubsub.verify(b"wrong-domain", &payload).await.is_err());

    // Tampering with the signed data must be rejected too.
    let mut tampered = payload.clone();
    tampered.data[0] ^= 1;
    assert!(pubsub.verify(domain, &tampered).await.is_err());
}

#[tokio::test]
#[serial_test::serial]
async fn iroh_gossip_fans_out_to_multiple_subscribers() {
    let net1 = new_test_network().await;
    let net2 = new_test_network().await;
    let net3 = new_test_network().await;
    let router1 = net1
        .create_router_builder()
        .unwrap()
        .spawn()
        .expect("spawn first gossip router");
    let router2 = net2
        .create_router_builder()
        .unwrap()
        .spawn()
        .expect("spawn second gossip router");
    let router3 = net3
        .create_router_builder()
        .unwrap()
        .spawn()
        .expect("spawn third gossip router");

    let topic_id = TopicId::new([9u8; 32]);
    let topic1 = net1
        .pubsub()
        .expect("pubsub enabled")
        .subscribe(topic_id, vec![])
        .await
        .expect("open topic");
    let topic2 = net2
        .pubsub()
        .expect("pubsub enabled")
        .subscribe(topic_id, vec![peer_addr(&net1)])
        .await
        .expect("join topic from net2");
    let topic3 = net3
        .pubsub()
        .expect("pubsub enabled")
        .subscribe(topic_id, vec![peer_addr(&net1)])
        .await
        .expect("join topic from net3");

    // Wait for both subscribers to become neighbors of the publisher before
    // broadcasting, so the single broadcast below isn't lost to mesh churn.
    for topic in [&topic2, &topic3] {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if let PubSubEvent::NeighborUp(_) = topic.recv().await.expect("topic event") {
                    break;
                }
            }
        })
        .await
        .expect("subscriber should see the publisher as a neighbor");
    }

    topic1
        .broadcast(bytes::Bytes::from_static(b"fan-out payload"))
        .await
        .expect("broadcast to all subscribers");

    for topic in [&topic2, &topic3] {
        let received = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if let PubSubEvent::Received(message) = topic.recv().await.expect("topic event") {
                    return message;
                }
            }
        })
        .await
        .expect("each subscriber should receive the fan-out broadcast");
        assert_eq!(received.origin, net1.local_peer_id());
        assert_eq!(&received.data[..], b"fan-out payload");
    }

    router1.shutdown().await.unwrap();
    router2.shutdown().await.unwrap();
    router3.shutdown().await.unwrap();
}

#[test]
fn message_construction() {
    trait_tests::test_message_construction();
}

#[test]
fn peer_id_operations() {
    trait_tests::test_peer_id_operations();
}

// ============================================================================
// Iroh-Specific Tests
// ============================================================================

#[tokio::test]
#[serial_test::serial]
async fn iroh_builder_default_config() {
    let network = IrohNetwork::builder()
        .build()
        .await
        .expect("Should build with defaults");

    let config = network.config();
    assert_eq!(
        config.max_message_size,
        1024 * 1024,
        "Default max message size should be 1MB"
    );
    assert_eq!(config.ingress_limits.max_concurrent_work, 1024);
    assert_eq!(config.ingress_limits.max_events_per_peer_per_second, 512);
    assert_eq!(config.ingress_limits.max_concurrent_streams, 4096);
    assert_eq!(config.ingress_limits.max_streams_per_peer, 32);
    assert_eq!(
        config.ingress_limits.max_inbound_body_bytes,
        256 * 1024 * 1024
    );
    assert_eq!(
        config.stream_read_timeout,
        std::time::Duration::from_secs(30)
    );
}

#[tokio::test]
#[serial_test::serial]
async fn iroh_builder_custom_max_message_size() {
    let custom_size = 512 * 1024; // 512KB
    let network = IrohNetwork::builder()
        .max_message_size(custom_size)
        .max_concurrent_ingress_work(17)
        .max_ingress_events_per_peer_per_second(23)
        .max_concurrent_streams(29)
        .max_streams_per_peer(7)
        .max_inbound_body_bytes(9 * 1024 * 1024)
        .stream_read_timeout_ms(4_500)
        .build()
        .await
        .expect("Should build with custom config");

    let config = network.config();
    assert_eq!(config.max_message_size, custom_size);
    assert_eq!(config.ingress_limits.max_concurrent_work, 17);
    assert_eq!(config.ingress_limits.max_events_per_peer_per_second, 23);
    assert_eq!(config.ingress_limits.max_concurrent_streams, 29);
    assert_eq!(config.ingress_limits.max_streams_per_peer, 7);
    assert_eq!(
        config.ingress_limits.max_inbound_body_bytes,
        9 * 1024 * 1024
    );
    assert_eq!(
        config.stream_read_timeout,
        std::time::Duration::from_millis(4_500)
    );
}

#[tokio::test]
#[serial_test::serial]
async fn iroh_builder_rejects_zero_read_timeout() {
    let Err(error) = IrohNetwork::builder()
        .stream_read_timeout_ms(0)
        .build()
        .await
    else {
        panic!("a zero read timeout must be rejected at build time");
    };
    assert!(matches!(error, crate::NetworkError::InvalidConfig(_)));
}

#[tokio::test]
#[serial_test::serial]
async fn iroh_builder_rejects_body_budget_below_one_frame() {
    let Err(error) = IrohNetwork::builder()
        .max_message_size(4 * 1024 * 1024)
        .max_inbound_body_bytes(1024 * 1024)
        .build()
        .await
    else {
        panic!("body budget below max_message_size must be rejected");
    };
    assert!(matches!(error, crate::NetworkError::InvalidConfig(_)));
}

#[tokio::test]
#[serial_test::serial]
async fn iroh_endpoint_access() {
    let network = IrohNetwork::new().await.expect("Should create network");

    // Should be able to access the underlying iroh endpoint
    let endpoint = network.endpoint();
    let node_id = endpoint.id();

    // The endpoint's node ID should match the network's peer ID
    let peer_id = network.local_peer_id();
    assert_eq!(
        peer_id.as_bytes(),
        node_id.as_bytes(),
        "Endpoint ID should match peer ID"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn iroh_bound_addresses_populated() {
    let network = IrohNetwork::new().await.expect("Should create network");

    let bound_addrs = network.bound_addresses();

    // IrohNetwork should have at least one bound address
    assert!(
        !bound_addrs.is_empty(),
        "IrohNetwork should have bound socket addresses"
    );

    // All addresses should be valid socket addresses
    for addr in &bound_addrs {
        assert!(addr.port() > 0, "Port should be non-zero");
    }
}

#[tokio::test]
#[serial_test::serial]
async fn iroh_local_address_format() {
    let network = IrohNetwork::new().await.expect("Should create network");

    let address = network.local_address().expect("Should get local address");

    // Iroh addresses are node IDs (public keys in base32)
    assert!(!address.is_empty(), "Address should not be empty");
    // Node IDs are 52 characters (32 bytes in base32)
    assert!(
        address.len() >= 50,
        "Address should be a valid node ID format"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn iroh_router_builder_max_message_size() {
    struct LargeMessageHandler {
        expected_size: usize,
    }

    #[async_trait]
    impl ProtocolHandler for LargeMessageHandler {
        async fn handle(&self, connection: Box<dyn Connection>) -> Result<()> {
            if let Ok(msg) = connection.recv().await {
                assert_eq!(msg.data.len(), self.expected_size);
                connection.send(msg).await?;
                // Drain until remote closes — keeps stream alive for client read.
                let _ = connection.recv().await;
            }
            Ok(())
        }
    }

    // Both networks need larger max message size
    let large_size = 2 * 1024 * 1024; // 2MB
    let net1 = IrohNetwork::builder()
        .bind_addr_v4(loopback())
        .private_routes_only()
        .max_message_size(large_size)
        .build()
        .await
        .expect("Should create network 1");
    let net2 = IrohNetwork::builder()
        .bind_addr_v4(loopback())
        .private_routes_only()
        .build()
        .await
        .expect("Should create network 2");

    // Set max message size via router builder
    let router_builder = net2
        .create_router_builder()
        .expect("Should create router builder");
    let router = router_builder
        .max_message_size(large_size)
        .accept(
            b"test/large".to_vec(),
            Arc::new(LargeMessageHandler {
                expected_size: large_size - 1000, // Slightly under limit
            }),
        )
        .spawn()
        .expect("Should spawn router");

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let node_id_str = net2.local_address().expect("Should get local address");
    let bound_addrs = net2.bound_addresses();
    let peer_addr = if let Some(addr) = bound_addrs.first() {
        PeerId::from_bytes(format!("{}@{}", node_id_str, addr).as_bytes())
    } else {
        PeerId::from_bytes(node_id_str.as_bytes())
    };

    let conn = net1
        .connect(&peer_addr, b"test/large")
        .await
        .expect("Should connect");

    // Send a large message (just under 2MB)
    let large_data: Vec<u8> = vec![42u8; large_size - 1000];
    let msg = Message::new(
        bytes::Bytes::from(large_data.clone()),
        b"test/large".as_slice(),
    );
    let stream = conn.open_stream().await.expect("Should open stream");
    stream.send(msg).await.expect("Should send large message");

    let response = tokio::time::timeout(std::time::Duration::from_secs(10), stream.recv())
        .await
        .expect("Should not timeout")
        .expect("Should receive response");

    assert_eq!(response.data.len(), large_size - 1000);

    conn.close().await.expect("Should close");
    Box::new(router)
        .shutdown()
        .await
        .expect("Router should shutdown");
}

#[tokio::test]
#[serial_test::serial]
async fn iroh_router_builder_limits_concurrent_inbound_work() {
    struct HoldingHandler {
        started: mpsc::Sender<()>,
        release: Arc<Notify>,
    }

    #[async_trait]
    impl ProtocolHandler for HoldingHandler {
        async fn handle(&self, connection: Box<dyn Connection>) -> Result<()> {
            // Frame admission — the single work permit — is taken inside
            // `recv()`. Signal only after it succeeds, and hold the message so
            // the permit stays taken while this handler blocks.
            let _held = connection.recv().await?;
            let _ = self.started.send(()).await;
            self.release.notified().await;
            Ok(())
        }
    }

    let net1 = new_test_network().await;
    let net2 = IrohNetwork::builder()
        .bind_addr_v4(loopback())
        .private_routes_only()
        .max_concurrent_ingress_work(1)
        .build()
        .await
        .expect("Should create limited network");
    let (started_tx, mut started_rx) = mpsc::channel(4);
    let release = Arc::new(Notify::new());

    let router = net2
        .create_router_builder()
        .expect("Should create router builder")
        .accept(
            b"test/concurrency-limit".to_vec(),
            Arc::new(HoldingHandler {
                started: started_tx,
                release: Arc::clone(&release),
            }),
        )
        .spawn()
        .expect("Should spawn router");

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let conn = net1
        .connect(&peer_addr(&net2), b"test/concurrency-limit")
        .await
        .expect("Should connect");

    let stream1 = conn.open_stream().await.expect("Should open stream 1");
    stream1
        .send(Message::new(
            bytes::Bytes::from_static(b"one"),
            b"test/concurrency-limit".as_slice(),
        ))
        .await
        .expect("Should send first stream");

    tokio::time::timeout(std::time::Duration::from_secs(5), started_rx.recv())
        .await
        .expect("First handler should start")
        .expect("First handler signal should be present");

    let stream2 = conn.open_stream().await.expect("Should open stream 2");
    let _ = stream2
        .send(Message::new(
            bytes::Bytes::from_static(b"two"),
            b"test/concurrency-limit".as_slice(),
        ))
        .await;

    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(250), started_rx.recv())
            .await
            .is_err(),
        "second stream's frame should be refused while the work permit is held"
    );

    release.notify_waiters();
    conn.close().await.expect("Should close");
    Box::new(router)
        .shutdown()
        .await
        .expect("Router should shutdown");
}

#[tokio::test]
#[serial_test::serial]
async fn iroh_multiple_networks_unique_ids() {
    let net1 = IrohNetwork::new().await.expect("Should create network 1");
    let net2 = IrohNetwork::new().await.expect("Should create network 2");
    let net3 = IrohNetwork::new().await.expect("Should create network 3");

    let id1 = net1.local_peer_id();
    let id2 = net2.local_peer_id();
    let id3 = net3.local_peer_id();

    // All peer IDs should be unique
    assert_ne!(id1, id2, "Networks should have unique peer IDs");
    assert_ne!(id2, id3, "Networks should have unique peer IDs");
    assert_ne!(id1, id3, "Networks should have unique peer IDs");
}

#[tokio::test]
#[serial_test::serial]
async fn iroh_deterministic_peer_id_from_secret_key() {
    // Create a fixed 32-byte secret key
    let secret_bytes: [u8; 32] = [0xaa; 32];

    // Create first network with the secret key
    let secret_key1 = SecretKey::from_bytes(&secret_bytes);
    let network1 = IrohNetwork::builder()
        .secret_key(secret_key1)
        .build()
        .await
        .expect("Should create network 1");
    let peer_id1 = network1.local_peer_id();

    // Create second network with the same secret key bytes
    let secret_key2 = SecretKey::from_bytes(&secret_bytes);
    let network2 = IrohNetwork::builder()
        .secret_key(secret_key2)
        .build()
        .await
        .expect("Should create network 2");
    let peer_id2 = network2.local_peer_id();

    // Both networks should have identical peer IDs since they use the same secret key
    assert_eq!(
        peer_id1.as_bytes(),
        peer_id2.as_bytes(),
        "Same secret key should produce same peer ID"
    );

    // The peer ID should be non-empty
    assert!(
        !peer_id1.as_bytes().is_empty(),
        "Peer ID should not be empty"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn iroh_different_secret_keys_produce_different_peer_ids() {
    let secret_bytes_a: [u8; 32] = [0xaa; 32];
    let secret_bytes_b: [u8; 32] = [0xbb; 32];

    let network_a = IrohNetwork::builder()
        .secret_key(SecretKey::from_bytes(&secret_bytes_a))
        .build()
        .await
        .expect("Should create network A");

    let network_b = IrohNetwork::builder()
        .secret_key(SecretKey::from_bytes(&secret_bytes_b))
        .build()
        .await
        .expect("Should create network B");

    // Different secret keys should produce different peer IDs
    assert_ne!(
        network_a.local_peer_id().as_bytes(),
        network_b.local_peer_id().as_bytes(),
        "Different secret keys should produce different peer IDs"
    );
}

// ============================================================================
// QUIC ingress-control hardening
// ============================================================================

/// A peer that opens a stream, announces a body length, then sends only part of
/// the body and stalls must not pin its ingress stream slot forever: the
/// per-frame read deadline in `recv()` fails the read, the handler returns, and
/// the slot is released for a later well-formed request from the same peer.
#[tokio::test]
#[serial_test::serial]
async fn iroh_partial_frame_read_times_out_and_frees_the_stream_slot() {
    const PROTOCOL: &[u8] = b"test/slow-loris";

    let attacker = new_test_network().await;
    let victim = IrohNetwork::builder()
        .bind_addr_v4(loopback())
        .private_routes_only()
        // One inbound stream slot for this peer: the parked partial-frame stream
        // must free it, or the honest request below can never be admitted.
        .max_streams_per_peer(1)
        .stream_read_timeout_ms(500)
        .build()
        .await
        .expect("build victim");

    let router = victim
        .create_router_builder()
        .unwrap()
        .accept(
            PROTOCOL.to_vec(),
            Arc::new(trait_tests::RequestResponseHandler::new("pong")),
        )
        .spawn()
        .expect("spawn victim router");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Raw stream: announce a 64-byte body, deliver 8 bytes, then stall.
    let victim_addr =
        iroh::EndpointAddr::new(victim.endpoint().id()).with_ip_addr(victim.bound_addresses()[0]);
    let raw_conn = attacker
        .endpoint()
        .connect(victim_addr, PROTOCOL)
        .await
        .expect("raw connect");
    let (mut raw_send, _raw_recv) = raw_conn.open_bi().await.expect("raw open_bi");
    raw_send
        .write_all(&64u32.to_be_bytes())
        .await
        .expect("write length prefix");
    raw_send
        .write_all(&[0u8; 8])
        .await
        .expect("write partial body");

    // Let the victim accept the stream and enter the blocked read.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Once the 500ms read deadline fires the slot frees; a well-formed request
    // from the same endpoint identity then succeeds.
    let response = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let attempt = async {
                let conn = attacker.connect(&peer_addr(&victim), PROTOCOL).await?;
                let stream = conn.open_stream().await?;
                stream
                    .send(Message::new(bytes::Bytes::from_static(b"ping"), PROTOCOL))
                    .await?;
                let response = stream.recv().await?;
                Ok::<_, crate::NetworkError>(response.data)
            }
            .await;
            if let Ok(data) = attempt {
                return data;
            }
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }
    })
    .await
    .expect("an honest request must be served once the partial-frame slot frees");
    assert_eq!(&response[..], b"pong");

    drop(raw_send);
    drop(raw_conn);
    router.shutdown().await.unwrap();
}

/// Every frame — not just the first on a stream — is charged against the sending
/// peer's one-second budget, so one admitted long-lived stream cannot pump
/// unlimited messages for free.
#[tokio::test]
#[serial_test::serial]
async fn iroh_per_frame_rate_limit_bounds_a_single_long_lived_stream() {
    const PROTOCOL: &[u8] = b"test/frame-rate";
    const RATE: usize = 5;
    const SENT: usize = 12;

    let client = new_test_network().await;
    let server = IrohNetwork::builder()
        .bind_addr_v4(loopback())
        .private_routes_only()
        .max_ingress_events_per_peer_per_second(RATE)
        .build()
        .await
        .expect("build server");
    let router = server
        .create_router_builder()
        .unwrap()
        .accept(PROTOCOL.to_vec(), Arc::new(trait_tests::EchoHandler))
        .spawn()
        .expect("spawn server router");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let conn = client
        .connect(&peer_addr(&server), PROTOCOL)
        .await
        .expect("connect");
    let stream = conn.open_stream().await.expect("open stream");

    // All frames ride one already-admitted stream. The peer budget (spent by the
    // stream open plus one tick per frame) cuts the echo loop off well before
    // the 12th frame.
    let mut echoed = 0usize;
    for i in 0..SENT {
        if stream
            .send(Message::new(bytes::Bytes::from(format!("f{i}")), PROTOCOL))
            .await
            .is_err()
        {
            break;
        }
        match tokio::time::timeout(std::time::Duration::from_secs(2), stream.recv()).await {
            Ok(Ok(_)) => echoed += 1,
            _ => break,
        }
    }
    assert!(
        (1..SENT).contains(&echoed),
        "one stream must be frame-rate throttled before all {SENT} frames (echoed {echoed}, rate {RATE})"
    );

    conn.close().await.unwrap();
    router.shutdown().await.unwrap();
}

/// A flood of large frames cannot commit unbounded buffer memory: the node-wide
/// receive-byte budget refuses a body it cannot cover while an earlier one is
/// still in flight, and recovers when that message is dropped.
#[tokio::test]
#[serial_test::serial]
async fn iroh_receive_byte_budget_refuses_oversized_backlog_and_recovers() {
    const PROTOCOL: &[u8] = b"test/byte-budget";
    const FRAME: usize = 256 * 1024;

    struct Parker {
        entered: mpsc::Sender<()>,
        release: Arc<Notify>,
    }
    #[async_trait]
    impl ProtocolHandler for Parker {
        async fn handle(&self, connection: Box<dyn Connection>) -> Result<()> {
            // Holding the message holds its receive-byte reservation.
            let _held = connection.recv().await?;
            let _ = self.entered.send(()).await;
            self.release.notified().await;
            Ok(())
        }
    }

    let client = new_test_network().await;
    let server = IrohNetwork::builder()
        .bind_addr_v4(loopback())
        .private_routes_only()
        .max_message_size(FRAME)
        // Room for exactly one in-flight FRAME-sized body.
        .max_inbound_body_bytes(FRAME)
        .build()
        .await
        .expect("build server");
    let (entered_tx, mut entered_rx) = mpsc::channel(4);
    let release = Arc::new(Notify::new());
    let router = server
        .create_router_builder()
        .unwrap()
        .accept(
            PROTOCOL.to_vec(),
            Arc::new(Parker {
                entered: entered_tx,
                release: Arc::clone(&release),
            }),
        )
        .spawn()
        .expect("spawn server router");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let conn = client
        .connect(&peer_addr(&server), PROTOCOL)
        .await
        .expect("connect");

    // First large frame is admitted; its handler parks holding the whole budget.
    let hold = conn.open_stream().await.expect("open hold stream");
    hold.send(Message::new(bytes::Bytes::from(vec![1u8; FRAME]), PROTOCOL))
        .await
        .expect("send frame 1");
    tokio::time::timeout(std::time::Duration::from_secs(5), entered_rx.recv())
        .await
        .expect("handler 1 enters")
        .expect("handler 1 signal");

    // Second large frame: the body cannot be reserved, so its handler errors and
    // the server closes the stream rather than buffering another 256 KiB.
    let blocked = conn.open_stream().await.expect("open blocked stream");
    blocked
        .send(Message::new(bytes::Bytes::from(vec![2u8; FRAME]), PROTOCOL))
        .await
        .expect("send frame 2");
    assert!(
        matches!(
            tokio::time::timeout(std::time::Duration::from_secs(5), blocked.recv()).await,
            Ok(Err(_))
        ),
        "a second large frame must be refused while the receive-byte budget is fully reserved"
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(300), entered_rx.recv())
            .await
            .is_err(),
        "the refused frame's handler must not have entered"
    );

    // Release the first handler; the budget frees and a fresh large frame is admitted.
    release.notify_waiters();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let after = conn.open_stream().await.expect("open post-release stream");
    after
        .send(Message::new(bytes::Bytes::from(vec![3u8; FRAME]), PROTOCOL))
        .await
        .expect("send frame 3");
    tokio::time::timeout(std::time::Duration::from_secs(5), entered_rx.recv())
        .await
        .expect("handler 3 enters once the budget frees")
        .expect("handler 3 signal");

    release.notify_waiters();
    conn.close().await.unwrap();
    router.shutdown().await.unwrap();
}

/// One endpoint identity cannot occupy an unbounded share of the node-wide
/// stream budget: concurrent inbound streams from a single peer are capped, and
/// the cap recovers when earlier streams finish.
#[tokio::test]
#[serial_test::serial]
async fn iroh_per_peer_stream_cap_refuses_excess_concurrent_streams() {
    struct HoldingHandler {
        started: mpsc::Sender<()>,
        release: Arc<Notify>,
    }

    #[async_trait]
    impl ProtocolHandler for HoldingHandler {
        async fn handle(&self, connection: Box<dyn Connection>) -> Result<()> {
            let _ = connection.recv().await?;
            let _ = self.started.send(()).await;
            self.release.notified().await;
            Ok(())
        }
    }

    const PROTOCOL: &[u8] = b"test/per-peer-streams";

    let client = new_test_network().await;
    let server = IrohNetwork::builder()
        .bind_addr_v4(loopback())
        .private_routes_only()
        .max_streams_per_peer(2)
        .build()
        .await
        .expect("build server");
    let (started_tx, mut started_rx) = mpsc::channel(8);
    let release = Arc::new(Notify::new());
    let router = server
        .create_router_builder()
        .unwrap()
        .accept(
            PROTOCOL.to_vec(),
            Arc::new(HoldingHandler {
                started: started_tx,
                release: Arc::clone(&release),
            }),
        )
        .spawn()
        .expect("spawn server router");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let conn = client
        .connect(&peer_addr(&server), PROTOCOL)
        .await
        .expect("connect");

    // Two concurrent streams from this peer are admitted; their handlers run.
    let mut held = Vec::new();
    for _ in 0..2 {
        let stream = conn.open_stream().await.expect("open stream");
        stream
            .send(Message::new(bytes::Bytes::from_static(b"hold"), PROTOCOL))
            .await
            .expect("send hold");
        held.push(stream);
    }
    for _ in 0..2 {
        tokio::time::timeout(std::time::Duration::from_secs(5), started_rx.recv())
            .await
            .expect("handler should start")
            .expect("started signal");
    }

    // A third concurrent stream from the same peer is refused at ingress.
    let third = conn.open_stream().await.expect("open third stream");
    let _ = third
        .send(Message::new(
            bytes::Bytes::from_static(b"blocked"),
            PROTOCOL,
        ))
        .await;
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(500), started_rx.recv())
            .await
            .is_err(),
        "a third concurrent stream from one peer must be refused"
    );

    // Releasing the first two frees the per-peer slots; a later stream is
    // admitted.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    release.notify_waiters();
    drop(held);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let recovered = conn.open_stream().await.expect("open recovered stream");
    recovered
        .send(Message::new(bytes::Bytes::from_static(b"after"), PROTOCOL))
        .await
        .expect("send after release");
    tokio::time::timeout(std::time::Duration::from_secs(5), started_rx.recv())
        .await
        .expect("handler should start after slots free")
        .expect("started signal after release");

    conn.close().await.unwrap();
    router.shutdown().await.unwrap();
}
