//! Iroh-specific tests for the network crate
//!
//! This module runs the generic trait tests against the IrohNetwork implementation
//! and includes iroh-specific test cases.

use super::IrohNetwork;
use crate::r#trait::{Connection, Message, Network, ProtocolHandler};
use crate::tests as trait_tests;
use crate::{PeerId, Result, SecretKey};
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
        .no_relay()
        .build()
        .await
        .expect("Should create network")
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
}

#[tokio::test]
#[serial_test::serial]
async fn iroh_builder_custom_max_message_size() {
    let custom_size = 512 * 1024; // 512KB
    let network = IrohNetwork::builder()
        .max_message_size(custom_size)
        .build()
        .await
        .expect("Should build with custom config");

    let config = network.config();
    assert_eq!(config.max_message_size, custom_size);
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
        .no_relay()
        .max_message_size(large_size)
        .build()
        .await
        .expect("Should create network 1");
    let net2 = IrohNetwork::builder()
        .bind_addr_v4(loopback())
        .no_relay()
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
async fn iroh_router_builder_limits_concurrent_inbound_streams() {
    struct HoldingHandler {
        started: mpsc::Sender<()>,
        release: Arc<Notify>,
    }

    #[async_trait]
    impl ProtocolHandler for HoldingHandler {
        async fn handle(&self, connection: Box<dyn Connection>) -> Result<()> {
            let _ = self.started.send(()).await;
            let _ = connection.recv().await;
            self.release.notified().await;
            Ok(())
        }
    }

    let net1 = new_test_network().await;
    let net2 = new_test_network().await;
    let (started_tx, mut started_rx) = mpsc::channel(4);
    let release = Arc::new(Notify::new());

    let router = net2
        .create_router_builder()
        .expect("Should create router builder")
        .max_concurrent_streams(1)
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
        "second stream should be dropped while the concurrency permit is held"
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
