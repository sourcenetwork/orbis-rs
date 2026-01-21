//! Generic trait tests for the Network abstraction
//!
//! These tests define the contract that any Network implementation must satisfy.
//! They can be run against any backend (iroh, libp2p, etc.) by providing a
//! factory function that creates the network instances.

use crate::r#trait::{Connection, Message, Network, PeerId, ProtocolHandler};
use crate::Result;
use async_trait::async_trait;
use bytes::Bytes;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

const TEST_PROTOCOL: &[u8] = b"test/protocol/1";
const TEST_TIMEOUT: Duration = Duration::from_secs(15);
const CONCURRENT_CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

// ============================================================================
// Test Infrastructure
// ============================================================================

/// A simple echo handler that echoes back any received message
pub struct EchoHandler;

#[async_trait]
impl ProtocolHandler for EchoHandler {
    async fn handle(&self, connection: Box<dyn Connection>) -> Result<()> {
        loop {
            match connection.recv().await {
                Ok(msg) => {
                    connection.send(msg).await?;
                }
                Err(_) => break,
            }
        }
        Ok(())
    }
}

/// A handler that counts how many connections it has handled
pub struct CountingHandler {
    count: Arc<AtomicUsize>,
    sender: mpsc::Sender<()>,
}

impl CountingHandler {
    pub fn new(count: Arc<AtomicUsize>, sender: mpsc::Sender<()>) -> Self {
        Self { count, sender }
    }
}

#[async_trait]
impl ProtocolHandler for CountingHandler {
    async fn handle(&self, connection: Box<dyn Connection>) -> Result<()> {
        self.count.fetch_add(1, Ordering::SeqCst);
        let _ = self.sender.send(()).await;

        // Keep connection alive briefly to allow message exchange
        loop {
            match connection.recv().await {
                Ok(_) => {}
                Err(_) => break,
            }
        }
        Ok(())
    }
}

/// A request-response handler that processes one message and responds
pub struct RequestResponseHandler {
    response_data: Bytes,
}

impl RequestResponseHandler {
    pub fn new(response_data: impl Into<Bytes>) -> Self {
        Self {
            response_data: response_data.into(),
        }
    }
}

#[async_trait]
impl ProtocolHandler for RequestResponseHandler {
    async fn handle(&self, connection: Box<dyn Connection>) -> Result<()> {
        // Wait for request
        let _request = connection.recv().await?;

        // Send response
        let response = Message::new(self.response_data.clone(), connection.peer_id().as_bytes());
        connection.send(response).await?;

        Ok(())
    }
}

// ============================================================================
// Generic Trait Tests
// ============================================================================

/// Test that a network can be created and has a valid local peer ID
pub async fn test_network_creation<N: Network>(network: &N) {
    let peer_id = network.local_peer_id();
    assert!(
        !peer_id.as_bytes().is_empty(),
        "Peer ID should not be empty"
    );

    let address = network.local_address();
    assert!(address.is_ok(), "Should be able to get local address");
}

/// Build a peer address from a network's local address and bound addresses
fn build_peer_addr<N: Network>(net: &N) -> PeerId {
    let node_id_str = net.local_address().expect("Should get local address");
    let bound_addrs = net.bound_addresses();

    if let Some(addr) = bound_addrs.first() {
        PeerId::from_bytes(format!("{}@{}", node_id_str, addr).as_bytes())
    } else {
        PeerId::from_bytes(node_id_str.as_bytes())
    }
}

/// Test basic connection establishment between two peers
pub async fn test_connection_establishment<N: Network>(net1: &N, net2: &N) {
    // Set up net2 to accept connections via router
    let router_builder = net2
        .create_router_builder()
        .expect("Should create router builder");
    let router = router_builder
        .accept(TEST_PROTOCOL.to_vec(), Arc::new(EchoHandler))
        .spawn()
        .expect("Should spawn router");

    // Give router time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Get net2's address for connection
    let peer_addr = build_peer_addr(net2);

    // Connect from net1 to net2
    let conn_result = timeout(TEST_TIMEOUT, net1.connect(&peer_addr, TEST_PROTOCOL)).await;

    assert!(conn_result.is_ok(), "Connection should not timeout");
    let conn = conn_result.unwrap();
    assert!(conn.is_ok(), "Connection should succeed: {:?}", conn.err());

    let conn = conn.unwrap();
    conn.close().await.expect("Should close connection");

    // Cleanup
    Box::new(router)
        .shutdown()
        .await
        .expect("Router should shutdown");
}

/// Test sending and receiving a single message
pub async fn test_single_message_roundtrip<N: Network>(net1: &N, net2: &N) {
    // Set up net2 with echo handler
    let router_builder = net2
        .create_router_builder()
        .expect("Should create router builder");
    let router = router_builder
        .accept(TEST_PROTOCOL.to_vec(), Arc::new(EchoHandler))
        .spawn()
        .expect("Should spawn router");

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Build peer address
    let peer_addr = build_peer_addr(net2);

    // Connect
    let conn = net1
        .connect(&peer_addr, TEST_PROTOCOL)
        .await
        .expect("Should connect");

    // Send message
    let test_data = b"Hello, Network!";
    let msg = Message::new(Bytes::from_static(test_data), TEST_PROTOCOL);
    conn.send(msg).await.expect("Should send message");

    // Receive echo
    let response = timeout(TEST_TIMEOUT, conn.recv())
        .await
        .expect("Should not timeout")
        .expect("Should receive response");

    assert_eq!(
        response.data.as_ref(),
        test_data,
        "Should echo back same data"
    );

    conn.close().await.expect("Should close");
    Box::new(router)
        .shutdown()
        .await
        .expect("Router should shutdown");
}

/// Test sending multiple messages in sequence
pub async fn test_multiple_messages<N: Network>(net1: &N, net2: &N) {
    let router_builder = net2
        .create_router_builder()
        .expect("Should create router builder");
    let router = router_builder
        .accept(TEST_PROTOCOL.to_vec(), Arc::new(EchoHandler))
        .spawn()
        .expect("Should spawn router");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let peer_addr = build_peer_addr(net2);

    let conn = net1
        .connect(&peer_addr, TEST_PROTOCOL)
        .await
        .expect("Should connect");

    // Send multiple messages
    for i in 0..5 {
        let test_data = format!("Message {}", i);
        let msg = Message::new(Bytes::from(test_data.clone()), TEST_PROTOCOL);
        conn.send(msg).await.expect("Should send message");

        let response = timeout(TEST_TIMEOUT, conn.recv())
            .await
            .expect("Should not timeout")
            .expect("Should receive response");

        assert_eq!(
            response.data.as_ref(),
            test_data.as_bytes(),
            "Should echo back message {}",
            i
        );
    }

    conn.close().await.expect("Should close");
    Box::new(router)
        .shutdown()
        .await
        .expect("Router should shutdown");
}

/// Test that large messages can be sent and received
pub async fn test_large_message<N: Network>(net1: &N, net2: &N) {
    let router_builder = net2
        .create_router_builder()
        .expect("Should create router builder");
    let router = router_builder
        .accept(TEST_PROTOCOL.to_vec(), Arc::new(EchoHandler))
        .spawn()
        .expect("Should spawn router");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let peer_addr = build_peer_addr(net2);

    let conn = net1
        .connect(&peer_addr, TEST_PROTOCOL)
        .await
        .expect("Should connect");

    // Send a large message (100KB)
    let large_data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
    let msg = Message::new(Bytes::from(large_data.clone()), TEST_PROTOCOL);
    conn.send(msg).await.expect("Should send large message");

    let response = timeout(TEST_TIMEOUT, conn.recv())
        .await
        .expect("Should not timeout")
        .expect("Should receive response");

    assert_eq!(
        response.data.as_ref(),
        large_data.as_slice(),
        "Should echo back large message intact"
    );

    conn.close().await.expect("Should close");
    Box::new(router)
        .shutdown()
        .await
        .expect("Router should shutdown");
}

/// Test router with multiple protocol handlers
pub async fn test_router_multiple_protocols<N: Network>(net1: &N, net2: &N) {
    const PROTOCOL_A: &[u8] = b"test/protocol-a/1";
    const PROTOCOL_B: &[u8] = b"test/protocol-b/1";

    let response_a = RequestResponseHandler::new("Response A");
    let response_b = RequestResponseHandler::new("Response B");

    let router_builder = net2
        .create_router_builder()
        .expect("Should create router builder");
    let router = router_builder
        .accept(PROTOCOL_A.to_vec(), Arc::new(response_a))
        .accept(PROTOCOL_B.to_vec(), Arc::new(response_b))
        .spawn()
        .expect("Should spawn router");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let peer_addr = build_peer_addr(net2);

    // Test protocol A
    let conn_a = net1
        .connect(&peer_addr, PROTOCOL_A)
        .await
        .expect("Should connect to protocol A");

    conn_a
        .send(Message::new(Bytes::from("Request A"), PROTOCOL_A))
        .await
        .expect("Should send");

    let response = timeout(TEST_TIMEOUT, conn_a.recv())
        .await
        .expect("Should not timeout")
        .expect("Should receive");

    assert_eq!(response.data.as_ref(), b"Response A");
    conn_a.close().await.expect("Should close");

    // Test protocol B
    let conn_b = net1
        .connect(&peer_addr, PROTOCOL_B)
        .await
        .expect("Should connect to protocol B");

    conn_b
        .send(Message::new(Bytes::from("Request B"), PROTOCOL_B))
        .await
        .expect("Should send");

    let response = timeout(TEST_TIMEOUT, conn_b.recv())
        .await
        .expect("Should not timeout")
        .expect("Should receive");

    assert_eq!(response.data.as_ref(), b"Response B");
    conn_b.close().await.expect("Should close");

    Box::new(router)
        .shutdown()
        .await
        .expect("Router should shutdown");
}

/// Test that peer_id is correctly reported on connections
pub async fn test_connection_peer_id<N: Network>(net1: &N, net2: &N) {
    let router_builder = net2
        .create_router_builder()
        .expect("Should create router builder");
    let router = router_builder
        .accept(TEST_PROTOCOL.to_vec(), Arc::new(EchoHandler))
        .spawn()
        .expect("Should spawn router");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let net2_id = net2.local_peer_id();
    let peer_addr = build_peer_addr(net2);

    let conn = net1
        .connect(&peer_addr, TEST_PROTOCOL)
        .await
        .expect("Should connect");

    // The connection's peer_id should match net2's peer_id
    let conn_peer_id = conn.peer_id();
    assert_eq!(
        conn_peer_id.as_bytes(),
        net2_id.as_bytes(),
        "Connection peer_id should match the remote network's peer_id"
    );

    conn.close().await.expect("Should close");
    Box::new(router)
        .shutdown()
        .await
        .expect("Router should shutdown");
}

/// Test concurrent connections from multiple clients
pub async fn test_concurrent_connections<N: Network>(net1: &N, net2: &N, net3: &N) {
    let (tx, mut rx) = mpsc::channel::<()>(10);
    let count = Arc::new(AtomicUsize::new(0));

    let router_builder = net2
        .create_router_builder()
        .expect("Should create router builder");
    let router = router_builder
        .accept(
            TEST_PROTOCOL.to_vec(),
            Arc::new(CountingHandler::new(Arc::clone(&count), tx)),
        )
        .spawn()
        .expect("Should spawn router");

    // Give router more time to start accepting connections
    tokio::time::sleep(Duration::from_millis(200)).await;

    let peer_addr = build_peer_addr(net2);

    // Connect from both net1 and net3 concurrently with timeout
    let peer_addr_clone = peer_addr.clone();
    let conn1_future = timeout(
        CONCURRENT_CONNECTION_TIMEOUT,
        net1.connect(&peer_addr, TEST_PROTOCOL),
    );
    let conn2_future = timeout(
        CONCURRENT_CONNECTION_TIMEOUT,
        net3.connect(&peer_addr_clone, TEST_PROTOCOL),
    );

    let (conn1_result, conn2_result) = tokio::join!(conn1_future, conn2_future);

    let conn1 = conn1_result
        .expect("Connection 1 should not timeout")
        .expect("Connection 1 should succeed");
    let conn2 = conn2_result
        .expect("Connection 2 should not timeout")
        .expect("Connection 2 should succeed");

    // Wait for both handlers to be invoked
    timeout(CONCURRENT_CONNECTION_TIMEOUT, rx.recv())
        .await
        .expect("Should receive first notification");
    timeout(CONCURRENT_CONNECTION_TIMEOUT, rx.recv())
        .await
        .expect("Should receive second notification");

    assert_eq!(
        count.load(Ordering::SeqCst),
        2,
        "Should have handled 2 connections"
    );

    conn1.close().await.expect("Should close conn1");
    conn2.close().await.expect("Should close conn2");
    Box::new(router)
        .shutdown()
        .await
        .expect("Router should shutdown");
}

/// Test that Message can be created with various input types
pub fn test_message_construction() {
    // From static bytes
    let msg1 = Message::new(Bytes::from_static(b"hello"), b"proto".as_slice());
    assert_eq!(msg1.data.as_ref(), b"hello");

    // From Vec
    let msg2 = Message::with_vec(vec![1, 2, 3], vec![4, 5, 6]);
    assert_eq!(msg2.data.as_ref(), &[1, 2, 3]);
    assert_eq!(msg2.protocol.as_ref(), &[4, 5, 6]);

    // From String
    let msg3 = Message::new(Bytes::from("world"), b"proto".as_slice());
    assert_eq!(msg3.data.as_ref(), b"world");
}

/// Test PeerId operations
pub fn test_peer_id_operations() {
    let bytes = b"test-peer-id";

    let peer1 = PeerId::new(bytes.to_vec());
    let peer2 = PeerId::from_bytes(bytes);

    assert_eq!(peer1.as_bytes(), bytes);
    assert_eq!(peer2.as_bytes(), bytes);
    assert_eq!(peer1, peer2);

    // Test hashing (for use in HashMap)
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(peer1.clone());
    assert!(set.contains(&peer2));
}
