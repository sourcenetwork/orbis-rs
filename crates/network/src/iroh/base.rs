//! Base Iroh QUIC connection implementation
//!
//! This module implements the Network trait using iroh's QUIC-based networking.

use async_trait::async_trait;
use futures::StreamExt;
use iroh::endpoint::Connection as IrohConnection;
use iroh::{Endpoint, EndpointAddr};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::{NetworkError, Result};
use crate::r#trait::{Connection, Message, Network, PeerId, ProtocolHandler};

/// Iroh-based network implementation
pub struct IrohNetwork {
    endpoint: Endpoint,
    local_peer_id: PeerId,
    handlers: Arc<RwLock<HashMap<Vec<u8>, Arc<dyn ProtocolHandler>>>>,
}

impl IrohNetwork {
    /// Create a new Iroh network instance
    pub async fn new() -> Result<Self> {
        let endpoint = Endpoint::bind()
            .await
            .map_err(|e| NetworkError::Connection(format!("Failed to bind endpoint: {}", e)))?;

        let node_id = endpoint.id();
        let peer_id = PeerId::new(node_id.as_bytes().to_vec());

        Ok(Self {
            endpoint,
            local_peer_id: peer_id,
            handlers: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Get a reference to the underlying iroh endpoint
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Start accepting incoming connections
    pub async fn start_accept_loop(&self) -> Result<()> {
        let handlers = Arc::clone(&self.handlers);
        // Clone endpoint to move into spawn
        let endpoint = self.endpoint.clone();

        tokio::spawn(async move {
            let mut incoming = endpoint.accept();

            // TODO: Fix Accept stream iteration
            // Accept doesn't implement Stream directly - need to check iroh 0.95 docs
            // for correct usage (may need to use a different method or trait)
            // Placeholder implementation - this will not compile until fixed
            #[allow(unused)]
            let _incoming = incoming;
            // TODO: Implement proper connection acceptance loop
            // Example (needs verification):
            // while let Some(conn_result) = /* correct stream method */ {
            //     match conn_result {
            //         Ok(conn) => {
            //             let alpn = conn.alpn();
            //             let protocol = String::from_utf8_lossy(&alpn).to_string();
            //
            //             let handlers_read = handlers.read().await;
            //             if let Some(handler) = handlers_read.get(&protocol) {
            //                 let handler = Arc::clone(handler);
            //                 drop(handlers_read);
            //
            //                 tokio::spawn(async move {
            //                     let connection = IrohConnectionWrapper::new(conn);
            //                     if let Err(e) = handler.handle(Box::new(connection)).await {
            //                         eprintln!("Error handling connection: {:?}", e);
            //                     }
            //                 });
            //             }
            //         }
            //         Err(e) => eprintln!("Error: {:?}", e),
            //     }
            // }
        });

        Ok(())
    }
}

#[async_trait]
impl Network for IrohNetwork {
    async fn connect(&self, peer_id: &PeerId, protocol: &[u8]) -> Result<Box<dyn Connection>> {
        use iroh::PublicKey;
        use std::net::SocketAddr;
        use std::str::FromStr;

        // Convert peer_id bytes to PublicKey
        // The peer_id might be in format "node_id" or "node_id@ip:port"
        let peer_id_str = std::str::from_utf8(peer_id.as_bytes()).map_err(|_| {
            NetworkError::InvalidAddress("Invalid peer ID format - not UTF-8".to_string())
        })?;

        // Parse the address - could be "node_id" or "node_id@ip:port"
        let (node_id_str, socket_addr_opt) = if let Some((id, addr)) = peer_id_str.split_once('@') {
            (id, Some(addr))
        } else {
            (peer_id_str, None)
        };

        let public_key = PublicKey::from_str(node_id_str)
            .map_err(|e| NetworkError::InvalidAddress(format!("Invalid peer ID: {}", e)))?;

        // Create EndpointAddr from the public key
        let peer_addr = if let Some(addr_str) = socket_addr_opt {
            let socket_addr: SocketAddr = addr_str.parse().map_err(|e| {
                NetworkError::InvalidAddress(format!(
                    "Invalid socket address '{}': {}",
                    addr_str, e
                ))
            })?;

            // Add the IP address to the endpoint address
            EndpointAddr::new(public_key).with_ip_addr(socket_addr)
        } else {
            // No address provided - just use the node ID
            // iroh will try to discover the peer via its discovery mechanisms
            EndpointAddr::new(public_key)
        };

        let alpn = protocol.to_vec();

        // Connect to the peer
        let conn = self
            .endpoint
            .connect(peer_addr, &alpn)
            .await
            .map_err(|e| NetworkError::Connection(format!("Failed to connect: {}", e)))?;

        Ok(Box::new(IrohConnectionWrapper::new(conn)))
    }

    async fn listen(&mut self, protocol: &[u8], handler: Box<dyn ProtocolHandler>) -> Result<()> {
        let mut handlers = self.handlers.write().await;
        handlers.insert(protocol.to_vec(), Arc::from(handler));
        Ok(())
    }

    fn local_peer_id(&self) -> PeerId {
        self.local_peer_id.clone()
    }

    fn local_address(&self) -> Result<String> {
        // Get the node ID as the address identifier
        let node_id = self.endpoint.id();
        Ok(format!("{}", node_id))
    }
}

/// Wrapper around iroh Connection to implement our Connection trait
pub struct IrohConnectionWrapper {
    conn: IrohConnection,
    peer_id: PeerId,
}

impl IrohConnectionWrapper {
    pub fn new(conn: IrohConnection) -> Self {
        // remote_id() returns a PublicKey
        let node_id = conn.remote_id();
        let peer_id = PeerId::new(node_id.as_bytes().to_vec());
        Self { conn, peer_id }
    }
}

#[async_trait]
impl Connection for IrohConnectionWrapper {
    async fn send(&mut self, message: Message) -> Result<()> {
        // Use bidirectional stream for reliable message delivery
        let (mut send, mut recv) = self
            .conn
            .open_bi()
            .await
            .map_err(|e| NetworkError::Connection(format!("Failed to open stream: {}", e)))?;

        // Send message data
        use tokio::io::AsyncWriteExt;
        send.write_all(&message.data)
            .await
            .map_err(|e| NetworkError::Io(e.into()))?;
        send.finish()
            .map_err(|e| NetworkError::Connection(format!("Failed to finish stream: {}", e)))?;

        // Wait for response (optional - could be made configurable)
        // iroh's read_to_end takes a size limit (usize), not a buffer
        let _ = recv.read_to_end(1024).await;

        Ok(())
    }

    async fn recv(&mut self) -> Result<Message> {
        // Accept incoming bidirectional stream
        let (mut send, mut recv) = self
            .conn
            .accept_bi()
            .await
            .map_err(|e| NetworkError::Connection(format!("Failed to accept stream: {}", e)))?;

        // Read message data
        // iroh's read_to_end takes a size limit (usize) and returns Vec<u8>
        let buffer = recv
            .read_to_end(1024 * 1024) // 1MB limit
            .await
            .map_err(|e| NetworkError::Connection(format!("Failed to read data: {}", e)))?;

        // Get protocol from ALPN
        let protocol = self.conn.alpn().to_vec();

        // Send acknowledgment (optional)
        send.write_all(b"OK")
            .await
            .map_err(|e| NetworkError::Io(e.into()))?;
        send.finish()
            .map_err(|e| NetworkError::Connection(format!("Failed to finish stream: {}", e)))?;

        Ok(Message::new(buffer, protocol))
    }

    async fn close(&mut self) -> Result<()> {
        self.conn.close(0u32.into(), b"Goodbye");
        Ok(())
    }

    fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }
}
