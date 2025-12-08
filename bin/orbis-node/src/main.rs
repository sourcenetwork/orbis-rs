use anyhow::{Context, Result};
use clap::Parser;
use network::{IrohNetwork, IrohRouter, Message, Network, PeerId, ProtocolHandler};
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(name = "orbis-node")]
#[command(about = "Orbis network node")]
struct Args {
    /// Mode: 'listen' to wait for connections, 'connect' to connect to a peer, or 'auto' to try connecting then listen
    #[arg(short, long, default_value = "auto")]
    mode: String,
    
    /// Peer address to connect to (required if mode is 'connect')
    #[arg(short, long)]
    peer: Option<String>,
    
    /// Port to bind to (optional, defaults to random)
    #[arg(short = 'p', long)]
    port: Option<u16>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    println!("Starting Orbis Node with Iroh networking...");

    // Create a network instance using the network crate
    let mut network = IrohNetwork::new().await?;
    
    let node_id = network.local_peer_id();
    let node_id_str = network.local_address()?;
    println!("Node ID: {}", node_id_str);
    println!("To connect to this node, use: {}@127.0.0.1:4337", node_id_str);
    println!("(Or just the node ID if using discovery)");
    
    // Define the ALPN (Application-Layer Protocol Negotiation) identifier
    const ALPN: &str = "orbis-node/0";
    
    // Register our protocol handler
    network.listen(ALPN, Box::new(OrbisHandler)).await?;
    
    // Create a router using the network's endpoint
    let router = IrohRouter::builder(network.endpoint().clone())
        .accept(ALPN.as_bytes().to_vec(), Arc::new(OrbisHandler))
        .spawn();
    
    println!("Router started, listening for connections on ALPN: {:?}", ALPN);
    
    // Handle different modes
    match args.mode.as_str() {
        "listen" => {
            println!("Mode: LISTEN - Waiting for incoming connections...");
            println!("Node is running. Press Ctrl+C to stop.");
            tokio::signal::ctrl_c().await?;
        }
        "connect" => {
            if let Some(peer_addr_str) = args.peer {
                println!("Mode: CONNECT - Attempting to connect to: {}", peer_addr_str);
                connect_to_peer(&network, &peer_addr_str, ALPN).await?;
                println!("Connected! Press Ctrl+C to stop.");
                tokio::signal::ctrl_c().await?;
            } else {
                eprintln!("Error: --peer address required when using --mode connect");
                eprintln!("Example: --mode connect --peer <node_id>");
                return Ok(());
            }
        }
        "auto" => {
            println!("Mode: AUTO - Will try to connect, then listen if no peer found");
            if let Some(peer_addr_str) = args.peer {
                println!("Attempting to connect to: {}", peer_addr_str);
                match connect_to_peer(&network, &peer_addr_str, ALPN).await {
                    Ok(_) => {
                        println!("Connected! Press Ctrl+C to stop.");
                        tokio::signal::ctrl_c().await?;
                    }
                    Err(e) => {
                        println!("Could not connect to peer: {}", e);
                        println!("Switching to listen mode...");
                        println!("Node is running. Press Ctrl+C to stop.");
                        tokio::signal::ctrl_c().await?;
                    }
                }
            } else {
                println!("No peer specified, listening for connections...");
                println!("Node is running. Press Ctrl+C to stop.");
                tokio::signal::ctrl_c().await?;
            }
        }
        _ => {
            eprintln!("Invalid mode: {}. Use 'listen', 'connect', or 'auto'", args.mode);
            return Ok(());
        }
    }
    
    println!("\nShutting down...");
    router.shutdown().await?;
    network.endpoint().close().await;
    
    Ok(())
}

/// Connect to a peer using the network crate
async fn connect_to_peer(network: &IrohNetwork, peer_addr_str: &str, protocol: &str) -> Result<()> {
    use iroh::PublicKey;
    
    // Parse the peer address - can be "node_id" or "node_id@ip:port"
    let (node_id_str, socket_addr_opt) = if let Some((id, addr)) = peer_addr_str.split_once('@') {
        (id, Some(addr))
    } else {
        (peer_addr_str, None)
    };
    
    // Parse the node ID as a PublicKey
    let peer_public_key: PublicKey = node_id_str.parse()
        .context("Failed to parse peer address as PublicKey. Expected format: <node_id> or <node_id>@<ip>:<port>")?;
    
    // Convert PublicKey to PeerId, including socket address if provided
    let peer_id_bytes = if let Some(addr) = socket_addr_opt {
        format!("{}@{}", node_id_str, addr).into_bytes()
    } else {
        node_id_str.as_bytes().to_vec()
    };
    let peer_id = PeerId::new(peer_id_bytes);
    
    if let Some(addr) = socket_addr_opt {
        println!("Connecting to peer with node ID: {} at address: {}", peer_public_key, addr);
    } else {
        println!("Connecting to peer with node ID: {} (no address specified, using discovery)", peer_public_key);
    }
    
    // Connect using the network trait
    let mut conn = network.connect(&peer_id, protocol).await
        .context("Failed to connect to peer")?;
    
    let remote_id = conn.peer_id();
    println!("✅ Successfully connected to peer: {:?}", remote_id);
    
    // Send a greeting message
    let message = Message::new(
        b"Hello from orbis-node!".to_vec(),
        protocol
    );
    conn.send(message).await?;
    println!("Sent greeting message");
    
    // Receive response
    match conn.recv().await {
        Ok(response) => {
            println!("Received response: {} bytes", response.data.len());
            if let Ok(text) = std::str::from_utf8(&response.data) {
                println!("Response: {}", text);
            }
        }
        Err(e) => {
            println!("Error receiving response: {}", e);
        }
    }
    
    // Close the connection
    conn.close().await?;
    println!("Connection closed");
    
    Ok(())
}

/// Protocol handler for Orbis node using the network crate's ProtocolHandler trait
#[derive(Debug, Clone)]
struct OrbisHandler;

#[async_trait::async_trait]
impl ProtocolHandler for OrbisHandler {
    async fn handle(&self, connection: Box<dyn network::Connection>) -> network::Result<()> {
        let mut connection = connection;
        let peer_id = connection.peer_id();
        println!("New connection from: {:?}", peer_id);
        
        // Receive a message
        match connection.recv().await {
            Ok(message) => {
                println!("Received: {} bytes on protocol: {}", std::str::from_utf8(&message.data).unwrap().to_string(), message.protocol);
                
                // Echo the message back
                let echo_message = Message::new(message.data, message.protocol);
                if let Err(e) = connection.send(echo_message).await {
                    eprintln!("Error sending echo: {}", e);
                }
            }
            Err(e) => {
                eprintln!("Error receiving message: {}", e);
            }
        }
        
        // Close the connection
        connection.close().await?;
        
        Ok(())
    }
}
