mod node;

pub use node::{DefraDbNode, SourceHubConfig};

/// Ports assigned to a DefraDB node.
pub struct DefraDbPorts {
    /// HTTP API port (default 9181). Serves GraphQL, REST, and health checks.
    pub http: u16,
    /// P2P port (default 9171). libp2p for node-to-node sync.
    pub p2p: u16,
}

/// Allocate ports for a single DefraDB instance.
pub fn allocate_defra_ports() -> eyre::Result<DefraDbPorts> {
    let ports = crate::allocate_ports(2)?;
    Ok(DefraDbPorts {
        http: ports[0],
        p2p: ports[1],
    })
}
