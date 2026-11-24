//! Integration-test network type: a Vera chain plus orbis-node instances,
//! constructed by `VeraTestEnvironment`.

#[cfg(all(unix, feature = "vera"))]
mod vera;
#[cfg(all(unix, feature = "vera"))]
pub use vera::VeraNetworkAdapter;

/// Node info returned from the info endpoint
#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub grpc_endpoint: String,
    pub node_key: String,
    pub peer_id: String,
    pub p2p_address: String,
    pub public_address: String,
}
