//! Per-backend integration-test network types: a chain plus orbis-node
//! instances. [`CosmosNetwork`]/[`VeraNetworkAdapter`] are constructed
//! directly by each backend's own `TestEnvironment` implementation
//! (`CosmosTestEnvironment`/`VeraTestEnvironment`) — there is no shared
//! runtime-dispatch wrapper; backend selection happens once, at compile
//! time, via which concrete environment a test's entry point registers.

#[cfg(feature = "cosmos")]
mod cosmos;
#[cfg(feature = "cosmos")]
pub(crate) use cosmos::select_publish_port;
#[cfg(feature = "cosmos")]
pub use cosmos::CosmosNetwork;

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
