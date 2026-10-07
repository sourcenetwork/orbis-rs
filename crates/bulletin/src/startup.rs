//! Backend-owned identity preparation before network connection.

#[cfg(feature = "cosmos-identity")]
pub mod cosmos;

use crate::{error::BulletinError, r#trait::Bulletin};
use async_trait::async_trait;
use std::{path::PathBuf, sync::Arc};
use thiserror::Error;

/// Public identity exposed by the node before and after backend connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeIdentity {
    pub node_key: String,
    pub public_address: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionPhase {
    Connecting,
    WaitingForFunding,
    Funded,
}

/// A prepared identity whose backend has not yet connected.
#[async_trait]
pub trait PreparedBulletin: Send {
    fn identity(&self) -> &NodeIdentity;
    fn name(&self) -> &'static str;
    fn registered_phase(&self) -> Option<ConnectionPhase> {
        None
    }
    async fn connect(
        self: Box<Self>,
        progress: &(dyn Fn(ConnectionPhase) + Send + Sync),
    ) -> Result<Arc<dyn Bulletin + Send + Sync>, StartupError>;
}

#[derive(Debug, Error)]
pub enum StartupError {
    #[error("{operation}: {path:?}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[cfg(any(feature = "cosmos-identity", feature = "native"))]
    #[error("signing identity storage failed")]
    Storage(#[from] local_storage::error::LocalStorageError),
    #[cfg(any(feature = "cosmos-identity", feature = "native"))]
    #[error("signing identity entropy failed")]
    Entropy(#[from] getrandom::Error),
    #[cfg(feature = "cosmos-identity")]
    #[error("stored signing identity is not UTF-8")]
    Encoding(#[from] std::str::Utf8Error),
    #[cfg(feature = "cosmos-identity")]
    #[error("chain signing identity failed")]
    Signer(#[from] common::blockchain::BlockchainError),
    #[cfg(feature = "native")]
    #[error("native worker initialization failed")]
    NativeWorker(#[from] vera_client::ClientError),
    #[error("node signing identity is missing")]
    MissingIdentity,
    #[error("bulletin connection failed")]
    Connection(#[from] BulletinError),
    #[error("bulletin connection timed out")]
    Timeout(#[from] tokio::time::error::Elapsed),
}
