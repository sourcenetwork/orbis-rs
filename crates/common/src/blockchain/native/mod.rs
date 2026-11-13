//! The native (Commonware / vera.rs) client, chain configuration, and
//! deployment-trust bootstrap, shared by `authz::native` and
//! `bulletin::native`.

mod client;
mod config;
mod trust;
mod worker_store;

pub use client::{decode_node_signing_key, NativeVeraClient};
pub use config::{
    NativeChainConfig, NativeConfig, NativeConfigError, NativeTrustChainConfig, NativeTrustConfig,
};
pub use trust::{verify_deployment_root, DeploymentTrustError};
pub use worker_store::open_native_worker;
#[cfg(feature = "test-helpers")]
pub use worker_store::test_key;
