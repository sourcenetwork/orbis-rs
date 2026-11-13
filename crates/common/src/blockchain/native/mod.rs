//! Chain configuration, deployment-trust bootstrap, and the worker-key store
//! for the native (Commonware / vera.rs) backend, shared by `authz::native`
//! and `bulletin::native`.

mod client;
mod config;
mod worker_store;

pub use client::{verify_deployment_root, DeploymentTrustError};
pub use config::{
    NativeChainConfig, NativeConfig, NativeConfigError, NativeTrustChainConfig, NativeTrustConfig,
};
pub use worker_store::open_native_worker;
#[cfg(feature = "test-helpers")]
pub use worker_store::test_key;
