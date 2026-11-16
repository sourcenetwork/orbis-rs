//! The Vera (Commonware / vera.rs) client, chain configuration, and
//! deployment-trust bootstrap, shared by `authz::vera` and
//! `bulletin::vera`.

mod client;
mod config;
mod trust;
mod worker_store;

pub use client::{decode_node_signing_key, VeraClient};
pub use config::{
    VeraChainConfig, VeraConfig, VeraConfigError, VeraTrustChainConfig, VeraTrustConfig,
};
pub use trust::{verify_deployment_root, DeploymentTrustError};
pub use worker_store::open_vera_worker;
#[cfg(feature = "test-helpers")]
pub use worker_store::test_key;
