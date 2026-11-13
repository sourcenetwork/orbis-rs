//! Chain configuration and deployment-trust bootstrap for the native
//! (Commonware / vera.rs) backend, shared by `authz::native` and
//! `bulletin::native`.

mod client;
mod config;

pub use client::{verify_deployment_root, DeploymentTrustError};
pub use config::{NativeChainConfig, NativeConfig, NativeConfigError};
