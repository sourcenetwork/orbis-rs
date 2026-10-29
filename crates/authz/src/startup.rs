//! Compile-time-selected authorization construction, parallel to
//! `bulletin::startup`. The node never constructs an `Authz` implementation
//! directly — it goes through whichever `AuthzFactoryImpl` the build selected.

use crate::r#trait::Authz;
use async_trait::async_trait;
use common::startup::{PrepareContext, StartupProgress};
use serde::de::DeserializeOwned;
use std::sync::Arc;

/// Selects and constructs one `Authz` implementation. `Config` is loaded by
/// `serde` as part of the node's single services-config file (see
/// `bulletin::startup::NodeServicesConfig`). `validate` is side-effect free;
/// `prepare` may use local storage after every selected service has validated.
pub trait AuthzFactory {
    /// Diagnostics name (logging/tracing), e.g. `"authz/native"`.
    const NAME: &'static str;
    type Config: DeserializeOwned;
    type ValidatedConfig;
    type Prepared: PreparedAuthz;

    fn validate(config: Self::Config) -> Result<Self::ValidatedConfig, AuthzStartupError>;

    fn prepare(
        config: Self::ValidatedConfig,
        context: PrepareContext<'_>,
    ) -> Result<Self::Prepared, AuthzStartupError>;
}

#[async_trait]
pub trait PreparedAuthz: Send {
    async fn connect(
        self,
        progress: &dyn StartupProgress,
    ) -> Result<Arc<dyn Authz>, AuthzStartupError>;
}

#[derive(Debug, thiserror::Error)]
pub enum AuthzStartupError {
    #[error("invalid authorization configuration: {0}")]
    Configuration(String),
    #[error("authorization connection failed: {0}")]
    Connection(#[from] crate::error::AuthZError),
    #[error("authorization connection timed out")]
    Timeout(#[from] tokio::time::error::Elapsed),
}
