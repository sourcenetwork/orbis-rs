//! Native authorization construction via `AuthzFactory`.

use super::NativeAuth;
use crate::{
    error::AuthZError,
    r#trait::Authz,
    startup::{AuthzFactory, AuthzStartupError, PreparedAuthz},
};
use async_trait::async_trait;
use common::blockchain::native::{NativeTrustChainConfig, NativeTrustConfig};
use common::startup::{PrepareContext, StartupProgress};
use std::sync::Arc;
use vera_client::VeraClient;

pub struct NativeAuthzFactory;

impl AuthzFactory for NativeAuthzFactory {
    const NAME: &'static str = "authz/native";
    type Config = NativeTrustChainConfig;
    type ValidatedConfig = NativeTrustConfig;
    type Prepared = PreparedNativeAuthz;

    fn validate(config: Self::Config) -> Result<Self::ValidatedConfig, AuthzStartupError> {
        NativeTrustConfig::try_from(config)
            .map_err(|e| AuthzStartupError::Configuration(e.to_string()))
    }

    fn prepare(
        config: Self::ValidatedConfig,
        _context: PrepareContext<'_>,
    ) -> Result<Self::Prepared, AuthzStartupError> {
        Ok(PreparedNativeAuthz { config })
    }
}

pub struct PreparedNativeAuthz {
    config: NativeTrustConfig,
}

#[async_trait]
impl PreparedAuthz for PreparedNativeAuthz {
    async fn connect(
        self,
        _progress: &dyn StartupProgress,
    ) -> Result<Arc<dyn Authz>, AuthzStartupError> {
        let auth = tokio::time::timeout(
            self.config.timeout,
            NativeAuth::connect(
                VeraClient::new(&self.config.endpoint),
                self.config.trusted,
                self.config.root,
                self.config.maximum_age,
            ),
        )
        .await?
        .map_err(AuthZError::from)?;
        Ok(Arc::new(auth))
    }
}
