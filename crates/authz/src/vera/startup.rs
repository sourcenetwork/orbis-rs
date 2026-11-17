//! Vera authorization construction via `AuthzFactory`.

use super::VeraAuth;
use crate::{
    error::AuthZError,
    r#trait::Authz,
    startup::{AuthzFactory, AuthzStartupError, PreparedAuthz},
};
use async_trait::async_trait;
use common::blockchain::vera::{VeraTrustChainConfig, VeraTrustConfig};
use common::startup::{PrepareContext, StartupProgress};
use std::sync::Arc;
use vera_client::VeraClient;

pub struct VeraAuthzFactory;

impl AuthzFactory for VeraAuthzFactory {
    const NAME: &'static str = "authz/vera";
    type Config = VeraTrustChainConfig;
    type ValidatedConfig = VeraTrustConfig;
    type Prepared = PreparedVeraAuthz;

    fn validate(config: Self::Config) -> Result<Self::ValidatedConfig, AuthzStartupError> {
        VeraTrustConfig::try_from(config)
            .map_err(|e| AuthzStartupError::Configuration(e.to_string()))
    }

    fn prepare(
        config: Self::ValidatedConfig,
        _context: PrepareContext<'_>,
    ) -> Result<Self::Prepared, AuthzStartupError> {
        Ok(PreparedVeraAuthz { config })
    }
}

pub struct PreparedVeraAuthz {
    config: VeraTrustConfig,
}

#[async_trait]
impl PreparedAuthz for PreparedVeraAuthz {
    async fn connect(
        self,
        _progress: &dyn StartupProgress,
    ) -> Result<Arc<dyn Authz>, AuthzStartupError> {
        let auth = tokio::time::timeout(
            self.config.timeout,
            VeraAuth::connect(
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
