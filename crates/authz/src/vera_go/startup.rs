//! Vera (Cosmos) authorization construction via `AuthzFactory`.

use super::VeraGoAuth;
use crate::{
    r#trait::Authz,
    startup::{AuthzFactory, AuthzStartupError, PreparedAuthz},
};
use async_trait::async_trait;
use common::{
    blockchain::ChainConfigBuilder,
    startup::{ConnectionPhase, PrepareContext, StartupProgress},
};
use std::sync::Arc;

pub struct VeraGoAuthzFactory;

impl AuthzFactory for VeraGoAuthzFactory {
    const NAME: &'static str = "authz/vera-go";
    type Config = ChainConfigBuilder;
    type ValidatedConfig = ChainConfigBuilder;
    type Prepared = PreparedVeraGoAuthz;

    fn validate(config: Self::Config) -> Result<Self::ValidatedConfig, AuthzStartupError> {
        config
            .validate()
            .map_err(AuthzStartupError::Configuration)?;
        Ok(config)
    }

    fn prepare(
        config: Self::ValidatedConfig,
        _context: PrepareContext<'_>,
    ) -> Result<Self::Prepared, AuthzStartupError> {
        Ok(PreparedVeraGoAuthz { config })
    }
}

pub struct PreparedVeraGoAuthz {
    config: ChainConfigBuilder,
}

#[async_trait]
impl PreparedAuthz for PreparedVeraGoAuthz {
    async fn connect(
        self,
        progress: &dyn StartupProgress,
    ) -> Result<Arc<dyn Authz>, AuthzStartupError> {
        progress.set_phase(ConnectionPhase::Connecting);
        let auth = VeraGoAuth::new(self.config).await?;
        Ok(Arc::new(auth))
    }
}
