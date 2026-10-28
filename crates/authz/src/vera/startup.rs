//! Vera (Cosmos) authorization construction via `AuthzFactory`.

use super::VeraAuth;
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

pub struct VeraAuthzFactory;

impl AuthzFactory for VeraAuthzFactory {
    const NAME: &'static str = "authz/vera";
    type Config = ChainConfigBuilder;
    type Prepared = PreparedVeraAuthz;

    fn prepare(
        config: Self::Config,
        _context: PrepareContext<'_>,
    ) -> Result<Self::Prepared, AuthzStartupError> {
        config
            .validate()
            .map_err(AuthzStartupError::Configuration)?;
        Ok(PreparedVeraAuthz { config })
    }
}

pub struct PreparedVeraAuthz {
    config: ChainConfigBuilder,
}

#[async_trait]
impl PreparedAuthz for PreparedVeraAuthz {
    async fn connect(
        self,
        progress: &dyn StartupProgress,
    ) -> Result<Arc<dyn Authz>, AuthzStartupError> {
        progress.set_phase(ConnectionPhase::Connecting);
        let auth = VeraAuth::new(self.config).await?;
        Ok(Arc::new(auth))
    }
}
