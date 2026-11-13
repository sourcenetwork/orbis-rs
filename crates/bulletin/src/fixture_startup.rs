//! Deterministic Vera/Cosmos startup used by integration fixtures.

use crate::{startup::BulletinStartupError, vera::startup::VeraStartupPolicy};
use async_trait::async_trait;
use common::blockchain::ChainConfigBuilder;

pub struct FixtureVeraStartup;

#[async_trait]
impl VeraStartupPolicy for FixtureVeraStartup {
    fn initial_signing_key() -> Option<String> {
        std::env::var("ORBIS_SIGNING_KEY").ok()
    }

    async fn ensure_funded(
        address: String,
        config: ChainConfigBuilder,
        minimum: u64,
    ) -> Result<(), BulletinStartupError> {
        common::blockchain::cosmos::funding::ensure_funded(address, config.build(), minimum)
            .await?;
        Ok(())
    }
}
