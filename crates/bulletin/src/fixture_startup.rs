//! Deterministic Vera/Cosmos startup used by integration fixtures.

use crate::{startup::BulletinStartupError, vera_go::startup::VeraGoStartupPolicy};
use async_trait::async_trait;
use common::blockchain::ChainConfigBuilder;

pub struct FixtureVeraGoStartup;

#[async_trait]
impl VeraGoStartupPolicy for FixtureVeraGoStartup {
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
