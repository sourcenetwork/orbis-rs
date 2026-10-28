//! Cosmos signing identity and bulletin preparation.

use super::VeraBulletin;
use crate::startup::cosmos::{identity, prepare_signer};
use crate::startup::{BulletinFactory, BulletinStartupError, NodeIdentity, PreparedBulletin};
use async_trait::async_trait;
use common::{
    blockchain::{ChainConfigBuilder, TxSigner},
    startup::{ConnectionPhase, PrepareContext, StartupProgress},
};
use local_storage::r#trait::LocalStorage;
use std::{path::Path, sync::Arc};

/// Minimum account balance the node waits for before registering itself.
/// Also the threshold the devnet-only `ensure_funded` bootstrap (below) tops
/// an account up to, so a brand-new integration-test node isn't stuck
/// waiting on a balance nothing will ever supply. Exposed for test harnesses
/// that construct a `VeraBulletin` directly (bypassing this factory) and
/// need the same threshold.
pub const MIN_NODE_BALANCE: u64 = 1_000_000;

#[derive(Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VeraBulletinConfig {
    #[serde(flatten)]
    pub chain: ChainConfigBuilder,
    /// Bech32 address of an account that has granted this node a fee
    /// allowance (Cosmos SDK x/feegrant). The grant must already exist on
    /// chain.
    #[serde(default)]
    pub fee_granter: Option<String>,
}

pub struct VeraBulletinFactory;

impl BulletinFactory for VeraBulletinFactory {
    const NAME: &'static str = "bulletin/vera";
    type Config = VeraBulletinConfig;
    type Prepared = PreparedVeraBulletin;

    fn prepare(
        config: Self::Config,
        context: PrepareContext<'_>,
    ) -> Result<Self::Prepared, BulletinStartupError> {
        config
            .chain
            .validate()
            .map_err(BulletinStartupError::Configuration)?;
        #[cfg(feature = "integration-test-cosmos")]
        let initial_key = std::env::var("ORBIS_SIGNING_KEY").ok();
        #[cfg(not(feature = "integration-test-cosmos"))]
        let initial_key: Option<String> = None;
        PreparedVeraBulletin::prepare(
            context.storage,
            context.runtime_base_path,
            config.chain,
            config.fee_granter.as_deref(),
            initial_key.as_deref(),
            Some(MIN_NODE_BALANCE),
        )
    }
}

pub struct PreparedVeraBulletin {
    identity: NodeIdentity,
    config: ChainConfigBuilder,
    signer: TxSigner,
    minimum_balance: Option<u64>,
}

impl PreparedVeraBulletin {
    pub fn prepare(
        storage: &impl LocalStorage,
        base: &Path,
        config: ChainConfigBuilder,
        fee_granter: Option<&str>,
        initial_key: Option<&str>,
        minimum_balance: Option<u64>,
    ) -> Result<Self, BulletinStartupError> {
        let signer = prepare_signer(storage, config.clone().build(), base, initial_key)?;
        let signer = match fee_granter {
            Some(granter) => signer.with_fee_granter(granter)?,
            None => signer,
        };
        Ok(Self {
            identity: identity(&signer),
            config,
            signer,
            minimum_balance,
        })
    }
}

#[async_trait]
impl PreparedBulletin for PreparedVeraBulletin {
    fn identity(&self) -> &NodeIdentity {
        &self.identity
    }
    fn name(&self) -> &'static str {
        "bulletin/vera"
    }

    async fn connect(
        self: Box<Self>,
        progress: &dyn StartupProgress,
    ) -> Result<Arc<dyn crate::r#trait::Bulletin + Send + Sync>, BulletinStartupError> {
        progress.set_phase(ConnectionPhase::Connecting);
        progress.set_phase(ConnectionPhase::WaitingForFunding);
        #[cfg(feature = "integration-test-cosmos")]
        if let Some(minimum) = self.minimum_balance {
            common::blockchain::cosmos::funding::ensure_funded(
                self.identity.public_address.clone(),
                self.config.clone().build(),
                minimum,
            )
            .await?;
        }
        let bulletin =
            VeraBulletin::with_signer(self.config, self.signer, self.minimum_balance).await?;
        progress.set_phase(ConnectionPhase::Funded);
        Ok(Arc::new(bulletin))
    }
}
