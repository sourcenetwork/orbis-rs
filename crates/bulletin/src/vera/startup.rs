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
use std::{marker::PhantomData, path::Path, sync::Arc};

/// Minimum account balance the node waits for before registering itself.
/// Also the threshold the devnet-only startup policy tops
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

#[async_trait]
pub trait VeraStartupPolicy: Send + 'static {
    fn initial_signing_key() -> Option<String>;

    async fn ensure_funded(
        _address: String,
        _config: ChainConfigBuilder,
        _minimum: u64,
    ) -> Result<(), BulletinStartupError> {
        Ok(())
    }
}

pub struct ProductionVeraStartup;

#[async_trait]
impl VeraStartupPolicy for ProductionVeraStartup {
    fn initial_signing_key() -> Option<String> {
        None
    }
}

pub struct VeraBulletinFactory<P = ProductionVeraStartup>(PhantomData<P>);

pub struct ValidatedVeraBulletinConfig {
    chain: ChainConfigBuilder,
    fee_granter: Option<String>,
}

impl<P: VeraStartupPolicy> BulletinFactory for VeraBulletinFactory<P> {
    const NAME: &'static str = "bulletin/vera";
    type Config = VeraBulletinConfig;
    type ValidatedConfig = ValidatedVeraBulletinConfig;
    type Prepared = PreparedVeraBulletin<P>;

    fn validate(config: Self::Config) -> Result<Self::ValidatedConfig, BulletinStartupError> {
        config
            .chain
            .validate()
            .map_err(BulletinStartupError::Configuration)?;
        if let Some(granter) = config.fee_granter.as_deref() {
            TxSigner::validate_fee_granter(granter)?;
        }
        Ok(ValidatedVeraBulletinConfig {
            chain: config.chain,
            fee_granter: config.fee_granter,
        })
    }

    fn prepare(
        config: Self::ValidatedConfig,
        context: PrepareContext<'_>,
    ) -> Result<Self::Prepared, BulletinStartupError> {
        let initial_key = P::initial_signing_key();
        PreparedVeraBulletin::<P>::prepare(
            context.storage,
            context.runtime_base_path,
            config.chain,
            config.fee_granter.as_deref(),
            initial_key.as_deref(),
            Some(MIN_NODE_BALANCE),
        )
    }
}

pub struct PreparedVeraBulletin<P: VeraStartupPolicy> {
    identity: NodeIdentity,
    config: ChainConfigBuilder,
    signer: TxSigner,
    minimum_balance: Option<u64>,
    policy: PhantomData<P>,
}

impl<P: VeraStartupPolicy> PreparedVeraBulletin<P> {
    pub fn prepare(
        storage: &(impl LocalStorage + ?Sized),
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
            policy: PhantomData,
        })
    }
}

#[async_trait]
impl<P: VeraStartupPolicy> PreparedBulletin for PreparedVeraBulletin<P> {
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
        if let Some(minimum) = self.minimum_balance {
            P::ensure_funded(
                self.identity.public_address.clone(),
                self.config.clone(),
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
