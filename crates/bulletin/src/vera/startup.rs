//! Cosmos signing identity and bulletin preparation.

use super::VeraBulletin;
use crate::startup::cosmos::{identity, prepare_signer};
use crate::startup::{ConnectionPhase, NodeIdentity, PreparedBulletin, StartupError};
use async_trait::async_trait;
use common::blockchain::{ChainConfigBuilder, TxSigner};
use local_storage::r#trait::LocalStorage;
use std::{path::Path, sync::Arc};

pub struct PreparedVeraBulletin {
    identity: NodeIdentity,
    config: ChainConfigBuilder,
    signer: TxSigner,
    minimum_balance: Option<u64>,
    funded: bool,
}

impl PreparedVeraBulletin {
    pub fn prepare(
        storage: &impl LocalStorage,
        base: &Path,
        config: ChainConfigBuilder,
        fee_granter: Option<&str>,
        initial_key: Option<&str>,
        minimum_balance: Option<u64>,
    ) -> Result<Self, StartupError> {
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
            funded: false,
        })
    }

    /// Integration setup has already funded the prepared public address.
    pub fn with_funding_complete(mut self) -> Self {
        self.funded = true;
        self
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
    fn registered_phase(&self) -> Option<ConnectionPhase> {
        Some(ConnectionPhase::Funded)
    }

    async fn connect(
        self: Box<Self>,
        progress: &(dyn Fn(ConnectionPhase) + Send + Sync),
    ) -> Result<Arc<dyn crate::r#trait::Bulletin + Send + Sync>, StartupError> {
        progress(ConnectionPhase::Connecting);
        progress(if self.funded {
            ConnectionPhase::Funded
        } else {
            ConnectionPhase::WaitingForFunding
        });
        let bulletin =
            VeraBulletin::with_signer(self.config, self.signer, self.minimum_balance).await?;
        Ok(Arc::new(bulletin))
    }
}
