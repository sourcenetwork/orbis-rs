//! Startup composition; implementations own their identity and worker preparation.

use super::bootstrap::BootstrapStatus;
use crate::helpers::launch::Args;
use authz::{error::AuthZError, r#trait::Authz};
use bulletin::{
    r#trait::Bulletin,
    startup::{ConnectionPhase, NodeIdentity, PreparedBulletin, StartupError},
};
use local_storage::LocalStorageImpl;
use proto::info_service::NodeStatus;
use std::{future::Future, path::Path, pin::Pin, sync::Arc, time::Duration};

#[derive(Debug, thiserror::Error)]
pub(super) enum Error {
    #[error("bulletin preparation failed")]
    Bulletin(#[from] StartupError),
    #[error("authorization initialization failed")]
    Authorization(#[from] AuthZError),
    #[cfg(feature = "native")]
    #[error("native configuration failed")]
    Configuration(#[from] bulletin::native::ConfigError),
    #[cfg(feature = "integration-test-cosmos")]
    #[error("integration account funding failed")]
    Funding(#[from] common::blockchain::BlockchainError),
    #[error("backend connection timed out")]
    Timeout(#[from] tokio::time::error::Elapsed),
    #[error("native Vera support requires building with --features native")]
    #[cfg(not(feature = "native"))]
    NativeUnavailable,
    #[error("this build requires --vera-config for the native backend")]
    #[cfg(not(all(feature = "authz-vera", feature = "bulletin-vera")))]
    ConfigurationRequired,
}

pub(super) struct Services {
    pub(super) authz: Arc<dyn Authz>,
    pub(super) bulletin: Arc<dyn Bulletin + Send + Sync>,
    registered_phase: Option<ConnectionPhase>,
}

fn update_status(status: &BootstrapStatus, phase: ConnectionPhase) {
    status.set_status(match phase {
        ConnectionPhase::Connecting => NodeStatus::ConnectingToChain,
        ConnectionPhase::WaitingForFunding => NodeStatus::WaitingForFunding,
        ConnectionPhase::Funded => NodeStatus::Funded,
    });
}

impl Services {
    pub(super) fn registration_complete(&self, status: &BootstrapStatus) {
        if let Some(phase) = self.registered_phase {
            update_status(status, phase);
        }
    }
}

type Authorization = Pin<Box<dyn Future<Output = Result<Arc<dyn Authz>, AuthZError>> + Send>>;

#[cfg(feature = "integration-test-cosmos")]
struct Funding {
    address: String,
    config: common::blockchain::ChainConfig,
}

pub(super) struct PreparedServices {
    pub(super) identity: NodeIdentity,
    bulletin: Box<dyn PreparedBulletin>,
    authorization: Authorization,
    timeout: Option<Duration>,
    #[cfg(feature = "integration-test-cosmos")]
    funding: Option<Funding>,
}

impl PreparedServices {
    pub(super) async fn connect(self, status: &BootstrapStatus) -> Result<Services, Error> {
        let timeout = self.timeout;
        let connect = async {
            let authz = self.authorization.await?;
            #[cfg(feature = "integration-test-cosmos")]
            if let Some(funding) = self.funding {
                status.set_status(NodeStatus::ConnectingToChain);
                status.set_status(NodeStatus::WaitingForFunding);
                cli_tool::ensure_funded(
                    funding.address,
                    funding.config,
                    crate::constants::MIN_NODE_BALANCE,
                )
                .await?;
                status.set_status(NodeStatus::Funded);
            }
            let progress = |phase| update_status(status, phase);
            let registered_phase = self.bulletin.registered_phase();
            let bulletin = self.bulletin.connect(&progress).await?;
            Ok(Services {
                authz,
                bulletin,
                registered_phase,
            })
        };
        match timeout {
            Some(timeout) => tokio::time::timeout(timeout, connect).await?,
            None => connect.await,
        }
    }
}

pub(super) struct Configuration {
    #[cfg(feature = "native")]
    native: Option<bulletin::native::NativeConfig>,
}

impl Configuration {
    pub(super) fn load(args: &Args) -> Result<Self, Error> {
        #[cfg(not(feature = "native"))]
        if args.vera_config.is_some() {
            return Err(Error::NativeUnavailable);
        }
        #[cfg(not(all(feature = "authz-vera", feature = "bulletin-vera")))]
        if args.vera_config.is_none() {
            return Err(Error::ConfigurationRequired);
        }
        Ok(Self {
            #[cfg(feature = "native")]
            native: args
                .vera_config
                .as_deref()
                .map(bulletin::native::NativeConfig::load)
                .transpose()?,
        })
    }

    pub(super) fn names(&self) -> (String, String) {
        #[cfg(feature = "native")]
        if self.native.is_some() {
            return ("native Vera".into(), "native Vera".into());
        }
        #[cfg(all(feature = "authz-vera", feature = "bulletin-vera"))]
        return (authz::AuthzImpl::name(), bulletin::BulletinImpl::name());
        #[cfg(not(all(feature = "authz-vera", feature = "bulletin-vera")))]
        ("injected".into(), "injected".into())
    }

    pub(super) async fn prepare(
        self,
        args: &Args,
        storage: &LocalStorageImpl,
        base: &Path,
    ) -> Result<PreparedServices, Error> {
        #[cfg(feature = "native")]
        if let Some(config) = self.native {
            let timeout = config.timeout;
            let bulletin = Box::new(bulletin::native::startup::PreparedNativeBulletin::prepare(
                config.clone(),
                storage,
                base,
            )?);
            let authorization: Authorization = Box::pin(async move {
                Ok(Arc::new(
                    authz::native::NativeAuth::connect(
                        vera_client::VeraClient::new(&config.endpoint),
                        config.trusted,
                        config.root,
                        config.maximum_age,
                    )
                    .await
                    .map_err(AuthZError::from)?,
                ) as Arc<dyn Authz>)
            });
            return Ok(PreparedServices {
                identity: bulletin.identity().clone(),
                bulletin,
                authorization,
                timeout: Some(timeout),
                #[cfg(feature = "integration-test-cosmos")]
                funding: None,
            });
        }
        #[cfg(all(feature = "authz-vera", feature = "bulletin-vera"))]
        {
            use common::blockchain::ChainConfigBuilder;
            let chain = || {
                ChainConfigBuilder::default()
                    .chain_id(args.chain_id.clone())
                    .rpc_url(args.chain_rpc.clone())
                    .rest_url(args.chain_rest.clone())
                    .denom(args.denom.clone())
                    .gas_multiplier(args.chain_gas_multiplier)
                    .allow_insecure_rpc(Some(args.allow_insecure_rpc))
            };
            let authz: Arc<dyn Authz> =
                Arc::new(authz::AuthzImpl::new(chain().grpc_url(args.authz_grpc.clone())).await?);
            let config = chain().grpc_url(args.bulletin_grpc.clone());
            #[cfg(feature = "integration-test")]
            let initial_key = std::env::var("ORBIS_SIGNING_KEY").ok();
            #[cfg(not(feature = "integration-test"))]
            let initial_key: Option<String> = None;
            let bulletin = bulletin::vera::startup::PreparedVeraBulletin::prepare(
                storage,
                base,
                config,
                args.fee_granter.as_deref(),
                initial_key.as_deref(),
                Some(crate::constants::MIN_NODE_BALANCE),
            )?;
            #[cfg(feature = "integration-test-cosmos")]
            let (bulletin, funding) = {
                let funding = Funding {
                    address: bulletin.identity().public_address.clone(),
                    config: ChainConfigBuilder::default()
                        .chain_id(args.chain_id.clone())
                        .rpc_url(args.chain_rpc.clone())
                        .rest_url(args.chain_rest.clone())
                        .grpc_url(args.bulletin_grpc.clone())
                        .gas_multiplier(args.chain_gas_multiplier)
                        .allow_insecure_rpc(Some(args.allow_insecure_rpc))
                        .build(),
                };
                (bulletin.with_funding_complete(), Some(funding))
            };
            Ok(PreparedServices {
                identity: bulletin.identity().clone(),
                bulletin: Box::new(bulletin),
                authorization: Box::pin(async move { Ok(authz) }),
                timeout: None,
                #[cfg(feature = "integration-test-cosmos")]
                funding,
            })
        }
        #[cfg(not(all(feature = "authz-vera", feature = "bulletin-vera")))]
        {
            let _ = (args, storage, base);
            Err(Error::ConfigurationRequired)
        }
    }
}
