use super::bootstrap::BootstrapStatus;
#[cfg(feature = "native")]
use super::native;
#[cfg(all(feature = "authz-vera", feature = "bulletin-vera"))]
use crate::constants::MIN_NODE_BALANCE;
#[cfg(all(feature = "authz-vera", feature = "bulletin-vera"))]
use crate::helpers::launch::create_and_store_node_key;
use crate::helpers::launch::Args;
use authz::r#trait::Authz;
#[cfg(all(feature = "authz-vera", feature = "bulletin-vera"))]
use authz::AuthzImpl;
use bulletin::r#trait::Bulletin;
#[cfg(all(feature = "authz-vera", feature = "bulletin-vera"))]
use bulletin::BulletinImpl;
#[cfg(all(feature = "authz-vera", feature = "bulletin-vera"))]
use common::blockchain::{ChainConfigBuilder, TxSigner};
use local_storage::LocalStorageImpl;
#[cfg(all(feature = "authz-vera", feature = "bulletin-vera"))]
use proto::info_service::NodeStatus;
use std::{path::Path, sync::Arc};

pub(super) struct Services {
    pub(super) authz: Arc<dyn Authz>,
    pub(super) bulletin: Arc<dyn Bulletin + Send + Sync>,
}

#[cfg(all(feature = "authz-vera", feature = "bulletin-vera"))]
pub(super) struct ChainBackend {
    config: ChainConfigBuilder,
    signer: TxSigner,
    authz: Arc<dyn Authz>,
}

pub(super) enum Backend {
    #[cfg(all(feature = "authz-vera", feature = "bulletin-vera"))]
    Chain(Box<ChainBackend>),
    #[cfg(feature = "native")]
    Native(Box<native::Config>),
}

impl Backend {
    pub(super) async fn prepare(
        args: &Args,
        storage: &LocalStorageImpl,
        base: &Path,
        #[cfg(feature = "native")] native_config: Option<native::Config>,
    ) -> Result<(String, Self), Box<dyn std::error::Error>> {
        #[cfg(feature = "native")]
        if let Some(config) = native_config {
            let node_key = native::initialize_identity(storage, base)?;
            return Ok((node_key, Self::Native(Box::new(config))));
        }

        #[cfg(all(feature = "authz-vera", feature = "bulletin-vera"))]
        {
            let authz_config = ChainConfigBuilder::default()
                .chain_id(args.chain_id.clone())
                .grpc_url(args.authz_grpc.clone())
                .rpc_url(args.chain_rpc.clone())
                .rest_url(args.chain_rest.clone())
                .denom(args.denom.clone())
                .gas_multiplier(args.chain_gas_multiplier)
                .allow_insecure_rpc(Some(args.allow_insecure_rpc));
            let authz = Arc::new(
                AuthzImpl::new(authz_config)
                    .await
                    .map_err(|e| format!("Failed to initialize authz: {e}"))?,
            );
            let config = ChainConfigBuilder::default()
                .chain_id(args.chain_id.clone())
                .grpc_url(args.bulletin_grpc.clone())
                .rpc_url(args.chain_rpc.clone())
                .rest_url(args.chain_rest.clone())
                .denom(args.denom.clone())
                .gas_multiplier(args.chain_gas_multiplier)
                .allow_insecure_rpc(Some(args.allow_insecure_rpc));
            let signer = create_and_store_node_key(storage.clone(), config.clone().build(), base)
                .map_err(|e| format!("Failed to create or store node key: {e}"))?;
            let signer = match args.fee_granter.as_deref() {
                Some(granter) => {
                    tracing::info!(
                        granter,
                        "Transactions will request a fee grant from this address"
                    );
                    signer
                        .with_fee_granter(granter)
                        .map_err(|e| format!("Invalid --fee-granter address: {e}"))?
                }
                None => signer,
            };
            Ok((
                signer.public_key_hex(),
                Self::Chain(Box::new(ChainBackend {
                    config,
                    signer,
                    authz,
                })),
            ))
        }
        #[cfg(not(all(feature = "authz-vera", feature = "bulletin-vera")))]
        {
            let _ = (args, storage, base);
            Err("this build requires --vera-config for the native backend".into())
        }
    }

    pub(super) async fn connect(
        self,
        args: &Args,
        storage: &LocalStorageImpl,
        base: &Path,
        status: &BootstrapStatus,
    ) -> Result<Services, Box<dyn std::error::Error>> {
        #[cfg(not(feature = "integration-test"))]
        let _ = args;
        #[cfg(not(feature = "native"))]
        let _ = (storage, base);
        #[cfg(not(all(feature = "authz-vera", feature = "bulletin-vera")))]
        let _ = status;
        match self {
            #[cfg(feature = "native")]
            Self::Native(config) => native::connect(*config, storage, base).await,
            #[cfg(all(feature = "authz-vera", feature = "bulletin-vera"))]
            Self::Chain(chain) => {
                let ChainBackend {
                    config,
                    signer,
                    authz,
                } = *chain;
                status.set_status(NodeStatus::ConnectingToChain);
                #[cfg(feature = "integration-test")]
                {
                    status.set_status(NodeStatus::WaitingForFunding);
                    let fund_config = ChainConfigBuilder::default()
                        .chain_id(args.chain_id.clone())
                        .rpc_url(args.chain_rpc.clone())
                        .rest_url(args.chain_rest.clone())
                        .grpc_url(args.bulletin_grpc.clone())
                        .gas_multiplier(args.chain_gas_multiplier)
                        .allow_insecure_rpc(Some(args.allow_insecure_rpc))
                        .build();
                    cli_tool::fund(signer.address(), fund_config)
                        .await
                        .map_err(|e| format!("Failed to fund node account: {e}"))?;
                    status.set_status(NodeStatus::Funded);
                }
                #[cfg(not(feature = "integration-test"))]
                status.set_status(NodeStatus::WaitingForFunding);
                let bulletin = Arc::new(
                    BulletinImpl::with_signer(config, signer, Some(MIN_NODE_BALANCE))
                        .await
                        .map_err(|e| format!("Failed to initialize bulletin: {e}"))?,
                );
                Ok(Services { authz, bulletin })
            }
        }
    }
}

pub(super) fn names(native: bool) -> (String, String) {
    if native {
        return ("native Vera".into(), "native Vera".into());
    }
    #[cfg(all(feature = "authz-vera", feature = "bulletin-vera"))]
    return (AuthzImpl::name(), BulletinImpl::name());
    #[cfg(not(all(feature = "authz-vera", feature = "bulletin-vera")))]
    ("injected".into(), "injected".into())
}
