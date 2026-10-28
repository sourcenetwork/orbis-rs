//! Generic node-services composer: combines whichever `authz::AuthzFactory`
//! and `bulletin::BulletinFactory` implementations a build selected. This
//! module contains no implementation-specific branches — the only way to add
//! a backend is to implement the two factory traits, never to change this.

use crate::{
    r#trait::Bulletin,
    startup::{
        BulletinFactory, BulletinStartupError, NodeIdentity, NodeRegistration, PreparedBulletin,
    },
};
use authz::{
    r#trait::Authz,
    startup::{AuthzFactory, AuthzStartupError, PreparedAuthz},
};
use common::startup::{ConnectionPhase, PrepareContext, StartupProgress};
use serde::{de::DeserializeOwned, Deserialize};
use std::{
    io::Read,
    marker::PhantomData,
    path::{Path, PathBuf},
    sync::Arc,
};
use thiserror::Error;

/// Bounds the whole services-config file (both sections together) — up from
/// the 16 KiB the old, native-only trust file alone used to allow, since this
/// now also carries the vera/cosmos chain config in the common case.
const MAX_SERVICES_CONFIG_BYTES: u64 = 64 * 1024;

/// The node's single services-config file: one section per selected
/// implementation. Deserialized directly by `serde`; each factory then
/// performs side-effect-free semantic validation before either is prepared.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeServicesConfig<A, B> {
    pub authz: A,
    pub bulletin: B,
}

pub struct ValidatedNodeServicesConfig<A, B> {
    authz: A,
    bulletin: B,
}

#[derive(Debug, Error)]
pub enum NodeServicesStartupError {
    #[error("{operation}: {path:?}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid services configuration: {0}")]
    Configuration(String),
    #[error("authorization startup failed: {0}")]
    Authz(#[from] AuthzStartupError),
    #[error("bulletin startup failed: {0}")]
    Bulletin(#[from] BulletinStartupError),
}

impl<A: DeserializeOwned, B: DeserializeOwned> NodeServicesConfig<A, B> {
    /// Load from `path` if given, otherwise deserialize both sections from
    /// an empty object. That works for any implementation whose `Config` has
    /// sensible defaults for every field (e.g. the vera backends, against a
    /// default-everything local chain), and fails with a clear "missing
    /// field" error for one that doesn't (e.g. the native backends, which
    /// have no sensible default endpoint or trust root) — no separate
    /// "config required" error type needed.
    pub fn load_or_default(path: Option<&Path>) -> Result<Self, NodeServicesStartupError> {
        match path {
            Some(path) => Self::load(path),
            None => serde_json::from_value(serde_json::json!({"authz": {}, "bulletin": {}}))
                .map_err(|e| NodeServicesStartupError::Configuration(e.to_string())),
        }
    }

    /// Read a bounded JSON document, rejecting unknown/duplicate fields and
    /// oversized input.
    pub fn load(path: &Path) -> Result<Self, NodeServicesStartupError> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .map_err(|source| NodeServicesStartupError::Io {
                operation: "open services config",
                path: path.into(),
                source,
            })?
            .take(MAX_SERVICES_CONFIG_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|source| NodeServicesStartupError::Io {
                operation: "read services config",
                path: path.into(),
                source,
            })?;
        if bytes.len() as u64 > MAX_SERVICES_CONFIG_BYTES {
            return Err(NodeServicesStartupError::Configuration(
                "services config exceeds 64 KiB".into(),
            ));
        }
        serde_json::from_slice(&bytes)
            .map_err(|e| NodeServicesStartupError::Configuration(e.to_string()))
    }
}

pub struct ServicesFactory<A, B>(PhantomData<(A, B)>);

impl<A: AuthzFactory, B: BulletinFactory> ServicesFactory<A, B> {
    pub fn load_and_validate(
        path: Option<&Path>,
    ) -> Result<
        ValidatedNodeServicesConfig<A::ValidatedConfig, B::ValidatedConfig>,
        NodeServicesStartupError,
    > {
        let config = NodeServicesConfig::<A::Config, B::Config>::load_or_default(path)?;
        // Validate both sections before either implementation is allowed to
        // touch storage or create an identity.
        let authz = A::validate(config.authz)?;
        let bulletin = B::validate(config.bulletin)?;
        Ok(ValidatedNodeServicesConfig { authz, bulletin })
    }

    pub fn prepare(
        config: ValidatedNodeServicesConfig<A::ValidatedConfig, B::ValidatedConfig>,
        context: PrepareContext<'_>,
    ) -> Result<PreparedNodeServices<A::Prepared, B::Prepared>, NodeServicesStartupError> {
        let bulletin = B::prepare(config.bulletin, context)?;
        let identity = bulletin.identity().clone();
        let authz = A::prepare(config.authz, context)?;
        Ok(PreparedNodeServices {
            identity,
            authz,
            bulletin,
        })
    }
}

pub struct PreparedNodeServices<A: PreparedAuthz, B: PreparedBulletin> {
    identity: NodeIdentity,
    authz: A,
    bulletin: B,
}

impl<A: PreparedAuthz, B: PreparedBulletin> PreparedNodeServices<A, B> {
    pub fn identity(&self) -> &NodeIdentity {
        &self.identity
    }

    /// Connect authorization first, then connect/register the bulletin. The
    /// ordering keeps the shared progress state monotonic and avoids creating
    /// durable bulletin registration if authorization cannot start.
    pub async fn connect_and_register(
        self,
        registration: NodeRegistration,
        progress: &dyn StartupProgress,
    ) -> Result<ConnectedNodeServices, NodeServicesStartupError> {
        let Self {
            identity,
            authz,
            bulletin,
        } = self;
        progress.set_phase(ConnectionPhase::Connecting);
        let authz = authz.connect(progress).await?;
        let bulletin = Box::new(bulletin)
            .connect_and_register(registration, progress)
            .await?;
        Ok(ConnectedNodeServices {
            identity,
            authz,
            bulletin,
        })
    }
}

pub struct ConnectedNodeServices {
    pub identity: NodeIdentity,
    pub authz: Arc<dyn Authz>,
    pub bulletin: Arc<dyn Bulletin + Send + Sync>,
}
