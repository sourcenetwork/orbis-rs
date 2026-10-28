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
    startup::{AuthzFactory, PreparedAuthz},
};
use common::startup::{PrepareContext, StartupProgress};
use serde::{de::DeserializeOwned, Deserialize};
use std::{io::Read, marker::PhantomData, path::Path, sync::Arc};

/// Bounds the whole services-config file (both sections together) — up from
/// the 16 KiB the old, native-only trust file alone used to allow, since this
/// now also carries the vera/cosmos chain config in the common case.
const MAX_SERVICES_CONFIG_BYTES: u64 = 64 * 1024;

/// The node's single services-config file: one section per selected
/// implementation. Deserialized directly by `serde` — structural parsing is
/// all that's left to do once each implementation's own `prepare()` owns the
/// remaining (semantic) validation.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeServicesConfig<A, B> {
    pub authz: A,
    pub bulletin: B,
}

impl<A: DeserializeOwned, B: DeserializeOwned> NodeServicesConfig<A, B> {
    /// Load from `path` if given, otherwise deserialize both sections from
    /// an empty object. That works for any implementation whose `Config` has
    /// sensible defaults for every field (e.g. the vera backends, against a
    /// default-everything local chain), and fails with a clear "missing
    /// field" error for one that doesn't (e.g. the native backends, which
    /// have no sensible default endpoint or trust root) — no separate
    /// "config required" error type needed.
    pub fn load_or_default(path: Option<&Path>) -> Result<Self, BulletinStartupError> {
        match path {
            Some(path) => Self::load(path),
            None => serde_json::from_value(serde_json::json!({"authz": {}, "bulletin": {}}))
                .map_err(|e| BulletinStartupError::Configuration(e.to_string())),
        }
    }

    /// Read a bounded JSON document, rejecting unknown/duplicate fields and
    /// oversized input.
    pub fn load(path: &Path) -> Result<Self, BulletinStartupError> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .map_err(|source| BulletinStartupError::Io {
                operation: "open services config",
                path: path.into(),
                source,
            })?
            .take(MAX_SERVICES_CONFIG_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|source| BulletinStartupError::Io {
                operation: "read services config",
                path: path.into(),
                source,
            })?;
        if bytes.len() as u64 > MAX_SERVICES_CONFIG_BYTES {
            return Err(BulletinStartupError::Configuration(
                "services config exceeds 64 KiB".into(),
            ));
        }
        serde_json::from_slice(&bytes)
            .map_err(|e| BulletinStartupError::Configuration(e.to_string()))
    }
}

pub struct ServicesFactory<A, B>(PhantomData<(A, B)>);

impl<A: AuthzFactory, B: BulletinFactory> ServicesFactory<A, B> {
    pub fn load(
        path: Option<&Path>,
    ) -> Result<NodeServicesConfig<A::Config, B::Config>, BulletinStartupError> {
        NodeServicesConfig::load_or_default(path)
    }

    pub fn prepare(
        config: NodeServicesConfig<A::Config, B::Config>,
        context: PrepareContext<'_>,
    ) -> Result<PreparedNodeServices<A::Prepared, B::Prepared>, BulletinStartupError> {
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

    /// Connect both services — concurrently, since neither depends on the
    /// other — then register this node on the bulletin.
    pub async fn connect_and_register(
        self,
        registration: NodeRegistration,
        progress: &dyn StartupProgress,
    ) -> Result<ConnectedNodeServices, BulletinStartupError> {
        let Self {
            identity,
            authz,
            bulletin,
        } = self;
        let (authz, bulletin) = tokio::try_join!(
            async {
                authz
                    .connect(progress)
                    .await
                    .map_err(BulletinStartupError::from)
            },
            Box::new(bulletin).connect_and_register(registration, progress),
        )?;
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
