//! Native authorization construction via `AuthzFactory`.
//!
//! Deliberately not shared with `bulletin::native`'s own config, even though
//! a real deployment's values usually match: keeping them separate is what
//! lets native authz pair with a non-native bulletin backend (or vice versa)
//! instead of permanently coupling the two.

use super::NativeAuth;
use crate::{
    error::AuthZError,
    r#trait::Authz,
    startup::{AuthzFactory, AuthzStartupError, PreparedAuthz},
};
use async_trait::async_trait;
use common::startup::{PrepareContext, StartupProgress};
use commonware_codec::DecodeExt;
use serde::Deserialize;
use std::{sync::Arc, time::Duration};
use vera_client::VeraClient;
use vera_domain::ConsensusPublicKey;

fn default_timeout() -> u64 {
    30
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAuthzConfig {
    /// HTTP(S) endpoint serving native requests and evidence.
    pub endpoint: String,
    /// Independently provisioned deployment root (hex-encoded, 32 bytes).
    pub deployment_root: String,
    /// Independently provisioned consensus public key (hex-encoded).
    pub consensus_key: String,
    /// Maximum age in seconds for current-state evidence.
    #[serde(default = "default_timeout")]
    pub max_evidence_age_secs: u64,
    /// Overall request deadline for the initial connection check.
    #[serde(default = "default_timeout")]
    pub request_timeout_secs: u64,
}

pub struct NativeAuthzFactory;

pub struct ValidatedNativeAuthzConfig {
    endpoint: String,
    root: [u8; 32],
    trusted: ConsensusPublicKey,
    maximum_age: u64,
    timeout: Duration,
}

impl AuthzFactory for NativeAuthzFactory {
    const NAME: &'static str = "authz/native";
    type Config = NativeAuthzConfig;
    type ValidatedConfig = ValidatedNativeAuthzConfig;
    type Prepared = PreparedNativeAuthz;

    fn validate(config: Self::Config) -> Result<Self::ValidatedConfig, AuthzStartupError> {
        let endpoint = url::Url::parse(&config.endpoint).map_err(|e| {
            AuthzStartupError::Configuration(format!("invalid native Vera endpoint: {e}"))
        })?;
        if !matches!(endpoint.scheme(), "http" | "https")
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(AuthzStartupError::Configuration(
                "native Vera endpoint must be an HTTP(S) URL without credentials or a fragment"
                    .into(),
            ));
        }
        let root: [u8; 32] = hex::decode(&config.deployment_root)
            .map_err(|e| AuthzStartupError::Configuration(format!("invalid deployment_root: {e}")))?
            .try_into()
            .map_err(|_| {
                AuthzStartupError::Configuration(
                    "deployment_root must encode exactly 32 bytes".into(),
                )
            })?;
        let trusted = ConsensusPublicKey::decode(alloy_primitives::bytes::Bytes::from(
            hex::decode(&config.consensus_key).map_err(|e| {
                AuthzStartupError::Configuration(format!("invalid consensus_key: {e}"))
            })?,
        ))
        .map_err(|e| {
            AuthzStartupError::Configuration(format!("invalid consensus public key: {e}"))
        })?;
        if root == [0; 32] || config.max_evidence_age_secs == 0 || config.request_timeout_secs == 0
        {
            return Err(AuthzStartupError::Configuration(
                "deployment root and time bounds must be nonzero".into(),
            ));
        }
        Ok(ValidatedNativeAuthzConfig {
            endpoint: endpoint.into(),
            root,
            trusted,
            maximum_age: config.max_evidence_age_secs,
            timeout: Duration::from_secs(config.request_timeout_secs),
        })
    }

    fn prepare(
        config: Self::ValidatedConfig,
        _context: PrepareContext<'_>,
    ) -> Result<Self::Prepared, AuthzStartupError> {
        Ok(PreparedNativeAuthz {
            endpoint: config.endpoint,
            root: config.root,
            trusted: config.trusted,
            maximum_age: config.maximum_age,
            timeout: config.timeout,
        })
    }
}

pub struct PreparedNativeAuthz {
    endpoint: String,
    root: [u8; 32],
    trusted: ConsensusPublicKey,
    maximum_age: u64,
    timeout: Duration,
}

#[async_trait]
impl PreparedAuthz for PreparedNativeAuthz {
    async fn connect(
        self,
        _progress: &dyn StartupProgress,
    ) -> Result<Arc<dyn Authz>, AuthzStartupError> {
        let auth = tokio::time::timeout(
            self.timeout,
            NativeAuth::connect(
                VeraClient::new(&self.endpoint),
                self.trusted,
                self.root,
                self.maximum_age,
            ),
        )
        .await?
        .map_err(AuthZError::from)?;
        Ok(Arc::new(auth))
    }
}
