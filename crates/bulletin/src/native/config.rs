use commonware_codec::DecodeExt;
use serde::Deserialize;
use std::time::Duration;
use vera_domain::ConsensusPublicKey;

/// Raw, directly-`Deserialize`-able shape of the `bulletin` section of the
/// node's services-config file — the `BulletinFactory::Config` for
/// `NativeBulletinFactory`. Deliberately not shared with `authz::native`'s
/// own config, even though a real deployment's values usually match: keeping
/// them separate is what lets native bulletin pair with a non-native authz
/// backend (or vice versa) instead of permanently coupling the two.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBulletinConfig {
    pub endpoint: String,
    pub deployment_id: u64,
    pub deployment_root: String,
    pub consensus_key: String,
    #[serde(default = "default_timeout")]
    pub max_evidence_age_secs: u64,
    #[serde(default = "default_timeout")]
    pub request_timeout_secs: u64,
}

fn default_timeout() -> u64 {
    30
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("invalid native Vera endpoint")]
    Url(#[from] url::ParseError),
    #[error("native Vera endpoint must be an HTTP(S) URL without credentials or a fragment")]
    Endpoint,
    #[error("invalid native Vera deployment key encoding")]
    Hex(#[from] hex::FromHexError),
    #[error("deployment_root must encode exactly 32 bytes")]
    RootLength,
    #[error("invalid native Vera consensus public key")]
    ConsensusKey(#[from] commonware_codec::Error),
    #[error("deployment identity and time bounds must be nonzero")]
    ZeroBound,
}

/// Validated native deployment trust and request bounds, shared by nodes and operator tools.
#[derive(Clone)]
pub struct NativeConfig {
    /// HTTP(S) endpoint serving native requests and evidence.
    pub endpoint: String,
    /// Deployment identifier included in signed submissions.
    pub deployment_id: u64,
    /// Independently provisioned deployment root.
    pub root: [u8; 32],
    /// Independently provisioned consensus public key.
    pub trusted: ConsensusPublicKey,
    /// Maximum age in seconds for current-state evidence.
    pub maximum_age: u64,
    /// Overall request deadline.
    pub timeout: Duration,
}

impl TryFrom<NativeBulletinConfig> for NativeConfig {
    type Error = ConfigError;

    /// Validate a deserialized `bulletin` config section: reject invalid
    /// bounds and encodings. Unknown/duplicate fields are already rejected
    /// by `NativeBulletinConfig`'s own `Deserialize` derive.
    fn try_from(raw: NativeBulletinConfig) -> Result<Self, ConfigError> {
        let endpoint = url::Url::parse(&raw.endpoint)?;
        if !matches!(endpoint.scheme(), "http" | "https")
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(ConfigError::Endpoint);
        }
        let root: [u8; 32] = hex::decode(&raw.deployment_root)?
            .try_into()
            .map_err(|_| ConfigError::RootLength)?;
        let trusted = ConsensusPublicKey::decode(alloy_primitives::bytes::Bytes::from(
            hex::decode(&raw.consensus_key)?,
        ))?;
        if root == [0; 32]
            || raw.deployment_id == 0
            || raw.max_evidence_age_secs == 0
            || raw.request_timeout_secs == 0
        {
            return Err(ConfigError::ZeroBound);
        }
        Ok(Self {
            endpoint: endpoint.into(),
            deployment_id: raw.deployment_id,
            root,
            trusted,
            maximum_age: raw.max_evidence_age_secs,
            timeout: Duration::from_secs(raw.request_timeout_secs),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Encode;

    fn load(value: &serde_json::Value) -> Result<NativeConfig, ()> {
        let raw: NativeBulletinConfig = serde_json::from_value(value.clone()).map_err(|_| ())?;
        NativeConfig::try_from(raw).map_err(|_| ())
    }

    #[test]
    fn native_config_rejects_ambiguous_or_invalid_trust() {
        let valid = serde_json::json!({
            "endpoint": "http://127.0.0.1:8545", "deployment_id": 9001,
            "deployment_root": hex::encode([7; 32]),
            "consensus_key": hex::encode(vera_harness::cluster::KeySet::builder().seed(9001).build().unwrap().epoch_info().output.public().public().encode()),
        });
        assert!(load(&valid).is_ok());
        for (key, value) in [
            (
                "endpoint",
                serde_json::json!("http://user:secret@localhost"),
            ),
            ("deployment_root", serde_json::json!(hex::encode([0; 32]))),
            ("consensus_key", serde_json::json!("00")),
            ("request_timeout_secs", serde_json::json!(0)),
            ("unexpected", serde_json::json!(true)),
        ] {
            let mut invalid = valid.clone();
            invalid[key] = value;
            assert!(load(&invalid).is_err(), "{key}");
        }
        // Duplicate JSON keys are rejected by `NativeBulletinConfig`'s derived
        // `Deserialize` itself (serde errors on a field visited twice) — test
        // the raw text directly, since parsing into an untyped `Value` first
        // would silently collapse the duplicate before this struct ever sees it.
        let duplicate =
            serde_json::to_string(&valid)
                .unwrap()
                .replacen('{', "{\"deployment_id\":1,", 1);
        assert!(serde_json::from_str::<NativeBulletinConfig>(&duplicate).is_err());
    }
}
