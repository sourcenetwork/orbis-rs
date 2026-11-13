//! Chain configuration for the native (Commonware / vera.rs) backend.

use commonware_codec::DecodeExt;
use serde::Deserialize;
use std::time::Duration;
use vera_domain::ConsensusPublicKey;

fn default_timeout() -> u64 {
    30
}

#[derive(Debug, thiserror::Error)]
pub enum NativeConfigError {
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

/// Shared validation behind both `NativeTrustConfig` and `NativeConfig`:
/// reject an invalid endpoint/root/consensus-key encoding or a zero time
/// bound. Does not check `deployment_id` — only `NativeConfig` (bulletin's
/// submission config) has that field.
fn validate_trust(
    endpoint: &str,
    deployment_root: &str,
    consensus_key: &str,
    max_evidence_age_secs: u64,
    request_timeout_secs: u64,
) -> Result<(String, [u8; 32], ConsensusPublicKey, u64, Duration), NativeConfigError> {
    let endpoint = url::Url::parse(endpoint)?;
    if !matches!(endpoint.scheme(), "http" | "https")
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(NativeConfigError::Endpoint);
    }
    let root: [u8; 32] = hex::decode(deployment_root)?
        .try_into()
        .map_err(|_| NativeConfigError::RootLength)?;
    let trusted = ConsensusPublicKey::decode(alloy_primitives::bytes::Bytes::from(hex::decode(
        consensus_key,
    )?))?;
    if root == [0; 32] || max_evidence_age_secs == 0 || request_timeout_secs == 0 {
        return Err(NativeConfigError::ZeroBound);
    }
    Ok((
        endpoint.into(),
        root,
        trusted,
        max_evidence_age_secs,
        Duration::from_secs(request_timeout_secs),
    ))
}

/// Raw, directly-`Deserialize`-able shape of `authz::native`'s services-config
/// section — deployment trust and request bounds, with no submission
/// identity (authz never submits anything, only reads).
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeTrustChainConfig {
    /// HTTP(S) endpoint serving native requests and evidence.
    pub endpoint: String,
    /// Independently provisioned deployment root (hex-encoded, 32 bytes).
    pub deployment_root: String,
    /// Independently provisioned consensus public key (hex-encoded).
    pub consensus_key: String,
    /// Maximum age in seconds for current-state evidence.
    #[serde(default = "default_timeout")]
    pub max_evidence_age_secs: u64,
    /// Overall request deadline.
    #[serde(default = "default_timeout")]
    pub request_timeout_secs: u64,
}

/// Validated deployment trust and request bounds, used directly by
/// `authz::native` (bulletin's `NativeConfig` carries the same fields plus
/// `deployment_id`).
#[derive(Clone)]
pub struct NativeTrustConfig {
    /// HTTP(S) endpoint serving native requests and evidence.
    pub endpoint: String,
    /// Independently provisioned deployment root.
    pub root: [u8; 32],
    /// Independently provisioned consensus public key.
    pub trusted: ConsensusPublicKey,
    /// Maximum age in seconds for current-state evidence.
    pub maximum_age: u64,
    /// Overall request deadline.
    pub timeout: Duration,
}

impl TryFrom<NativeTrustChainConfig> for NativeTrustConfig {
    type Error = NativeConfigError;

    fn try_from(raw: NativeTrustChainConfig) -> Result<Self, NativeConfigError> {
        let (endpoint, root, trusted, maximum_age, timeout) = validate_trust(
            &raw.endpoint,
            &raw.deployment_root,
            &raw.consensus_key,
            raw.max_evidence_age_secs,
            raw.request_timeout_secs,
        )?;
        Ok(Self {
            endpoint,
            root,
            trusted,
            maximum_age,
            timeout,
        })
    }
}

/// Raw, directly-`Deserialize`-able shape of `bulletin::native`'s
/// services-config section — deployment trust and request bounds, plus the
/// submission identity included in signed writes.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeChainConfig {
    /// HTTP(S) endpoint serving native requests and evidence.
    pub endpoint: String,
    /// Deployment identifier included in signed submissions.
    pub deployment_id: u64,
    /// Independently provisioned deployment root (hex-encoded, 32 bytes).
    pub deployment_root: String,
    /// Independently provisioned consensus public key (hex-encoded).
    pub consensus_key: String,
    /// Maximum age in seconds for current-state evidence.
    #[serde(default = "default_timeout")]
    pub max_evidence_age_secs: u64,
    /// Overall request deadline.
    #[serde(default = "default_timeout")]
    pub request_timeout_secs: u64,
}

/// Validated native deployment trust, request bounds, and submission
/// identity, used by `bulletin::native` and operator tools.
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

impl TryFrom<NativeChainConfig> for NativeConfig {
    type Error = NativeConfigError;

    /// Validate a deserialized native config section: reject invalid bounds
    /// and encodings. Unknown/duplicate fields are already rejected by
    /// `NativeChainConfig`'s own `Deserialize` derive.
    fn try_from(raw: NativeChainConfig) -> Result<Self, NativeConfigError> {
        let (endpoint, root, trusted, maximum_age, timeout) = validate_trust(
            &raw.endpoint,
            &raw.deployment_root,
            &raw.consensus_key,
            raw.max_evidence_age_secs,
            raw.request_timeout_secs,
        )?;
        if raw.deployment_id == 0 {
            return Err(NativeConfigError::ZeroBound);
        }
        Ok(Self {
            endpoint,
            deployment_id: raw.deployment_id,
            root,
            trusted,
            maximum_age,
            timeout,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Encode;

    fn trust_key() -> String {
        hex::encode(
            vera_harness::cluster::KeySet::builder()
                .seed(9001)
                .build()
                .unwrap()
                .epoch_info()
                .output
                .public()
                .public()
                .encode(),
        )
    }

    fn load(value: &serde_json::Value) -> Result<NativeConfig, ()> {
        let raw: NativeChainConfig = serde_json::from_value(value.clone()).map_err(|_| ())?;
        NativeConfig::try_from(raw).map_err(|_| ())
    }

    fn load_trust(value: &serde_json::Value) -> Result<NativeTrustConfig, ()> {
        let raw: NativeTrustChainConfig = serde_json::from_value(value.clone()).map_err(|_| ())?;
        NativeTrustConfig::try_from(raw).map_err(|_| ())
    }

    #[test]
    fn native_config_rejects_ambiguous_or_invalid_trust() {
        let valid = serde_json::json!({
            "endpoint": "http://127.0.0.1:8545", "deployment_id": 9001,
            "deployment_root": hex::encode([7; 32]),
            "consensus_key": trust_key(),
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
            ("deployment_id", serde_json::json!(0)),
            ("unexpected", serde_json::json!(true)),
        ] {
            let mut invalid = valid.clone();
            invalid[key] = value;
            assert!(load(&invalid).is_err(), "{key}");
        }
        // Duplicate JSON keys are rejected by `NativeChainConfig`'s derived
        // `Deserialize` itself (serde errors on a field visited twice) — test
        // the raw text directly, since parsing into an untyped `Value` first
        // would silently collapse the duplicate before this struct ever sees it.
        let duplicate =
            serde_json::to_string(&valid)
                .unwrap()
                .replacen('{', "{\"deployment_id\":1,", 1);
        assert!(serde_json::from_str::<NativeChainConfig>(&duplicate).is_err());
    }

    #[test]
    fn native_trust_config_rejects_invalid_trust_and_has_no_deployment_id() {
        let valid = serde_json::json!({
            "endpoint": "http://127.0.0.1:8545",
            "deployment_root": hex::encode([7; 32]),
            "consensus_key": trust_key(),
        });
        assert!(load_trust(&valid).is_ok());
        for (key, value) in [
            (
                "endpoint",
                serde_json::json!("http://user:secret@localhost"),
            ),
            ("deployment_root", serde_json::json!(hex::encode([0; 32]))),
            ("consensus_key", serde_json::json!("00")),
            ("request_timeout_secs", serde_json::json!(0)),
            // authz never submits anything, so its config has no
            // `deployment_id` field at all — supplying one is an unknown field.
            ("deployment_id", serde_json::json!(9001)),
        ] {
            let mut invalid = valid.clone();
            invalid[key] = value;
            assert!(load_trust(&invalid).is_err(), "{key}");
        }
    }
}
