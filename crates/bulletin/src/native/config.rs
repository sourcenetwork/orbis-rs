use commonware_codec::DecodeExt;
use serde::Deserialize;
use std::{fs, io::Read, path::Path, time::Duration};
use vera_domain::ConsensusPublicKey;

const MAX_CONFIG_BYTES: u64 = 16 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    endpoint: String,
    deployment_id: u64,
    deployment_root: String,
    consensus_key: String,
    #[serde(default = "default_timeout")]
    max_evidence_age_secs: u64,
    #[serde(default = "default_timeout")]
    request_timeout_secs: u64,
}

fn default_timeout() -> u64 {
    30
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read native Vera configuration")]
    Read(#[from] std::io::Error),
    #[error("native Vera configuration exceeds 16 KiB")]
    TooLarge,
    #[error("invalid native Vera configuration JSON")]
    Json(#[from] serde_json::Error),
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

impl NativeConfig {
    /// Read a bounded trust file, rejecting unknown or duplicate fields and invalid bounds.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let mut bytes = Vec::new();
        fs::File::open(path)?
            .take(MAX_CONFIG_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge);
        }
        let raw: ConfigFile = serde_json::from_slice(&bytes)?;
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

    #[test]
    fn native_config_rejects_ambiguous_or_invalid_trust() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vera.json");
        let valid = serde_json::json!({
            "endpoint": "http://127.0.0.1:8545", "deployment_id": 9001,
            "deployment_root": hex::encode([7; 32]),
            "consensus_key": hex::encode(vera_harness::cluster::KeySet::builder().seed(9001).build().unwrap().epoch_info().output.public().public().encode()),
        });
        fs::write(&path, serde_json::to_vec(&valid).unwrap()).unwrap();
        assert!(NativeConfig::load(&path).is_ok());
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
            fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
            assert!(NativeConfig::load(&path).is_err(), "{key}");
        }
        let duplicate = serde_json::to_string(&valid)
            .unwrap()
            .replace("{", "{\"deployment_id\":1,");
        fs::write(&path, duplicate).unwrap();
        assert!(NativeConfig::load(&path).is_err());
        fs::write(&path, vec![b' '; MAX_CONFIG_BYTES as usize + 1]).unwrap();
        assert!(NativeConfig::load(&path).is_err());
    }
}
