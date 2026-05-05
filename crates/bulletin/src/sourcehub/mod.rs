use crate::{
    error::{BulletinError, Result},
    r#trait::{Bulletin, BulletinPost},
};
use async_trait::async_trait;
use common::blockchain::{ChainConfigBuilder, SourceHubClient, TxSigner};
use sha2::{Digest, Sha256};

#[cfg(test)]
mod tests;

#[cfg(any(feature = "bls12-381", feature = "decaf377"))]
const DEFAULT_THRESHOLD_SIGNATURE_SCHEME: &str = crypto::THRESHOLD_SIGNATURE_SCHEME;
const RESHARE_THRESHOLD_SIGNATURE_ARTIFACT_PREFIX: &str = "reshare-threshold-signature";

pub struct SourceHubBulletin {
    pub chain_client: SourceHubClient,
}

#[async_trait]
impl Bulletin for SourceHubBulletin {
    async fn register(&self, namespace: String) -> Result<()> {
        let result = self
            .chain_client
            .bulletin_register_namespace(&namespace)
            .await
            .map_err(|e| BulletinError::ChainError(e.to_string()))?;

        if result.code != 0 {
            return Err(BulletinError::ChainError(format!(
                "Failed to register namespace: code {}",
                result.code
            )));
        }

        Ok(())
    }

    async fn post(
        &self,
        namespace: String,
        payload: Vec<u8>,
        artifact: Option<String>,
    ) -> Result<()> {
        let result = self
            .chain_client
            .bulletin_create_post(&namespace, payload, artifact)
            .await
            .map_err(|e| BulletinError::ChainError(e.to_string()))?;

        if result.code != 0 {
            return Err(BulletinError::ChainError(format!(
                "Failed to create post: code {}",
                result.code
            )));
        }

        Ok(())
    }

    async fn update(&self, namespace: String, id: String, artifact: Option<String>) -> Result<()> {
        let (signature_scheme, signature) = Self::parse_threshold_signature_artifact(&artifact)?;
        let result = self
            .chain_client
            .bulletin_update_post_by_threshold_signature(
                &namespace,
                &id,
                artifact,
                &signature_scheme,
                signature,
            )
            .await
            .map_err(|e| BulletinError::ChainError(e.to_string()))?;

        if result.code != 0 {
            return Err(BulletinError::ChainError(format!(
                "Failed to update post: code {}",
                result.code
            )));
        }

        Ok(())
    }

    async fn read(&self, namespace: String, id: String) -> Result<BulletinPost> {
        // SourceHub stores posts under "bulletin/{namespace}" on-chain.
        let full_namespace = format!("bulletin/{}", namespace);
        let post = self
            .chain_client
            .bulletin_read_post(&full_namespace, &id)
            .await
            .map_err(|e| BulletinError::ChainError(e.to_string()))?
            .ok_or_else(|| BulletinError::NotFound {
                namespace: namespace.clone(),
                id: id.clone(),
            })?;

        Ok(BulletinPost {
            id: post.id,
            namespace: post.namespace,
            payload: post.payload,
        })
    }

    fn chain_id(&self) -> String {
        self.chain_client.config().chain_id.clone()
    }

    fn get_post_id(&self, namespace: &str, payload: &[u8]) -> Result<String> {
        Ok(Self::compute_post_id(namespace, payload))
    }
}

impl SourceHubBulletin {
    pub fn name() -> String {
        "bulletin/sourcehub".to_string()
    }

    pub async fn new(chain_config_builder: ChainConfigBuilder) -> Result<Self> {
        Ok(SourceHubBulletin {
            chain_client: SourceHubClient::new(chain_config_builder.build())
                .await
                .map_err(|e| BulletinError::ChainError(e.to_string()))?,
        })
    }

    pub async fn with_signer(
        chain_config_builder: ChainConfigBuilder,
        signer: TxSigner,
        balance_check_amount: Option<u64>,
    ) -> Result<Self> {
        // Get the address before moving the signer
        let address = signer.address();
        let denom = chain_config_builder
            .clone()
            .gas_price
            .map(|gp| gp.denom)
            .unwrap_or_else(|| "uopen".to_string());

        let client = SourceHubBulletin {
            chain_client: SourceHubClient::with_signer(chain_config_builder.build(), signer)
                .await
                .map_err(|e| BulletinError::ChainError(e.to_string()))?,
        };

        if let Some(balance_check_amount) = balance_check_amount {
            let address_clone = address.clone();
            let client_ref = &client.chain_client;

            // Helper to create backoff config for balance check
            let create_backoff = || backoff::ExponentialBackoff {
                max_elapsed_time: Some(std::time::Duration::from_secs(15 * 60)),
                initial_interval: std::time::Duration::from_secs(2),
                max_interval: std::time::Duration::from_secs(30),
                ..Default::default()
            };
            // Phase 2: Verify balance is sufficient (retry in case balance increases)
            let check_sufficient_balance = || async {
                let current_balance = client_ref
                    .get_balance(&address_clone, &denom)
                    .await
                    .map_err(|e| {
                        backoff::Error::Permanent(BulletinError::ChainError(format!(
                            "Balance check: Failed to query balance after connection: {}",
                            e
                        )))
                    })?;

                if current_balance >= balance_check_amount {
                    eprintln!(
                        "Balance check: Balance {} is sufficient (required: {})",
                        current_balance, balance_check_amount
                    );
                    Ok(())
                } else {
                    eprintln!(
                        "Balance check: Balance {} is insufficient (required: {}) for address: {}. Retrying...",
                        current_balance, balance_check_amount, address_clone
                    );
                    Err(backoff::Error::Transient {
                        err: BulletinError::ChainError(format!(
                            "Balance check: Balance {} is less than required {} for node address: {}",
                            current_balance, balance_check_amount, address_clone
                        )),
                        retry_after: None,
                    })
                }
            };

            backoff::future::retry(create_backoff(), check_sufficient_balance)
                .await
                .map_err(|e| {
                    BulletinError::ChainError(format!(
                        "Balance check: Balance insufficient after retries: {}",
                        e
                    ))
                })?;
        }
        // Transfer to self to register account on-chain (registers public key)
        let amount = 1u64;

        let _result = client
            .chain_client
            .transfer(&address, amount, &denom)
            .await
            .map_err(|e| BulletinError::ChainError(e.to_string()))?;

        Ok(client)
    }

    /// Compute the deterministic post ID matching SourceHub's on-chain behavior.
    /// The chain stores posts under "bulletin/{namespace}", so we hash
    /// "bulletin/{namespace}" || payload regardless of what namespace string the caller passes.
    pub fn compute_post_id(namespace: &str, payload: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(format!("bulletin/{}", namespace).as_bytes());
        hasher.update(payload);
        hex::encode(hasher.finalize())
    }

    fn parse_threshold_signature_artifact(artifact: &Option<String>) -> Result<(String, Vec<u8>)> {
        let artifact = artifact.as_deref().ok_or_else(|| {
            BulletinError::ParseError(
                "threshold-signature update requires a signature artifact".to_string(),
            )
        })?;

        let (signature_scheme, signature_hex) = if let Some(rest) =
            artifact.strip_prefix(&format!("{RESHARE_THRESHOLD_SIGNATURE_ARTIFACT_PREFIX}:"))
        {
            match rest.split(':').collect::<Vec<_>>().as_slice() {
                [_, signature_hex] => (DEFAULT_THRESHOLD_SIGNATURE_SCHEME, *signature_hex),
                [_, signature_scheme, signature_hex] => (*signature_scheme, *signature_hex),
                _ => {
                    return Err(BulletinError::ParseError(format!(
                        "invalid threshold-signature artifact format: {artifact}"
                    )));
                }
            }
        } else {
            (DEFAULT_THRESHOLD_SIGNATURE_SCHEME, artifact)
        };

        let signature_scheme = if signature_scheme.trim().is_empty() {
            DEFAULT_THRESHOLD_SIGNATURE_SCHEME
        } else {
            signature_scheme.trim()
        };
        let signature_hex = signature_hex.trim();
        let signature_hex = signature_hex
            .strip_prefix("0x")
            .or_else(|| signature_hex.strip_prefix("0X"))
            .unwrap_or(signature_hex);
        let signature = hex::decode(signature_hex).map_err(|e| {
            BulletinError::ParseError(format!("invalid threshold signature hex: {e}"))
        })?;

        if signature.is_empty() {
            return Err(BulletinError::ParseError(
                "threshold signature cannot be empty".to_string(),
            ));
        }

        Ok((signature_scheme.to_string(), signature))
    }
}
