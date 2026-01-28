use crate::{
    error::{BulletinError, Result},
    r#trait::{Bulletin, BulletinPost},
};
use async_trait::async_trait;
use common::blockchain::{ChainConfigBuilder, SourceHubClient, TxSigner};
use sha2::{Digest, Sha256};

#[cfg(test)]
mod tests;

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
        proof: Vec<u8>,
        artifact: Option<String>,
    ) -> Result<()> {
        let result = self
            .chain_client
            .bulletin_create_post_with_proof(&namespace, payload, proof, artifact)
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
    async fn read(&self, namespace: String, id: String) -> Result<BulletinPost> {
        let post = self
            .chain_client
            .bulletin_read_post(&namespace, &id)
            .await
            .map_err(|e| BulletinError::ChainError(e.to_string()))?;

        Ok(BulletinPost {
            id: post.id,
            namespace: post.namespace,
            payload: post.payload,
            proof: post.proof,
        })
    }

    fn get_post_id(&self, namespace: &str, payload: &[u8]) -> Result<String> {
        Ok(Self::compute_post_id(namespace, payload))
    }
}

impl SourceHubBulletin {
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
            let create_backoff = || {
                let mut backoff = backoff::ExponentialBackoff::default();
                backoff.max_elapsed_time = Some(std::time::Duration::from_secs(15 * 60));
                backoff.initial_interval = std::time::Duration::from_secs(2);
                backoff.max_interval = std::time::Duration::from_secs(30);
                backoff
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

    pub fn compute_post_id(namespace: &str, payload: &[u8]) -> String {
        let mut hasher = Sha256::new();

        hasher.update(namespace.as_bytes());
        hasher.update(payload);

        let hash = hasher.finalize();
        hex::encode(hash)
    }
}
