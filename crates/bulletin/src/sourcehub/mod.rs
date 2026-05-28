use crate::{
    error::{BulletinError, Result},
    r#trait::{
        Bulletin, BulletinKind, BulletinPost, BulletinWriteKind, DocumentPayload, KeyDerivation,
        NodeInfo, RingFinalizationPayload, RingPayload,
    },
};
use async_trait::async_trait;
use common::blockchain::{
    orbis::{self, generate_document_id, generate_key_derivation_id, ring_state_hash},
    BlockchainError, ChainConfigBuilder, SourceHubClient, TxSigner,
};

#[cfg(test)]
mod tests;

pub struct SourceHubBulletin {
    pub chain_client: SourceHubClient,
}

#[async_trait]
impl Bulletin for SourceHubBulletin {
    async fn register(&self) -> Result<()> {
        Ok(())
    }

    async fn post(&self, kind: BulletinWriteKind, payload: Vec<u8>) -> Result<String> {
        match kind {
            BulletinWriteKind::Finalize => {
                let finalize: RingFinalizationPayload = serde_json::from_slice(&payload)
                    .map_err(|e| BulletinError::ParseError(e.to_string()))?;
                let result = self
                    .chain_client
                    .orbis_finalize_ring(&finalize.ring_id, &finalize.ring_pk)
                    .await
                    .map_err(|e| BulletinError::ChainError(e.to_string()))?;
                check_result(result, "finalize ring")?;
                Ok(finalize.ring_id)
            }
            BulletinWriteKind::Document => {
                let doc: DocumentPayload = serde_json::from_slice(&payload)
                    .map_err(|e| BulletinError::ParseError(e.to_string()))?;
                let (result, document_id) = match self
                    .chain_client
                    .orbis_store_document_get_id(
                        &doc.ring_id,
                        &doc.document,
                        &doc.proof,
                        &doc.policy_id,
                        &doc.resource,
                        &doc.permission,
                        doc.tier.clone(),
                        doc.timestamp,
                    )
                    .await
                {
                    Ok(result) => result,
                    Err(BlockchainError::TxFailed { log, .. }) if is_already_exists_log(&log) => {
                        let document_id = generate_document_id(
                            &doc.ring_id,
                            &doc.document,
                            &doc.proof,
                            &doc.policy_id,
                            &doc.resource,
                            &doc.permission,
                            doc.tier.as_deref(),
                            doc.timestamp,
                        );
                        return Ok(document_id);
                    }
                    Err(e) => return Err(BulletinError::ChainError(e.to_string())),
                };
                check_result(result, "store document")?;
                Ok(document_id)
            }
            BulletinWriteKind::KeyDerivation => {
                let kd: KeyDerivation = serde_json::from_slice(&payload)
                    .map_err(|e| BulletinError::ParseError(e.to_string()))?;
                let (result, key_derivation_id) = match self
                    .chain_client
                    .orbis_store_key_derivation_get_id(
                        &kd.ring_id,
                        &kd.derivation,
                        &kd.policy_id,
                        &kd.resource,
                        &kd.permission,
                    )
                    .await
                {
                    Ok(result) => result,
                    Err(BlockchainError::TxFailed { log, .. }) if is_already_exists_log(&log) => {
                        let key_derivation_id = generate_key_derivation_id(
                            &kd.ring_id,
                            &kd.derivation,
                            &kd.policy_id,
                            &kd.resource,
                            &kd.permission,
                        );
                        return Ok(key_derivation_id);
                    }
                    Err(e) => return Err(BulletinError::ChainError(e.to_string())),
                };
                check_result(result, "store key derivation")?;
                Ok(key_derivation_id)
            }
            BulletinWriteKind::NodeInfo => {
                let node_info: NodeInfo = serde_json::from_slice(&payload)
                    .map_err(|e| BulletinError::ParseError(e.to_string()))?;
                let node_key = self
                    .chain_client
                    .signer()
                    .ok_or_else(|| {
                        BulletinError::ChainError(
                            "No signer configured for node info creation".to_string(),
                        )
                    })?
                    .public_key_hex();
                let result = self
                    .chain_client
                    .orbis_create_node_info(
                        &node_info.peer_id,
                        &node_info.controller_key,
                        node_info.whitelisted_policy_ids,
                        node_info.whitelisted_ring_ids,
                    )
                    .await
                    .map_err(|e| BulletinError::ChainError(e.to_string()))?;
                check_result(result, "create node info")?;
                Ok(node_key)
            }
        }
    }

    async fn update(&self, id: String, signature_scheme: String, signature: Vec<u8>) -> Result<()> {
        let result = self
            .chain_client
            .orbis_finalize_ring_reshare(&id, &signature_scheme, signature)
            .await
            .map_err(|e| BulletinError::ChainError(e.to_string()))?;
        check_result(result, "finalize ring reshare")
    }

    async fn read(&self, id: String, kind: BulletinKind) -> Result<BulletinPost> {
        match kind {
            BulletinKind::Ring => self
                .chain_client
                .orbis_read_ring(&id)
                .await
                .map_err(|e| BulletinError::ChainError(e.to_string()))?
                .ok_or(BulletinError::NotFound { id })
                .and_then(ring_to_bulletin_post),
            BulletinKind::Document => self
                .chain_client
                .orbis_read_document(&id)
                .await
                .map_err(|e| BulletinError::ChainError(e.to_string()))?
                .ok_or(BulletinError::NotFound { id })
                .and_then(document_to_bulletin_post),
            BulletinKind::KeyDerivation => self
                .chain_client
                .orbis_read_key_derivation(&id)
                .await
                .map_err(|e| BulletinError::ChainError(e.to_string()))?
                .ok_or(BulletinError::NotFound { id })
                .and_then(key_derivation_to_bulletin_post),
            BulletinKind::NodeInfo => {
                let node_info = self
                    .chain_client
                    .orbis_read_node_info(&id)
                    .await
                    .map_err(|e| BulletinError::ChainError(e.to_string()))?
                    .ok_or_else(|| BulletinError::NotFound { id: id.clone() })?;
                node_info_to_bulletin_post(node_info, &id)
            }
        }
    }

    fn chain_id(&self) -> String {
        self.chain_client.config().chain_id.clone()
    }

    async fn ring_canonical_hash(&self, ring_id: &str) -> Result<[u8; 32]> {
        let ring = self
            .chain_client
            .orbis_read_ring(ring_id)
            .await
            .map_err(|e| BulletinError::ChainError(e.to_string()))?
            .ok_or_else(|| BulletinError::NotFound {
                id: ring_id.to_string(),
            })?;
        Ok(ring_state_hash(&ring))
    }

    async fn ring_finalized_canonical_hash(&self, ring_id: &str) -> Result<[u8; 32]> {
        let ring = self
            .chain_client
            .orbis_read_ring(ring_id)
            .await
            .map_err(|e| BulletinError::ChainError(e.to_string()))?
            .ok_or_else(|| BulletinError::NotFound {
                id: ring_id.to_string(),
            })?;
        let finalized = orbis::Ring {
            peer_node_keys: if ring.new_peer_node_keys.is_empty() {
                ring.peer_node_keys.clone()
            } else {
                ring.new_peer_node_keys.clone()
            },
            threshold: ring.new_threshold.unwrap_or(ring.threshold),
            new_peer_node_keys: vec![],
            new_threshold: None,
            ..ring
        };
        Ok(ring_state_hash(&finalized))
    }

    fn ring_reshare_finalize_sign_bytes(
        &self,
        chain_id: &str,
        ring_id: &str,
        ring_pk: &str,
        current_ring_sha256: Vec<u8>,
        finalized_ring_sha256: Vec<u8>,
        block_number_nonce: u64,
    ) -> Result<Vec<u8>> {
        orbis::ring_reshare_finalize_sign_bytes(
            chain_id,
            ring_id,
            ring_pk,
            current_ring_sha256,
            finalized_ring_sha256,
            block_number_nonce,
        )
        .map_err(|e| BulletinError::ParseError(e.to_string()))
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

            let create_backoff = || backoff::ExponentialBackoff {
                max_elapsed_time: Some(std::time::Duration::from_secs(15 * 60)),
                initial_interval: std::time::Duration::from_secs(2),
                max_interval: std::time::Duration::from_secs(30),
                ..Default::default()
            };
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
        let result = client
            .chain_client
            .transfer(&address, 1u64, &denom)
            .await
            .map_err(|e| BulletinError::ChainError(e.to_string()))?;
        check_result(result, "register account self-transfer")?;

        Ok(client)
    }
}

// ============================================================================
// Conversion helpers: on-chain types → BulletinPost
// ============================================================================

fn ring_to_bulletin_post(ring: orbis::Ring) -> Result<BulletinPost> {
    let payload = RingPayload {
        ring_pk: ring.ring_pk,
        peer_node_keys: ring.peer_node_keys,
        new_peer_node_keys: if ring.new_peer_node_keys.is_empty() {
            None
        } else {
            Some(ring.new_peer_node_keys)
        },
        new_threshold: ring.new_threshold,
        threshold: ring.threshold,
        pss_interval: ring.pss_interval,
        block_number_nonce: ring.block_number_nonce,
        policy_id: if ring.policy_id.is_empty() {
            None
        } else {
            Some(ring.policy_id)
        },
    };
    Ok(BulletinPost {
        id: ring.id,
        payload: serde_json::to_vec(&payload)
            .map_err(|e| BulletinError::ParseError(e.to_string()))?,
    })
}

fn document_to_bulletin_post(doc: orbis::Document) -> Result<BulletinPost> {
    let payload = DocumentPayload {
        ring_id: doc.ring_id,
        document: doc.document,
        proof: doc.proof,
        policy_id: doc.policy_id,
        resource: doc.resource,
        permission: doc.permission,
        tier: doc.tier,
        timestamp: doc.timestamp,
    };
    Ok(BulletinPost {
        id: doc.id,
        payload: serde_json::to_vec(&payload)
            .map_err(|e| BulletinError::ParseError(e.to_string()))?,
    })
}

fn key_derivation_to_bulletin_post(kd: orbis::KeyDerivation) -> Result<BulletinPost> {
    let payload = KeyDerivation {
        ring_id: kd.ring_id,
        derivation: kd.derivation,
        policy_id: kd.policy_id,
        resource: kd.resource,
        permission: kd.permission,
    };
    Ok(BulletinPost {
        id: kd.id,
        payload: serde_json::to_vec(&payload)
            .map_err(|e| BulletinError::ParseError(e.to_string()))?,
    })
}

fn node_info_to_bulletin_post(node_info: orbis::NodeInfo, node_key: &str) -> Result<BulletinPost> {
    let payload = NodeInfo {
        peer_id: node_info.peer_id,
        controller_key: node_info.controller_key,
        whitelisted_policy_ids: node_info.whitelisted_policy_ids,
        whitelisted_ring_ids: node_info.whitelisted_ring_ids,
    };
    Ok(BulletinPost {
        id: node_key.to_string(),
        payload: serde_json::to_vec(&payload)
            .map_err(|e| BulletinError::ParseError(e.to_string()))?,
    })
}

fn check_result(result: common::blockchain::BroadcastResult, op: &str) -> Result<()> {
    if result.code != 0 {
        return Err(BulletinError::ChainError(format!(
            "Failed to {op}: code {}",
            result.code
        )));
    }
    Ok(())
}

fn is_already_exists_log(log: &str) -> bool {
    log.to_ascii_lowercase().contains("already exists")
}
