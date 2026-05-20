use crate::{
    error::{BulletinError, Result},
    r#trait::{Bulletin, BulletinKind, BulletinPost, DocumentPayload, KeyDerivation, RingPayload},
};
use async_trait::async_trait;
use common::blockchain::{
    orbis::{
        self, generate_document_id, generate_key_derivation_id, generate_ring_id, ring_state_hash,
    },
    ChainConfigBuilder, SourceHubClient, TxSigner,
};
use sha2::{Digest, Sha256};

#[cfg(test)]
mod tests;

const DEFAULT_THRESHOLD_SIGNATURE_SCHEME: &str = "bls12_381_g1_pk_g2_sig_nul";
const DECAF377_FROST_THRESHOLD_SIGNATURE_SCHEME: &str = "decaf377_frost";
const RESHARE_THRESHOLD_SIGNATURE_ARTIFACT_PREFIX: &str = "reshare-threshold-signature";

pub struct SourceHubBulletin {
    pub chain_client: SourceHubClient,
}

#[async_trait]
impl Bulletin for SourceHubBulletin {
    async fn register(&self, _namespace: String) -> Result<()> {
        Ok(())
    }

    async fn post(
        &self,
        namespace: String,
        kind: BulletinKind,
        payload: Vec<u8>,
        artifact: Option<String>,
    ) -> Result<()> {
        match kind {
            BulletinKind::Ring => {
                let ring: RingPayload = serde_json::from_slice(&payload)
                    .map_err(|e| BulletinError::ParseError(e.to_string()))?;
                let (result, _) = self
                    .chain_client
                    .orbis_create_ring_get_id(
                        &namespace,
                        &ring.ring_pk,
                        ring.peer_ids,
                        ring.threshold,
                        ring.pss_interval,
                        ring.policy_id.as_deref().unwrap_or(""),
                        artifact,
                    )
                    .await
                    .map_err(|e| BulletinError::ChainError(e.to_string()))?;
                check_result(result, "create ring")
            }
            BulletinKind::Document => {
                let doc: DocumentPayload = serde_json::from_slice(&payload)
                    .map_err(|e| BulletinError::ParseError(e.to_string()))?;
                let result = self
                    .chain_client
                    .orbis_store_document(
                        &namespace,
                        &doc.ring_id,
                        &doc.document,
                        &doc.proof,
                        &doc.policy_id,
                        &doc.resource,
                        &doc.permission,
                        doc.tier,
                        doc.timestamp,
                        artifact,
                    )
                    .await
                    .map_err(|e| BulletinError::ChainError(e.to_string()))?;
                check_result(result, "store document")
            }
            BulletinKind::KeyDerivation => {
                let kd: KeyDerivation = serde_json::from_slice(&payload)
                    .map_err(|e| BulletinError::ParseError(e.to_string()))?;
                let result = self
                    .chain_client
                    .orbis_store_key_derivation(
                        &namespace,
                        &kd.ring_id,
                        &kd.derivation,
                        &kd.policy_id,
                        &kd.resource,
                        &kd.permission,
                        artifact,
                    )
                    .await
                    .map_err(|e| BulletinError::ChainError(e.to_string()))?;
                check_result(result, "store key derivation")
            }
        }
    }

    async fn update(&self, _namespace: String, id: String, artifact: Option<String>) -> Result<()> {
        let (signature_scheme, signature) = parse_threshold_signature_artifact(&artifact)?;
        let result = self
            .chain_client
            .orbis_finalize_ring_reshare(&id, artifact, &signature_scheme, signature)
            .await
            .map_err(|e| BulletinError::ChainError(e.to_string()))?;
        check_result(result, "finalize ring reshare")
    }

    async fn read(
        &self,
        namespace: String,
        id: String,
        kind: BulletinKind,
    ) -> Result<BulletinPost> {
        match kind {
            BulletinKind::Ring => self
                .chain_client
                .orbis_read_ring(&id)
                .await
                .map_err(|e| BulletinError::ChainError(e.to_string()))?
                .ok_or(BulletinError::NotFound { namespace, id })
                .and_then(ring_to_bulletin_post),
            BulletinKind::Document => self
                .chain_client
                .orbis_read_document(&namespace, &id)
                .await
                .map_err(|e| BulletinError::ChainError(e.to_string()))?
                .ok_or(BulletinError::NotFound { namespace, id })
                .and_then(document_to_bulletin_post),
            BulletinKind::KeyDerivation => self
                .chain_client
                .orbis_read_key_derivation(&namespace, &id)
                .await
                .map_err(|e| BulletinError::ChainError(e.to_string()))?
                .ok_or(BulletinError::NotFound { namespace, id })
                .and_then(key_derivation_to_bulletin_post),
        }
    }

    fn chain_id(&self) -> String {
        self.chain_client.config().chain_id.clone()
    }

    fn get_post_id(&self, namespace: &str, payload: &[u8]) -> Result<String> {
        if let Ok(doc) = serde_json::from_slice::<DocumentPayload>(payload) {
            return Ok(generate_document_id(
                namespace,
                &doc.ring_id,
                &doc.document,
                &doc.proof,
                &doc.policy_id,
                &doc.resource,
                &doc.permission,
                doc.tier.as_deref(),
                doc.timestamp,
            ));
        }
        if let Ok(kd) = serde_json::from_slice::<KeyDerivation>(payload) {
            return Ok(generate_key_derivation_id(
                namespace,
                &kd.ring_id,
                &kd.derivation,
                &kd.policy_id,
                &kd.resource,
                &kd.permission,
            ));
        }
        if let Ok(ring) = serde_json::from_slice::<RingPayload>(payload) {
            return Ok(generate_ring_id(
                namespace,
                &ring.ring_pk,
                &ring.peer_ids,
                ring.threshold,
                ring.pss_interval,
                ring.policy_id.as_deref().unwrap_or(""),
            ));
        }

        let mut hasher = Sha256::new();
        hasher.update(namespace.as_bytes());
        hasher.update(payload);
        Ok(hex::encode(hasher.finalize()))
    }

    fn get_ring_id(
        &self,
        namespace: &str,
        ring_pk: &str,
        peer_ids: &[String],
        threshold: u32,
        pss_interval: Option<u64>,
        policy_id: &str,
    ) -> Result<String> {
        Ok(generate_ring_id(
            namespace,
            ring_pk,
            peer_ids,
            threshold,
            pss_interval,
            policy_id,
        ))
    }

    async fn ring_canonical_hash(&self, ring_id: &str) -> Result<[u8; 32]> {
        let ring = self
            .chain_client
            .orbis_read_ring(ring_id)
            .await
            .map_err(|e| BulletinError::ChainError(e.to_string()))?
            .ok_or_else(|| BulletinError::NotFound {
                namespace: String::new(),
                id: ring_id.to_string(),
            })?;
        Ok(ring_state_hash(&ring))
    }

    fn ring_reshare_finalize_sign_bytes(
        &self,
        chain_id: &str,
        namespace: &str,
        ring_id: &str,
        ring_pk: &str,
        current_ring_sha256: Vec<u8>,
        finalized_ring_sha256: Vec<u8>,
        block_number_nonce: u64,
    ) -> Result<Vec<u8>> {
        orbis::ring_reshare_finalize_sign_bytes(
            chain_id,
            namespace,
            ring_id,
            ring_pk,
            current_ring_sha256,
            finalized_ring_sha256,
            block_number_nonce,
        )
        .map_err(|e| BulletinError::ParseError(e.to_string()))
    }

    async fn ring_finalized_canonical_hash(&self, ring_id: &str) -> Result<[u8; 32]> {
        let ring = self
            .chain_client
            .orbis_read_ring(ring_id)
            .await
            .map_err(|e| BulletinError::ChainError(e.to_string()))?
            .ok_or_else(|| BulletinError::NotFound {
                namespace: String::new(),
                id: ring_id.to_string(),
            })?;
        let finalized = orbis::Ring {
            peer_ids: if ring.new_peer_ids.is_empty() {
                ring.peer_ids.clone()
            } else {
                ring.new_peer_ids.clone()
            },
            threshold: if ring.has_new_threshold {
                ring.new_threshold
            } else {
                ring.threshold
            },
            new_peer_ids: vec![],
            new_threshold: 0,
            has_new_threshold: false,
            ..ring
        };
        Ok(ring_state_hash(&finalized))
    }
}

impl SourceHubBulletin {
    pub fn name() -> String {
        "bulletin/sourcehub".to_string()
    }

    #[cfg(test)]
    pub(crate) fn parse_threshold_signature_artifact(
        artifact: &Option<String>,
    ) -> Result<(String, Vec<u8>)> {
        parse_threshold_signature_artifact(artifact)
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
        let _result = client
            .chain_client
            .transfer(&address, 1u64, &denom)
            .await
            .map_err(|e| BulletinError::ChainError(e.to_string()))?;

        Ok(client)
    }
}

// ============================================================================
// Conversion helpers: on-chain types → BulletinPost
// ============================================================================

fn ring_to_bulletin_post(ring: orbis::Ring) -> Result<BulletinPost> {
    let payload = RingPayload {
        ring_pk: ring.ring_pk,
        peer_ids: ring.peer_ids,
        new_peer_ids: if ring.new_peer_ids.is_empty() {
            None
        } else {
            Some(ring.new_peer_ids)
        },
        new_threshold: if ring.has_new_threshold {
            Some(ring.new_threshold)
        } else {
            None
        },
        threshold: ring.threshold,
        pss_interval: if ring.has_pss_interval {
            Some(ring.pss_interval)
        } else {
            None
        },
        block_number_nonce: ring.block_number_nonce,
        policy_id: if ring.policy_id.is_empty() {
            None
        } else {
            Some(ring.policy_id)
        },
    };
    Ok(BulletinPost {
        id: ring.id,
        namespace: ring.namespace,
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
        tier: if doc.has_tier { Some(doc.tier) } else { None },
        timestamp: if doc.has_timestamp {
            Some(doc.timestamp)
        } else {
            None
        },
    };
    Ok(BulletinPost {
        id: doc.id,
        namespace: doc.namespace,
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
        namespace: kd.namespace,
        payload: serde_json::to_vec(&payload)
            .map_err(|e| BulletinError::ParseError(e.to_string()))?,
    })
}

// ============================================================================
// Artifact parsing
// ============================================================================

fn parse_threshold_signature_artifact(artifact: &Option<String>) -> Result<(String, Vec<u8>)> {
    let artifact = artifact.as_deref().ok_or_else(|| {
        BulletinError::ParseError(
            "threshold-signature update requires a signature artifact".to_string(),
        )
    })?;

    let rest = artifact
        .strip_prefix(&format!("{RESHARE_THRESHOLD_SIGNATURE_ARTIFACT_PREFIX}:"))
        .ok_or_else(|| {
            BulletinError::ParseError(format!(
                "invalid threshold-signature artifact prefix: {artifact}"
            ))
        })?;

    let (signature_scheme, signature_hex) = match rest.split(':').collect::<Vec<_>>().as_slice() {
        [_, signature_hex] => (DEFAULT_THRESHOLD_SIGNATURE_SCHEME, *signature_hex),
        [_, signature_scheme, signature_hex] => (*signature_scheme, *signature_hex),
        _ => {
            return Err(BulletinError::ParseError(format!(
                "invalid threshold-signature artifact format: {artifact}"
            )));
        }
    };

    let signature_scheme = if signature_scheme.trim().is_empty() {
        DEFAULT_THRESHOLD_SIGNATURE_SCHEME
    } else {
        signature_scheme.trim()
    };

    let signature_scheme = signature_scheme.to_ascii_lowercase();
    if !matches!(
        signature_scheme.as_str(),
        DEFAULT_THRESHOLD_SIGNATURE_SCHEME | DECAF377_FROST_THRESHOLD_SIGNATURE_SCHEME
    ) {
        return Err(BulletinError::ParseError(format!(
            "unsupported threshold signature scheme: {signature_scheme}"
        )));
    }

    let signature_hex = signature_hex
        .trim()
        .strip_prefix("0x")
        .or_else(|| signature_hex.trim().strip_prefix("0X"))
        .unwrap_or(signature_hex.trim());

    let signature = hex::decode(signature_hex)
        .map_err(|e| BulletinError::ParseError(format!("invalid threshold signature hex: {e}")))?;

    if signature.is_empty() {
        return Err(BulletinError::ParseError(
            "threshold signature cannot be empty".to_string(),
        ));
    }

    Ok((signature_scheme, signature))
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
