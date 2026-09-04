//! Vera-backed bulletin implementation.

use crate::{
    error::{BulletinError, Result},
    r#trait::{
        Bulletin, BulletinKind, BulletinPost, BulletinReportSubmission, BulletinWriteKind,
        DemeritConfig, DocumentPayload, KeyDerivation, NodeInfo, ReportingConfig,
        RingCancellationPayload, RingFinalizationPayload, RingFinalizationStatus, RingPayload,
        UpgradeInfo,
    },
};
use async_trait::async_trait;
use common::blockchain::{
    orbis::{self, generate_document_id, generate_key_derivation_id, SubmitReportRequest},
    BlockchainError, ChainConfigBuilder, TxSigner, VeraClient,
};

#[cfg(test)]
mod tests;

pub struct VeraBulletin {
    pub chain_client: VeraClient,
}

#[async_trait]
impl Bulletin for VeraBulletin {
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
            BulletinWriteKind::CancelPendingRing => {
                let cancellation: RingCancellationPayload = serde_json::from_slice(&payload)
                    .map_err(|e| BulletinError::ParseError(e.to_string()))?;
                let result = self
                    .chain_client
                    .orbis_cancel_pending_ring(&cancellation.ring_id)
                    .await
                    .map_err(|e| BulletinError::ChainError(e.to_string()))?;
                check_result(result, "cancel pending ring")?;
                Ok(cancellation.ring_id)
            }
            BulletinWriteKind::Document => {
                let doc: DocumentPayload = serde_json::from_slice(&payload)
                    .map_err(|e| BulletinError::ParseError(e.to_string()))?;
                match self
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
                    Ok((result, document_id)) => {
                        check_result(result, "store document")?;
                        Ok(document_id)
                    }
                    Err(e) if is_already_exists_error(&e) => generate_document_id(
                        &doc.ring_id,
                        &doc.document,
                        &doc.proof,
                        &doc.policy_id,
                        &doc.resource,
                        &doc.permission,
                        doc.tier.as_deref(),
                        doc.timestamp,
                    )
                    .map_err(|e| BulletinError::ParseError(e.to_string())),
                    Err(e) => Err(BulletinError::ChainError(e.to_string())),
                }
            }
            BulletinWriteKind::KeyDerivation => {
                let kd: KeyDerivation = serde_json::from_slice(&payload)
                    .map_err(|e| BulletinError::ParseError(e.to_string()))?;
                match self
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
                    Ok((result, key_derivation_id)) => {
                        check_result(result, "store key derivation")?;
                        Ok(key_derivation_id)
                    }
                    Err(e) if is_already_exists_error(&e) => Ok(generate_key_derivation_id(
                        &kd.ring_id,
                        &kd.derivation,
                        &kd.policy_id,
                        &kd.resource,
                        &kd.permission,
                    )),
                    Err(e) => Err(BulletinError::ChainError(e.to_string())),
                }
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

    async fn submit_report(&self, s: BulletinReportSubmission) -> Result<()> {
        let result = self
            .chain_client
            .orbis_submit_report(SubmitReportRequest {
                domain: s.domain,
                report_type: s.report_type,
                chain_id: s.chain_id,
                ring_id: s.ring_id,
                ring_pk: s.ring_pk,
                ring_state_sha256: s.ring_state_sha256,
                reporter_node_key: s.reporter_node_key,
                accused_node_key: s.accused_node_key,
                accused_peer_id: s.accused_peer_id,
                observed_at: s.observed_at,
                expires_at: s.expires_at,
                payload: s.payload,
                session_id: s.session_id,
                report_id: s.report_id,
                signature_scheme: s.signature_scheme,
                signature: s.signature,
            })
            .await
            .map_err(|e| BulletinError::ChainError(e.to_string()))?;
        check_result(result, "submit report")
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

    async fn ring_finalization_status(&self, id: String) -> Result<RingFinalizationStatus> {
        let ring = self
            .chain_client
            .orbis_read_ring(&id)
            .await
            .map_err(|e| BulletinError::ChainError(e.to_string()))?
            .ok_or(BulletinError::NotFound { id })?;
        Ok(RingFinalizationStatus {
            ring_pk: ring.ring_pk,
            confirmation_node_keys: Some(
                ring.confirmations
                    .into_iter()
                    .map(|confirmation| confirmation.node_key)
                    .collect(),
            ),
        })
    }

    fn chain_id(&self) -> String {
        self.chain_client.config().chain_id.clone()
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

impl VeraBulletin {
    pub fn name() -> String {
        "bulletin/vera".to_string()
    }

    pub async fn new(chain_config_builder: ChainConfigBuilder) -> Result<Self> {
        Ok(VeraBulletin {
            chain_client: VeraClient::new(chain_config_builder.build())
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

        let client = VeraBulletin {
            chain_client: VeraClient::with_signer(chain_config_builder.build(), signer)
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

        // Transfer to self to register account on-chain (registers public
        // key). This is this signing key's first-ever transaction, so a
        // nonzero resynced sequence means an earlier boot of this same node
        // (e.g. a process restart) already sent it — either already
        // committed, or still landing on chain right as this process
        // started. Either way the account is already registered, or about
        // to be, so there is nothing left to do here.
        //
        // Two independent boots of this same node can race this exact
        // registration transfer within the same block window in two ways:
        // - Cosmos SDK signing is deterministic, so two attempts at the same
        //   (account_number, sequence) produce a byte-identical signed
        //   transaction: if the other boot's copy is already sitting in
        //   CometBFT's mempool cache, ours is rejected as a literal
        //   duplicate before either lands on chain ("tx already exists in
        //   cache").
        // - The other boot's transaction can instead have already been
        //   simulated/broadcast (but not yet committed) by the time ours is
        //   simulated, which the chain rejects as a sequence mismatch rather
        //   than a mempool duplicate.
        // In both cases a resync taken immediately afterwards can still read
        // sequence 0 (nothing has committed yet), so a single resync-and-
        // check is not enough to tell "genuinely failed" apart from "still
        // landing" — retry a few times, giving the other boot's transaction
        // a chance to commit, before treating it as fatal.
        const MAX_REGISTRATION_ATTEMPTS: u32 = 5;
        const RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(3);
        for attempt in 1..=MAX_REGISTRATION_ATTEMPTS {
            // The signer was initialized (account_number captured) when this
            // client was constructed above, which can be before this address
            // had ever received funds — the chain reports account_number 0
            // for an account that doesn't exist yet. If something else (e.g.
            // an external funder, or another boot of this node) created the
            // account in the meantime, that cached account_number is now
            // wrong and every signature this signer produces will fail
            // verification. Resync before every registration attempt below.
            let (_, sequence) = client
                .chain_client
                .resync_account()
                .await
                .map_err(|e| BulletinError::ChainError(e.to_string()))?;
            if sequence != 0 {
                break;
            }

            match client.chain_client.transfer(&address, 1u64, &denom).await {
                Ok(result) => {
                    check_result(result, "register account self-transfer")?;
                    break;
                }
                Err(error) => {
                    let message = error.to_string().to_lowercase();
                    let racing_registration = message.contains("tx already exists in cache")
                        || message.contains("account sequence mismatch");
                    if !racing_registration || attempt == MAX_REGISTRATION_ATTEMPTS {
                        return Err(BulletinError::ChainError(error.to_string()));
                    }
                    tokio::time::sleep(RETRY_DELAY).await;
                }
            }
        }

        Ok(client)
    }
}

// ============================================================================
// Conversion helpers: on-chain types → BulletinPost
// ============================================================================

fn ring_to_bulletin_post(ring: orbis::Ring) -> Result<BulletinPost> {
    let upgrade_info = ring.upgrade_info.ok_or_else(|| {
        BulletinError::ParseError(format!("ring {} is missing upgrade_info", ring.id))
    })?;
    if upgrade_info.next_version.is_some() != upgrade_info.activation_time.is_some() {
        return Err(BulletinError::ParseError(format!(
            "ring {} has malformed upgrade_info",
            ring.id
        )));
    }
    if !ring.allow_trusted_auth_relays && !ring.trusted_auth_relay_dids.is_empty() {
        return Err(BulletinError::ParseError(format!(
            "ring {} has relays configured while relay updates are disabled",
            ring.id
        )));
    }
    let trusted_auth_relay_dids = ring
        .allow_trusted_auth_relays
        .then_some(ring.trusted_auth_relay_dids);
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
        trusted_auth_relay_dids,
        upgrade_info: UpgradeInfo {
            current_version: upgrade_info.current_version,
            next_version: upgrade_info.next_version,
            activation_time: upgrade_info.activation_time,
        },
        // Nil chain config falls back to defaults that mirror the chain's module params;
        // see the DEFAULT_* constants in crate::trait.
        reporting: ring
            .reporting
            .map_or_else(ReportingConfig::default, |reporting| ReportingConfig {
                demerit_config: reporting.demerit_config.map_or_else(
                    DemeritConfig::default,
                    |dc| DemeritConfig {
                        node_offline_demerits: dc.node_offline_demerits,
                        reset_interval_seconds: dc.reset_interval_seconds,
                        invalid_crypto_response_demerits: dc.invalid_crypto_response_demerits,
                        unauthorized_request_demerits: dc.unauthorized_request_demerits,
                    },
                ),
                backup_node_keys: reporting.backup_node_keys,
                kick_threshold: reporting.kick_threshold,
            }),
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

fn is_already_exists_error(e: &BlockchainError) -> bool {
    match e {
        BlockchainError::TxFailed { log, .. } => is_already_exists_log(log),
        BlockchainError::Signing(msg) => is_already_exists_log(msg),
        _ => false,
    }
}
