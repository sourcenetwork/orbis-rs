//! `VeraClient` extension methods for x/orbis: transaction submission and queries.

use super::decode::{
    decode_create_ring_id, decode_store_document_id, decode_store_key_derivation_id,
};
use super::types::*;
use crate::blockchain::{BlockchainError, BroadcastResult, Result, VeraClient};
use prost::Message;

impl VeraClient {
    pub async fn orbis_create_ring(
        &self,
        peer_node_keys: Vec<String>,
        threshold: u32,
        pss_interval: u64,
        policy_id: &str,
        nonce: Option<String>,
        current_version: u64,
        reporting: Option<ReportingConfig>,
        trusted_auth_relay_dids: Option<Vec<String>>,
    ) -> Result<BroadcastResult> {
        let signer = self.require_signer()?;
        let msg = MsgCreateRing::new(
            &signer.address(),
            peer_node_keys,
            threshold,
            pss_interval,
            policy_id,
            nonce,
            current_version,
            reporting,
            trusted_auth_relay_dids,
        );
        self.broadcast_proto_msg_with_gas(
            MsgCreateRing::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    /// Create a ring and return the chain-assigned ring_id alongside the broadcast result.
    ///
    /// The ring_id is decoded from `MsgCreateRingResponse` in the ABCI response data.
    pub async fn orbis_create_ring_get_id(
        &self,
        peer_node_keys: Vec<String>,
        threshold: u32,
        pss_interval: u64,
        policy_id: &str,
        nonce: Option<String>,
        current_version: u64,
        reporting: Option<ReportingConfig>,
        trusted_auth_relay_dids: Option<Vec<String>>,
    ) -> Result<(BroadcastResult, String)> {
        let result = self
            .orbis_create_ring(
                peer_node_keys,
                threshold,
                pss_interval,
                policy_id,
                nonce,
                current_version,
                reporting,
                trusted_auth_relay_dids,
            )
            .await?;

        if result.code != 0 {
            return Err(BlockchainError::TxFailed {
                code: result.code,
                log: result.log.clone(),
            });
        }

        let ring_id = decode_create_ring_id(result.data.as_ref()).ok_or_else(|| {
            BlockchainError::Serialization(format!(
                "Failed to decode ring_id from create ring response for tx {}",
                result.tx_hash
            ))
        })?;

        Ok((result, ring_id))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn orbis_store_document(
        &self,
        ring_id: &str,
        document: &str,
        proof: &str,
        policy_id: &str,
        resource: &str,
        permission: &str,
        tier: Option<String>,
        timestamp: Option<u64>,
        pet_tag: Option<String>,
        pet_tag_proof: Option<String>,
    ) -> Result<BroadcastResult> {
        let signer = self.require_signer()?;
        let msg = MsgStoreDocument {
            creator: signer.address(),
            ring_id: ring_id.to_string(),
            document: document.to_string(),
            proof: proof.to_string(),
            policy_id: policy_id.to_string(),
            resource: resource.to_string(),
            permission: permission.to_string(),
            tier,
            timestamp,
            pet_tag,
            pet_tag_proof,
        };
        self.broadcast_proto_msg_with_gas(
            MsgStoreDocument::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    /// Store a document and return the chain-assigned document_id alongside the broadcast result.
    #[allow(clippy::too_many_arguments)]
    pub async fn orbis_store_document_get_id(
        &self,
        ring_id: &str,
        document: &str,
        proof: &str,
        policy_id: &str,
        resource: &str,
        permission: &str,
        tier: Option<String>,
        timestamp: Option<u64>,
        pet_tag: Option<String>,
        pet_tag_proof: Option<String>,
    ) -> Result<(BroadcastResult, String)> {
        let result = self
            .orbis_store_document(
                ring_id,
                document,
                proof,
                policy_id,
                resource,
                permission,
                tier,
                timestamp,
                pet_tag,
                pet_tag_proof,
            )
            .await?;

        if result.code != 0 {
            return Err(BlockchainError::TxFailed {
                code: result.code,
                log: result.log.clone(),
            });
        }

        let document_id = decode_store_document_id(result.data.as_ref()).ok_or_else(|| {
            BlockchainError::Serialization(format!(
                "Failed to decode document_id from store document response for tx {}",
                result.tx_hash
            ))
        })?;

        Ok((result, document_id))
    }

    pub async fn orbis_store_key_derivation(
        &self,
        ring_id: &str,
        derivation: &str,
        policy_id: &str,
        resource: &str,
        permission: &str,
    ) -> Result<BroadcastResult> {
        let signer = self.require_signer()?;
        let msg = MsgStoreKeyDerivation {
            creator: signer.address(),
            ring_id: ring_id.to_string(),
            derivation: derivation.to_string(),
            policy_id: policy_id.to_string(),
            resource: resource.to_string(),
            permission: permission.to_string(),
        };
        self.broadcast_proto_msg_with_gas(
            MsgStoreKeyDerivation::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    /// Store a key derivation and return the chain-assigned key_derivation_id alongside the broadcast result.
    pub async fn orbis_store_key_derivation_get_id(
        &self,
        ring_id: &str,
        derivation: &str,
        policy_id: &str,
        resource: &str,
        permission: &str,
    ) -> Result<(BroadcastResult, String)> {
        let result = self
            .orbis_store_key_derivation(ring_id, derivation, policy_id, resource, permission)
            .await?;

        if result.code != 0 {
            return Err(BlockchainError::TxFailed {
                code: result.code,
                log: result.log.clone(),
            });
        }

        let key_derivation_id =
            decode_store_key_derivation_id(result.data.as_ref()).ok_or_else(|| {
                BlockchainError::Serialization(format!(
                    "Failed to decode key_derivation_id from store key derivation response for tx {}",
                    result.tx_hash
                ))
            })?;

        Ok((result, key_derivation_id))
    }

    pub async fn orbis_create_node_info(
        &self,
        peer_id: &str,
        controller_key: &str,
        whitelisted_policy_ids: Vec<String>,
        whitelisted_ring_ids: Vec<String>,
    ) -> Result<BroadcastResult> {
        let signer = self.require_signer()?;
        let msg = MsgCreateNodeInfo {
            creator: signer.address(),
            peer_id: peer_id.to_string(),
            controller_key: controller_key.to_string(),
            whitelisted_policy_ids,
            whitelisted_ring_ids,
        };
        self.broadcast_proto_msg_with_gas(
            MsgCreateNodeInfo::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    pub async fn orbis_start_ring_reshare_by_acp(
        &self,
        ring_id: &str,
        new_peer_node_keys: Vec<String>,
        new_threshold: Option<u32>,
    ) -> Result<BroadcastResult> {
        let signer = self.require_signer()?;
        let msg = MsgStartRingReshareByAcp::new(
            &signer.address(),
            ring_id,
            new_peer_node_keys,
            new_threshold,
        );
        self.broadcast_proto_msg_with_gas(
            MsgStartRingReshareByAcp::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    pub async fn orbis_cancel_ring_reshare_by_acp(&self, ring_id: &str) -> Result<BroadcastResult> {
        let signer = self.require_signer()?;
        let msg = MsgCancelRingReshareByAcp::new(&signer.address(), ring_id);
        self.broadcast_proto_msg_with_gas(
            MsgCancelRingReshareByAcp::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    pub async fn orbis_set_ring_pss_interval_by_acp(
        &self,
        ring_id: &str,
        pss_interval: u64,
    ) -> Result<BroadcastResult> {
        let signer = self.require_signer()?;
        let msg = MsgSetRingPssIntervalByAcp::new(&signer.address(), ring_id, pss_interval);
        self.broadcast_proto_msg_with_gas(
            MsgSetRingPssIntervalByAcp::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    pub async fn orbis_set_ring_reporting_by_acp(
        &self,
        ring_id: &str,
        reporting: ReportingConfig,
    ) -> Result<BroadcastResult> {
        let signer = self.require_signer()?;
        let msg = MsgSetRingReportingByAcp::new(&signer.address(), ring_id, reporting);
        self.broadcast_proto_msg_with_gas(
            MsgSetRingReportingByAcp::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    pub async fn orbis_add_ring_trusted_auth_relay_by_acp(
        &self,
        ring_id: &str,
        relay_did: &str,
    ) -> Result<BroadcastResult> {
        let signer = self.require_signer()?;
        let msg = MsgAddRingTrustedAuthRelayByAcp::new(&signer.address(), ring_id, relay_did);
        self.broadcast_proto_msg_with_gas(
            MsgAddRingTrustedAuthRelayByAcp::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    pub async fn orbis_remove_ring_trusted_auth_relay_by_acp(
        &self,
        ring_id: &str,
        relay_did: &str,
    ) -> Result<BroadcastResult> {
        let signer = self.require_signer()?;
        let msg = MsgRemoveRingTrustedAuthRelayByAcp::new(&signer.address(), ring_id, relay_did);
        self.broadcast_proto_msg_with_gas(
            MsgRemoveRingTrustedAuthRelayByAcp::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    pub async fn orbis_schedule_ring_upgrade_by_acp(
        &self,
        ring_id: &str,
        next_version: u64,
        activation_time: u64,
    ) -> Result<BroadcastResult> {
        let signer = self.require_signer()?;
        let msg = MsgScheduleRingUpgradeByAcp::new(
            &signer.address(),
            ring_id,
            next_version,
            activation_time,
        );
        self.broadcast_proto_msg_with_gas(
            MsgScheduleRingUpgradeByAcp::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    pub async fn orbis_cancel_ring_upgrade_by_acp(&self, ring_id: &str) -> Result<BroadcastResult> {
        let signer = self.require_signer()?;
        let msg = MsgCancelRingUpgradeByAcp::new(&signer.address(), ring_id);
        self.broadcast_proto_msg_with_gas(
            MsgCancelRingUpgradeByAcp::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    pub async fn orbis_cancel_pending_ring(&self, ring_id: &str) -> Result<BroadcastResult> {
        let signer = self.require_signer()?;
        let msg = MsgCancelPendingRing::new(&signer.address(), ring_id);
        self.broadcast_proto_msg_with_gas(
            MsgCancelPendingRing::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    pub async fn orbis_update_node_peer_id(
        &self,
        node_key: &str,
        peer_id: &str,
    ) -> Result<BroadcastResult> {
        let signer = self.require_signer()?;
        let msg = MsgUpdateNodePeerId::new(&signer.address(), node_key, peer_id);
        self.broadcast_proto_msg_with_gas(
            MsgUpdateNodePeerId::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    pub async fn orbis_transfer_node_controller(
        &self,
        node_key: &str,
        controller_key: &str,
    ) -> Result<BroadcastResult> {
        let signer = self.require_signer()?;
        let msg = MsgTransferNodeController::new(&signer.address(), node_key, controller_key);
        self.broadcast_proto_msg_with_gas(
            MsgTransferNodeController::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    pub async fn orbis_add_node_to_whitelist(
        &self,
        node_key: &str,
        target: WhitelistTarget,
    ) -> Result<BroadcastResult> {
        let signer = self.require_signer()?;
        let msg = MsgAddNodeToWhitelist::new(&signer.address(), node_key, target);
        self.broadcast_proto_msg_with_gas(
            MsgAddNodeToWhitelist::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    pub async fn orbis_remove_node_from_whitelist(
        &self,
        node_key: &str,
        target: WhitelistTarget,
    ) -> Result<BroadcastResult> {
        let signer = self.require_signer()?;
        let msg = MsgRemoveNodeFromWhitelist::new(&signer.address(), node_key, target);
        self.broadcast_proto_msg_with_gas(
            MsgRemoveNodeFromWhitelist::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    pub async fn orbis_finalize_ring(
        &self,
        ring_id: &str,
        ring_pk: &str,
    ) -> Result<BroadcastResult> {
        let signer = self.require_signer()?;
        let msg = MsgFinalizeRing::new(&signer.address(), ring_id, ring_pk);
        self.broadcast_proto_msg_with_gas(
            MsgFinalizeRing::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    pub async fn orbis_finalize_ring_reshare(
        &self,
        ring_id: &str,
        signature_scheme: &str,
        signature: Vec<u8>,
    ) -> Result<BroadcastResult> {
        let signer = self.require_signer()?;
        let msg = MsgFinalizeRingReshareByThresholdSignature::new(
            &signer.address(),
            ring_id,
            signature_scheme,
            signature,
        );
        self.broadcast_proto_msg_with_gas(
            MsgFinalizeRingReshareByThresholdSignature::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }

    pub async fn orbis_read_ring(&self, ring_id: &str) -> Result<Option<Ring>> {
        let request = QueryRingRequest {
            id: ring_id.to_string(),
        };
        let Some(response_bytes) = self
            .abci_query_optional(
                "/vera.orbis.Query/Ring",
                request.encode_to_vec(),
                None,
                false,
            )
            .await?
        else {
            return Ok(None);
        };
        let response = QueryRingResponse::decode(response_bytes.as_slice()).map_err(|e| {
            BlockchainError::Serialization(format!("Failed to decode ring response: {}", e))
        })?;
        Ok(response.ring)
    }

    pub async fn orbis_read_document(&self, id: &str) -> Result<Option<Document>> {
        let request = QueryDocumentRequest { id: id.to_string() };
        let Some(response_bytes) = self
            .abci_query_optional(
                "/vera.orbis.Query/Document",
                request.encode_to_vec(),
                None,
                false,
            )
            .await?
        else {
            return Ok(None);
        };
        let response = QueryDocumentResponse::decode(response_bytes.as_slice()).map_err(|e| {
            BlockchainError::Serialization(format!("Failed to decode document response: {}", e))
        })?;
        Ok(response.document)
    }

    pub async fn orbis_read_key_derivation(&self, id: &str) -> Result<Option<KeyDerivation>> {
        let request = QueryKeyDerivationRequest { id: id.to_string() };
        let Some(response_bytes) = self
            .abci_query_optional(
                "/vera.orbis.Query/KeyDerivation",
                request.encode_to_vec(),
                None,
                false,
            )
            .await?
        else {
            return Ok(None);
        };
        let response =
            QueryKeyDerivationResponse::decode(response_bytes.as_slice()).map_err(|e| {
                BlockchainError::Serialization(format!(
                    "Failed to decode key derivation response: {}",
                    e
                ))
            })?;
        Ok(response.key_derivation)
    }

    pub async fn orbis_read_node_info(&self, node_key: &str) -> Result<Option<NodeInfo>> {
        let request = QueryNodeInfoRequest {
            node_key: node_key.to_string(),
        };
        let Some(response_bytes) = self
            .abci_query_optional(
                "/vera.orbis.Query/NodeInfo",
                request.encode_to_vec(),
                None,
                false,
            )
            .await?
        else {
            return Ok(None);
        };
        let response = QueryNodeInfoResponse::decode(response_bytes.as_slice()).map_err(|e| {
            BlockchainError::Serialization(format!("Failed to decode node info response: {}", e))
        })?;
        Ok(response.node_info)
    }

    pub async fn orbis_read_node_demerits(&self, ring_id: &str, node_key: &str) -> Result<u64> {
        let request = QueryNodeDemeritsRequest {
            ring_id: ring_id.to_string(),
            node_key: node_key.to_string(),
        };
        let response_bytes = self
            .abci_query(
                "/vera.orbis.Query/NodeDemerits",
                request.encode_to_vec(),
                None,
                false,
            )
            .await?;
        let response =
            QueryNodeDemeritsResponse::decode(response_bytes.as_slice()).map_err(|e| {
                BlockchainError::Serialization(format!(
                    "Failed to decode node demerits response: {}",
                    e
                ))
            })?;
        Ok(response.points)
    }

    /// Whether a fault report for this `(ring, report_type, origin_protocol,
    /// accused, session)` has already been accepted on-chain — mirrors the
    /// dedupe key `reportSessionDedupeID` computes in Vera's `x/orbis/keeper`
    /// before applying a demerit. Lets a reporter skip a threshold-signing
    /// round for an incident that's already recorded, rather than discovering
    /// the duplicate only after paying for the round.
    pub async fn orbis_read_accepted_report_session(
        &self,
        ring_id: &str,
        report_type: &str,
        origin_protocol: &str,
        accused_node_key: &str,
        session_id: &str,
    ) -> Result<bool> {
        let request = QueryAcceptedReportSessionRequest {
            ring_id: ring_id.to_string(),
            report_type: report_type.to_string(),
            origin_protocol: origin_protocol.to_string(),
            accused_node_key: accused_node_key.to_string(),
            session_id: session_id.to_string(),
            attempt_id: Vec::new(),
        };
        let response_bytes = self
            .abci_query(
                "/vera.orbis.Query/AcceptedReportSession",
                request.encode_to_vec(),
                None,
                false,
            )
            .await?;
        let response = QueryAcceptedReportSessionResponse::decode(response_bytes.as_slice())
            .map_err(|e| {
                BlockchainError::Serialization(format!(
                    "Failed to decode accepted report session response: {}",
                    e
                ))
            })?;
        Ok(response.accepted)
    }

    pub async fn orbis_submit_report(&self, req: SubmitReportRequest) -> Result<BroadcastResult> {
        let signer = self.require_signer()?;
        let msg = MsgSubmitReport {
            creator: signer.address(),
            report: Some(ReportEnvelopeProto {
                domain: req.domain,
                report_type: req.report_type,
                chain_id: req.chain_id,
                ring_id: req.ring_id,
                ring_pk: req.ring_pk,
                ring_state_sha256: req.ring_state_sha256,
                reporter_node_key: req.reporter_node_key,
                accused_node_key: req.accused_node_key,
                accused_peer_id: req.accused_peer_id,
                observed_at: req.observed_at,
                expires_at: req.expires_at,
                payload: req.payload,
                session_id: req.session_id,
            }),
            report_id: req.report_id,
            signature_scheme: req.signature_scheme,
            signature: req.signature,
        };
        self.broadcast_proto_msg_with_gas(
            MsgSubmitReport::TYPE_URL,
            &msg,
            self.config().gas_multiplier,
        )
        .await
    }
}
