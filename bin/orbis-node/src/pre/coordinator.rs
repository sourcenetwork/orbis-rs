//! PRE Coordinator
//!
//! This module implements the PRE protocol coordinator for each node.
//! Each node has its own instance that manages its participation in PRE sessions.
//!
//! **Architecture: Decentralized (Peer-to-Peer)**
//!
//! This is NOT a central coordinator. Each node has its own coordinator that:
//! - Initiates PRE requests to other nodes
//! - Responds to incoming PRE requests from other nodes
//! - Manages reencryption share collection and recovery

use crate::app_state::AppState;
use crate::pre::error::{PreError, Result};
use crate::pre::messages::PreMessage;
use ark_bls12_381::{Fr, G1Affine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use crypto::bls12_381::pre::ThresholdDealerNode;
use crypto::r#trait::{DistKeyShare, PriShare, PubShare, ReencryptReply, Secret, ThresholdDealer};
use local_storage::r#trait::LocalStorage;
use network::iroh::router::alpn::REENCRYPT;
use network::Message as NetworkMessage;
use network::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Response structure containing reencrypted commitment and original secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreResponse {
    /// Recovered reencrypted commitment (xnc_cmt) as hex string
    pub xnc_cmt: String,
    /// Original encrypted secret (for Bob to decrypt) as JSON
    pub secret: Secret,
}

/// PRE Coordinator
///
/// Each node has its own instance that manages this node's participation
/// in PRE sessions. This is NOT a central coordinator - the protocol is
/// decentralized with each node managing its own state.
pub struct PreCoordinator {
    app_state: Arc<AppState>,
    /// Storage for collecting reencryption responses
    /// request_id -> (responses, expected_count)
    responses: Arc<RwLock<HashMap<String, (Vec<PreMessage>, usize)>>>,
}

impl PreCoordinator {
    /// Create a new PRE coordinator for this node
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self {
            app_state,
            responses: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Handle an incoming PRE message
    ///
    /// Routes the message to the appropriate handler based on message type.
    pub async fn handle_message(
        &self,
        _peer_id: &PeerId,
        message: PreMessage,
    ) -> Result<Option<PreMessage>> {
        match message {
            PreMessage::ReencryptRequest {
                request_id,
                from_node_id,
                secret,
                rdr_pk,
                ring_pk,
            } => {
                println!(
                    "PRE Coordinator: Received ReencryptRequest {} from node {}",
                    request_id, from_node_id
                );

                // Handle the reencryption request
                self.handle_reencrypt_request(request_id, from_node_id, secret, rdr_pk, ring_pk)
                    .await
            }
            PreMessage::ReencryptResponse { .. } => {
                println!(
                    "PRE Coordinator: Received ReencryptResponse for request {}",
                    message.request_id()
                );
                // Responses are collected by initiate_reencryption, not here
                Ok(None)
            }
            PreMessage::Error { request_id, error } => {
                eprintln!(
                    "PRE Coordinator: Received error for request {}: {}",
                    request_id, error
                );
                Ok(None)
            }
        }
    }

    /// Handle a reencryption request (responder side)
    async fn handle_reencrypt_request(
        &self,
        request_id: String,
        from_node_id: u32,
        secret_bytes: Vec<u8>,
        rdr_pk_bytes: Vec<u8>,
        ring_pk_bytes: Vec<u8>,
    ) -> Result<Option<PreMessage>> {
        // 1. Deserialize the secret
        let secret: Secret = serde_json::from_slice(&secret_bytes).map_err(|e| {
            PreError::Deserialization(format!("Failed to deserialize secret: {}", e))
        })?;

        // 2. Deserialize reader public key
        let rdr_pk = G1Affine::deserialize_compressed(&rdr_pk_bytes[..]).map_err(|e| {
            PreError::Deserialization(format!("Failed to deserialize reader public key: {}", e))
        })?;

        // 3. Deserialize ring public key to get the storage key
        let ring_pk = G1Affine::deserialize_compressed(&ring_pk_bytes[..]).map_err(|e| {
            PreError::Deserialization(format!("Failed to deserialize ring public key: {}", e))
        })?;

        // 4. Retrieve final share from local storage
        let final_share_bytes = self
            .app_state
            .local_storage
            .get_encrypted(local_storage::r#trait::LocalStorageKeys::RingKey(
                ring_pk.to_string(),
            ))
            .map_err(|e| {
                PreError::Storage(format!(
                    "Failed to retrieve final share from storage: {}",
                    e
                ))
            })?
            .ok_or_else(|| {
                PreError::Storage("Final share not found in storage for ring_pk".to_string())
            })?;

        // 5. Deserialize final share
        let final_share: Fr = Fr::deserialize_compressed(&final_share_bytes[..]).map_err(|e| {
            PreError::Deserialization(format!("Failed to deserialize final share: {}", e))
        })?;

        // 6. Get node ID from DKG session
        let dkg_session = self
            .app_state
            .get_dkg_session_by_ring_pk(&ring_pk_bytes)
            .await
            .ok_or_else(|| {
                PreError::SessionNotFound("DKG session not found for ring_pk".to_string())
            })?;

        let node_id = {
            let session = dkg_session.read().await;
            session.id
        };

        // 7. Create distributed key share
        let dist_key_share = DistKeyShare {
            pri_share: PriShare {
                i: node_id,
                v: final_share,
            },
        };

        // 8. Perform reencryption
        let dealer = ThresholdDealerNode::new();
        let reply = dealer
            .reencrypt(&dist_key_share, &secret, &rdr_pk)
            .map_err(|e| PreError::Crypto(format!("Reencryption failed: {}", e)))?;

        // 9. Serialize the reply components
        let mut share_bytes = Vec::new();
        reply
            .share
            .v
            .serialize_compressed(&mut share_bytes)
            .map_err(|e| PreError::Serialization(format!("Failed to serialize share: {}", e)))?;

        let mut challenge_bytes = Vec::new();
        reply
            .challenge
            .serialize_compressed(&mut challenge_bytes)
            .map_err(|e| {
                PreError::Serialization(format!("Failed to serialize challenge: {}", e))
            })?;

        let mut proof_bytes = Vec::new();
        reply
            .proof
            .serialize_compressed(&mut proof_bytes)
            .map_err(|e| PreError::Serialization(format!("Failed to serialize proof: {}", e)))?;

        // 10. Create response message
        let response = PreMessage::ReencryptResponse {
            request_id: request_id.clone(),
            from_node_id: node_id,
            share: share_bytes,
            challenge: challenge_bytes,
            proof: proof_bytes,
        };

        println!(
            "PRE Coordinator: Sending ReencryptResponse for request {} to node {}",
            request_id, from_node_id
        );

        Ok(Some(response))
    }

    /// Send a PRE message to a peer
    pub async fn send_message_to_peer(&self, peer_id_str: &str, message: PreMessage) -> Result<()> {
        use crate::helpers::helpers::connect_to_peer;

        // Connect to peer
        let connection =
            connect_to_peer(&self.app_state.network, peer_id_str.to_string(), REENCRYPT)
                .await
                .map_err(|e| {
                    PreError::NetworkConnection(format!(
                        "Failed to connect to peer {}: {}",
                        peer_id_str, e
                    ))
                })?;

        // Serialize message
        let message_data = serde_json::to_vec(&message)
            .map_err(|e| PreError::Serialization(format!("Failed to serialize message: {}", e)))?;

        // Send message
        connection
            .send(NetworkMessage::new(message_data, REENCRYPT))
            .await
            .map_err(|e| {
                PreError::NetworkCommunication(format!(
                    "Failed to send message to peer {}: {}",
                    peer_id_str, e
                ))
            })?;

        Ok(())
    }

    /// Initiate reencryption (initiator side)
    ///
    /// Sends reencryption requests to all ring nodes, collects responses,
    /// verifies them, and recovers the reencrypted commitment.
    pub async fn initiate_reencryption(
        &self,
        request_id: String,
        ring_pk_bytes: Vec<u8>,
        secret_bytes: Vec<u8>,
        rdr_pk_bytes: Vec<u8>,
        peer_ids: &[String],
    ) -> Result<Vec<u8>> {
        println!(
            "PRE Coordinator: Initiating reencryption for request {} with {} peers",
            request_id,
            peer_ids.len()
        );

        // 1. Find DKG session to get threshold and public polynomial
        let dkg_session = self
            .app_state
            .get_dkg_session_by_ring_pk(&ring_pk_bytes)
            .await
            .ok_or_else(|| {
                PreError::SessionNotFound("DKG session not found for ring_pk".to_string())
            })?;

        let (threshold, total_participants, pub_poly_commits) = {
            let session = dkg_session.read().await;
            (
                session.threshold,
                session.total_nodes,
                session.commitment.coefficients.clone(),
            )
        };

        // 2. Deserialize reader public key
        let rdr_pk = G1Affine::deserialize_compressed(&rdr_pk_bytes[..]).map_err(|e| {
            PreError::Deserialization(format!("Failed to deserialize reader public key: {}", e))
        })?;

        // 3. Deserialize secret to get enc_cmt
        let secret: Secret = serde_json::from_slice(&secret_bytes).map_err(|e| {
            PreError::Deserialization(format!("Failed to deserialize secret: {}", e))
        })?;

        let enc_cmt = G1Affine::deserialize_compressed(&secret.enc_cmt[..]).map_err(|e| {
            PreError::Deserialization(format!("Failed to deserialize enc_cmt: {}", e))
        })?;

        // 4. Initialize response collection
        {
            let mut responses = self.responses.write().await;
            responses.insert(request_id.clone(), (Vec::new(), peer_ids.len()));
        }

        // 5. Send reencryption requests to all peers
        let node_id = self.app_state.config.node_id;
        for peer_id_str in peer_ids {
            let request = PreMessage::ReencryptRequest {
                request_id: request_id.clone(),
                from_node_id: node_id,
                secret: secret_bytes.clone(),
                rdr_pk: rdr_pk_bytes.clone(),
                ring_pk: ring_pk_bytes.clone(),
            };

            if let Err(e) = self.send_message_to_peer(peer_id_str, request).await {
                eprintln!(
                    "Failed to send reencryption request to peer {}: {}",
                    peer_id_str, e
                );
            }
        }

        // 6. Wait for and collect responses
        // Note: In production, this should use proper async coordination with timeouts
        // For now, we'll use a simple polling approach
        let collected_responses = self.collect_responses(&request_id, threshold).await?;

        // 7. Verify and extract shares
        let dealer = ThresholdDealerNode::new();
        let mut verified_shares: Vec<PubShare<G1Affine>> = Vec::new();

        // Create pub_poly for verification
        let pub_poly = crypto::bls12_381::common::PubPoly {
            commits: pub_poly_commits,
        };

        for response in collected_responses {
            if let PreMessage::ReencryptResponse {
                from_node_id,
                share: share_bytes,
                challenge: challenge_bytes,
                proof: proof_bytes,
                ..
            } = response
            {
                // Deserialize components
                let share_v = G1Affine::deserialize_compressed(&share_bytes[..]).map_err(|e| {
                    PreError::Deserialization(format!("Failed to deserialize share: {}", e))
                })?;

                let challenge = Fr::deserialize_compressed(&challenge_bytes[..]).map_err(|e| {
                    PreError::Deserialization(format!("Failed to deserialize challenge: {}", e))
                })?;

                let proof = Fr::deserialize_compressed(&proof_bytes[..]).map_err(|e| {
                    PreError::Deserialization(format!("Failed to deserialize proof: {}", e))
                })?;

                // Create ReencryptReply for verification
                let reply = ReencryptReply {
                    share: PubShare {
                        i: from_node_id,
                        v: share_v,
                    },
                    challenge,
                    proof,
                };

                // Verify the reply
                match dealer.verify(&rdr_pk, &pub_poly, &enc_cmt, &reply) {
                    Ok(_) => {
                        println!("PRE Coordinator: Verified share from node {}", from_node_id);
                        verified_shares.push(reply.share);
                    }
                    Err(e) => {
                        eprintln!(
                            "PRE Coordinator: Failed to verify share from node {}: {}",
                            from_node_id, e
                        );
                    }
                }
            }
        }

        // 8. Check if we have enough verified shares
        if verified_shares.len() < threshold {
            return Err(PreError::InsufficientShares {
                got: verified_shares.len(),
                need: threshold,
            });
        }

        // 9. Recover the reencrypted commitment
        let xnc_cmt_opt = dealer
            .recover(&verified_shares, threshold, total_participants)
            .map_err(|e| {
                PreError::RecoveryFailed(format!("Failed to recover commitment: {}", e))
            })?;

        let xnc_cmt = xnc_cmt_opt
            .ok_or_else(|| PreError::RecoveryFailed("Recovery returned None".to_string()))?;

        // 10. Serialize xnc_cmt to bytes then hex
        let mut xnc_cmt_bytes = Vec::new();
        xnc_cmt
            .serialize_compressed(&mut xnc_cmt_bytes)
            .map_err(|e| PreError::Serialization(format!("Failed to serialize xnc_cmt: {}", e)))?;
        let xnc_cmt_hex = hex::encode(&xnc_cmt_bytes);

        // 11. Deserialize secret from bytes
        let secret: Secret = serde_json::from_slice(&secret_bytes).map_err(|e| {
            PreError::Deserialization(format!("Failed to deserialize secret: {}", e))
        })?;

        // 12. Create response structure
        let pre_response = PreResponse {
            xnc_cmt: xnc_cmt_hex,
            secret,
        };

        // 13. Serialize response to JSON bytes
        let response_bytes = serde_json::to_vec(&pre_response)
            .map_err(|e| PreError::Serialization(format!("Failed to serialize response: {}", e)))?;

        // 14. Cleanup
        {
            let mut responses = self.responses.write().await;
            responses.remove(&request_id);
        }

        println!(
            "PRE Coordinator: Successfully recovered reencrypted commitment for request {}",
            request_id
        );

        Ok(response_bytes)
    }

    /// Collect responses for a request
    ///
    /// This is a simplified implementation that polls for responses.
    /// In production, this should use proper async channels with timeouts.
    async fn collect_responses(
        &self,
        request_id: &str,
        threshold: usize,
    ) -> Result<Vec<PreMessage>> {
        use tokio::time::{sleep, Duration};

        let max_wait_seconds = 30;
        let poll_interval_ms = 100;
        let max_polls = (max_wait_seconds * 1000) / poll_interval_ms;

        for _ in 0..max_polls {
            {
                let responses = self.responses.read().await;
                if let Some((collected, _expected)) = responses.get(request_id) {
                    if collected.len() >= threshold {
                        return Ok(collected.clone());
                    }
                }
            }
            sleep(Duration::from_millis(poll_interval_ms as u64)).await;
        }

        // Timeout - return what we have
        let responses = self.responses.read().await;
        if let Some((collected, _expected)) = responses.get(request_id) {
            if !collected.is_empty() {
                return Ok(collected.clone());
            }
        }

        Err(PreError::Timeout(format!(
            "Timeout waiting for reencryption responses for request {}",
            request_id
        )))
    }

    /// Store a received response (called by protocol handler)
    pub async fn store_response(&self, message: PreMessage) {
        let request_id = message.request_id().to_string();
        let mut responses = self.responses.write().await;

        if let Some((collected, _expected)) = responses.get_mut(&request_id) {
            collected.push(message);
            println!(
                "PRE Coordinator: Stored response for request {}, total: {}",
                request_id,
                collected.len()
            );
        }
    }
}
