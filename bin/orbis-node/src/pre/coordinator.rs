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
use crate::helpers::helpers::{connect_to_peer, is_self_peer_id};
use crate::pre::error::{PreError, Result};
use crate::pre::messages::PreMessage;
use ark_bls12_381::{Fr, G1Affine};
use crypto::r#trait::{
    DistKeyShare, Dkg, PriShare, PubShare, ReencryptReply, Secret, ThresholdDealer,
};
use crypto::{CryptoDeserialize, CryptoSerialize};
use local_storage::r#trait::LocalStorage;
use network::Message as NetworkMessage;
use network::REENCRYPT;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

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
///
/// Type parameters:
/// - D: DKG implementation (must use Fr and G1Affine)
/// - T: ThresholdDealer implementation (must use compatible types)
pub struct PreCoordinator<D, T>
where
    D: Dkg + Clone,
    T: ThresholdDealer,
{
    app_state: Arc<AppState<D>>,
    _phantom: std::marker::PhantomData<T>,
}

impl<D, T> PreCoordinator<D, T>
where
    D: Dkg<ShareValue = Fr, PublicKey = G1Affine> + Clone + Send + Sync + 'static,
    T: ThresholdDealer<
            ShareValue = Fr,
            PublicKey = G1Affine,
            DistKeyShare = DistKeyShare<Fr>,
            Secret = Secret,
            ReencryptReply = ReencryptReply<Fr, G1Affine>,
            PubPoly = D::PubPoly,
        > + Send
        + Sync
        + 'static,
{
    /// Create a new PRE coordinator for this node
    pub fn new(app_state: Arc<AppState<D>>) -> Self {
        Self {
            app_state,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Handle an incoming PRE message
    ///
    /// Routes the message to the appropriate handler based on message type.
    pub async fn handle_message(&self, message: PreMessage) -> Result<Option<PreMessage>> {
        match message {
            PreMessage::ReencryptRequest {
                request_id,
                from_node_id,
                secret,
                rdr_pk,
                ring_pk,
            } => {
                tracing::info!(
                    request_id = %request_id,
                    from_node_id = from_node_id,
                    "PRE Coordinator: Received ReencryptRequest"
                );

                // Handle the reencryption request
                self.handle_reencrypt_request(request_id, from_node_id, secret, rdr_pk, ring_pk)
                    .await
            }
            PreMessage::ReencryptResponse { .. } => {
                tracing::debug!(
                    request_id = %message.request_id(),
                    "PRE Coordinator: Received ReencryptResponse"
                );
                // Responses are collected by initiate_reencryption, not here
                Ok(None)
            }
            PreMessage::Error { request_id, error } => {
                tracing::error!(
                    request_id = %request_id,
                    error = %error,
                    "PRE Coordinator: Received error"
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
        let rdr_pk = <D::PublicKey>::from_bytes(&rdr_pk_bytes[..]).map_err(|e| {
            PreError::Deserialization(format!("Failed to deserialize reader public key: {}", e))
        })?;

        // 3. Deserialize ring public key to get the storage key
        let ring_pk = <D::PublicKey>::from_bytes(&ring_pk_bytes[..]).map_err(|e| {
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

        // 5. Deserialize final share using trait method
        let pri_share: PriShare<D::ShareValue> =
            PriShare::from_bytes(&final_share_bytes).map_err(|e| {
                PreError::Deserialization(format!("Failed to deserialize final share: {}", e))
            })?;
        let node_id = pri_share.i;

        // 6. Create distributed key share
        let dist_key_share = DistKeyShare { pri_share };

        // 7. Perform reencryption
        let dealer = T::new();
        let reply = dealer
            .reencrypt(&dist_key_share, &secret, &rdr_pk)
            .map_err(|e| PreError::Crypto(format!("Reencryption failed: {}", e)))?;

        // 8. Serialize the reply components using trait methods
        let share_bytes =
            reply.share.v.to_bytes().map_err(|e| {
                PreError::Serialization(format!("Failed to serialize share: {}", e))
            })?;

        let challenge_bytes = reply.challenge.to_bytes().map_err(|e| {
            PreError::Serialization(format!("Failed to serialize challenge: {}", e))
        })?;

        let proof_bytes = reply
            .proof
            .to_bytes()
            .map_err(|e| PreError::Serialization(format!("Failed to serialize proof: {}", e)))?;

        // 9. Create response message
        let response = PreMessage::ReencryptResponse {
            request_id: request_id.clone(),
            from_node_id: node_id,
            share: share_bytes,
            challenge: challenge_bytes,
            proof: proof_bytes,
        };

        tracing::debug!(
            request_id = %request_id,
            to_node_id = from_node_id,
            "PRE Coordinator: Sending ReencryptResponse"
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

    /// Send a PRE request to a peer and wait for the response
    ///
    /// This method sends a request and waits for the response on the same connection,
    /// storing the response for later collection.
    pub async fn send_request_and_receive_response(
        &self,
        peer_id_str: &str,
        message: PreMessage,
        _request_id: &str,
    ) -> Result<()> {
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

        // Wait for response on the same connection
        let response_msg = connection.recv().await.map_err(|e| {
            PreError::NetworkCommunication(format!(
                "Failed to receive response from peer {}: {}",
                peer_id_str, e
            ))
        })?;

        // Deserialize response
        let response: PreMessage = serde_json::from_slice(&response_msg.data).map_err(|e| {
            PreError::Deserialization(format!("Failed to deserialize response: {}", e))
        })?;

        // Store the response
        self.store_response(response).await;

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
        // Count how many peers we'll actually contact (excluding self)
        let self_in_list = peer_ids
            .iter()
            .any(|pid| is_self_peer_id(&self.app_state.network, pid));
        let actual_peer_count = if self_in_list {
            peer_ids.len() - 1
        } else {
            peer_ids.len()
        };

        tracing::info!(
            request_id = %request_id,
            peer_count = actual_peer_count,
            self_in_list = self_in_list,
            "PRE Coordinator: Initiating reencryption"
        );

        // 1. Find DKG session to get threshold and public polynomial
        let dkg_session = self
            .app_state
            .get_dkg_session_by_ring_pk(&ring_pk_bytes)
            .await
            .ok_or_else(|| {
                PreError::SessionNotFound("DKG session not found for ring_pk".to_string())
            })?;

        let (threshold, total_participants, pub_poly, node_id) = {
            let session = dkg_session.read().await;
            let pub_poly = session.compute_public_polynomial().map_err(|e| {
                PreError::Crypto(format!("Failed to compute public polynomial: {}", e))
            })?;
            (
                session.threshold(),
                session.total_nodes(),
                pub_poly,
                session.node_id(),
            )
        };

        // Validate we have enough potential shares to meet threshold
        // If we're in the list, we can contribute our own share locally
        let potential_shares = if self_in_list {
            actual_peer_count + 1 // peers + our local share
        } else {
            actual_peer_count
        };

        if potential_shares < threshold {
            return Err(PreError::InsufficientShares {
                got: potential_shares,
                need: threshold,
            });
        }

        // 2. Deserialize reader public key
        let rdr_pk = <D::PublicKey>::from_bytes(&rdr_pk_bytes[..]).map_err(|e| {
            PreError::Deserialization(format!("Failed to deserialize reader public key: {}", e))
        })?;

        // 3. Deserialize secret to get enc_cmt
        let secret: Secret = serde_json::from_slice(&secret_bytes).map_err(|e| {
            PreError::Deserialization(format!("Failed to deserialize secret: {}", e))
        })?;

        let enc_cmt = <D::PublicKey>::from_bytes(&secret.enc_cmt[..]).map_err(|e| {
            PreError::Deserialization(format!("Failed to deserialize enc_cmt: {}", e))
        })?;

        // 4. Initialize response collection (with limit checking)
        // Clone request_id before moving into Arc (we need it later)
        let request_id_for_storage = request_id.clone();
        if !self
            .app_state
            .init_pre_response(request_id_for_storage, actual_peer_count)
            .await
        {
            return Err(PreError::ProtocolError(
                "PRE response limit exceeded, too many pending requests".to_string(),
            ));
        }

        // 5. Send reencryption requests to all peers concurrently and receive responses
        // node_id is already obtained from DKG session above
        let mut handles = Vec::new();

        // Use Arc to share byte vectors across all tasks (cheap clone)
        // Clone secret_bytes before moving into Arc (we need it later for deserialization)
        let secret_bytes_for_later = secret_bytes.clone();
        let secret_bytes_arc = Arc::new(secret_bytes);
        let rdr_pk_bytes_arc = Arc::new(rdr_pk_bytes);
        let ring_pk_bytes_arc = Arc::new(ring_pk_bytes);
        let request_id_arc = Arc::new(request_id);

        for peer_id_str in peer_ids {
            // Skip self - don't try to connect to ourselves
            if is_self_peer_id(&self.app_state.network, peer_id_str) {
                tracing::debug!(peer_id = %peer_id_str, "Skipping self when sending reencrypt request");
                continue;
            }

            let request = PreMessage::ReencryptRequest {
                request_id: request_id_arc.as_ref().clone(),
                from_node_id: node_id,
                secret: secret_bytes_arc.as_ref().clone(),
                rdr_pk: rdr_pk_bytes_arc.as_ref().clone(),
                ring_pk: ring_pk_bytes_arc.as_ref().clone(),
            };

            let peer_id = peer_id_str.clone();
            let req_id = request_id_arc.as_ref().clone();
            let app_state = self.app_state.clone();

            // Spawn a task for each peer to send request and receive response
            // Note: Creating new coordinator is cheap (just holds Arc<AppState>)
            let handle = tokio::spawn(async move {
                let coordinator = PreCoordinator::<D, T>::new(app_state);
                coordinator
                    .send_request_and_receive_response(&peer_id, request, &req_id)
                    .await
            });
            handles.push(handle);
        }

        // Wait for all responses
        for handle in handles {
            if let Err(e) = handle.await {
                tracing::error!(error = ?e, "Task failed");
            }
        }

        // 6. Collect the stored responses
        let collected_responses = self
            .app_state
            .get_pre_responses(request_id_arc.as_ref())
            .await
            .ok_or_else(|| {
                PreError::Timeout(format!(
                    "No responses found for request {}",
                    request_id_arc.as_ref()
                ))
            })?;

        // Check if we have enough responses (accounting for local share if self is participating)
        let min_needed_from_network = if self_in_list {
            threshold.saturating_sub(1) // We'll contribute our own share locally
        } else {
            threshold
        };

        if collected_responses.len() < min_needed_from_network {
            return Err(PreError::Timeout(format!(
                "Insufficient responses: got {}, need at least {}",
                collected_responses.len(),
                min_needed_from_network
            )));
        }

        // 7. Verify and extract shares
        let dealer = T::new();
        let mut verified_shares: Vec<PubShare<D::PublicKey>> = Vec::new();

        // If we're in the peer list (self_in_list), compute our own share locally
        if self_in_list {
            // Try to get our local share and compute reencryption
            let ring_pk = <D::PublicKey>::from_bytes(&ring_pk_bytes_arc[..]).map_err(|e| {
                PreError::Deserialization(format!("Failed to deserialize ring public key: {}", e))
            })?;

            if let Ok(Some(final_share_bytes)) = self.app_state.local_storage.get_encrypted(
                local_storage::r#trait::LocalStorageKeys::RingKey(ring_pk.to_string()),
            ) {
                // We have a local share, compute our reencryption
                if let Ok(pri_share) = PriShare::<D::ShareValue>::from_bytes(&final_share_bytes) {
                    let dist_key_share = DistKeyShare { pri_share };

                    // Perform local reencryption
                    match dealer.reencrypt(&dist_key_share, &secret, &rdr_pk) {
                        Ok(reply) => {
                            tracing::debug!(
                                from_node_id = reply.share.i,
                                "PRE Coordinator: Added local share"
                            );
                            verified_shares.push(reply.share);
                        }
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                "PRE Coordinator: Local reencryption failed"
                            );
                        }
                    }
                }
            }
        }

        for response in collected_responses {
            if let PreMessage::ReencryptResponse {
                from_node_id,
                share: share_bytes,
                challenge: challenge_bytes,
                proof: proof_bytes,
                ..
            } = response
            {
                // Deserialize components using trait methods
                let share_v = <D::PublicKey>::from_bytes(&share_bytes[..]).map_err(|e| {
                    PreError::Deserialization(format!("Failed to deserialize share: {}", e))
                })?;

                let challenge = <D::ShareValue>::from_bytes(&challenge_bytes[..]).map_err(|e| {
                    PreError::Deserialization(format!("Failed to deserialize challenge: {}", e))
                })?;

                let proof = <D::ShareValue>::from_bytes(&proof_bytes[..]).map_err(|e| {
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
                        tracing::debug!(
                            from_node_id = from_node_id,
                            "PRE Coordinator: Verified share"
                        );
                        verified_shares.push(reply.share);
                    }
                    Err(e) => {
                        tracing::error!(
                            from_node_id = from_node_id,
                            error = %e,
                            "PRE Coordinator: Failed to verify share"
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

        // 10. Serialize xnc_cmt to bytes then hex using trait method
        let xnc_cmt_bytes = xnc_cmt
            .to_bytes()
            .map_err(|e| PreError::Serialization(format!("Failed to serialize xnc_cmt: {}", e)))?;
        let xnc_cmt_hex = hex::encode(&xnc_cmt_bytes);

        // 11. Deserialize secret from bytes (use cloned version)
        let secret: Secret = serde_json::from_slice(&secret_bytes_for_later).map_err(|e| {
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
        self.app_state
            .remove_pre_response(request_id_arc.as_ref())
            .await;

        tracing::info!(
            request_id = %request_id_arc.as_ref(),
            "PRE Coordinator: Successfully recovered reencrypted commitment"
        );

        Ok(response_bytes)
    }

    /// Store a received response (called by protocol handler)
    pub async fn store_response(&self, message: PreMessage) {
        let request_id = message.request_id().to_string();
        self.app_state
            .store_pre_response(&request_id, message)
            .await;
        tracing::debug!(request_id = %request_id, "PRE Coordinator: Stored response");
    }
}
