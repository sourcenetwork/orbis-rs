//! Sign Coordinator
//!
//! This module implements the threshold BLS signing protocol coordinator for each node.
//! Each node has its own instance that manages its participation in signing sessions.
//!
//! **Architecture: Decentralized (Peer-to-Peer)**
//!
//! This is NOT a central coordinator. Each node has its own coordinator that:
//! - Initiates sign requests to other nodes
//! - Responds to incoming sign requests from other nodes
//! - Manages signature share collection and recovery

use crate::app_state::AppState;
use crate::constants::{BULLETIN_RING_NAMESPACE, PEER_RESPONSE_TIMEOUT};
use crate::helpers::helpers::{connect_to_peer, determine_session_node_id, is_self_peer_id};
use crate::sign::error::{Result, SignError};
use crate::sign::messages::SignMessage;
use bulletin::r#trait::{BulletinPost, DocumentPayload, RingPayload};
use crypto::r#trait::{
    CryptoDeserialize, CryptoSerialize, DistKeyShare, Dkg, PriShare, PubShare, ThresholdSigner,
};
use crypto::SignaturePoint as G2Point;
use crypto::{GroupAffine as G1Affine, ScalarField as Fr};
use local_storage::r#trait::LocalStorage;
use network::Message as NetworkMessage;
use network::SIGN;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;

/// Response structure containing the recovered signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResponse {
    /// Recovered BLS signature as hex string (G2Point serialized)
    pub signature: String,
}

/// Sign Coordinator
///
/// Each node has its own instance that manages this node's participation
/// in threshold BLS signing sessions. This is NOT a central coordinator - the protocol is
/// decentralized with each node managing its own state.
///
/// Type parameters:
/// - D: DKG implementation (must use Fr and G1Affine)
/// - S: ThresholdSigner implementation (must use compatible types)
pub struct SignCoordinator<D, S>
where
    D: Dkg + Clone + 'static,
    S: ThresholdSigner,
{
    app_state: Arc<AppState<D>>,
    _phantom: std::marker::PhantomData<S>,
}

impl<D, S> SignCoordinator<D, S>
where
    D: Dkg<ShareValue = Fr, PublicKey = G1Affine> + Clone + Send + Sync + 'static,
    S: ThresholdSigner<
            ShareValue = Fr,
            PublicKey = G1Affine,
            DistKeyShare = DistKeyShare<Fr>,
            PubPoly = D::PubPoly,
            Signature = G2Point,
            SigShare = PubShare<G2Point>,
        > + Send
        + Sync
        + 'static,
{
    /// Create a new Sign coordinator for this node
    pub fn new(app_state: Arc<AppState<D>>) -> Self {
        Self {
            app_state,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Handle an incoming Sign message
    ///
    /// Routes the message to the appropriate handler based on message type.
    pub async fn handle_message(&self, message: SignMessage) -> Result<Option<SignMessage>> {
        match message {
            SignMessage::SignRequest {
                request_id,
                from_node_id,
                message,
            } => {
                tracing::info!(
                    request_id = %request_id,
                    from_node_id = from_node_id,
                    "Sign Coordinator: Received SignRequest"
                );

                // Handle the sign request
                self.handle_sign_request(request_id, from_node_id, message)
                    .await
            }
            SignMessage::SignResponse { .. } => {
                tracing::debug!(
                    request_id = %message.request_id(),
                    "Sign Coordinator: Received SignResponse"
                );
                // Responses are collected by initiate_signing, not here
                Ok(None)
            }
            SignMessage::Error { request_id, error } => {
                tracing::error!(
                    request_id = %request_id,
                    error = %error,
                    "Sign Coordinator: Received error"
                );
                Ok(None)
            }
        }
    }

    /// Handle a sign request (responder side)
    async fn handle_sign_request(
        &self,
        request_id: String,
        from_node_id: u32,
        message: Vec<u8>,
    ) -> Result<Option<SignMessage>> {
        // 1. Verify the message exists on bulletin and get the associated ring_pk
        let ring_pk_hex = self.verify_message(&message).await?;

        // 2. Deserialize ring public key to get the storage key
        let ring_pk_bytes = hex::decode(&ring_pk_hex).map_err(|e| {
            SignError::Deserialization(format!("Failed to decode ring_pk hex: {}", e))
        })?;
        let ring_pk = <D::PublicKey>::from_bytes(&ring_pk_bytes[..]).map_err(|e| {
            SignError::Deserialization(format!("Failed to deserialize ring public key: {}", e))
        })?;

        // 3. Retrieve final share from local storage
        let final_share_bytes = self
            .app_state
            .local_storage
            .get_encrypted(local_storage::r#trait::LocalStorageKeys::RingKey(
                ring_pk.to_string(),
            ))
            .map_err(|e| {
                SignError::Storage(format!(
                    "Failed to retrieve final share from storage: {}",
                    e
                ))
            })?
            .ok_or_else(|| {
                SignError::Storage("Final share not found in storage for ring_pk".to_string())
            })?;

        // 4. Deserialize final share
        let pri_share: PriShare<D::ShareValue> =
            PriShare::from_bytes(&final_share_bytes).map_err(|e| {
                SignError::Deserialization(format!("Failed to deserialize final share: {}", e))
            })?;
        let node_id = pri_share.i;

        // 5. Create distributed key share
        let dist_key_share = DistKeyShare { pri_share };

        // 6. Sign the message (hash-to-curve is handled internally by the signer)
        let signer = S::new();
        let sig_share = signer
            .sign(&dist_key_share, &message)
            .map_err(|e| SignError::Crypto(format!("Signing failed: {}", e)))?;

        // 7. Serialize the signature share
        let sig_share_bytes = sig_share.v.to_bytes().map_err(|e| {
            SignError::Serialization(format!("Failed to serialize signature share: {}", e))
        })?;

        // 8. Create response message
        let response = SignMessage::SignResponse {
            request_id: request_id.clone(),
            from_node_id: node_id,
            sig_share: sig_share_bytes,
        };

        tracing::debug!(
            request_id = %request_id,
            to_node_id = from_node_id,
            "Sign Coordinator: Sending SignResponse"
        );

        Ok(Some(response))
    }

    /// Send a Sign message to a peer
    pub async fn send_message_to_peer(
        &self,
        peer_id_str: &str,
        message: SignMessage,
    ) -> Result<()> {
        // Connect to peer
        let connection = connect_to_peer(&self.app_state.network, peer_id_str.to_string(), SIGN)
            .await
            .map_err(|e| {
                SignError::NetworkConnection(format!(
                    "Failed to connect to peer {}: {}",
                    peer_id_str, e
                ))
            })?;

        // Serialize message
        let message_data = serde_json::to_vec(&message)
            .map_err(|e| SignError::Serialization(format!("Failed to serialize message: {}", e)))?;

        // Send message
        connection
            .send(NetworkMessage::new(message_data, SIGN))
            .await
            .map_err(|e| {
                SignError::NetworkCommunication(format!(
                    "Failed to send message to peer {}: {}",
                    peer_id_str, e
                ))
            })?;

        Ok(())
    }

    /// Send a Sign request to a peer and wait for the response
    ///
    /// This method sends a request and waits for the response on the same connection,
    /// storing the response for later collection.
    pub async fn send_request_and_receive_response(
        &self,
        peer_id_str: &str,
        message: SignMessage,
        _request_id: &str,
    ) -> Result<()> {
        // Connect to peer
        let connection = connect_to_peer(&self.app_state.network, peer_id_str.to_string(), SIGN)
            .await
            .map_err(|e| {
                SignError::NetworkConnection(format!(
                    "Failed to connect to peer {}: {}",
                    peer_id_str, e
                ))
            })?;

        // Serialize message
        let message_data = serde_json::to_vec(&message)
            .map_err(|e| SignError::Serialization(format!("Failed to serialize message: {}", e)))?;

        // Send message
        connection
            .send(NetworkMessage::new(message_data, SIGN))
            .await
            .map_err(|e| {
                SignError::NetworkCommunication(format!(
                    "Failed to send message to peer {}: {}",
                    peer_id_str, e
                ))
            })?;

        // Wait for response on the same connection with timeout
        let response_msg = tokio::time::timeout(PEER_RESPONSE_TIMEOUT, connection.recv())
            .await
            .map_err(|_| {
                SignError::Timeout(format!(
                    "Timed out waiting for response from peer {}",
                    peer_id_str
                ))
            })?
            .map_err(|e| {
                SignError::NetworkCommunication(format!(
                    "Failed to receive response from peer {}: {}",
                    peer_id_str, e
                ))
            })?;

        // Deserialize response
        let response: SignMessage = serde_json::from_slice(&response_msg.data).map_err(|e| {
            SignError::Deserialization(format!("Failed to deserialize response: {}", e))
        })?;

        // Store the response
        self.store_response(response).await;

        Ok(())
    }

    /// Initiate signing (initiator side)
    ///
    /// Sends sign requests to all ring nodes, collects responses,
    /// verifies them, and recovers the full signature.
    ///
    /// Ring information (threshold, public_polynomial, total_nodes) is passed to this function.
    pub async fn initiate_signing(
        &self,
        request_id: String,
        ring_pk_bytes: Vec<u8>,
        message: Vec<u8>,
        peer_ids: &[String],
        threshold: usize,
        total_participants: usize,
        public_polynomial_hex: &str,
    ) -> Result<Vec<u8>> {
        // Determine our node_id (if we're in the ring) - single source of truth
        let our_peer_id = hex::encode(self.app_state.network.local_peer_id().as_bytes());
        let node_id_opt = determine_session_node_id(&our_peer_id, peer_ids);

        // self_in_list derived from node_id - guarantees consistency
        let self_in_list = node_id_opt.is_some();

        // 0 is a safe sentinel: DKG node_ids are 1-indexed, so 0 means "external requester"
        let node_id = node_id_opt.unwrap_or(0);

        // Count how many peers we'll actually contact (excluding self)
        let actual_peer_count = if self_in_list {
            peer_ids.len() - 1
        } else {
            peer_ids.len()
        };

        tracing::info!(
            request_id = %request_id,
            peer_count = actual_peer_count,
            self_in_list = self_in_list,
            threshold = threshold,
            "Sign Coordinator: Initiating signing"
        );

        // Initialize response collection before calling inner function
        // This allows us to guarantee cleanup regardless of how inner function exits
        let request_id_for_cleanup = request_id.clone();
        if !self
            .app_state
            .sign_response_state
            .init_response(request_id.clone())
            .await
        {
            return Err(SignError::ProtocolError(
                "Sign response limit exceeded, too many pending requests".to_string(),
            ));
        }

        // Execute inner function and ensure cleanup happens regardless of result
        let result = self
            .initiate_signing_inner(
                request_id,
                ring_pk_bytes,
                message,
                peer_ids,
                threshold,
                total_participants,
                public_polynomial_hex,
                node_id,
                self_in_list,
                actual_peer_count,
            )
            .await;

        // Always cleanup, regardless of success or failure
        self.app_state
            .sign_response_state
            .remove_response(&request_id_for_cleanup)
            .await;

        result
    }

    /// Inner implementation of initiate_signing
    ///
    /// This is separated so that cleanup can be guaranteed by the outer function.
    /// Assumes init_response has already been called.
    async fn initiate_signing_inner(
        &self,
        request_id: String,
        ring_pk_bytes: Vec<u8>,
        message: Vec<u8>,
        peer_ids: &[String],
        threshold: usize,
        total_participants: usize,
        public_polynomial_hex: &str,
        node_id: u32,
        self_in_list: bool,
        actual_peer_count: usize,
    ) -> Result<Vec<u8>> {
        // 1. Deserialize public polynomial from bulletin data
        let pub_poly_bytes = hex::decode(public_polynomial_hex).map_err(|e| {
            SignError::Deserialization(format!("Failed to decode public polynomial hex: {}", e))
        })?;
        let pub_poly = <D::PubPoly>::from_bytes(&pub_poly_bytes).map_err(|e| {
            SignError::Deserialization(format!("Failed to deserialize public polynomial: {}", e))
        })?;

        // Validate we have enough potential shares to meet threshold
        // If we're in the list, we can contribute our own share locally
        let potential_shares = if self_in_list {
            actual_peer_count + 1 // peers + our local share
        } else {
            actual_peer_count
        };

        if potential_shares < threshold {
            return Err(SignError::InsufficientShares {
                got: potential_shares,
                need: threshold,
            });
        }

        // 2. Send sign requests to all peers concurrently and receive responses
        let mut handles = Vec::new();

        for peer_id_str in peer_ids {
            // Skip self - don't try to connect to ourselves
            if is_self_peer_id(&self.app_state.network, peer_id_str) {
                tracing::debug!(peer_id = %peer_id_str, "Skipping self when sending sign request");
                continue;
            }

            let request = SignMessage::SignRequest {
                request_id: request_id.clone(),
                from_node_id: node_id,
                message: message.clone(),
            };

            let peer_id = peer_id_str.clone();
            let req_id = request_id.clone();
            let app_state = self.app_state.clone();

            // Spawn a task for each peer to send request and receive response
            let handle = tokio::spawn(async move {
                let coordinator = SignCoordinator::<D, S>::new(app_state);
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

        // 3. Collect the stored responses
        let collected_responses = self
            .app_state
            .sign_response_state
            .get_responses(&request_id)
            .await
            .ok_or_else(|| {
                SignError::Timeout(format!("No responses found for request {}", &request_id))
            })?;

        // Check if we have enough responses (accounting for local share if self is participating)
        let min_needed_from_network = if self_in_list {
            threshold.saturating_sub(1) // We'll contribute our own share locally
        } else {
            threshold
        };

        if collected_responses.len() < min_needed_from_network {
            return Err(SignError::Timeout(format!(
                "Insufficient responses: got {}, need at least {}",
                collected_responses.len(),
                min_needed_from_network
            )));
        }

        // 4. Verify and extract shares
        let signer = S::new();
        let mut verified_shares: Vec<PubShare<G2Point>> = Vec::new();
        let mut seen_node_ids: HashSet<u32> = HashSet::new();

        // If we're in the peer list (self_in_list), compute our own share locally
        if self_in_list {
            // Try to get our local share and compute signature
            let ring_pk = <D::PublicKey>::from_bytes(&ring_pk_bytes[..]).map_err(|e| {
                SignError::Deserialization(format!("Failed to deserialize ring public key: {}", e))
            })?;

            if let Ok(Some(final_share_bytes)) = self.app_state.local_storage.get_encrypted(
                local_storage::r#trait::LocalStorageKeys::RingKey(ring_pk.to_string()),
            ) {
                // We have a local share, compute our signature share
                if let Ok(pri_share) = PriShare::<D::ShareValue>::from_bytes(&final_share_bytes) {
                    let dist_key_share = DistKeyShare { pri_share };

                    // Perform local signing
                    match signer.sign(&dist_key_share, &message) {
                        Ok(sig_share) => {
                            // Verify our own share
                            match signer.verify_share(&message, &pub_poly, &sig_share) {
                                Ok(_) => {
                                    tracing::debug!(
                                        from_node_id = sig_share.i,
                                        "Sign Coordinator: Added local share"
                                    );
                                    seen_node_ids.insert(sig_share.i);
                                    verified_shares.push(sig_share);
                                }
                                Err(e) => {
                                    tracing::error!(
                                        error = %e,
                                        "Sign Coordinator: Local share verification failed"
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                "Sign Coordinator: Local signing failed"
                            );
                        }
                    }
                }
            }
        }

        for response in collected_responses {
            if let SignMessage::SignResponse {
                from_node_id,
                sig_share: sig_share_bytes,
                ..
            } = response
            {
                // Skip if this node_id matches our local share (local-vs-network conflict)
                if seen_node_ids.contains(&from_node_id) {
                    continue;
                }

                // Deserialize signature share
                let sig_share_v = G2Point::from_bytes(&sig_share_bytes[..]).map_err(|e| {
                    SignError::Deserialization(format!("Failed to deserialize sig_share: {}", e))
                })?;

                let sig_share = PubShare {
                    i: from_node_id,
                    v: sig_share_v,
                };

                // Verify the share
                match signer.verify_share(&message, &pub_poly, &sig_share) {
                    Ok(_) => {
                        tracing::debug!(
                            from_node_id = from_node_id,
                            "Sign Coordinator: Verified share"
                        );
                        verified_shares.push(sig_share);
                    }
                    Err(e) => {
                        tracing::error!(
                            from_node_id = from_node_id,
                            error = %e,
                            "Sign Coordinator: Failed to verify share"
                        );
                    }
                }
            }
        }

        // 5. Check if we have enough verified shares
        if verified_shares.len() < threshold {
            return Err(SignError::InsufficientShares {
                got: verified_shares.len(),
                need: threshold,
            });
        }

        // 6. Recover the full signature
        let signature_opt = signer
            .recover(&verified_shares, threshold, total_participants)
            .map_err(|e| {
                SignError::RecoveryFailed(format!("Failed to recover signature: {}", e))
            })?;

        let signature = signature_opt
            .ok_or_else(|| SignError::RecoveryFailed("Recovery returned None".to_string()))?;

        // 7. Serialize signature to bytes then hex
        let signature_bytes = signature.to_bytes().map_err(|e| {
            SignError::Serialization(format!("Failed to serialize signature: {}", e))
        })?;
        let signature_hex = hex::encode(&signature_bytes);

        // 8. Create response structure
        let sign_response = SignResponse {
            signature: signature_hex,
        };

        // 9. Serialize response to JSON bytes
        let response_bytes = serde_json::to_vec(&sign_response).map_err(|e| {
            SignError::Serialization(format!("Failed to serialize response: {}", e))
        })?;

        tracing::info!(
            request_id = %request_id,
            "Sign Coordinator: Successfully recovered signature"
        );

        Ok(response_bytes)
    }

    /// Store a received response (called by protocol handler)
    pub async fn store_response(&self, message: SignMessage) {
        let request_id = message.request_id().to_string();
        self.app_state
            .sign_response_state
            .store_response(&request_id, message)
            .await;
        tracing::debug!(request_id = %request_id, "Sign Coordinator: Stored response");
    }

    /// Verify that a message exists on the bulletin and return the associated ring public key
    ///
    /// This provides security by ensuring:
    /// 1. The message was actually posted to the bulletin (existence proof)
    /// 2. The payload content matches what's on the bulletin (integrity)
    /// 3. The ring_pk is derived from the bulletin's trusted data, not the requester
    async fn verify_message(&self, message: &[u8]) -> Result<String> {
        // 1. Deserialize the BulletinPost from the message
        let post: BulletinPost = message.to_vec().try_into().map_err(|e| {
            SignError::Deserialization(format!("Failed to deserialize BulletinPost: {}", e))
        })?;

        // 2. Verify it exists on bulletin (read by namespace + id)
        let actual_post = self
            .app_state
            .bulletin
            .read(post.namespace.clone(), post.id.clone())
            .await
            .map_err(|e| {
                SignError::VerificationFailed(format!(
                    "Failed to read from bulletin (namespace={}, id={}): {}",
                    post.namespace, post.id, e
                ))
            })?;

        // 3. Verify payload matches what's on bulletin
        if actual_post.payload != post.payload {
            return Err(SignError::VerificationFailed(
                "Payload mismatch: message payload does not match bulletin".to_string(),
            ));
        }

        // 4. Parse the DocumentPayload to get ring_id
        let doc_payload: DocumentPayload = serde_json::from_slice(&post.payload).map_err(|e| {
            SignError::Deserialization(format!("Failed to parse DocumentPayload: {}", e))
        })?;

        // 5. Look up ring info from bulletin
        let ring_info = self
            .app_state
            .bulletin
            .read(
                BULLETIN_RING_NAMESPACE.to_string(),
                doc_payload.ring_id.clone(),
            )
            .await
            .map_err(|e| {
                SignError::VerificationFailed(format!(
                    "Failed to read ring info for ring_id={}: {}",
                    doc_payload.ring_id, e
                ))
            })?;

        let ring_payload: RingPayload =
            serde_json::from_slice(&ring_info.payload).map_err(|e| {
                SignError::Deserialization(format!("Failed to parse RingPayload: {}", e))
            })?;

        tracing::debug!(
            post_id = %post.id,
            ring_id = %doc_payload.ring_id,
            "Sign Coordinator: Message verified on bulletin"
        );

        // 6. Return ring_pk for signing
        Ok(ring_payload.ring_pk)
    }
}
