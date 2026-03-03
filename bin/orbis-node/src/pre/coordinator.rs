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
use crate::constants::MAX_TOKEN_LIFETIME_SECS;
use crate::constants::PEER_RESPONSE_TIMEOUT;
use crate::constants::PRE_COLLECTION_TIMEOUT;
use crate::helpers::helpers::{connect_to_peer, determine_session_node_id, is_self_peer_id};
use crate::pre::error::{PreError, Result};
use crate::pre::helpers::{
    check_policy_access, decode_ring_pk, deserialize_secret, fetch_bulletin_payloads,
    validate_pre_claims, verify_encryption_binding,
};
use crate::pre::messages::PreMessage;
use authn::{resolve_jwt_did, BearerToken, PreClaims};
use authz::sourcehub::ValidWindow;
use crypto::r#trait::{
    DistKeyShare, Dkg, PriShare, PubShare, ReencryptReply, Secret, ThresholdDealer,
};
use crypto::{CryptoDeserialize, CryptoSerialize};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr};
use local_storage::r#trait::LocalStorage;
use network::Message as NetworkMessage;
use network::PeerId;
use network::REENCRYPT;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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
    D: Dkg + Clone + 'static,
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
                rdr_pk,
                object_id,
                token_string,
                namespace,
                derivation,
                salt,
                valid_window,
            } => {
                tracing::info!(
                    request_id = %request_id,
                    from_node_id = from_node_id,
                    "PRE Coordinator: Received ReencryptRequest"
                );

                // Handle the reencryption request
                // Note: from_node_id is not validated here (initiator may not be in ring).
                self.handle_reencrypt_request(
                    request_id,
                    from_node_id,
                    rdr_pk,
                    object_id,
                    token_string,
                    namespace,
                    derivation,
                    salt,
                    valid_window,
                )
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
        rdr_pk_bytes: Vec<u8>, // Serialized reader public key (G1Affine)
        object_id: String,
        token_string: String, // Client's token passed to ring nodes for auth
        namespace: String,
        derivation: Option<Vec<u8>>,
        salt: Option<String>,
        valid_window: Option<ValidWindow>,
    ) -> Result<Option<PreMessage>> {
        // Get current timestamp (needed for both auth and response)
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PreError::Generic(format!("Failed to get timestamp: {}", e)))?
            .as_secs();

        let token: BearerToken<PreClaims> =
            resolve_jwt_did(&token_string, current_time, MAX_TOKEN_LIFETIME_SECS)
                .map_err(|e| PreError::Unauthorized(format!("JWT validation failed: {}", e)))?;

        // 2. Authorize: Validate JWT claims match request fields
        validate_pre_claims(
            &token,
            &rdr_pk_bytes,
            &object_id,
            &namespace,
            &derivation,
            &salt,
        )?;

        let (document_payload, ring_payload) =
            fetch_bulletin_payloads(&*self.app_state.bulletin, &namespace, &object_id).await?;

        // Note: We do NOT validate from_node_id here because the reencrypt request initiator
        // may not be in the ring (external requesters use node_id=0).

        // Generate policy metadata for proof binding verification (before fields are moved)
        let policy_metadata = T::encode_metadata(
            &document_payload.policy_id,
            &document_payload.resource,
            &document_payload.permission,
            document_payload.tier.as_deref(),
            document_payload.timestamp,
            salt.as_deref(),
        );

        check_policy_access(
            &*self.app_state.authz,
            &document_payload,
            &object_id,
            &token.issuer_id,
            valid_window,
        )
        .await?;

        // 1. Deserialize the secret
        let secret = deserialize_secret(&document_payload.document)?;

        // 2. Deserialize reader public key
        let rdr_pk = <D::PublicKey>::from_bytes(&rdr_pk_bytes[..]).map_err(|e| {
            PreError::Deserialization(format!("Failed to deserialize reader public key: {}", e))
        })?;

        // 3. Deserialize ring public key to get the storage key
        let (_, ring_pk) = decode_ring_pk(&ring_payload.ring_pk)?;

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
        // Check permission binding - verify proof before re-encryption
        verify_encryption_binding(
            &ring_pk,
            derivation.as_deref(),
            document_payload.proof,
            &secret.enc_cmt,
            &policy_metadata,
        )?;
        let reply = dealer
            .reencrypt(&dist_key_share, &secret, &rdr_pk, derivation.as_deref())
            .map_err(|e| PreError::Crypto(format!("Reencryption failed: {}", e)))?;

        // 8. Serialize the reply components using trait methods
        let share_bytes = CryptoSerialize::to_bytes(&reply.share.v)
            .map_err(|e| PreError::Serialization(format!("Failed to serialize share: {}", e)))?;

        let challenge_bytes = CryptoSerialize::to_bytes(&reply.challenge).map_err(|e| {
            PreError::Serialization(format!("Failed to serialize challenge: {}", e))
        })?;

        let proof_bytes = CryptoSerialize::to_bytes(&reply.proof)
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

        // Wait for response on the same connection with timeout
        let response_msg = tokio::time::timeout(PEER_RESPONSE_TIMEOUT, connection.recv())
            .await
            .map_err(|_| {
                PreError::Timeout(format!(
                    "Timed out waiting for response from peer {}",
                    peer_id_str
                ))
            })?
            .map_err(|e| {
                PreError::NetworkCommunication(format!(
                    "Failed to receive response from peer {}: {}",
                    peer_id_str, e
                ))
            })?;

        // Deserialize response
        let response: PreMessage = serde_json::from_slice(&response_msg.data).map_err(|e| {
            PreError::Deserialization(format!("Failed to deserialize response: {}", e))
        })?;

        // Store the response with the authenticated peer identity
        let authenticated_peer_id = connection.peer_id().clone();
        self.store_response(response, &authenticated_peer_id).await;

        Ok(())
    }

    /// Initiate reencryption (initiator side)
    ///
    /// Sends reencryption requests to all ring nodes, collects responses,
    /// verifies them, and recovers the reencrypted commitment.
    ///
    /// Ring information (threshold, public_polynomial, total_nodes) is read from the bulletin
    /// by the service layer and passed to this function.
    pub async fn initiate_reencryption(
        &self,
        request_id: String,
        ring_pk_bytes: Vec<u8>,
        secret_bytes: Vec<u8>,
        rdr_pk_bytes: Vec<u8>,
        peer_ids: &[String],
        threshold: usize,
        total_participants: usize,
        public_polynomial_hex: &str,
        object_id: String,
        token_string: String,
        namespace: String,
        derivation: Option<Vec<u8>>,
        salt: Option<String>,
        valid_window: Option<ValidWindow>,
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
            "PRE Coordinator: Initiating reencryption"
        );

        // Build the list of peers we expect responses from (everyone except self)
        let expected_peers: Vec<String> = peer_ids
            .iter()
            .filter(|pid| !is_self_peer_id(&self.app_state.network, pid))
            .cloned()
            .collect();

        // Initialize response collection before calling inner function
        // This allows us to guarantee cleanup regardless of how inner function exits
        let request_id_for_cleanup = request_id.clone();
        if !self
            .app_state
            .pre_response_state
            .init_response(request_id.clone(), &expected_peers)
            .await
        {
            return Err(PreError::ProtocolError(
                "PRE response limit exceeded, too many pending requests".to_string(),
            ));
        }

        // Execute inner function and ensure cleanup happens regardless of result
        let result = self
            .initiate_reencryption_inner(
                request_id,
                ring_pk_bytes,
                secret_bytes,
                rdr_pk_bytes,
                peer_ids,
                threshold,
                total_participants,
                public_polynomial_hex,
                object_id,
                token_string,
                namespace,
                node_id,
                self_in_list,
                actual_peer_count,
                derivation,
                salt,
                valid_window,
            )
            .await;

        // Always cleanup, regardless of success or failure
        self.app_state
            .pre_response_state
            .remove_response(&request_id_for_cleanup)
            .await;

        result
    }

    /// Inner implementation of initiate_reencryption
    ///
    /// This is separated so that cleanup can be guaranteed by the outer function.
    /// Assumes init_pre_response has already been called.
    async fn initiate_reencryption_inner(
        &self,
        request_id: String,
        ring_pk_bytes: Vec<u8>,
        secret_bytes: Vec<u8>,
        rdr_pk_bytes: Vec<u8>,
        peer_ids: &[String],
        threshold: usize,
        total_participants: usize,
        public_polynomial_hex: &str,
        object_id: String,
        token_string: String,
        namespace: String,
        node_id: u32,
        self_in_list: bool,
        actual_peer_count: usize,
        derivation: Option<Vec<u8>>,
        salt: Option<String>,
        valid_window: Option<ValidWindow>,
    ) -> Result<Vec<u8>> {
        // 1. Deserialize public polynomial from bulletin data
        let pub_poly_bytes = hex::decode(public_polynomial_hex).map_err(|e| {
            PreError::Deserialization(format!("Failed to decode public polynomial hex: {}", e))
        })?;
        let pub_poly = <D::PubPoly>::from_bytes(&pub_poly_bytes).map_err(|e| {
            PreError::Deserialization(format!("Failed to deserialize public polynomial: {}", e))
        })?;

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

        // 4. Send reencryption requests to all peers concurrently and receive responses
        // Note: init_pre_response is called by the outer function to ensure cleanup on all paths
        // node_id is already obtained from DKG session above
        let mut set = tokio::task::JoinSet::new();

        // Keep a copy of secret_bytes for later deserialization
        let secret_bytes_for_later = secret_bytes.clone();

        for peer_id_str in peer_ids {
            // Skip self - don't try to connect to ourselves
            if is_self_peer_id(&self.app_state.network, peer_id_str) {
                tracing::debug!(peer_id = %peer_id_str, "Skipping self when sending reencrypt request");
                continue;
            }

            let request = PreMessage::ReencryptRequest {
                request_id: request_id.clone(),
                from_node_id: node_id,
                rdr_pk: rdr_pk_bytes.clone(),
                object_id: object_id.clone(),
                token_string: token_string.clone(),
                namespace: namespace.clone(),
                derivation: derivation.clone(),
                salt: salt.clone(),
                valid_window: valid_window.clone(),
            };

            let peer_id = peer_id_str.clone();
            let req_id = request_id.clone();
            let app_state = self.app_state.clone();

            // Spawn a task for each peer to send request and receive response
            // Note: Creating new coordinator is cheap (just holds Arc<AppState>)
            set.spawn(async move {
                let coordinator = PreCoordinator::<D, T>::new(app_state);
                coordinator
                    .send_request_and_receive_response(&peer_id, request, &req_id)
                    .await
            });
        }

        // Wait for all responses with an overall deadline.
        // If the timeout fires, JoinSet drops here, aborting any remaining tasks.
        tokio::time::timeout(PRE_COLLECTION_TIMEOUT, async {
            while let Some(res) = set.join_next().await {
                if let Err(e) = res {
                    tracing::error!(error = ?e, "Peer reencrypt task panicked");
                }
            }
        })
        .await
        .unwrap_or_else(|_| {
            tracing::warn!(
                request_id = %request_id,
                "PRE collection timed out; proceeding with partial responses"
            );
        });

        // 6. Collect the stored responses (moves Vec out, no clone; outer fn removes entry on exit)
        let collected_responses = self
            .app_state
            .pre_response_state
            .take_responses(&request_id)
            .await
            .ok_or_else(|| {
                PreError::Timeout(format!("No responses found for request {}", &request_id))
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
        let mut seen_node_ids: HashSet<u32> = HashSet::new();

        // If we're in the peer list (self_in_list), compute our own share locally
        if self_in_list {
            // Try to get our local share and compute reencryption
            let ring_pk = <D::PublicKey>::from_bytes(&ring_pk_bytes[..]).map_err(|e| {
                PreError::Deserialization(format!("Failed to deserialize ring public key: {}", e))
            })?;

            if let Ok(Some(final_share_bytes)) = self.app_state.local_storage.get_encrypted(
                local_storage::r#trait::LocalStorageKeys::RingKey(ring_pk.to_string()),
            ) {
                // We have a local share, compute our reencryption
                if let Ok(pri_share) = PriShare::<D::ShareValue>::from_bytes(&final_share_bytes) {
                    let dist_key_share = DistKeyShare { pri_share };

                    // Perform local reencryption
                    match dealer.reencrypt(&dist_key_share, &secret, &rdr_pk, derivation.as_deref())
                    {
                        Ok(reply) => {
                            tracing::debug!(
                                from_node_id = reply.share.i,
                                "PRE Coordinator: Added local share"
                            );
                            seen_node_ids.insert(reply.share.i);
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
                // Skip if this node_id matches our local share (local-vs-network conflict)
                if seen_node_ids.contains(&from_node_id) {
                    continue;
                }

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
                match dealer.verify(&rdr_pk, &pub_poly, &enc_cmt, &reply, derivation.as_deref()) {
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
        let xnc_cmt_bytes = CryptoSerialize::to_bytes(&xnc_cmt)
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

        // Note: Cleanup is handled by the outer initiate_reencryption function

        tracing::info!(
            request_id = %request_id,
            "PRE Coordinator: Successfully recovered reencrypted commitment"
        );

        Ok(response_bytes)
    }

    /// Store a received response (called by protocol handler)
    ///
    /// The response is only accepted if the authenticated `sender_peer_id` is in the
    /// expected responder set (established at init time). This rejects both unknown peers
    /// and duplicate responses from the same peer. Fake `from_node_id` values are caught
    /// downstream by crypto verification (`dealer.verify()`).
    pub async fn store_response(&self, message: PreMessage, sender_peer_id: &PeerId) {
        let request_id = message.request_id().to_string();

        tracing::debug!(
            request_id = %request_id,
            from_node_id = ?message.from_node_id(),
            sender_peer = %hex::encode(sender_peer_id.as_bytes()),
            "PRE Coordinator: Storing response"
        );
        self.app_state
            .pre_response_state
            .store_response(&request_id, message, sender_peer_id.as_bytes())
            .await;
    }
}
