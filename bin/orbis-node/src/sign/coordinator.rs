//! Sign Coordinator
//!
//! This module implements the threshold signing protocol coordinator for each node.
//! Each node has its own instance that manages its participation in signing sessions.
//!
//! **Architecture: Decentralized (Peer-to-Peer)**
//!
//! This is NOT a central coordinator. Each node has its own coordinator that:
//! - Initiates sign requests to other nodes
//! - Responds to incoming sign requests from other nodes
//! - Manages signature share collection and recovery
//!
//! Supports both non-interactive (BLS) and interactive (FROST) signing via
//! the `ThresholdSigner::INTERACTIVE` flag. For FROST, an additional nonce
//! commitment round is performed before the signing round.

use crate::app_state::AppState;
use crate::constants::{
    BULLETIN_RING_NAMESPACE, MAX_COMMITMENTS, MAX_COMMITMENT_COEFFICIENTS, MAX_COMMITMENT_SIZE,
    MIN_ITEM_SIZE, PEER_RESPONSE_TIMEOUT,
};
use crate::helpers::helpers::{connect_to_peer, determine_session_node_id, is_self_peer_id};
use crate::sign::error::{Result, SignError};
use crate::sign::messages::SignMessage;
use bulletin::r#trait::{BulletinPost, DocumentPayload, RingPayload};
use crypto::r#trait::{
    CryptoDeserialize, CryptoSerialize, DistKeyShare, Dkg, PriShare, PubShare, ThresholdSigner,
};
use crypto::SigShareInner;
use crypto::SignaturePoint;
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
    /// Recovered signature as hex string
    pub signature: String,
}

/// Sign Coordinator
///
/// Each node has its own instance that manages this node's participation
/// in threshold signing sessions. This is NOT a central coordinator - the protocol is
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
            Signature = SignaturePoint,
            SigShare = PubShare<SigShareInner>,
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
            SignMessage::NonceRequest {
                request_id,
                from_node_id,
                ring_pk,
            } => {
                tracing::info!(
                    request_id = %request_id,
                    from_node_id = from_node_id,
                    "Sign Coordinator: Received NonceRequest"
                );
                self.handle_nonce_request(request_id, from_node_id, ring_pk)
                    .await
            }
            SignMessage::SignRequest {
                request_id,
                from_node_id,
                message,
                all_commitments,
            } => {
                tracing::info!(
                    request_id = %request_id,
                    from_node_id = from_node_id,
                    "Sign Coordinator: Received SignRequest"
                );
                self.handle_sign_request(request_id, from_node_id, message, all_commitments)
                    .await
            }
            SignMessage::SignResponse { .. } | SignMessage::NonceResponse { .. } => {
                tracing::debug!(
                    request_id = %message.request_id(),
                    "Sign Coordinator: Received response (stored by protocol handler)"
                );
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

    /// Handle a nonce request (responder side, FROST Round 1)
    ///
    /// Generates nonces and stores the signing state for later use in Round 2.
    async fn handle_nonce_request(
        &self,
        request_id: String,
        _from_node_id: u32,
        ring_pk_bytes: Vec<u8>,
    ) -> Result<Option<SignMessage>> {
        // 1. Deserialize ring public key
        let ring_pk = <D::PublicKey>::from_bytes(&ring_pk_bytes[..]).map_err(|e| {
            SignError::Deserialization(format!("Failed to deserialize ring public key: {}", e))
        })?;

        // 2. Retrieve DKG share from local storage
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

        let pri_share: PriShare<D::ShareValue> =
            PriShare::from_bytes(&final_share_bytes).map_err(|e| {
                SignError::Deserialization(format!("Failed to deserialize final share: {}", e))
            })?;
        let node_id = pri_share.i;
        let dist_key_share = DistKeyShare { pri_share };

        // 3. Generate nonces
        let signer = S::new();
        let (commitment, signing_state) = signer
            .generate_nonces(&dist_key_share)
            .map_err(|e| SignError::Crypto(format!("Nonce generation failed: {}", e)))?;

        // 4. Serialize and store signing state
        let state_bytes = CryptoSerialize::to_bytes(&signing_state).map_err(|e| {
            SignError::Serialization(format!("Failed to serialize signing state: {}", e))
        })?;

        if !self
            .app_state
            .sign_response_state
            .store_nonce(request_id.clone(), state_bytes)
            .await
        {
            return Err(SignError::NonceState(
                "Failed to store nonce state (limit exceeded or duplicate)".to_string(),
            ));
        }

        // 5. Serialize commitment
        let commitment_bytes = CryptoSerialize::to_bytes(&commitment).map_err(|e| {
            SignError::Serialization(format!("Failed to serialize nonce commitment: {}", e))
        })?;

        Ok(Some(SignMessage::NonceResponse {
            request_id,
            from_node_id: node_id,
            nonce_commitment: commitment_bytes,
        }))
    }

    /// Handle a sign request (responder side)
    async fn handle_sign_request(
        &self,
        request_id: String,
        from_node_id: u32,
        message: Vec<u8>,
        all_commitments_bytes: Vec<u8>,
    ) -> Result<Option<SignMessage>> {
        // 1. Verify the message exists on bulletin and get the associated ring_pk
        let (ring_pk_hex, pub_poly) = self.verify_message_and_get_info(&message).await?;

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

        // 6. Deserialize all_commitments and retrieve signing state if interactive
        let all_commitments = deserialize_commitments::<S>(&all_commitments_bytes)?;

        let signing_state = if S::INTERACTIVE {
            let nonce_key = format!("nonce-{}", request_id);
            let state_bytes = self
                .app_state
                .sign_response_state
                .take_nonce(&nonce_key)
                .await
                .ok_or_else(|| {
                    SignError::NonceState(format!(
                        "No nonce state found for request_id {}",
                        request_id
                    ))
                })?;
            Some(<S::SigningState>::from_bytes(&state_bytes).map_err(|e| {
                SignError::Deserialization(format!("Failed to deserialize signing state: {}", e))
            })?)
        } else {
            None
        };

        // 7. Sign the message
        let signer = S::new();
        let sig_share = signer
            .sign(
                &dist_key_share,
                &message,
                &pub_poly,
                signing_state.as_ref(),
                &all_commitments,
            )
            .map_err(|e| SignError::Crypto(format!("Signing failed: {}", e)))?;

        // 8. Serialize the signature share
        let sig_share_bytes = CryptoSerialize::to_bytes(&sig_share.v).map_err(|e| {
            SignError::Serialization(format!("Failed to serialize signature share: {}", e))
        })?;

        // 9. Create response message
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
    /// For interactive schemes (FROST), performs nonce collection round first.
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
            interactive = S::INTERACTIVE,
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
        let potential_shares = if self_in_list {
            actual_peer_count + 1
        } else {
            actual_peer_count
        };

        if potential_shares < threshold {
            return Err(SignError::InsufficientShares {
                got: potential_shares,
                need: threshold,
            });
        }

        // =====================================================================
        // ROUND 1 (FROST only): Collect nonce commitments
        // =====================================================================
        let (all_commitments, local_signing_state) = if S::INTERACTIVE {
            self.collect_nonces(&request_id, &ring_pk_bytes, peer_ids, node_id, self_in_list)
                .await?
        } else {
            (Vec::new(), None)
        };

        // Serialize all_commitments for the SignRequest message
        let all_commitments_bytes = serialize_commitments::<S>(&all_commitments)?;

        // =====================================================================
        // ROUND 2: Collect signature shares
        // =====================================================================

        // 2. Send sign requests to all peers concurrently and receive responses
        let mut handles = Vec::new();

        for peer_id_str in peer_ids {
            if is_self_peer_id(&self.app_state.network, peer_id_str) {
                tracing::debug!(peer_id = %peer_id_str, "Skipping self when sending sign request");
                continue;
            }

            let request = SignMessage::SignRequest {
                request_id: request_id.clone(),
                from_node_id: node_id,
                message: message.clone(),
                all_commitments: all_commitments_bytes.clone(),
            };

            let peer_id = peer_id_str.clone();
            let req_id = request_id.clone();
            let app_state = self.app_state.clone();

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

        let min_needed_from_network = if self_in_list {
            threshold.saturating_sub(1)
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
        let mut verified_shares: Vec<PubShare<SigShareInner>> = Vec::new();
        let mut seen_node_ids: HashSet<u32> = HashSet::new();

        // If we're in the peer list, compute our own share locally
        if self_in_list {
            let ring_pk = <D::PublicKey>::from_bytes(&ring_pk_bytes[..]).map_err(|e| {
                SignError::Deserialization(format!("Failed to deserialize ring public key: {}", e))
            })?;

            if let Ok(Some(final_share_bytes)) = self.app_state.local_storage.get_encrypted(
                local_storage::r#trait::LocalStorageKeys::RingKey(ring_pk.to_string()),
            ) {
                if let Ok(pri_share) = PriShare::<D::ShareValue>::from_bytes(&final_share_bytes) {
                    let dist_key_share = DistKeyShare { pri_share };

                    match signer.sign(
                        &dist_key_share,
                        &message,
                        &pub_poly,
                        local_signing_state.as_ref(),
                        &all_commitments,
                    ) {
                        Ok(sig_share) => {
                            match signer.verify_share(
                                &message,
                                &pub_poly,
                                &sig_share,
                                &all_commitments,
                            ) {
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
                if seen_node_ids.contains(&from_node_id) {
                    continue;
                }

                // Deserialize signature share using SigShareInner
                let sig_share_v = SigShareInner::from_bytes(&sig_share_bytes[..]).map_err(|e| {
                    SignError::Deserialization(format!("Failed to deserialize sig_share: {}", e))
                })?;

                let sig_share = PubShare {
                    i: from_node_id,
                    v: sig_share_v,
                };

                match signer.verify_share(&message, &pub_poly, &sig_share, &all_commitments) {
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
            .recover(
                &verified_shares,
                threshold,
                total_participants,
                &message,
                &all_commitments,
            )
            .map_err(|e| {
                SignError::RecoveryFailed(format!("Failed to recover signature: {}", e))
            })?;

        let signature = signature_opt
            .ok_or_else(|| SignError::RecoveryFailed("Recovery returned None".to_string()))?;

        // 7. Serialize signature to bytes then hex
        let signature_bytes = CryptoSerialize::to_bytes(&signature).map_err(|e| {
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

    /// Collect nonce commitments from all peers (FROST Round 1, initiator side)
    ///
    /// Returns the collected commitments and optionally our own signing state.
    async fn collect_nonces(
        &self,
        request_id: &str,
        ring_pk_bytes: &[u8],
        peer_ids: &[String],
        node_id: u32,
        self_in_list: bool,
    ) -> Result<(Vec<(u32, S::NonceCommitment)>, Option<S::SigningState>)> {
        let nonce_request_id = format!("nonce-{}", request_id);
        let mut all_commitments: Vec<(u32, S::NonceCommitment)> = Vec::new();
        let mut local_signing_state: Option<S::SigningState> = None;

        // Generate our own nonces if we're in the ring
        if self_in_list {
            let ring_pk = <D::PublicKey>::from_bytes(ring_pk_bytes).map_err(|e| {
                SignError::Deserialization(format!("Failed to deserialize ring public key: {}", e))
            })?;

            if let Ok(Some(final_share_bytes)) = self.app_state.local_storage.get_encrypted(
                local_storage::r#trait::LocalStorageKeys::RingKey(ring_pk.to_string()),
            ) {
                if let Ok(pri_share) = PriShare::<D::ShareValue>::from_bytes(&final_share_bytes) {
                    let dist_key_share = DistKeyShare { pri_share };
                    let signer = S::new();
                    let (commitment, state) =
                        signer.generate_nonces(&dist_key_share).map_err(|e| {
                            SignError::Crypto(format!("Local nonce generation failed: {}", e))
                        })?;
                    all_commitments.push((node_id, commitment));
                    local_signing_state = Some(state);
                }
            }
        }

        // Initialize response collection for nonce round using existing SignResponseManager
        if !self
            .app_state
            .sign_response_state
            .init_response(nonce_request_id.clone())
            .await
        {
            return Err(SignError::ProtocolError(
                "Nonce response limit exceeded".to_string(),
            ));
        }

        // Send nonce requests to all peers concurrently
        let mut handles = Vec::new();
        for peer_id_str in peer_ids {
            if is_self_peer_id(&self.app_state.network, peer_id_str) {
                continue;
            }

            let nonce_req = SignMessage::NonceRequest {
                request_id: nonce_request_id.clone(),
                from_node_id: node_id,
                ring_pk: ring_pk_bytes.to_vec(),
            };

            let peer_id = peer_id_str.clone();
            let req_id = nonce_request_id.clone();
            let app_state = self.app_state.clone();

            let handle = tokio::spawn(async move {
                let coordinator = SignCoordinator::<D, S>::new(app_state);
                coordinator
                    .send_request_and_receive_response(&peer_id, nonce_req, &req_id)
                    .await
            });
            handles.push(handle);
        }

        for handle in handles {
            if let Err(e) = handle.await {
                tracing::error!(error = ?e, "Nonce collection task failed");
            }
        }

        // Collect nonce responses and always cleanup, even on error
        let nonce_responses = self
            .app_state
            .sign_response_state
            .get_responses(&nonce_request_id)
            .await;

        // Cleanup nonce response state before any fallible operations
        self.app_state
            .sign_response_state
            .remove_response(&nonce_request_id)
            .await;

        let nonce_responses = nonce_responses.ok_or_else(|| {
            SignError::Timeout(format!(
                "No nonce responses found for request {}",
                nonce_request_id
            ))
        })?;

        for response in nonce_responses {
            if let SignMessage::NonceResponse {
                from_node_id,
                nonce_commitment,
                ..
            } = response
            {
                let commitment =
                    <S::NonceCommitment>::from_bytes(&nonce_commitment).map_err(|e| {
                        SignError::Deserialization(format!(
                            "Failed to deserialize nonce commitment from node {}: {}",
                            from_node_id, e
                        ))
                    })?;
                all_commitments.push((from_node_id, commitment));
            }
        }

        // Sort commitments by participant ID for deterministic ordering
        all_commitments.sort_by_key(|(id, _)| *id);

        Ok((all_commitments, local_signing_state))
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

    /// Verify that a message exists on the bulletin and return the ring_pk and pub_poly
    async fn verify_message_and_get_info(&self, message: &[u8]) -> Result<(String, D::PubPoly)> {
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

        // 6. Deserialize pub_poly
        let pub_poly_bytes = hex::decode(&ring_payload.public_polynomial).map_err(|e| {
            SignError::Deserialization(format!("Failed to decode public polynomial hex: {}", e))
        })?;
        let pub_poly = <D::PubPoly>::from_bytes(&pub_poly_bytes).map_err(|e| {
            SignError::Deserialization(format!("Failed to deserialize public polynomial: {}", e))
        })?;

        tracing::debug!(
            post_id = %post.id,
            ring_id = %doc_payload.ring_id,
            "Sign Coordinator: Message verified on bulletin"
        );

        Ok((ring_payload.ring_pk, pub_poly))
    }
}

// ============================================================================
// Commitment serialization helpers
// ============================================================================

/// Serialize a list of (node_id, commitment) pairs to bytes
fn serialize_commitments<S: ThresholdSigner>(
    commitments: &[(u32, S::NonceCommitment)],
) -> Result<Vec<u8>> {
    if commitments.is_empty() {
        return Ok(Vec::new());
    }

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(commitments.len() as u32).to_le_bytes());
    for (id, commitment) in commitments {
        bytes.extend_from_slice(&id.to_le_bytes());
        let commitment_bytes = CryptoSerialize::to_bytes(commitment).map_err(|e| {
            SignError::Serialization(format!("Failed to serialize commitment: {}", e))
        })?;
        bytes.extend_from_slice(&(commitment_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&commitment_bytes);
    }
    Ok(bytes)
}

/// Deserialize a list of (node_id, commitment) pairs from bytes
fn deserialize_commitments<S: ThresholdSigner>(
    bytes: &[u8],
) -> Result<Vec<(u32, S::NonceCommitment)>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }

    if bytes.len() < 4 {
        return Err(SignError::Deserialization(
            "Commitment bytes too short".to_string(),
        ));
    }

    let count = u32::from_le_bytes(
        bytes[0..4]
            .try_into()
            .map_err(|_| SignError::Deserialization("Invalid commitment count".to_string()))?,
    ) as usize;

    if count > MAX_COMMITMENTS {
        return Err(SignError::Deserialization(format!(
            "Commitment count {} exceeds maximum {}",
            count, MAX_COMMITMENTS
        )));
    }

    // Verify the payload can physically hold `count` items
    let remaining = bytes.len() - 4;
    if count > remaining / MIN_ITEM_SIZE {
        return Err(SignError::Deserialization(format!(
            "Commitment count {} exceeds what fits in {} remaining bytes",
            count, remaining
        )));
    }

    let mut offset = 4usize;
    let mut commitments = Vec::with_capacity(count);

    for _ in 0..count {
        if offset.checked_add(8).map_or(true, |end| end > bytes.len()) {
            return Err(SignError::Deserialization(
                "Commitment bytes truncated".to_string(),
            ));
        }

        let id = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| SignError::Deserialization("Invalid node_id".to_string()))?,
        );
        offset += 4;

        let commitment_len = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| SignError::Deserialization("Invalid commitment length".to_string()))?,
        ) as usize;
        offset += 4;

        if commitment_len > MAX_COMMITMENT_SIZE {
            return Err(SignError::Deserialization(format!(
                "Commitment length {} exceeds maximum {}",
                commitment_len, MAX_COMMITMENT_SIZE
            )));
        }

        if offset
            .checked_add(commitment_len)
            .map_or(true, |end| end > bytes.len())
        {
            return Err(SignError::Deserialization(
                "Commitment data truncated".to_string(),
            ));
        }

        let commitment = <S::NonceCommitment>::from_bytes(&bytes[offset..offset + commitment_len])
            .map_err(|e| {
                SignError::Deserialization(format!("Failed to deserialize commitment: {}", e))
            })?;
        offset += commitment_len;

        commitments.push((id, commitment));
    }

    if offset != bytes.len() {
        return Err(SignError::Deserialization(format!(
            "Trailing bytes: consumed {} of {} bytes",
            offset,
            bytes.len()
        )));
    }

    Ok(commitments)
}
