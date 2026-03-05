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
    BULLETIN_RING_NAMESPACE, MAX_TOKEN_LIFETIME_SECS, PEER_RESPONSE_TIMEOUT,
    SIGN_COLLECTION_TIMEOUT,
};
use crate::helpers::helpers::{connect_to_peer, determine_session_node_id, is_self_peer_id};
use crate::sign::error::{Result, SignError};
use crate::sign::helpers::{
    check_policy_access, decode_ring_pk_bytes, deserialize_commitments, fetch_bulletin_payloads,
    load_dist_key_share, serialize_commitments, try_load_dist_key_share, validate_sign_claims,
};
use crate::sign::messages::{SignContext, SignMessage};
use authn::{resolve_jwt_did, BearerToken, SignClaims};
use bulletin::r#trait::{BulletinPost, DocumentPayload, RingPayload};
use crypto::r#trait::{
    CryptoDeserialize, CryptoSerialize, DistKeyShare, Dkg, PubShare, ThresholdSigner,
};
use crypto::SigShareInner;
use crypto::SignaturePoint;
use crypto::{GroupAffine as G1Affine, ScalarField as Fr};
use network::Message as NetworkMessage;
use network::PeerId;
use network::SIGN;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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
    pub async fn handle_message(
        &self,
        message: SignMessage,
        sender_peer_id: &PeerId,
    ) -> Result<Option<SignMessage>> {
        match message {
            SignMessage::NonceRequest {
                request_id,
                from_node_id,
                ring_pk,
            } => {
                tracing::info!(
                    request_id = %request_id,
                    from_node_id = from_node_id,
                    sender_peer = %hex::encode(sender_peer_id.as_bytes()),
                    "Sign Coordinator: Received NonceRequest"
                );
                // Note: from_node_id is informational only for nonce requests (unused in handler).
                // Sender validation for sign protocol is done in handle_sign_request where
                // the ring's peer list is available from the bulletin lookup.
                self.handle_nonce_request(request_id, from_node_id, ring_pk)
                    .await
            }
            SignMessage::SignRequest {
                request_id,
                from_node_id,
                message,
                all_commitments,
                context,
            } => {
                tracing::info!(
                    request_id = %request_id,
                    from_node_id = from_node_id,
                    "Sign Coordinator: Received SignRequest"
                );
                self.handle_sign_request(
                    request_id,
                    from_node_id,
                    message,
                    all_commitments,
                    context,
                )
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
        // 1. Deserialize ring public key and load DKG share from local storage
        let ring_pk = decode_ring_pk_bytes(&ring_pk_bytes)?;
        let dist_key_share = load_dist_key_share(&self.app_state.local_storage, &ring_pk)?;
        let node_id = dist_key_share.pri_share.i;

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
        context: SignContext,
    ) -> Result<Option<SignMessage>> {
        // Note: We do NOT validate from_node_id here because the sign request initiator
        // may not be in the ring (external requesters use node_id=0).

        // Resolve ring info and auth based on pathway
        let (ring_pk_hex, pub_poly, derivation, metadata) = match context {
            SignContext::Bulletin => {
                // Message is a BulletinPost; on-chain existence is the authorization.
                // Signs from root key: no derivation, no metadata.
                let (ring_pk_hex, pub_poly) = self.verify_message_and_get_info(&message).await?;
                (ring_pk_hex, pub_poly, None, None)
            }
            SignContext::Policy {
                token_string,
                namespace,
                derivation_id,
                valid_window,
            } => {
                // Validate JWT
                let current_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| SignError::Generic(format!("Failed to get timestamp: {}", e)))?
                    .as_secs();
                let token: BearerToken<SignClaims> =
                    resolve_jwt_did(&token_string, current_time, MAX_TOKEN_LIFETIME_SECS).map_err(
                        |e| SignError::Unauthorized(format!("JWT validation failed: {}", e)),
                    )?;

                // Verify claims bind to this exact request
                validate_sign_claims(&token, &namespace, &derivation_id)?;

                // Fetch key derivation and ring info from bulletin
                let (key_derivation, ring_payload) =
                    fetch_bulletin_payloads(&*self.app_state.bulletin, &namespace, &derivation_id)
                        .await?;

                // Authorize: check on-chain policy access
                check_policy_access(
                    &*self.app_state.authz,
                    &key_derivation,
                    &derivation_id,
                    &token.issuer_id,
                    valid_window,
                )
                .await?;

                // Derivation and metadata come from the bulletin, not the client
                let derivation = Some(key_derivation.derivation.into_bytes());
                let metadata = Some(S::encode_metadata(
                    &key_derivation.policy_id,
                    &key_derivation.permission,
                    &key_derivation.resource,
                ));

                // Deserialize pub_poly from ring payload
                let pub_poly_bytes = hex::decode(&ring_payload.public_polynomial).map_err(|e| {
                    SignError::Deserialization(format!(
                        "Failed to decode public polynomial hex: {}",
                        e
                    ))
                })?;
                let pub_poly = <D::PubPoly>::from_bytes(&pub_poly_bytes).map_err(|e| {
                    SignError::Deserialization(format!(
                        "Failed to deserialize public polynomial: {}",
                        e
                    ))
                })?;

                (ring_payload.ring_pk, pub_poly, derivation, metadata)
            }
        };

        // Deserialize ring public key and load DKG share from local storage
        let ring_pk_bytes = hex::decode(&ring_pk_hex).map_err(|e| {
            SignError::Deserialization(format!("Failed to decode ring_pk hex: {}", e))
        })?;
        let ring_pk = decode_ring_pk_bytes(&ring_pk_bytes)?;
        let dist_key_share = load_dist_key_share(&self.app_state.local_storage, &ring_pk)?;
        let node_id = dist_key_share.pri_share.i;

        // Deserialize all_commitments and retrieve signing state if interactive
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

        // Sign the message
        let signer = S::new();
        let sig_share = signer
            .sign(
                &dist_key_share,
                &message,
                &pub_poly,
                signing_state.as_ref(),
                &all_commitments,
                derivation.as_deref(),
                metadata.as_deref(),
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

        // Store the response with the authenticated peer identity
        let authenticated_peer_id = connection.peer_id().clone();
        self.store_response(response, &authenticated_peer_id).await;

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
        context: SignContext,
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
            .sign_response_state
            .init_response(request_id.clone(), &expected_peers)
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
                context,
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
        context: SignContext,
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

        // Resolve derivation and metadata for local signing.
        // Only needed when this node is in the ring and will sign locally.
        // Derivation comes from the bulletin (KeyDerivation), not from the client.
        let (derivation, metadata) = if self_in_list {
            match &context {
                SignContext::Bulletin => (None, None),
                SignContext::Policy {
                    namespace,
                    derivation_id,
                    ..
                } => {
                    let (key_derivation, _) = fetch_bulletin_payloads(
                        &*self.app_state.bulletin,
                        namespace,
                        derivation_id,
                    )
                    .await?;
                    let derivation = Some(key_derivation.derivation.into_bytes());
                    let meta = Some(S::encode_metadata(
                        &key_derivation.policy_id,
                        &key_derivation.permission,
                        &key_derivation.resource,
                    ));
                    (derivation, meta)
                }
            }
        } else {
            (None, None)
        };

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
        let mut set = tokio::task::JoinSet::new();

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
                context: context.clone(),
            };

            let peer_id = peer_id_str.clone();
            let req_id = request_id.clone();
            let app_state = self.app_state.clone();

            set.spawn(async move {
                let coordinator = SignCoordinator::<D, S>::new(app_state);
                coordinator
                    .send_request_and_receive_response(&peer_id, request, &req_id)
                    .await
            });
        }

        // Wait for all responses with an overall deadline.
        // If the timeout fires, JoinSet drops here, aborting any remaining tasks.
        tokio::time::timeout(SIGN_COLLECTION_TIMEOUT, async {
            while let Some(res) = set.join_next().await {
                if let Err(e) = res {
                    tracing::error!(error = ?e, "Task failed");
                }
            }
        })
        .await
        .unwrap_or_else(|_| {
            tracing::warn!(
                request_id = %request_id,
                "Sign collection timed out; proceeding with partial responses"
            );
        });

        // 3. Collect the stored responses (moves Vec out, no clone; outer fn removes entry on exit)
        let collected_responses = self
            .app_state
            .sign_response_state
            .take_responses(&request_id)
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
            let ring_pk = decode_ring_pk_bytes(&ring_pk_bytes)?;
            if let Some(dist_key_share) =
                try_load_dist_key_share(&self.app_state.local_storage, &ring_pk)
            {
                match signer.sign(
                    &dist_key_share,
                    &message,
                    &pub_poly,
                    local_signing_state.as_ref(),
                    &all_commitments,
                    derivation.as_deref(),
                    metadata.as_deref(),
                ) {
                    Ok(sig_share) => {
                        match signer.verify_share(
                            &message,
                            &pub_poly,
                            &sig_share,
                            &all_commitments,
                            derivation.as_deref(),
                            metadata.as_deref(),
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

                match signer.verify_share(
                    &message,
                    &pub_poly,
                    &sig_share,
                    &all_commitments,
                    derivation.as_deref(),
                    metadata.as_deref(),
                ) {
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
            let ring_pk = decode_ring_pk_bytes(ring_pk_bytes)?;
            if let Some(dist_key_share) =
                try_load_dist_key_share(&self.app_state.local_storage, &ring_pk)
            {
                let signer = S::new();
                let (commitment, state) = signer.generate_nonces(&dist_key_share).map_err(|e| {
                    SignError::Crypto(format!("Local nonce generation failed: {}", e))
                })?;
                all_commitments.push((node_id, commitment));
                local_signing_state = Some(state);
            }
        }

        // Build expected peers for nonce round (everyone except self)
        let nonce_expected_peers: Vec<String> = peer_ids
            .iter()
            .filter(|pid| !is_self_peer_id(&self.app_state.network, pid))
            .cloned()
            .collect();

        // Initialize response collection for nonce round using existing SignResponseManager
        if !self
            .app_state
            .sign_response_state
            .init_response(nonce_request_id.clone(), &nonce_expected_peers)
            .await
        {
            return Err(SignError::ProtocolError(
                "Nonce response limit exceeded".to_string(),
            ));
        }

        // Send nonce requests to all peers concurrently
        let mut set = tokio::task::JoinSet::new();
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

            set.spawn(async move {
                let coordinator = SignCoordinator::<D, S>::new(app_state);
                coordinator
                    .send_request_and_receive_response(&peer_id, nonce_req, &req_id)
                    .await
            });
        }

        // Wait for all nonce responses with an overall deadline.
        // If the timeout fires, JoinSet drops here, aborting any remaining tasks.
        tokio::time::timeout(SIGN_COLLECTION_TIMEOUT, async {
            while let Some(res) = set.join_next().await {
                if let Err(e) = res {
                    tracing::error!(error = ?e, "Nonce collection task failed");
                }
            }
        })
        .await
        .unwrap_or_else(|_| {
            tracing::warn!(
                request_id = %request_id,
                "Nonce collection timed out; proceeding with partial responses"
            );
        });

        // Collect nonce responses, removing the entry atomically (no clone, cleanup implicit)
        let nonce_responses = self
            .app_state
            .sign_response_state
            .take_responses(&nonce_request_id)
            .await
            .ok_or_else(|| {
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
    ///
    /// The response is only accepted if the authenticated `sender_peer_id` is in the
    /// expected responder set (established at init time). This rejects both unknown peers
    /// and duplicate responses from the same peer. Fake `from_node_id` values are caught
    /// downstream by crypto verification (`signer.verify_share()`).
    pub async fn store_response(&self, message: SignMessage, sender_peer_id: &PeerId) {
        let request_id = message.request_id().to_string();

        tracing::debug!(
            request_id = %request_id,
            from_node_id = ?message.from_node_id(),
            sender_peer = %hex::encode(sender_peer_id.as_bytes()),
            "Sign Coordinator: Storing response"
        );
        self.app_state
            .sign_response_state
            .store_response(&request_id, message, sender_peer_id.as_bytes())
            .await;
    }

    /// Verify that a message exists on the bulletin and return the ring_pk, pub_poly
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
