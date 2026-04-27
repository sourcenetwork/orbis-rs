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
use crate::constants::MAX_JWT_BYTES;
use crate::constants::MAX_TOKEN_LIFETIME_SECS;
use crate::constants::PEER_RESPONSE_TIMEOUT;
use crate::constants::PRE_COLLECTION_TIMEOUT;
use crate::helpers::helpers::{
    determine_session_node_id, is_ring_reshare_in_progress, is_self_peer_id,
    load_ring_pub_poly_and_bundle, RingConfig,
};
use crate::pre::error::{PreError, Result};
use crate::pre::helpers::{
    check_policy_access, decode_ring_pk, deserialize_secret, fetch_bulletin_payloads,
    store_response, validate_pre_claims, verify_encryption_binding,
};
use crate::pre::messages::{PreMessage, PreRequestContext, ReencryptRequest};
use crate::ring_state::RingShareBundle;
use authn::{resolve_jwt_did, BearerToken, PreClaims};
use crypto::r#trait::{
    DistKeyShare, Dkg, PriShare, PubShare, ReencryptReply, Secret, ThresholdDealer,
};
use crypto::{CryptoDeserialize, CryptoSerialize};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr};
use network::Message as NetworkMessage;
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
    pub app_state: Arc<AppState<D>>,
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
            PreMessage::ReencryptRequest(req) => {
                tracing::info!(
                    request_id = %req.request_id,
                    from_node_id = req.from_node_id,
                    "PRE Coordinator: Received ReencryptRequest"
                );
                // Note: from_node_id is not validated here (initiator may not be in ring).
                self.handle_reencrypt_request(req).await
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
    async fn handle_reencrypt_request(&self, req: ReencryptRequest) -> Result<Option<PreMessage>> {
        let ReencryptRequest {
            request_id,
            from_node_id,
            context: ctx,
        } = req;
        // Get current timestamp (needed for both auth and response)
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PreError::Generic(format!("Failed to get timestamp: {}", e)))?
            .as_secs();

        let token: BearerToken<PreClaims> = resolve_jwt_did(
            &ctx.token_string,
            current_time,
            MAX_TOKEN_LIFETIME_SECS,
            MAX_JWT_BYTES,
        )
        .map_err(|e| PreError::Unauthorized(format!("JWT validation failed: {}", e)))?;

        // 2. Authorize: Validate JWT claims match request fields
        validate_pre_claims(
            &token,
            &ctx.rdr_pk_bytes,
            &ctx.object_id,
            &ctx.namespace,
            &ctx.derivation,
            &ctx.salt,
        )?;

        let (document_payload, ring_payload) =
            fetch_bulletin_payloads(&*self.app_state.bulletin, &ctx.namespace, &ctx.object_id)
                .await?;

        // Note: We do NOT validate from_node_id here because the reencrypt request initiator
        // may not be in the ring (external requesters use node_id=0).

        // Generate policy metadata for proof binding verification (before fields are moved)
        let policy_metadata = T::encode_metadata(
            &document_payload.policy_id,
            &document_payload.resource,
            &document_payload.permission,
            document_payload.tier.as_deref(),
            document_payload.timestamp,
            ctx.salt.as_deref(),
        );

        check_policy_access(
            &*self.app_state.authz,
            &document_payload,
            &ctx.object_id,
            &token.issuer_id,
            ctx.valid_window,
        )
        .await?;

        // 1. Deserialize the secret
        let secret = deserialize_secret(&document_payload.document)?;

        // 2. Deserialize reader public key
        let rdr_pk = <D::PublicKey>::from_bytes(&ctx.rdr_pk_bytes[..]).map_err(|e| {
            PreError::Deserialization(format!("Failed to deserialize reader public key: {}", e))
        })?;

        // 3. Deserialize ring public key to get the storage key
        let (_, ring_pk) = decode_ring_pk(&ring_payload.ring_pk)?;

        // 4. Load share bundle from local storage (single encrypted entry = atomic share+poly)
        let bundle = RingShareBundle::load(&self.app_state.local_storage, &ring_pk)
            .map_err(|e| PreError::Storage(format!("Failed to load share bundle: {}", e)))?;

        // 5. Deserialize final share from bundle
        let pri_share: PriShare<D::ShareValue> = PriShare::from_bytes(&bundle.share_bytes)
            .map_err(|e| {
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
            ctx.derivation.as_deref(),
            document_payload.proof,
            &secret.enc_cmt,
            &policy_metadata,
        )?;
        let reply = dealer
            .reencrypt(&dist_key_share, &secret, &rdr_pk, ctx.derivation.as_deref())
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

    /// Send a PRE request to a peer and wait for the response
    ///
    /// This method sends a request and waits for the response on the same connection,
    /// storing the response for later collection. Returns the reencryption response
    /// when one was received and stored; peer errors and unexpected message types
    /// are logged and returned as `Ok(None)`.
    pub async fn send_request_and_receive_response(
        &self,
        peer_id_str: &str,
        message: PreMessage,
        request_id: &str,
    ) -> Result<Option<PreMessage>> {
        if !matches!(&message, PreMessage::ReencryptRequest(_)) {
            return Err(PreError::ProtocolError(
                "send_request_and_receive_response requires a ReencryptRequest".to_string(),
            ));
        }

        let stream = self
            .app_state
            .peer_connection_pool
            .open_stream(&self.app_state.network, peer_id_str, REENCRYPT)
            .await
            .map_err(|e| {
                PreError::NetworkConnection(format!(
                    "Failed to open stream to peer {}: {}",
                    peer_id_str, e
                ))
            })?;

        let message_data = serde_json::to_vec(&message)
            .map_err(|e| PreError::Serialization(format!("Failed to serialize message: {}", e)))?;

        stream
            .send(NetworkMessage::new(message_data, REENCRYPT))
            .await
            .map_err(|e| {
                PreError::NetworkCommunication(format!(
                    "Failed to send message to peer {}: {}",
                    peer_id_str, e
                ))
            })?;

        // Wait for response on the same stream with timeout
        let response_msg = tokio::time::timeout(PEER_RESPONSE_TIMEOUT, stream.recv())
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

        if response.request_id() != request_id {
            return Err(PreError::ProtocolError(format!(
                "Peer {} responded with mismatched request_id: expected {}, got {}",
                peer_id_str,
                request_id,
                response.request_id()
            )));
        }

        // Only store valid reencryption responses; log and drop peer errors
        let authenticated_peer_id = stream.peer_id().clone();
        match response {
            response @ PreMessage::ReencryptResponse { .. } => {
                store_response(
                    response.clone(),
                    &authenticated_peer_id,
                    &self.app_state.pre_response_state,
                )
                .await;
                Ok(Some(response))
            }
            PreMessage::Error { error, .. } => {
                tracing::warn!(
                    peer = %peer_id_str,
                    error = %error,
                    "PRE Coordinator: peer returned an error, skipping share"
                );
                Ok(None)
            }
            _ => {
                tracing::warn!(
                    peer = %peer_id_str,
                    "PRE Coordinator: unexpected response type from peer, skipping"
                );
                Ok(None)
            }
        }
    }

    fn verify_peer_response(
        dealer: &T,
        response: PreMessage,
        rdr_pk: &D::PublicKey,
        pub_poly: &D::PubPoly,
        enc_cmt: &D::PublicKey,
        derivation: Option<&[u8]>,
        seen_node_ids: &mut HashSet<u32>,
    ) -> Result<Option<PubShare<D::PublicKey>>> {
        let PreMessage::ReencryptResponse {
            from_node_id,
            share: share_bytes,
            challenge: challenge_bytes,
            proof: proof_bytes,
            ..
        } = response
        else {
            return Ok(None);
        };

        if seen_node_ids.contains(&from_node_id) {
            return Ok(None);
        }

        let share_v = <D::PublicKey>::from_bytes(&share_bytes[..]).map_err(|e| {
            PreError::Deserialization(format!("Failed to deserialize share: {}", e))
        })?;

        let challenge = <D::ShareValue>::from_bytes(&challenge_bytes[..]).map_err(|e| {
            PreError::Deserialization(format!("Failed to deserialize challenge: {}", e))
        })?;

        let proof = <D::ShareValue>::from_bytes(&proof_bytes[..]).map_err(|e| {
            PreError::Deserialization(format!("Failed to deserialize proof: {}", e))
        })?;

        let reply = ReencryptReply {
            share: PubShare {
                i: from_node_id,
                v: share_v,
            },
            challenge,
            proof,
        };

        match dealer.verify(rdr_pk, pub_poly, enc_cmt, &reply, derivation) {
            Ok(_) => {
                tracing::debug!(
                    from_node_id = from_node_id,
                    "PRE Coordinator: Verified share"
                );
                seen_node_ids.insert(reply.share.i);
                Ok(Some(reply.share.clone()))
            }
            Err(e) => {
                tracing::error!(
                    from_node_id = from_node_id,
                    error = %e,
                    "PRE Coordinator: Failed to verify share"
                );
                Ok(None)
            }
        }
    }

    /// Initiate reencryption (initiator side)
    ///
    /// Sends reencryption requests to all ring nodes, collects responses,
    /// verifies them, and recovers the reencrypted commitment.
    ///
    /// Ring information is read from the bulletin by the service layer and
    /// provided via `ring`. Request auth and object identity are in `ctx`.
    pub async fn initiate_reencryption(
        &self,
        request_id: String,
        ring: RingConfig,
        secret_bytes: Vec<u8>,
        ctx: PreRequestContext,
    ) -> Result<Vec<u8>> {
        // Determine our node_id (if we're in the ring) - single source of truth
        let our_peer_id = hex::encode(self.app_state.network.local_peer_id().as_bytes());
        let node_id_opt = determine_session_node_id(&our_peer_id, &ring.peer_ids);

        // self_in_list derived from node_id - guarantees consistency
        let self_in_list = node_id_opt.is_some();

        // 0 is a safe sentinel: DKG node_ids are 1-indexed, so 0 means "external requester"
        let node_id = node_id_opt.unwrap_or(0);

        // Count how many peers we'll actually contact (excluding self)
        let actual_peer_count = if self_in_list {
            ring.peer_ids.len() - 1
        } else {
            ring.peer_ids.len()
        };

        tracing::info!(
            request_id = %request_id,
            peer_count = actual_peer_count,
            self_in_list = self_in_list,
            threshold = ring.threshold,
            "PRE Coordinator: Initiating reencryption"
        );

        // Build the list of peers we expect responses from (everyone except self)
        let expected_peers: Vec<String> = ring
            .peer_ids
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
                ring,
                secret_bytes,
                node_id,
                self_in_list,
                actual_peer_count,
                ctx,
            )
            .await;

        // Always cleanup response state regardless of success or failure.
        // Pool connections are permanent — no per-request eviction needed.
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
        ring: RingConfig,
        secret_bytes: Vec<u8>,
        node_id: u32,
        self_in_list: bool,
        actual_peer_count: usize,
        ctx: PreRequestContext,
    ) -> Result<Vec<u8>> {
        // 1. Load the public polynomial and (when self_in_list) the local share bundle
        //    from a SINGLE atomic read of RingShareBundle.
        //
        //    Without this, there is a TOCTOU race: the service layer reads the polynomial
        //    in one bundle read, then `self_in_list` reads the share in a second bundle
        //    read.  If PSS Phase 4 fires between those two reads it updates the bundle
        //    atomically (new share + new polynomial together), so the two reads can see
        //    different generations.  A self-share from generation N+1 combined via
        //    Lagrange with peer shares from generation N produces a wrong xnc_cmt,
        //    which passes AES-GCM tag verification with a wrong key → "authentication
        //    failed".
        //
        //    Loading both fields from the same snapshot guarantees they are always from
        //    the same PSS generation, so Lagrange interpolation is correct.
        let (pub_poly, local_share_bundle) =
            load_ring_pub_poly_and_bundle::<D>(&self.app_state.local_storage, &ring, self_in_list)
                .map_err(PreError::Deserialization)?;

        // Validate we have enough potential shares to meet threshold
        // If we're in the list, we can contribute our own share locally
        let potential_shares = if self_in_list {
            actual_peer_count + 1 // peers + our local share
        } else {
            actual_peer_count
        };

        if potential_shares < ring.threshold {
            return Err(PreError::InsufficientShares {
                got: potential_shares,
                need: ring.threshold,
            });
        }

        // 2. Deserialize reader public key
        let rdr_pk = <D::PublicKey>::from_bytes(&ctx.rdr_pk_bytes[..]).map_err(|e| {
            PreError::Deserialization(format!("Failed to deserialize reader public key: {}", e))
        })?;

        // 3. Deserialize secret to get enc_cmt
        let secret: Secret = serde_json::from_slice(&secret_bytes).map_err(|e| {
            PreError::Deserialization(format!("Failed to deserialize secret: {}", e))
        })?;

        let enc_cmt = <D::PublicKey>::from_bytes(&secret.enc_cmt[..]).map_err(|e| {
            PreError::Deserialization(format!("Failed to deserialize enc_cmt: {}", e))
        })?;

        let dealer = T::new();
        let mut verified_shares: Vec<PubShare<D::PublicKey>> = Vec::new();
        let mut seen_node_ids: HashSet<u32> = HashSet::new();

        // If we're in the peer list, compute our own share locally before deciding
        // how many verified shares we still need from the network.
        if self_in_list {
            if let Some(bundle) = local_share_bundle {
                if let Ok(pri_share) = PriShare::<D::ShareValue>::from_bytes(&bundle.share_bytes) {
                    let dist_key_share = DistKeyShare { pri_share };

                    match dealer.reencrypt(
                        &dist_key_share,
                        &secret,
                        &rdr_pk,
                        ctx.derivation.as_deref(),
                    ) {
                        Ok(reply) => {
                            tracing::debug!(
                                from_node_id = reply.share.i,
                                "PRE Coordinator: Added local share"
                            );
                            seen_node_ids.insert(reply.share.i);
                            verified_shares.push(reply.share.clone());
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

        let min_needed_from_network = ring.threshold.saturating_sub(verified_shares.len());

        // 4. Send reencryption requests to all peers concurrently and receive responses
        // Note: init_pre_response is called by the outer function to ensure cleanup on all paths
        // node_id is already obtained from DKG session above
        let mut set = tokio::task::JoinSet::new();

        // Keep a copy of secret_bytes for later deserialization
        let secret_bytes_for_later = secret_bytes.clone();

        if min_needed_from_network > 0 {
            for peer_id_str in &ring.peer_ids {
                // Skip self - don't try to connect to ourselves
                if is_self_peer_id(&self.app_state.network, peer_id_str) {
                    tracing::debug!(peer_id = %peer_id_str, "Skipping self when sending reencrypt request");
                    continue;
                }

                let request = PreMessage::ReencryptRequest(ReencryptRequest {
                    request_id: request_id.clone(),
                    from_node_id: node_id,
                    context: ctx.clone(),
                });

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
        }

        // Wait until we have enough verified shares from the network or the overall
        // deadline fires.
        let mut successful_responses = 0usize;
        if min_needed_from_network > 0 {
            match tokio::time::timeout(PRE_COLLECTION_TIMEOUT, async {
                while let Some(res) = set.join_next().await {
                    match res {
                        Ok(Ok(Some(response))) => {
                            if let Some(share) = Self::verify_peer_response(
                                &dealer,
                                response,
                                &rdr_pk,
                                &pub_poly,
                                &enc_cmt,
                                ctx.derivation.as_deref(),
                                &mut seen_node_ids,
                            )? {
                                verified_shares.push(share);
                                successful_responses += 1;
                                if successful_responses >= min_needed_from_network {
                                    break;
                                }
                            }
                        }
                        Ok(Ok(None)) => {}
                        Ok(Err(e)) => {
                            tracing::warn!(
                                request_id = %request_id,
                                error = %e,
                                "PRE peer request failed"
                            );
                        }
                        Err(e) => {
                            tracing::error!(error = ?e, "Peer reencrypt task panicked");
                        }
                    }
                }
                Ok::<(), PreError>(())
            })
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    tracing::warn!(
                        request_id = %request_id,
                        "PRE collection timed out; proceeding with partial responses"
                    );
                }
            }
        }

        // Cancel any stragglers once we have enough verified shares or stop waiting.
        drop(set);

        // 6. Collect any responses that were already stored before cancellation and
        // verify the ones we have not counted yet.
        let collected_responses = self
            .app_state
            .pre_response_state
            .take_responses(&request_id)
            .await
            .ok_or_else(|| {
                PreError::Timeout(format!("No responses found for request {}", &request_id))
            })?;

        for response in collected_responses {
            if let Some(share) = Self::verify_peer_response(
                &dealer,
                response,
                &rdr_pk,
                &pub_poly,
                &enc_cmt,
                ctx.derivation.as_deref(),
                &mut seen_node_ids,
            )? {
                verified_shares.push(share);
            }
        }

        // 7. Check if we have enough verified shares
        if verified_shares.len() < ring.threshold {
            if is_ring_reshare_in_progress(&ring.ring_pk_bytes, &self.app_state.dkg_session_state)
                .await
            {
                tracing::info!(
                    request_id = %request_id,
                    "PRE Coordinator: insufficient shares due to ongoing reshare"
                );
                return Err(PreError::ReshareInProgress);
            }
            return Err(PreError::InsufficientShares {
                got: verified_shares.len(),
                need: ring.threshold,
            });
        }

        // 8. Recover the reencrypted commitment
        let xnc_cmt_opt = dealer
            .recover(&verified_shares, ring.threshold, ring.total_participants)
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
}
