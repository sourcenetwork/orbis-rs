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
    MAX_JWT_BYTES, MAX_SIGN_MESSAGE_BYTES, MAX_TOKEN_LIFETIME_SECS, PEER_RESPONSE_TIMEOUT,
    SIGN_COLLECTION_TIMEOUT,
};
use crate::helpers::helpers::{
    determine_session_node_id, is_ring_reshare_in_progress, is_self_peer_id,
    load_ring_pub_poly_and_bundle, RingConfig,
};
use crate::ring_state::RingShareBundle;
use crate::sign::error::{Result, SignError};
use crate::sign::helpers::{
    check_policy_access, decode_ring_pk_bytes, deserialize_commitments, fetch_bulletin_payloads,
    fetch_key_derivation, load_dist_key_share, serialize_commitments, store_response,
    validate_sign_claims, verify_message_and_get_info,
};
use crate::sign::messages::{NonceRequest, SignContext, SignMessage, SignRequest};
use authn::{resolve_jwt_did, BearerToken, SignClaims};
use crypto::r#trait::{
    CryptoDeserialize, CryptoSerialize, DistKeyShare, Dkg, PubPoly as PubPolyTrait, PubShare,
    ThresholdSigner,
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
    pub app_state: Arc<AppState<D>>,
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
            SignMessage::NonceRequest(req) => {
                tracing::info!(
                    request_id = %req.request_id,
                    sender_peer = %hex::encode(sender_peer_id.as_bytes()),
                    "Sign Coordinator: Received NonceRequest"
                );
                self.handle_nonce_request(req).await
            }
            SignMessage::SignRequest(req) => {
                tracing::info!(
                    request_id = %req.request_id,
                    from_node_id = req.from_node_id,
                    "Sign Coordinator: Received SignRequest"
                );
                self.handle_sign_request(req).await
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
    /// Auth is checked here — before generating (and burning) a nonce — so that
    /// an untrusted relayer cannot waste node resources by sending unauthenticated
    /// requests. Only if auth passes does the nonce get generated and stored.
    async fn handle_nonce_request(&self, req: NonceRequest) -> Result<Option<SignMessage>> {
        let NonceRequest {
            request_id,
            ring_pk: ring_pk_bytes,
            context,
            ..
        } = req;
        // Auth check first — fail fast before burning a nonce.
        if let SignContext::Policy(ref ctx) = context {
            let (token_string, namespace, derivation_id, valid_window) = (
                &ctx.token_string,
                &ctx.namespace,
                &ctx.derivation_id,
                &ctx.valid_window,
            );
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| SignError::Generic(format!("Failed to get timestamp: {}", e)))?
                .as_secs();
            let token: BearerToken<SignClaims> = resolve_jwt_did(
                token_string,
                current_time,
                MAX_TOKEN_LIFETIME_SECS,
                MAX_JWT_BYTES,
            )
            .map_err(|e| SignError::Unauthorized(format!("JWT validation failed: {}", e)))?;
            validate_sign_claims(&token, namespace, derivation_id, None)?;
            let key_derivation =
                fetch_key_derivation(&*self.app_state.bulletin, namespace, derivation_id).await?;
            check_policy_access(
                &*self.app_state.authz,
                &key_derivation,
                derivation_id,
                &token.issuer_id,
                valid_window.clone(),
            )
            .await?;
        }

        // Auth passed — load share and generate nonce.
        let ring_pk = decode_ring_pk_bytes(&ring_pk_bytes)?;
        let dist_key_share = load_dist_key_share(&self.app_state.local_storage, &ring_pk)?;
        let node_id = dist_key_share.pri_share.i;

        let signer = S::new();
        let (commitment, signing_state) = signer
            .generate_nonces(&dist_key_share)
            .map_err(|e| SignError::Crypto(format!("Nonce generation failed: {}", e)))?;

        let state_bytes = CryptoSerialize::to_bytes(&signing_state).map_err(|e| {
            SignError::Serialization(format!("Failed to serialize signing state: {}", e))
        })?;

        // Bind the nonce to the context that authorized it so Round 2 cannot
        // swap to a different derivation using this nonce.
        let context_key = match &context {
            SignContext::Bulletin => "bulletin".to_string(),
            SignContext::Policy(ctx) => ctx.derivation_id.clone(),
        };

        if !self
            .app_state
            .sign_response_state
            .store_nonce(request_id.clone(), state_bytes, context_key)
            .await
        {
            return Err(SignError::NonceState(
                "Failed to store nonce state (limit exceeded or duplicate)".to_string(),
            ));
        }

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
    async fn handle_sign_request(&self, req: SignRequest) -> Result<Option<SignMessage>> {
        let SignRequest {
            request_id,
            from_node_id,
            message,
            all_commitments: all_commitments_bytes,
            context,
        } = req;
        // Note: We do NOT validate from_node_id here because the sign request initiator
        // may not be in the ring (external requesters use node_id=0).

        if message.len() > MAX_SIGN_MESSAGE_BYTES {
            return Err(SignError::InvalidInput(format!(
                "Message too large: {} bytes exceeds maximum {}",
                message.len(),
                MAX_SIGN_MESSAGE_BYTES
            )));
        }

        // Resolve ring info and auth based on pathway
        let (ring_pk_hex, derivation, metadata) = match context {
            SignContext::Bulletin => {
                // Message is a BulletinPost; on-chain existence is the authorization.
                // Signs from root key: no derivation, no metadata.
                let (ring_pk_hex, _) = verify_message_and_get_info::<D>(
                    &message,
                    &self.app_state.local_storage,
                    &self.app_state.bulletin,
                )
                .await?;
                (ring_pk_hex, None, None)
            }
            SignContext::Policy(ref ctx) => {
                let (token_string, namespace, derivation_id, valid_window) = (
                    &ctx.token_string,
                    &ctx.namespace,
                    &ctx.derivation_id,
                    &ctx.valid_window,
                );
                // Always re-validate JWT (pure crypto, no IO)
                let current_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| SignError::Generic(format!("Failed to get timestamp: {}", e)))?
                    .as_secs();
                let token: BearerToken<SignClaims> = resolve_jwt_did(
                    token_string,
                    current_time,
                    MAX_TOKEN_LIFETIME_SECS,
                    MAX_JWT_BYTES,
                )
                .map_err(|e| SignError::Unauthorized(format!("JWT validation failed: {}", e)))?;

                validate_sign_claims(&token, namespace, derivation_id, Some(&message))?;

                // Always fetch bulletin data — needed for ring_pk, pub_poly, derivation, metadata
                let (key_derivation, ring_payload) =
                    fetch_bulletin_payloads(&*self.app_state.bulletin, namespace, derivation_id)
                        .await?;

                // For interactive (FROST), authz was already checked in handle_nonce_request
                // (Round 1) before the nonce was generated — can decide to skip the IO here (I choose not to but can if speed is needed).
                // For non-interactive (BLS), this is the first and only round, so check now.
                check_policy_access(
                    &*self.app_state.authz,
                    &key_derivation,
                    derivation_id,
                    &token.issuer_id,
                    valid_window.clone(),
                )
                .await?;

                // Derivation and metadata come from the bulletin, not the client
                let derivation = Some(key_derivation.derivation.into_bytes());
                let metadata = Some(S::encode_metadata(
                    &key_derivation.policy_id,
                    &key_derivation.resource,
                    &key_derivation.permission,
                ));

                (ring_payload.ring_pk, derivation, metadata)
            }
        };

        // Deserialize ring public key and load the share + public polynomial from one
        // RingShareBundle snapshot. This mirrors the initiator-side protection and
        // avoids a PSS Phase 4 write landing between separate polynomial/share reads.
        let ring_pk_bytes = hex::decode(&ring_pk_hex).map_err(|e| {
            SignError::Deserialization(format!("Failed to decode ring_pk hex: {}", e))
        })?;
        let ring_pk = decode_ring_pk_bytes(&ring_pk_bytes)?;
        let bundle = RingShareBundle::load(&self.app_state.local_storage, &ring_pk)
            .map_err(|e| SignError::Storage(format!("Failed to load share bundle: {}", e)))?;
        let pub_poly_bytes = hex::decode(&bundle.public_polynomial).map_err(|e| {
            SignError::Deserialization(format!("Failed to decode public polynomial hex: {}", e))
        })?;
        let pub_poly = <D::PubPoly>::from_bytes(&pub_poly_bytes).map_err(|e| {
            SignError::Deserialization(format!("Failed to deserialize public polynomial: {}", e))
        })?;
        let pri_share = bundle.pri_share().map_err(|e| {
            SignError::Deserialization(format!("Failed to deserialize final share: {}", e))
        })?;
        let dist_key_share = DistKeyShare { pri_share };
        let node_id = dist_key_share.pri_share.i;

        // Deserialize all_commitments and retrieve signing state if interactive
        let all_commitments = deserialize_commitments::<S>(&all_commitments_bytes)?;

        let signing_state = if S::INTERACTIVE {
            let nonce_key = format!("nonce-{}", request_id);
            let expected_context_key = match &context {
                SignContext::Bulletin => "bulletin".to_string(),
                SignContext::Policy(ctx) => ctx.derivation_id.clone(),
            };
            let state_bytes = self
                .app_state
                .sign_response_state
                .take_nonce(&nonce_key, &expected_context_key)
                .await
                .ok_or_else(|| {
                    SignError::NonceState(format!(
                        "No nonce state found for request_id {} (or context key mismatch)",
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

    /// Send a Sign request to a peer and wait for the response
    ///
    /// This method sends a request and waits for the response on the same connection,
    /// storing the response for later collection. Returns the response when one
    /// matching the request round was received and stored; peer errors and
    /// unexpected message types are logged and returned as `Ok(None)`.
    pub async fn send_request_and_receive_response(
        &self,
        peer_id_str: &str,
        message: SignMessage,
        request_id: &str,
    ) -> Result<Option<SignMessage>> {
        let expects_nonce_response = match &message {
            SignMessage::NonceRequest(_) => true,
            SignMessage::SignRequest(_) => false,
            _ => {
                return Err(SignError::ProtocolError(
                    "send_request_and_receive_response requires a NonceRequest or SignRequest"
                        .to_string(),
                ));
            }
        };

        let stream = self
            .app_state
            .peer_connection_pool
            .open_stream(&self.app_state.network, peer_id_str, SIGN)
            .await
            .map_err(|e| {
                SignError::NetworkConnection(format!(
                    "Failed to open stream to peer {}: {}",
                    peer_id_str, e
                ))
            })?;

        let message_data = serde_json::to_vec(&message)
            .map_err(|e| SignError::Serialization(format!("Failed to serialize message: {}", e)))?;

        stream
            .send(NetworkMessage::new(message_data, SIGN))
            .await
            .map_err(|e| {
                SignError::NetworkCommunication(format!(
                    "Failed to send message to peer {}: {}",
                    peer_id_str, e
                ))
            })?;

        // Wait for response on the same stream with timeout
        let response_msg = tokio::time::timeout(PEER_RESPONSE_TIMEOUT, stream.recv())
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

        if response.request_id() != request_id {
            return Err(SignError::ProtocolError(format!(
                "Peer {} responded with mismatched request_id: expected {}, got {}",
                peer_id_str,
                request_id,
                response.request_id()
            )));
        }

        let authenticated_peer_id = stream.peer_id().clone();
        match response {
            response @ SignMessage::NonceResponse { .. } if expects_nonce_response => {
                store_response(
                    response.clone(),
                    &authenticated_peer_id,
                    &self.app_state.sign_response_state,
                )
                .await;
                Ok(Some(response))
            }
            response @ SignMessage::SignResponse { .. } if !expects_nonce_response => {
                store_response(
                    response.clone(),
                    &authenticated_peer_id,
                    &self.app_state.sign_response_state,
                )
                .await;
                Ok(Some(response))
            }
            SignMessage::Error { error, .. } => {
                tracing::warn!(
                    peer = %peer_id_str,
                    error = %error,
                    "Sign Coordinator: peer returned an error, skipping response"
                );
                Ok(None)
            }
            _ => {
                tracing::warn!(
                    peer = %peer_id_str,
                    expected = if expects_nonce_response {
                        "NonceResponse"
                    } else {
                        "SignResponse"
                    },
                    "Sign Coordinator: unexpected response type from peer, skipping"
                );
                Ok(None)
            }
        }
    }

    fn verify_peer_signature_response(
        signer: &S,
        response: SignMessage,
        message: &[u8],
        pub_poly: &D::PubPoly,
        signing_commitments: &[(u32, S::NonceCommitment)],
        derivation: Option<&[u8]>,
        metadata: Option<&[u8]>,
        seen_node_ids: &mut HashSet<u32>,
    ) -> Result<Option<PubShare<SigShareInner>>> {
        let SignMessage::SignResponse {
            from_node_id,
            sig_share: sig_share_bytes,
            ..
        } = response
        else {
            return Ok(None);
        };

        if seen_node_ids.contains(&from_node_id) {
            return Ok(None);
        }

        let sig_share_v = match SigShareInner::from_bytes(&sig_share_bytes[..]) {
            Ok(sig_share_v) => sig_share_v,
            Err(e) => {
                tracing::error!(
                    from_node_id = from_node_id,
                    error = %e,
                    "Sign Coordinator: Failed to deserialize sig_share"
                );
                seen_node_ids.insert(from_node_id);
                return Ok(None);
            }
        };

        let sig_share = PubShare {
            i: from_node_id,
            v: sig_share_v,
        };

        match signer.verify_share(
            message,
            pub_poly,
            &sig_share,
            signing_commitments,
            derivation,
            metadata,
        ) {
            Ok(_) => {
                tracing::debug!(
                    from_node_id = from_node_id,
                    "Sign Coordinator: Verified share"
                );
                seen_node_ids.insert(sig_share.i);
                Ok(Some(sig_share))
            }
            Err(e) => {
                tracing::error!(
                    from_node_id = from_node_id,
                    error = %e,
                    "Sign Coordinator: Failed to verify share"
                );
                Ok(None)
            }
        }
    }

    fn parse_peer_nonce_response(
        response: SignMessage,
        seen_node_ids: &mut HashSet<u32>,
    ) -> Result<Option<(u32, S::NonceCommitment)>> {
        let SignMessage::NonceResponse {
            from_node_id,
            nonce_commitment,
            ..
        } = response
        else {
            return Ok(None);
        };

        if seen_node_ids.contains(&from_node_id) {
            return Ok(None);
        }

        let commitment = match <S::NonceCommitment>::from_bytes(&nonce_commitment) {
            Ok(commitment) => commitment,
            Err(e) => {
                tracing::error!(
                    from_node_id = from_node_id,
                    error = %e,
                    "Sign Coordinator: Failed to deserialize nonce commitment"
                );
                seen_node_ids.insert(from_node_id);
                return Ok(None);
            }
        };

        seen_node_ids.insert(from_node_id);
        Ok(Some((from_node_id, commitment)))
    }

    /// Initiate signing (initiator side)
    ///
    /// Sends sign requests to all ring nodes, collects responses,
    /// verifies them, and recovers the full signature.
    ///
    /// For interactive schemes (FROST), performs nonce collection round first.
    /// Ring configuration from the bulletin is provided via `ring`.
    pub async fn initiate_signing(
        &self,
        request_id: String,
        ring: RingConfig,
        message: Vec<u8>,
        context: SignContext,
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
            interactive = S::INTERACTIVE,
            "Sign Coordinator: Initiating signing"
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
                ring,
                message,
                node_id,
                self_in_list,
                actual_peer_count,
                context,
            )
            .await;

        // Always cleanup response state regardless of success or failure.
        // Pool connections are permanent — no per-request eviction needed.
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
        ring: RingConfig,
        message: Vec<u8>,
        node_id: u32,
        self_in_list: bool,
        actual_peer_count: usize,
        context: SignContext,
    ) -> Result<Vec<u8>> {
        // 1. Load the public polynomial and (when self_in_list) the local dist_key_share
        //    from a SINGLE atomic read of RingShareBundle — same TOCTOU fix as PRE.
        //
        //    Without this there are two races:
        //    • BLS: service reads polynomial (P_old), PSS fires, signing round reads
        //      share (S_new).  self-share verified against P_old fails → dropped →
        //      InsufficientShares when we were one share short of threshold.
        //    • FROST: collect_nonces reads share (S_old) to generate nonce, PSS fires,
        //      signing round reads share (S_new).  Nonce bound to S_old, signing with
        //      S_new → wrong sig share → verify_share rejects it → same InsufficientShares.
        //
        //    Loading from the same bundle snapshot eliminates both races: pub_poly,
        //    nonce generation, and signing all use the same PSS generation.
        let (pub_poly, local_dist_key_share) = {
            let (poly, bundle) = load_ring_pub_poly_and_bundle::<D>(
                &self.app_state.local_storage,
                &ring,
                self_in_list,
            )
            .map_err(SignError::Deserialization)?;
            let dks =
                bundle.and_then(|b| b.pri_share().map(|ps| DistKeyShare { pri_share: ps }).ok());
            (poly, dks)
        };

        // Validate we have enough potential shares to meet threshold
        let potential_shares = if self_in_list {
            actual_peer_count + 1
        } else {
            actual_peer_count
        };

        if potential_shares < ring.threshold {
            return Err(SignError::InsufficientShares {
                got: potential_shares,
                need: ring.threshold,
            });
        }

        // Resolve derivation and metadata from bulletin for Policy context.
        // Always fetched regardless of self_in_list — needed for local signing, share
        // verification, AND final signature verification. Without this, an external
        // requester (self_in_list=false) would verify shares against the root key
        // instead of the derived key.
        let (derivation, metadata) = match &context {
            SignContext::Bulletin => (None, None),
            SignContext::Policy(ctx) => {
                let key_derivation = &ctx.key_derivation;
                let derivation = Some(key_derivation.derivation.clone().into_bytes());
                let meta = Some(S::encode_metadata(
                    &key_derivation.policy_id,
                    &key_derivation.resource,
                    &key_derivation.permission,
                ));
                (derivation, meta)
            }
        };

        // =====================================================================
        // ROUND 1 (FROST only): Collect nonce commitments
        // =====================================================================
        let (all_commitments, local_signing_state) = if S::INTERACTIVE {
            self.collect_nonces(
                &request_id,
                &ring,
                node_id,
                self_in_list,
                &context,
                local_dist_key_share.as_ref(),
            )
            .await?
        } else {
            (Vec::new(), None)
        };

        let signing_commitments = if S::INTERACTIVE {
            Self::select_signing_commitments(
                &all_commitments,
                ring.threshold,
                self_in_list.then_some(node_id),
            )?
        } else {
            all_commitments
        };
        let selected_signer_ids: HashSet<u32> =
            signing_commitments.iter().map(|(id, _)| *id).collect();
        let should_attempt_local_share = local_dist_key_share.is_some()
            && (!S::INTERACTIVE || selected_signer_ids.contains(&node_id));

        // Serialize commitments for the exact FROST signing set. FROST shares are
        // bound to this participant list, so the recovery step must use the same
        // list that responders signed over.
        let all_commitments_bytes = serialize_commitments::<S>(&signing_commitments)?;

        // =====================================================================
        // ROUND 2: Collect signature shares
        // =====================================================================

        let signer = S::new();
        let mut verified_shares: Vec<PubShare<SigShareInner>> = Vec::new();
        let mut seen_node_ids: HashSet<u32> = HashSet::new();

        // If we are part of the signing set, compute our own share locally before
        // deciding how many verified shares we still need from the network.
        if should_attempt_local_share {
            if let Some(dist_key_share) = local_dist_key_share {
                match signer.sign(
                    &dist_key_share,
                    &message,
                    &pub_poly,
                    local_signing_state.as_ref(),
                    &signing_commitments,
                    derivation.as_deref(),
                    metadata.as_deref(),
                ) {
                    Ok(sig_share) => match signer.verify_share(
                        &message,
                        &pub_poly,
                        &sig_share,
                        &signing_commitments,
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
                    },
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "Sign Coordinator: Local signing failed"
                        );
                    }
                }
            }
        }

        let min_needed_from_network = ring.threshold.saturating_sub(verified_shares.len());

        // 2. Send sign requests to all peers concurrently and receive responses
        let mut set = tokio::task::JoinSet::new();

        if min_needed_from_network > 0 {
            for peer_id_str in &ring.peer_ids {
                if is_self_peer_id(&self.app_state.network, peer_id_str) {
                    tracing::debug!(
                        peer_id = %peer_id_str,
                        "Skipping self when sending sign request"
                    );
                    continue;
                }
                if S::INTERACTIVE {
                    let peer_node_id = determine_session_node_id(peer_id_str, &ring.peer_ids);
                    if !peer_node_id
                        .map(|id| selected_signer_ids.contains(&id))
                        .unwrap_or(false)
                    {
                        tracing::debug!(
                            peer_id = %peer_id_str,
                            "Skipping peer outside selected FROST signing set"
                        );
                        continue;
                    }
                }

                let request = SignMessage::SignRequest(SignRequest {
                    request_id: request_id.clone(),
                    from_node_id: node_id,
                    message: message.clone(),
                    all_commitments: all_commitments_bytes.clone(),
                    context: context.clone(),
                });

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
        }

        // Wait until we have enough verified signature shares from the network or
        // the deadline fires.
        let mut successful_responses = 0usize;
        if min_needed_from_network > 0 {
            match tokio::time::timeout(SIGN_COLLECTION_TIMEOUT, async {
                while let Some(res) = set.join_next().await {
                    match res {
                        Ok(Ok(Some(response))) => {
                            if let Some(share) = Self::verify_peer_signature_response(
                                &signer,
                                response,
                                &message,
                                &pub_poly,
                                &signing_commitments,
                                derivation.as_deref(),
                                metadata.as_deref(),
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
                                "Sign peer request failed"
                            );
                        }
                        Err(e) => {
                            tracing::error!(error = ?e, "Task failed");
                        }
                    }
                }
                Ok::<(), SignError>(())
            })
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    tracing::warn!(
                        request_id = %request_id,
                        "Sign collection timed out; proceeding with partial responses"
                    );
                }
            }
        }

        // Cancel any stragglers once we have enough verified shares or stop waiting.
        drop(set);

        // 3. Collect any responses that were already stored before cancellation and
        // verify the ones we have not counted yet.
        let collected_responses = self
            .app_state
            .sign_response_state
            .take_responses(&request_id)
            .await
            .ok_or_else(|| {
                SignError::Timeout(format!("No responses found for request {}", &request_id))
            })?;

        for response in collected_responses {
            if let Some(share) = Self::verify_peer_signature_response(
                &signer,
                response,
                &message,
                &pub_poly,
                &signing_commitments,
                derivation.as_deref(),
                metadata.as_deref(),
                &mut seen_node_ids,
            )? {
                verified_shares.push(share);
            }
        }

        // 4. Check if we have enough verified shares
        if verified_shares.len() < ring.threshold {
            if is_ring_reshare_in_progress(&ring.ring_pk_bytes, &self.app_state.dkg_session_state)
                .await
            {
                tracing::info!(
                    request_id = %request_id,
                    "Sign Coordinator: insufficient shares due to ongoing reshare"
                );
                return Err(SignError::ReshareInProgress);
            }
            return Err(SignError::InsufficientShares {
                got: verified_shares.len(),
                need: ring.threshold,
            });
        }

        // 5. Recover the full signature
        let signature_opt = signer
            .recover(
                &verified_shares,
                ring.threshold,
                ring.total_participants,
                &message,
                &signing_commitments,
            )
            .map_err(|e| {
                SignError::RecoveryFailed(format!("Failed to recover signature: {}", e))
            })?;

        let signature = signature_opt
            .ok_or_else(|| SignError::RecoveryFailed("Recovery returned None".to_string()))?;

        // 6. Verify the final recovered signature before serializing. This catches
        // aggregation bugs before a silently bad signature reaches the caller.
        let aggregate_pk = pub_poly.eval(0);
        let verify_pk = if let Some(deriv) = derivation.as_deref() {
            S::derive_public_key(&aggregate_pk, deriv, metadata.as_deref()).map_err(|e| {
                SignError::Crypto(format!("Key derivation for verification failed: {}", e))
            })?
        } else {
            aggregate_pk
        };
        signer
            .verify(&verify_pk, &message, &signature)
            .map_err(|e| {
                SignError::RecoveryFailed(format!("Final signature verification failed: {}", e))
            })?;

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
    /// The `context` is forwarded to each peer inside the `NonceRequest` so that
    /// responders can auth-check before generating their nonce.
    async fn collect_nonces(
        &self,
        request_id: &str,
        ring: &RingConfig,
        node_id: u32,
        self_in_list: bool,
        context: &SignContext,
        local_dist_key_share: Option<&DistKeyShare<Fr>>,
    ) -> Result<(Vec<(u32, S::NonceCommitment)>, Option<S::SigningState>)> {
        let nonce_request_id = format!("nonce-{}", request_id);
        let mut all_commitments: Vec<(u32, S::NonceCommitment)> = Vec::new();
        let mut local_signing_state: Option<S::SigningState> = None;
        let mut seen_node_ids: HashSet<u32> = HashSet::new();

        // Generate our own nonces using the pre-loaded dist_key_share (same PSS
        // generation snapshot as pub_poly and the signing-round share).
        if self_in_list {
            if let Some(dist_key_share) = local_dist_key_share {
                let signer = S::new();
                let (commitment, state) = signer.generate_nonces(dist_key_share).map_err(|e| {
                    SignError::Crypto(format!("Local nonce generation failed: {}", e))
                })?;
                seen_node_ids.insert(node_id);
                all_commitments.push((node_id, commitment));
                local_signing_state = Some(state);
            }
        }

        // Build expected peers for nonce round (everyone except self)
        let nonce_expected_peers: Vec<String> = ring
            .peer_ids
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

        let min_needed_from_network = ring.threshold.saturating_sub(all_commitments.len());

        // Send nonce requests to all peers concurrently
        let mut set = tokio::task::JoinSet::new();
        if min_needed_from_network > 0 {
            for peer_id_str in &ring.peer_ids {
                if is_self_peer_id(&self.app_state.network, peer_id_str) {
                    continue;
                }

                let nonce_req = SignMessage::NonceRequest(NonceRequest {
                    request_id: nonce_request_id.clone(),
                    from_node_id: node_id,
                    ring_pk: ring.ring_pk_bytes.clone(),
                    context: context.clone(),
                });

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
        }

        // Wait until we have enough deserializable nonce commitments or the
        // deadline fires. The signer trait does not expose a standalone
        // cryptographic verifier for round-1 commitments, so deserialization and
        // node-id dedupe are the strongest early validation available here.
        let mut successful_responses = 0usize;
        if min_needed_from_network > 0 {
            match tokio::time::timeout(SIGN_COLLECTION_TIMEOUT, async {
                while let Some(res) = set.join_next().await {
                    match res {
                        Ok(Ok(Some(response))) => {
                            if let Some(commitment) =
                                Self::parse_peer_nonce_response(response, &mut seen_node_ids)?
                            {
                                all_commitments.push(commitment);
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
                                "Nonce peer request failed"
                            );
                        }
                        Err(e) => {
                            tracing::error!(error = ?e, "Nonce collection task failed");
                        }
                    }
                }
                Ok::<(), SignError>(())
            })
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    tracing::warn!(
                        request_id = %request_id,
                        "Nonce collection timed out; proceeding with partial responses"
                    );
                }
            }
        }

        // Cancel any stragglers once we have enough commitments or stop waiting.
        drop(set);

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
            if let Some(commitment) = Self::parse_peer_nonce_response(response, &mut seen_node_ids)?
            {
                all_commitments.push(commitment);
            }
        }

        // Sort commitments by participant ID for deterministic ordering
        all_commitments.sort_by_key(|(id, _)| *id);

        Ok((all_commitments, local_signing_state))
    }

    fn select_signing_commitments(
        commitments: &[(u32, S::NonceCommitment)],
        threshold: usize,
        preferred_node_id: Option<u32>,
    ) -> Result<Vec<(u32, S::NonceCommitment)>> {
        if commitments.len() < threshold {
            return Err(SignError::InsufficientShares {
                got: commitments.len(),
                need: threshold,
            });
        }

        let mut selected: Vec<(u32, S::NonceCommitment)> = Vec::with_capacity(threshold);
        if let Some(preferred) = preferred_node_id {
            if let Some((id, commitment)) = commitments.iter().find(|(id, _)| *id == preferred) {
                selected.push((*id, commitment.clone()));
            }
        }

        for (id, commitment) in commitments {
            if selected.len() == threshold {
                break;
            }
            if selected.iter().any(|(selected_id, _)| selected_id == id) {
                continue;
            }
            selected.push((*id, commitment.clone()));
        }

        selected.sort_by_key(|(id, _)| *id);
        Ok(selected)
    }
}
