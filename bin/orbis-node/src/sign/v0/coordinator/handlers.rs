use super::SignCoordinator;
use crate::constants::{
    JWT_CLOCK_SKEW_LEEWAY_SECS, MAX_JWT_BYTES, MAX_SIGN_MESSAGE_BYTES, MAX_TOKEN_LIFETIME_SECS,
};
use crate::helpers::helpers::read_ring_for_route;
use crate::ring_state::RingShareBundle;
use crate::sign::v0::error::{Result, SignError};
use crate::sign::v0::helpers::{
    check_policy_access, decode_ring_pk_bytes, deserialize_commitments,
    fetch_bulletin_payloads_for_version, load_dist_key_share, refresh_health_check_context_key,
    ring_reshare_update_context_key, validate_refresh_health_check_statement,
    validate_ring_reshare_update_statement, validate_sign_claims,
    verify_message_and_get_info_for_version,
};
use crate::sign::v0::messages::{NonceRequest, SignContext, SignMessage, SignRequest};
use authn::{resolve_jwt_did, BearerToken, SignClaims};
use bulletin::r#trait::{BulletinKind, DocumentPayload};
use crypto::r#trait::{
    CryptoDeserialize, CryptoSerialize, DistKeyShare, Dkg, PubShare, ThresholdSigner,
};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr, SigShareInner, SignaturePoint};
use network::PeerId;
use std::time::{SystemTime, UNIX_EPOCH};
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
                self.handle_nonce_request(req, sender_peer_id).await
            }
            SignMessage::SignRequest(req) => {
                tracing::info!(
                    request_id = %req.request_id,
                    from_node_id = req.from_node_id,
                    "Sign Coordinator: Received SignRequest"
                );
                self.handle_sign_request(req, sender_peer_id).await
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
    async fn handle_nonce_request(
        &self,
        req: NonceRequest,
        sender_peer_id: &PeerId,
    ) -> Result<Option<SignMessage>> {
        let NonceRequest {
            request_id,
            ring_pk: ring_pk_bytes,
            context,
            ..
        } = req;
        // Auth check first — fail fast before burning a nonce.
        let mut refresh_candidate_bundle: Option<RingShareBundle> = None;
        let authoritative_ring_pk_hex = match &context {
            SignContext::Policy(ctx) => {
                let (token_string, derivation_id, valid_window) =
                    (&ctx.token_string, &ctx.derivation_id, &ctx.valid_window);
                let current_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| SignError::Generic(format!("Failed to get timestamp: {}", e)))?
                    .as_secs();
                let token: BearerToken<SignClaims> = resolve_jwt_did(
                    token_string,
                    current_time,
                    MAX_TOKEN_LIFETIME_SECS,
                    MAX_JWT_BYTES,
                    JWT_CLOCK_SKEW_LEEWAY_SECS,
                )
                .map_err(|e| SignError::Unauthorized(format!("JWT validation failed: {}", e)))?;
                validate_sign_claims(&token, derivation_id, None)?;
                let (key_derivation, ring_payload) = fetch_bulletin_payloads_for_version(
                    &*self.app_state.bulletin,
                    &self.app_state.local_storage,
                    derivation_id,
                    true,
                    self.routes.version,
                )
                .await?;
                check_policy_access(
                    &*self.app_state.authz,
                    &key_derivation,
                    derivation_id,
                    &token.issuer_id,
                    valid_window.clone(),
                )
                .await?;
                Some(ring_payload.ring_pk)
            }
            // The ready marker proves this signing round belongs to an already accepted
            // reshare session, which is allowed to finish across an activation boundary.
            SignContext::RingReshareUpdate(ctx) => Some(
                validate_ring_reshare_update_statement(
                    &*self.app_state.bulletin,
                    &self.app_state.dkg_session_state,
                    &ctx.statement,
                    None,
                    false,
                )
                .await?,
            ),
            SignContext::RefreshHealthCheck(ctx) => {
                let (ring_pk_hex, bundle) = validate_refresh_health_check_statement(
                    &self.app_state.dkg_session_state,
                    &ctx.statement,
                    None,
                )
                .await?;
                refresh_candidate_bundle = Some(bundle);
                Some(ring_pk_hex)
            }
            SignContext::Bulletin { object_id } => {
                let document_post = self
                    .app_state
                    .bulletin
                    .read(object_id.clone(), BulletinKind::Document)
                    .await
                    .map_err(|error| {
                        SignError::VerificationFailed(format!(
                            "Failed to read bulletin signing object '{}': {}",
                            object_id, error
                        ))
                    })?;
                let document_payload: DocumentPayload =
                    serde_json::from_slice(&document_post.payload).map_err(|error| {
                        SignError::Deserialization(format!(
                            "Failed to parse bulletin signing document '{}': {}",
                            object_id, error
                        ))
                    })?;
                let ring_payload = read_ring_for_route(
                    &*self.app_state.bulletin,
                    &document_payload.ring_id,
                    self.routes.version,
                )
                .await
                .map_err(SignError::ProtocolError)?;
                Some(ring_payload.ring_pk)
            }
        };

        // Auth passed — load share and generate nonce.
        let client_ring_pk = decode_ring_pk_bytes(&ring_pk_bytes)?;
        let ring_pk = if let Some(authoritative_ring_pk_hex) = authoritative_ring_pk_hex {
            let authoritative_ring_pk_bytes =
                hex::decode(&authoritative_ring_pk_hex).map_err(|e| {
                    SignError::Deserialization(format!(
                        "Failed to decode authoritative ring_pk: {}",
                        e
                    ))
                })?;
            let authoritative_ring_pk = decode_ring_pk_bytes(&authoritative_ring_pk_bytes)?;
            if client_ring_pk != authoritative_ring_pk {
                return Err(SignError::Unauthorized(
                    "Nonce request ring_pk does not match authorized context".to_string(),
                ));
            }
            authoritative_ring_pk
        } else {
            client_ring_pk
        };
        let dist_key_share = if let Some(bundle) = refresh_candidate_bundle {
            let pri_share = bundle.pri_share().map_err(|e| {
                SignError::Deserialization(format!(
                    "Failed to deserialize staged refresh share: {}",
                    e
                ))
            })?;
            DistKeyShare { pri_share }
        } else {
            load_dist_key_share(&self.app_state.local_storage, &ring_pk)?
        };
        let node_id = dist_key_share.pri_share.i;

        let signer = S::new();
        let (commitment, signing_state) = signer
            .generate_nonces(&dist_key_share)
            .map_err(|e| SignError::Crypto(format!("Nonce generation failed: {}", e)))?;

        let commitment_bytes = CryptoSerialize::to_bytes(&commitment).map_err(|e| {
            SignError::Serialization(format!("Failed to serialize nonce commitment: {}", e))
        })?;
        let state_bytes = CryptoSerialize::to_bytes(&signing_state).map_err(|e| {
            SignError::Serialization(format!("Failed to serialize signing state: {}", e))
        })?;

        // Bind the nonce to the context that authorized it so Round 2 cannot
        // swap to a different derivation using this nonce.
        let context_key = match &context {
            SignContext::Bulletin { object_id } => format!("bulletin:{object_id}"),
            SignContext::Policy(ctx) => ctx.derivation_id.clone(),
            SignContext::RingReshareUpdate(ctx) => {
                ring_reshare_update_context_key(&*self.app_state.bulletin, &ctx.statement)?
            }
            SignContext::RefreshHealthCheck(ctx) => {
                refresh_health_check_context_key(&ctx.statement)?
            }
        };

        if !self
            .app_state
            .sign_response_state
            .store_nonce_for_version(
                self.routes.version,
                request_id.clone(),
                state_bytes,
                context_key,
                sender_peer_id.as_bytes().to_vec(),
            )
            .await
        {
            return Err(SignError::NonceState(
                "Failed to store nonce state (limit exceeded or duplicate)".to_string(),
            ));
        }

        Ok(Some(SignMessage::NonceResponse {
            request_id,
            from_node_id: node_id,
            nonce_commitment: commitment_bytes,
        }))
    }

    /// Handle a sign request (responder side)
    async fn handle_sign_request(
        &self,
        req: SignRequest,
        sender_peer_id: &PeerId,
    ) -> Result<Option<SignMessage>> {
        let SignRequest {
            request_id,
            from_node_id,
            message,
            all_commitments: all_commitments_bytes,
            context,
        } = req;
        // Note: We do NOT validate from_node_id here because the sign request initiator
        // may not be in the ring (external requesters use node_id=0).

        // Consume responder-side FROST state before any fallible Round 2 work.
        // Every request from the coordinator that created the nonce therefore frees
        // its slot even when authorization, deserialization, or signing later fails.
        let consumed_nonce = if S::INTERACTIVE {
            let nonce_key = format!("nonce-{}", request_id);
            Some(
                self.app_state
                    .sign_response_state
                    .consume_nonce_for_sign_request_for_version(
                        self.routes.version,
                        &nonce_key,
                        sender_peer_id.as_bytes(),
                    )
                    .await
                    .ok_or_else(|| {
                        SignError::NonceState(format!(
                            "No nonce state found for request_id {} or coordinator mismatch",
                            request_id
                        ))
                    })?,
            )
        } else {
            None
        };

        if message.len() > MAX_SIGN_MESSAGE_BYTES {
            return Err(SignError::InvalidInput(format!(
                "Message too large: {} bytes exceeds maximum {}",
                message.len(),
                MAX_SIGN_MESSAGE_BYTES
            )));
        }

        // Resolve ring info and auth based on pathway
        let (ring_pk_hex, derivation, metadata) = match context {
            SignContext::Bulletin { ref object_id } => {
                // Message is a BulletinPost; on-chain existence is the authorization.
                // Signs from root key: no derivation, no metadata.
                let (ring_pk_hex, _) = verify_message_and_get_info_for_version::<D>(
                    &message,
                    &self.app_state.local_storage,
                    &self.app_state.bulletin,
                    object_id,
                    !S::INTERACTIVE,
                    self.routes.version,
                )
                .await?;
                (ring_pk_hex, None, None)
            }
            SignContext::Policy(ref ctx) => {
                let (token_string, derivation_id, valid_window) =
                    (&ctx.token_string, &ctx.derivation_id, &ctx.valid_window);
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
                    JWT_CLOCK_SKEW_LEEWAY_SECS,
                )
                .map_err(|e| SignError::Unauthorized(format!("JWT validation failed: {}", e)))?;

                validate_sign_claims(&token, derivation_id, Some(&message))?;

                // Always fetch bulletin data — needed for ring_pk, pub_poly, derivation, metadata
                let (key_derivation, ring_payload) = fetch_bulletin_payloads_for_version(
                    &*self.app_state.bulletin,
                    &self.app_state.local_storage,
                    derivation_id,
                    !S::INTERACTIVE,
                    self.routes.version,
                )
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
            SignContext::RingReshareUpdate(ref ctx) => {
                let ring_pk_hex = validate_ring_reshare_update_statement(
                    &*self.app_state.bulletin,
                    &self.app_state.dkg_session_state,
                    &ctx.statement,
                    Some(&message),
                    false,
                )
                .await?;
                (ring_pk_hex, None, None)
            }
            SignContext::RefreshHealthCheck(ref ctx) => {
                let (ring_pk_hex, _) = validate_refresh_health_check_statement(
                    &self.app_state.dkg_session_state,
                    &ctx.statement,
                    Some(&message),
                )
                .await?;
                (ring_pk_hex, None, None)
            }
        };

        // Deserialize ring public key and load the share + public polynomial from one
        // RingShareBundle snapshot. This mirrors the initiator-side protection and
        // avoids a PSS Phase 4 write landing between separate polynomial/share reads.
        let ring_pk_bytes = hex::decode(&ring_pk_hex).map_err(|e| {
            SignError::Deserialization(format!("Failed to decode ring_pk hex: {}", e))
        })?;
        let ring_pk = decode_ring_pk_bytes(&ring_pk_bytes)?;
        let bundle = match &context {
            SignContext::RefreshHealthCheck(ctx) => {
                let (_, bundle) = validate_refresh_health_check_statement(
                    &self.app_state.dkg_session_state,
                    &ctx.statement,
                    Some(&message),
                )
                .await?;
                bundle
            }
            _ => RingShareBundle::load(&self.app_state.local_storage, &ring_pk)
                .map_err(|e| SignError::Storage(format!("Failed to load share bundle: {}", e)))?,
        };
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
            let expected_context_key = match &context {
                SignContext::Bulletin { object_id } => format!("bulletin:{object_id}"),
                SignContext::Policy(ctx) => ctx.derivation_id.clone(),
                SignContext::RingReshareUpdate(ctx) => {
                    ring_reshare_update_context_key(&*self.app_state.bulletin, &ctx.statement)?
                }
                SignContext::RefreshHealthCheck(ctx) => {
                    refresh_health_check_context_key(&ctx.statement)?
                }
            };
            let consumed_nonce = consumed_nonce
                .ok_or_else(|| SignError::NonceState("Missing nonce state".into()))?;
            let state_bytes = consumed_nonce
                .into_bytes_for_context(&request_id, &expected_context_key)
                .ok_or_else(|| {
                    SignError::NonceState(format!(
                        "Nonce context key mismatch for request_id {}",
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
}
