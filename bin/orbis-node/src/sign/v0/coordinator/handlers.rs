use super::SignCoordinator;
use crate::constants::{
    JWT_CLOCK_SKEW_LEEWAY_SECS, MAX_JWT_BYTES, MAX_SIGN_MESSAGE_BYTES, MAX_TOKEN_LIFETIME_SECS,
};
use crate::helpers::auth::request_actor;
use crate::helpers::protocol_version::read_ring_for_route;
use crate::reporting::v0::types::{
    ring_state_sha256, CommitteeScope, InvalidCryptoResponse, NodeOffline, ReportEnvelope,
    ReportSigningContext, SignResponseStatement, INVALID_CRYPTO_RESPONSE_REPORT_TYPE,
    NODE_OFFLINE_REPORT_TYPE, SIGN_RESPONSE_DOMAIN,
};
use crate::reporting::v0::{
    report_unauthorized_relay, validate_relay_request_binding, validate_signing_report,
    RelayRequestBinding, RelayRequestTimestampBinding,
};
use crate::ring_state::{RingIndexEntry, RingShareBundle};
use crate::sign::v0::error::{Result, SignError};
use crate::sign::v0::helpers::{
    check_policy_access, decode_ring_pk_bytes, deserialize_commitments,
    fetch_bulletin_payloads_for_version, load_dist_key_share, refresh_health_check_context_key,
    ring_reshare_update_context_key, validate_refresh_health_check_statement,
    validate_ring_reshare_update_statement, validate_sign_claims,
    verify_message_and_get_info_for_version,
};
use crate::sign::v0::messages::{
    NonceRequest, PolicyContext, RefreshHealthCheckContext, RingReshareUpdateContext, SignContext,
    SignMessage, SignRequest,
};
use crate::sign::v0::response_state::NonceStoreOutcome;
use authn::{resolve_jwt_did, BearerToken, SignClaims};
use bulletin::r#trait::{BulletinKind, DocumentPayload, RingPayload};
use common::blockchain::sign_node_message_with_hex_key;
use crypto::r#trait::{
    CryptoDeserialize, CryptoSerialize, DistKeyShare, Dkg, PubShare, ThresholdSigner,
};
use crypto::{GroupAffine as G1Affine, ScalarField as Fr, SigShareInner, SignaturePoint};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use network::PeerId;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug)]
struct SignResponseReportBinding {
    ring_id: String,
    ring_pk: String,
    ring_state_sha256: String,
    origin_protocol: &'static str,
    accused_committee_scope: CommitteeScope,
    signing_committee_scope: CommitteeScope,
}

impl SignResponseReportBinding {
    fn from_ring(
        ring_id: String,
        ring: &RingPayload,
        origin_protocol: &'static str,
        accused_committee_scope: CommitteeScope,
        signing_committee_scope: CommitteeScope,
    ) -> Self {
        Self {
            ring_id,
            ring_pk: ring.ring_pk.clone(),
            ring_state_sha256: ring_state_sha256(ring),
            origin_protocol,
            accused_committee_scope,
            signing_committee_scope,
        }
    }
}

/// Ring, key-derivation, and fault-report data resolved by pathway-specific
/// authorization of a SignRequest (one `authorize_*_sign_request` method per
/// `SignContext` variant).
struct SignRequestAuthorization {
    ring_pk_hex: String,
    derivation: Option<Vec<u8>>,
    metadata: Option<Vec<u8>>,
    report_binding: Option<SignResponseReportBinding>,
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
    async fn read_ring_payload_unchecked(&self, ring_id: &str) -> Result<RingPayload> {
        let post = self
            .app_state
            .bulletin
            .read(ring_id.to_string(), BulletinKind::Ring)
            .await
            .map_err(|error| {
                SignError::VerificationFailed(format!(
                    "Failed to read ring bulletin post '{}': {}",
                    ring_id, error
                ))
            })?;
        serde_json::from_slice(&post.payload).map_err(|error| {
            SignError::Deserialization(format!("Failed to parse RingPayload: {}", error))
        })
    }

    async fn read_document_payload(&self, object_id: &str) -> Result<DocumentPayload> {
        let post = self
            .app_state
            .bulletin
            .read(object_id.to_string(), BulletinKind::Document)
            .await
            .map_err(|error| {
                SignError::VerificationFailed(format!(
                    "Failed to read signing object '{}': {}",
                    object_id, error
                ))
            })?;
        serde_json::from_slice(&post.payload).map_err(|error| {
            SignError::Deserialization(format!(
                "Failed to parse signing document '{}': {}",
                object_id, error
            ))
        })
    }

    async fn read_ring_payload_for_ring_pk_hex(
        &self,
        ring_pk_hex: &str,
    ) -> Result<(String, RingPayload)> {
        let ring_pk_bytes = hex::decode(ring_pk_hex).map_err(|error| {
            SignError::Deserialization(format!("Failed to decode ring_pk hex: {}", error))
        })?;
        let ring_pk = decode_ring_pk_bytes(&ring_pk_bytes)?;
        let ring_key = ring_pk.to_string();
        let index_bytes = self
            .app_state
            .local_storage
            .get(LocalStorageKeys::RingIndex)
            .map_err(|error| SignError::Storage(format!("Failed to read RingIndex: {}", error)))?
            .ok_or_else(|| SignError::Storage("RingIndex is not configured".to_string()))?;
        let ring_index: Vec<RingIndexEntry> = serde_json::from_slice(&index_bytes)
            .map_err(|error| SignError::Storage(format!("Failed to parse RingIndex: {}", error)))?;
        let entry = ring_index
            .iter()
            .find(|entry| entry.ring_pk_str == ring_key || entry.ring_pk_str == ring_pk_hex)
            .ok_or_else(|| {
                SignError::Storage(format!(
                    "RingIndex has no entry for ring_pk {}",
                    ring_pk_hex
                ))
            })?;
        let ring = self
            .read_ring_payload_unchecked(&entry.bulletin_post_id)
            .await?;
        Ok((entry.bulletin_post_id.clone(), ring))
    }

    fn report_signing_scope_from_envelope(envelope: &ReportEnvelope) -> Result<CommitteeScope> {
        match envelope.report_type.as_str() {
            NODE_OFFLINE_REPORT_TYPE => {
                let payload = NodeOffline::from_canonical_bytes(&envelope.payload)
                    .map_err(|error| SignError::Unauthorized(error.to_string()))?;
                Ok(payload.signing_committee_scope)
            }
            INVALID_CRYPTO_RESPONSE_REPORT_TYPE => {
                let evidence = InvalidCryptoResponse::from_canonical_bytes(&envelope.payload)
                    .map_err(|error| SignError::Unauthorized(error.to_string()))?;
                Ok(evidence.signing_committee_scope())
            }
            _ => Ok(CommitteeScope::Current),
        }
    }

    fn sign_node_response_statement(&self, statement: &SignResponseStatement) -> Result<Vec<u8>> {
        let signing_key = self
            .app_state
            .local_storage
            .get_encrypted(LocalStorageKeys::NodeSigningKey)
            .map_err(|error| {
                SignError::Storage(format!("Failed to read node signing key: {}", error))
            })?
            .ok_or_else(|| SignError::Storage("Node signing key is not configured".to_string()))?;
        let signing_key_hex = String::from_utf8(signing_key.to_vec()).map_err(|error| {
            SignError::Storage(format!("Stored node signing key is not UTF-8: {}", error))
        })?;
        sign_node_message_with_hex_key(&signing_key_hex, &statement.canonical_bytes())
            .map_err(|error| SignError::Crypto(format!("Failed to sign Sign response: {}", error)))
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
            from_node_id,
            ring_pk: ring_pk_bytes,
            context,
        } = req;
        // Auth check first — fail fast before burning a nonce.
        let mut staged_sign_bundle: Option<RingShareBundle> = None;
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
                // Reject a forwarded JWT this node has already accepted. A responder
                // sees the client token once here in FROST Round 1; Round 2
                // (`handle_sign_request`) is covered by the single-use nonce, not
                // this guard. A duplicate here means a replayed `NonceRequest`.
                self.app_state
                    .jti_guard
                    .check_and_record(&token.jwt_id, token.expiration_time, "sign_nonce_request")
                    .await
                    .map_err(|e| SignError::Unauthorized(e.to_string()))?;
                let (key_derivation, ring_payload) = fetch_bulletin_payloads_for_version(
                    &*self.app_state.bulletin,
                    derivation_id,
                    true,
                    self.routes.version,
                )
                .await?;
                let actor_id =
                    request_actor(&token, ring_payload.trusted_auth_relay_dids.as_deref())
                        .map_err(SignError::Unauthorized)?;
                if let Err(error) = check_policy_access(
                    &*self.app_state.authz,
                    &key_derivation,
                    derivation_id,
                    &actor_id,
                    valid_window.clone(),
                )
                .await
                {
                    // A relayed request that fails our ACP re-check is attributable to the relaying
                    // node, provided it signed a statement vouching that it forwarded this request.
                    if let SignError::Unauthorized(_) = &error {
                        if let Some(statement) = &ctx.relay_statement {
                            let chain_id = self.app_state.bulletin.chain_id();
                            let relay_request_id =
                                request_id.strip_prefix("nonce-").unwrap_or(&request_id);
                            let binding = RelayRequestBinding {
                                ring: ring_payload.clone(),
                                ring_id: key_derivation.ring_id.clone(),
                                protocol_version: self.routes.version,
                                chain_id,
                                request_id: relay_request_id.to_string(),
                                origin_protocol: "sign".to_string(),
                                actor_id: actor_id.clone(),
                                object_id: derivation_id.clone(),
                                user_signed_at: token.issued_time,
                                valid_window: valid_window.clone(),
                                timestamp: RelayRequestTimestampBinding::SignPolicy,
                                from_node_id,
                                document_inline: false,
                            };
                            match validate_relay_request_binding(statement, binding) {
                                Ok(()) => {
                                    report_unauthorized_relay::<D, S>(
                                        self.app_state.clone(),
                                        self.routes,
                                        statement.clone(),
                                        ctx.relay_signature.clone(),
                                        current_time,
                                        None,
                                    )
                                    .await;
                                }
                                Err(error) => {
                                    tracing::warn!(
                                        request_id = %request_id,
                                        %error,
                                        "Skipping unauthorized_request report: relay statement is not bound to failed Sign nonce request"
                                    );
                                }
                            }
                        }
                    }
                    return Err(error);
                }
                Some(ring_payload.ring_pk)
            }
            // The ready marker proves this signing round belongs to an already accepted
            // reshare session, which is allowed to finish across an activation boundary.
            SignContext::RingReshareUpdate(ctx) => {
                let (ring_pk_hex, bundle) = validate_ring_reshare_update_statement(
                    &*self.app_state.bulletin,
                    &self.app_state.dkg_session_state,
                    &ctx.statement,
                    None,
                    false,
                )
                .await?;
                staged_sign_bundle = bundle;
                Some(ring_pk_hex)
            }
            SignContext::RefreshHealthCheck(ctx) => {
                let (ring_pk_hex, bundle) = validate_refresh_health_check_statement(
                    &self.app_state.dkg_session_state,
                    &ctx.statement,
                    None,
                )
                .await?;
                staged_sign_bundle = Some(bundle);
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
            SignContext::Report(ctx) => Some(
                validate_signing_report(
                    &self.app_state,
                    self.routes,
                    ctx,
                    sender_peer_id.clone(),
                    true,
                )
                .await
                .map_err(|error| SignError::Unauthorized(error.to_string()))?,
            ),
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
        let dist_key_share = if let Some(bundle) = staged_sign_bundle {
            let pri_share = bundle.pri_share().map_err(|e| {
                SignError::Deserialization(format!("Failed to deserialize staged share: {}", e))
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
            SignContext::Report(ctx) => format!("report:{}", ctx.envelope.report_id()),
        };

        match self
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
            NonceStoreOutcome::Stored => {}
            NonceStoreOutcome::AlreadyExists => {
                return Err(SignError::NonceState(format!(
                    "Nonce state already exists for request {request_id}"
                )));
            }
            NonceStoreOutcome::LimitReached => {
                return Err(SignError::NonceState(
                    "Nonce state limit exceeded".to_string(),
                ));
            }
        }

        Ok(Some(SignMessage::NonceResponse {
            request_id,
            from_node_id: node_id,
            nonce_commitment: commitment_bytes,
        }))
    }

    /// Handle a sign request (responder side)
    /// Authorize a Bulletin-context sign request.
    ///
    /// Message is a BulletinPost; on-chain existence is the authorization.
    /// Signs from root key: no derivation, no metadata.
    async fn authorize_bulletin_sign_request(
        &self,
        message: &[u8],
        object_id: &str,
    ) -> Result<SignRequestAuthorization> {
        let (ring_pk_hex, _) = verify_message_and_get_info_for_version::<D>(
            message,
            &self.app_state.local_storage,
            &self.app_state.bulletin,
            object_id,
            !S::INTERACTIVE,
            self.routes.version,
        )
        .await?;
        let document_payload = self.read_document_payload(object_id).await?;
        let ring_payload = self
            .read_ring_payload_unchecked(&document_payload.ring_id)
            .await?;
        let report_binding = SignResponseReportBinding::from_ring(
            document_payload.ring_id,
            &ring_payload,
            "sign",
            CommitteeScope::Current,
            CommitteeScope::Current,
        );
        Ok(SignRequestAuthorization {
            ring_pk_hex,
            derivation: None,
            metadata: None,
            report_binding: Some(report_binding),
        })
    }

    /// Authorize a Policy-context sign request: validate the JWT, fetch the key
    /// derivation from the bulletin, and check policy access. Signs from the
    /// derived key; produces no report binding (unreportable by design).
    async fn authorize_policy_sign_request(
        &self,
        request_id: &str,
        from_node_id: u32,
        message: &[u8],
        ctx: &PolicyContext,
    ) -> Result<SignRequestAuthorization> {
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
        validate_sign_claims(&token, derivation_id, Some(message))?;

        // Always fetch bulletin data — needed for ring_pk, pub_poly, derivation, metadata
        let (key_derivation, ring_payload) = fetch_bulletin_payloads_for_version(
            &*self.app_state.bulletin,
            derivation_id,
            !S::INTERACTIVE,
            self.routes.version,
        )
        .await?;
        let actor_id = request_actor(&token, ring_payload.trusted_auth_relay_dids.as_deref())
            .map_err(SignError::Unauthorized)?;

        // For interactive (FROST), authz was already checked in handle_nonce_request
        // (Round 1) before the nonce was generated — can decide to skip the IO here (I choose not to but can if speed is needed).
        // For non-interactive (BLS), this is the first and only round, so check now.
        if let Err(error) = check_policy_access(
            &*self.app_state.authz,
            &key_derivation,
            derivation_id,
            &actor_id,
            valid_window.clone(),
        )
        .await
        {
            // A relayed request that fails our ACP re-check is attributable to the relaying node,
            // provided it signed a statement vouching that it forwarded this exact request.
            if let SignError::Unauthorized(_) = &error {
                if let Some(statement) = &ctx.relay_statement {
                    let chain_id = self.app_state.bulletin.chain_id();
                    let binding = RelayRequestBinding {
                        ring: ring_payload.clone(),
                        ring_id: key_derivation.ring_id.clone(),
                        protocol_version: self.routes.version,
                        chain_id,
                        request_id: request_id.to_string(),
                        origin_protocol: "sign".to_string(),
                        actor_id: actor_id.clone(),
                        object_id: derivation_id.clone(),
                        user_signed_at: token.issued_time,
                        valid_window: valid_window.clone(),
                        timestamp: RelayRequestTimestampBinding::SignPolicy,
                        from_node_id,
                        document_inline: false,
                    };
                    match validate_relay_request_binding(statement, binding) {
                        Ok(()) => {
                            report_unauthorized_relay::<D, S>(
                                self.app_state.clone(),
                                self.routes,
                                statement.clone(),
                                ctx.relay_signature.clone(),
                                current_time,
                                None,
                            )
                            .await;
                        }
                        Err(error) => {
                            tracing::warn!(
                                request_id = %request_id,
                                %error,
                                "Skipping unauthorized_request report: relay statement is not bound to failed Sign request"
                            );
                        }
                    }
                }
            }
            return Err(error);
        }

        // Derivation and metadata come from the bulletin, not the client
        let derivation = Some(key_derivation.derivation.into_bytes());
        let metadata = Some(S::encode_metadata(
            &key_derivation.policy_id,
            &key_derivation.resource,
            &key_derivation.permission,
        ));

        Ok(SignRequestAuthorization {
            ring_pk_hex: ring_payload.ring_pk,
            derivation,
            metadata,
            report_binding: None,
        })
    }

    /// Authorize a reshare bulletin-update sign request: validate the announced
    /// transition statement against the bulletin and local session state.
    async fn authorize_ring_reshare_update_sign_request(
        &self,
        message: &[u8],
        ctx: &RingReshareUpdateContext,
    ) -> Result<SignRequestAuthorization> {
        let (ring_pk_hex, _staged_bundle) = validate_ring_reshare_update_statement(
            &*self.app_state.bulletin,
            &self.app_state.dkg_session_state,
            &ctx.statement,
            Some(message),
            false,
        )
        .await?;
        let ring_payload = self
            .read_ring_payload_unchecked(&ctx.statement.ring_id)
            .await?;
        let report_binding = SignResponseReportBinding::from_ring(
            ctx.statement.ring_id.clone(),
            &ring_payload,
            "pss_reshare",
            CommitteeScope::PendingNew,
            CommitteeScope::PendingNew,
        );
        Ok(SignRequestAuthorization {
            ring_pk_hex,
            derivation: None,
            metadata: None,
            report_binding: Some(report_binding),
        })
    }

    /// Authorize a post-refresh health-check sign request: validate the canonical
    /// statement against this node's staged refreshed bundle.
    async fn authorize_refresh_health_check_sign_request(
        &self,
        message: &[u8],
        ctx: &RefreshHealthCheckContext,
    ) -> Result<SignRequestAuthorization> {
        let (ring_pk_hex, _) = validate_refresh_health_check_statement(
            &self.app_state.dkg_session_state,
            &ctx.statement,
            Some(message),
        )
        .await?;
        let (ring_id, ring_payload) = self.read_ring_payload_for_ring_pk_hex(&ring_pk_hex).await?;
        let report_binding = SignResponseReportBinding::from_ring(
            ring_id,
            &ring_payload,
            "pss_refresh",
            CommitteeScope::Current,
            CommitteeScope::Current,
        );
        Ok(SignRequestAuthorization {
            ring_pk_hex,
            derivation: None,
            metadata: None,
            report_binding: Some(report_binding),
        })
    }

    /// Authorize a fault-report sign request: the message must be the report's
    /// canonical envelope, independently re-validated for this report type.
    async fn authorize_report_sign_request(
        &self,
        message: &[u8],
        ctx: &ReportSigningContext,
        sender_peer_id: &PeerId,
    ) -> Result<SignRequestAuthorization> {
        let canonical = ctx.envelope.canonical_bytes();
        if canonical != message {
            return Err(SignError::Unauthorized(
                "fault report message does not match its canonical envelope".to_string(),
            ));
        }
        let ring_pk_hex = validate_signing_report(
            &self.app_state,
            self.routes,
            ctx,
            sender_peer_id.clone(),
            !S::INTERACTIVE,
        )
        .await
        .map_err(|error| SignError::Unauthorized(error.to_string()))?;
        let signing_scope = Self::report_signing_scope_from_envelope(&ctx.envelope)?;
        let report_binding = SignResponseReportBinding {
            ring_id: ctx.envelope.ring_id.clone(),
            ring_pk: ctx.envelope.ring_pk.clone(),
            ring_state_sha256: ctx.envelope.ring_state_sha256.clone(),
            origin_protocol: "report",
            accused_committee_scope: signing_scope,
            signing_committee_scope: signing_scope,
        };
        Ok(SignRequestAuthorization {
            ring_pk_hex,
            derivation: None,
            metadata: None,
            report_binding: Some(report_binding),
        })
    }

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

        // Resolve ring info and auth based on pathway.
        let SignRequestAuthorization {
            ring_pk_hex,
            derivation,
            metadata,
            report_binding,
        } = match &context {
            SignContext::Bulletin { object_id } => {
                self.authorize_bulletin_sign_request(&message, object_id)
                    .await?
            }
            SignContext::Policy(ctx) => {
                self.authorize_policy_sign_request(&request_id, from_node_id, &message, ctx)
                    .await?
            }
            SignContext::RingReshareUpdate(ctx) => {
                self.authorize_ring_reshare_update_sign_request(&message, ctx)
                    .await?
            }
            SignContext::RefreshHealthCheck(ctx) => {
                self.authorize_refresh_health_check_sign_request(&message, ctx)
                    .await?
            }
            SignContext::Report(ctx) => {
                self.authorize_report_sign_request(&message, ctx, sender_peer_id)
                    .await?
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
            // Reshare's staged bundle isn't written to disk until chain
            // confirmation promotes it (see `reshare/cleanup.rs`), so a
            // co-signer must sign with its own staged material here too —
            // not just in Round 1's nonce request — falling back to disk
            // only once its own readiness marker has been promoted.
            SignContext::RingReshareUpdate(ctx) => {
                let (_, staged_bundle) = validate_ring_reshare_update_statement(
                    &*self.app_state.bulletin,
                    &self.app_state.dkg_session_state,
                    &ctx.statement,
                    Some(&message),
                    false,
                )
                .await?;
                match staged_bundle {
                    Some(bundle) => bundle,
                    None => RingShareBundle::load(&self.app_state.local_storage, &ring_pk)
                        .map_err(|e| {
                            SignError::Storage(format!("Failed to load share bundle: {}", e))
                        })?,
                }
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
                SignContext::Report(ctx) => format!("report:{}", ctx.envelope.report_id()),
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

        let (signed_at, response_signature) = if let Some(binding) = report_binding {
            let signed_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| SignError::Generic(format!("Failed to get timestamp: {}", e)))?
                .as_secs();
            let statement = SignResponseStatement {
                domain: SIGN_RESPONSE_DOMAIN.to_string(),
                chain_id: self.app_state.bulletin.chain_id(),
                ring_id: binding.ring_id,
                ring_pk: binding.ring_pk,
                ring_state_sha256: binding.ring_state_sha256,
                protocol_version: self.routes.version,
                request_id: request_id.clone(),
                signed_at,
                responder_node_key: self.app_state.node_key.clone(),
                origin_protocol: binding.origin_protocol.to_string(),
                accused_committee_scope: binding.accused_committee_scope,
                signing_committee_scope: binding.signing_committee_scope,
                from_node_id: node_id,
                message: message.clone(),
                signing_commitments: all_commitments_bytes.clone(),
                derivation: derivation.clone(),
                metadata: metadata.clone(),
                sig_share: sig_share_bytes.clone(),
                crypto_backend: S::name(),
            };
            let response_signature = self.sign_node_response_statement(&statement)?;
            (signed_at, response_signature)
        } else {
            (0, Vec::new())
        };

        // 9. Create response message
        let response = SignMessage::SignResponse {
            request_id: request_id.clone(),
            from_node_id: node_id,
            sig_share: sig_share_bytes,
            signed_at,
            response_signature,
        };

        tracing::debug!(
            request_id = %request_id,
            to_node_id = from_node_id,
            "Sign Coordinator: Sending SignResponse"
        );

        Ok(Some(response))
    }
}
