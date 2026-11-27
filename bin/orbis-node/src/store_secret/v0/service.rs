use crate::app_state::AppState;
use crate::constants::{JWT_CLOCK_SKEW_LEEWAY_SECS, MAX_JWT_BYTES, MAX_TOKEN_LIFETIME_SECS};
use crate::helpers::node_routes::{peer_ids_from_routes, resolve_node_routes};
use crate::helpers::protocol_version::read_ring_for_route;
use crate::helpers::ring::RingConfig;
use crate::metrics;
use crate::ring_state::RingPolyState;
use crate::sign::v0::coordinator::{SignCoordinator, SignResponse, SigningOptions};
use crate::sign::v0::messages::SignContext;
use crate::store_secret::v0::error::StoreSecretError;
use authn::endpoints::store_secret::StoreSecretClaims;
use authn::{extract_bearer_token, BearerToken};
use bulletin::r#trait::{BulletinKind, BulletinWriteKind, DocumentPayload};
use crypto::r#trait::{Dkg, EncryptionProof};
use proto::v0::store_secret::{
    store_secret_service_server::StoreSecretService, StoreSecretRequest, StoreSecretResponse,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tonic::{Request, Response, Status};

/// Implementation of the StoreSecretService
///
/// This service acts as an authenticated relay for storing pre-encrypted secrets.
/// The node NEVER sees plaintext - users must encrypt locally before calling this service.
#[derive(Debug)]
pub struct StoreSecretServiceImpl<D, S>
where
    D: Dkg + Clone + 'static,
    S: crypto::r#trait::ThresholdSigner,
{
    pub state: Arc<AppState<D>>,
    pub routes: &'static network::ProtocolRoutes,
    _phantom: std::marker::PhantomData<S>,
}

impl<D, S> StoreSecretServiceImpl<D, S>
where
    D: Dkg + Clone + 'static,
    S: crypto::r#trait::ThresholdSigner,
{
    pub fn with_routes(
        state: impl Into<Arc<AppState<D>>>,
        routes: &'static network::ProtocolRoutes,
    ) -> Self {
        Self {
            state: state.into(),
            routes,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[tonic::async_trait]
impl<D, S> StoreSecretService for StoreSecretServiceImpl<D, S>
where
    D: Dkg<ShareValue = crypto::ScalarField, PublicKey = crypto::GroupAffine>
        + Clone
        + Send
        + Sync
        + 'static,
    S: crypto::r#trait::ThresholdSigner<
            ShareValue = crypto::ScalarField,
            PublicKey = crypto::GroupAffine,
            DistKeyShare = crypto::r#trait::DistKeyShare<crypto::ScalarField>,
            PubPoly = D::PubPoly,
            Signature = crypto::SignaturePoint,
            SigShare = crypto::r#trait::PubShare<crypto::SigShareInner>,
        > + Send
        + Sync
        + 'static,
{
    #[tracing::instrument(skip_all, fields(request))]
    async fn store_secret(
        &self,
        request: Request<StoreSecretRequest>,
    ) -> Result<Response<StoreSecretResponse>, Status> {
        let grpc_metrics = metrics::GrpcRequestGuard::new("store_secret", "store_secret");
        let request_metrics = metrics::track_store_secret_request();
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| StoreSecretError::SystemTime(format!("Failed to get timestamp: {}", e)))?
            .as_secs();

        // 1. Authenticate: JWT, WebAuthn, or email evidence (mutually
        // exclusive — see `WebAuthnAssertion`'s/`EmailAssertion`'s proto doc
        // comments). WebAuthn, then email, takes priority and the bearer
        // header, if either is present, is never even read.
        let has_evidence = request.get_ref().webauthn_assertion.is_some()
            || request.get_ref().email_assertion.is_some();
        let token_str = if has_evidence {
            None
        } else {
            Some(
                extract_bearer_token(&request)
                    .map_err(|e| StoreSecretError::Unauthorized(e.to_string()))?
                    .to_string(),
            )
        };

        let mut req = request.into_inner();
        let webauthn_assertion = req
            .webauthn_assertion
            .take()
            .map(super::webauthn_auth::evidence_from_proto);
        let email_assertion = req
            .email_assertion
            .take()
            .map(super::email_auth::evidence_from_proto);

        let encrypted_document_sha256 = Sha256::digest(&req.encrypted_document).to_vec();
        let fields = authn::endpoints::store_secret::StoreSecretFields {
            encrypted_document_sha256,
            enc_cmt: req.enc_cmt.clone(),
            ring_id: req.ring_id.clone(),
            policy_id: req.policy_id.clone(),
            resource: req.resource.clone(),
            permission: req.permission.clone(),
            challenge: req.challenge.clone(),
            response: req.response.clone(),
            with_proof: req.with_proof,
            tier: req.tier.clone(),
            timestamp: req.timestamp,
        };

        // 2. Authorize: resolve the caller's identity and validate its claims
        // (JWT path) or WebAuthn challenge binding (WebAuthn path) match
        // this exact request — see `authn::endpoints::store_secret`.
        let token: BearerToken<StoreSecretClaims> = crate::helpers::auth::resolve_request_auth::<
            authn::endpoints::store_secret::StoreSecretEndpoint,
        >(
            &fields,
            token_str.as_deref(),
            webauthn_assertion.as_ref(),
            self.state.webauthn_rp_id.as_deref(),
            self.state.webauthn_origin.as_deref(),
            email_assertion.as_ref(),
            self.state.email_authenticator.as_deref(),
            self.state.email_dns_cache.as_deref(),
            current_time,
            MAX_TOKEN_LIFETIME_SECS,
            MAX_JWT_BYTES,
            JWT_CLOCK_SKEW_LEEWAY_SECS,
        )
        .await
        .map_err(|e| StoreSecretError::Unauthorized(e.to_string()))?;
        if token.subject_id.is_some() {
            return Err(StoreSecretError::Unauthorized(
                "delegated actors must store documents through their Vera signer".to_string(),
            )
            .into());
        }

        // No `jti` single-use guard here (unlike start_pre / start_sign): storing
        // a secret is idempotent by design — the bulletin dedups by `object_id`,
        // so re-submitting the same document (including a client retry with the
        // same token) is a no-op that returns the same id. A replay carries no
        // authorization-sensitive effect, unlike a re-encryption or a signature.

        tracing::info!(
            ring_id = %req.ring_id,
            issuer = %token.issuer_id,
            "Authenticated StoreSecret request"
        );

        // Get ring public_key from bulletin.
        // Validates that the ring's effective protocol version matches this service (v0).
        // Returns an error with version details if the ring has migrated to a newer version.
        let ring_payload =
            read_ring_for_route(&*self.state.bulletin, &req.ring_id, self.routes.version)
                .await
                .map_err(StoreSecretError::ProtocolError)?;

        let proof = EncryptionProof {
            challenge: req.challenge,
            response: req.response,
        };

        // 3. Validate the encrypted document structure
        let _encrypted_secret = crate::helpers::encrypted_document::validate_encrypted_document(
            &req.encrypted_document,
            &req.enc_cmt,
        )
        .map_err(StoreSecretError::Validation)?;

        // 4. Create DocumentPayload with the pre-encrypted secret
        // DocumentPayload.document is a String (JSON), so convert from bytes (valid UTF-8)
        let encrypted_document_str =
            String::from_utf8(req.encrypted_document.clone()).map_err(|e| {
                StoreSecretError::Validation(format!(
                    "encrypted_document is not valid UTF-8: {}",
                    e
                ))
            })?;

        let (pet_tag, pet_tag_proof) = match req.pet_tag {
            Some(attachment) => {
                let (pet_tag, pet_tag_proof) =
                    crate::helpers::pet_tag::pet_tag_attachment_to_document_fields(
                        attachment.ephemeral_point,
                        attachment.masked_fingerprint,
                        attachment.knowledge_proof_challenge,
                        attachment.knowledge_proof_response,
                    )
                    .map_err(StoreSecretError::Validation)?;
                (Some(pet_tag), Some(pet_tag_proof))
            }
            None => (None, None),
        };

        let document_payload = DocumentPayload {
            ring_id: req.ring_id.clone(),
            document: encrypted_document_str,
            proof: proof.try_into().map_err(|e: crypto::error::CryptoError| {
                StoreSecretError::Serialization(format!("Failed to serialize proof: {}", e))
            })?,
            policy_id: req.policy_id,
            resource: req.resource,
            permission: req.permission,
            tier: req.tier,
            timestamp: req.timestamp,
            pet_tag,
            pet_tag_proof,
        };

        let payload_bytes: Vec<u8> =
            document_payload
                .try_into()
                .map_err(|e: bulletin::error::BulletinError| {
                    StoreSecretError::Serialization(format!(
                        "Failed to serialize DocumentPayload: {}",
                        e
                    ))
                })?;

        // 5. Post to bulletin and use the authoritative object id returned by the backend.
        let object_id = self
            .state
            .bulletin
            .post(BulletinWriteKind::Document, payload_bytes.clone())
            .await
            .map_err(|e| StoreSecretError::Storage(format!("Failed to post to bulletin: {}", e)))?;

        let created_at = current_time as i64;

        tracing::info!(
            object_id = %object_id,
            ring_id = %req.ring_id,
            requester = %token.issuer_id,
            "Successfully stored encrypted secret"
        );

        let mut signature = "".to_string();

        if req.with_proof {
            // Sign the bulletin's authoritative representation. Backends are
            // allowed to deserialize and canonically reserialize a document
            // while storing it, so the caller-side bytes above are not
            // necessarily byte-identical to what signing peers will read.
            let bulletin_post = self
                .state
                .bulletin
                .read(object_id.clone(), BulletinKind::Document)
                .await
                .map_err(|e| {
                    StoreSecretError::Storage(format!(
                        "Failed to read stored document for signing: {e}"
                    ))
                })?;

            // Serialize BulletinPost to bytes for signing
            let message_to_sign: Vec<u8> = bulletin_post.try_into().map_err(|e| {
                StoreSecretError::Serialization(format!("Failed to serialize BulletinPost: {}", e))
            })?;

            // Generate random session id
            let session_id: u128 = rand::random();
            let coordinator = SignCoordinator::<D, S>::with_routes(self.state.clone(), self.routes);
            let ring_pk_bytes = hex::decode(&ring_payload.ring_pk)
                .map_err(|e| StoreSecretError::Validation(format!("Invalid ring_pk hex: {}", e)))?;
            let routes = resolve_node_routes(&self.state.bulletin, &ring_payload.peer_node_keys)
                .await
                .map_err(StoreSecretError::Validation)?;
            let peer_ids = peer_ids_from_routes(&routes);
            let total_participants = peer_ids.len();
            let poly_state = RingPolyState::load_from_ring_pk_hex(
                &self.state.local_storage,
                &ring_payload.ring_pk,
            )
            .map_err(|e| {
                StoreSecretError::Storage(format!("Failed to load ring polynomial state: {}", e))
            })?;
            let ring = RingConfig {
                ring_id: req.ring_id.clone(),
                ring_pk_bytes,
                peer_ids,
                peer_node_keys: ring_payload.peer_node_keys,
                threshold: ring_payload.threshold as usize,
                total_participants,
                public_polynomial_hex: poly_state.public_polynomial,
                pre_share_endpoints: vec![],
            };
            let response_bytes = coordinator
                .initiate_signing(
                    session_id.to_string(),
                    ring,
                    message_to_sign,
                    SignContext::Bulletin {
                        object_id: object_id.clone(),
                    },
                    SigningOptions::default(),
                )
                .await
                .map_err(|e| StoreSecretError::Signing(format!("Signing failed: {}", e)))?;

            let sign_response: SignResponse =
                serde_json::from_slice(&response_bytes).map_err(|e| {
                    StoreSecretError::Signing(format!("Failed to parse sign response: {}", e))
                })?;
            signature = sign_response.signature;
        }

        request_metrics.complete();
        grpc_metrics.success();

        Ok(Response::new(StoreSecretResponse {
            status: "success".to_string(),
            message: "Secret stored successfully".to_string(),
            created_at,
            object_id,
            ring_id: req.ring_id,
            signature,
        }))
    }
}
