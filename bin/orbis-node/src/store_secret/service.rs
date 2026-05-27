use crate::app_state::AppState;
use crate::constants::{JWT_CLOCK_SKEW_LEEWAY_SECS, MAX_JWT_BYTES, MAX_TOKEN_LIFETIME_SECS};
use crate::helpers::helpers::RingConfig;
use crate::helpers::node_routes::{peer_ids_from_routes, resolve_node_routes};
use crate::metrics;
use crate::ring_state::RingPolyState;
use crate::sign::coordinator::{SignCoordinator, SignResponse};
use crate::sign::messages::SignContext;
use crate::store_secret::error::StoreSecretError;
use authn::{extract_bearer_token, resolve_jwt_did, BearerToken, StoreSecretClaims};
use bulletin::r#trait::{BulletinKind, BulletinPost, DocumentPayload, RingPayload};
use crypto::r#trait::{Dkg, EncryptionProof, Secret};
use proto::store_secret_service::{
    store_secret_service_server::StoreSecretService, StoreSecretRequest, StoreSecretResponse,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
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
    pub state: AppState<D>,
    _phantom: std::marker::PhantomData<S>,
}

impl<D, S> StoreSecretServiceImpl<D, S>
where
    D: Dkg + Clone + 'static,
    S: crypto::r#trait::ThresholdSigner,
{
    /// Create a new StoreSecretServiceImpl with shared application state
    pub fn new(state: AppState<D>) -> Self {
        Self {
            state,
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
        let start = Instant::now();
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Status::internal(format!("Failed to get timestamp: {}", e)))?
            .as_secs();

        // 1. Authenticate: Extract and validate JWT
        let token_str = extract_bearer_token(&request)
            .map_err(|e| StoreSecretError::Unauthorized(e.to_string()))?;
        let token: BearerToken<StoreSecretClaims> = resolve_jwt_did(
            token_str,
            current_time,
            MAX_TOKEN_LIFETIME_SECS,
            MAX_JWT_BYTES,
            JWT_CLOCK_SKEW_LEEWAY_SECS,
        )
        .map_err(|e| StoreSecretError::Unauthorized(format!("JWT validation failed: {}", e)))?;

        let req = request.into_inner();

        // 2. Validate JWT claims match request
        validate_store_secret_claims(&token, &req)?;

        tracing::info!(
            ring_id = %req.ring_id,
            issuer = %token.issuer_id,
            "Authenticated StoreSecret request"
        );

        // Get ring public_key from bulletin
        let ring_info = self
            .state
            .bulletin
            .read(req.ring_id.clone(), BulletinKind::Ring)
            .await
            .map_err(|e| {
                StoreSecretError::Storage(format!("Failed to read ring '{}': {}", req.ring_id, e))
            })?;

        let ring_payload =
            serde_json::from_slice::<RingPayload>(&ring_info.payload).map_err(|e| {
                StoreSecretError::Deserialization(format!("Failed to parse ring payload: {}", e))
            })?;

        let proof = EncryptionProof {
            shared_point: req.shared_point,
            challenge: req.challenge,
            response: req.response,
        };

        // 3. Validate the encrypted document structure
        let _encrypted_secret = validate_encrypted_document(&req.encrypted_document, &req.enc_cmt)?;

        // 4. Create DocumentPayload with the pre-encrypted secret
        // DocumentPayload.document is a String (JSON), so convert from bytes (valid UTF-8)
        let encrypted_document_str =
            String::from_utf8(req.encrypted_document.clone()).map_err(|e| {
                StoreSecretError::Validation(format!(
                    "encrypted_document is not valid UTF-8: {}",
                    e
                ))
            })?;

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

        // 5. Compute object_id before posting (deterministic typed Orbis hash).
        let object_id = self
            .state
            .bulletin
            .get_post_id(&payload_bytes)
            .map_err(|e| StoreSecretError::Storage(format!("Failed to compute post ID: {}", e)))?;

        // 6. Post to bulletin (only if it doesn't already exist)
        // Check if the post already exists (read returns NotFound error if not found)
        let post_exists = match self
            .state
            .bulletin
            .read(object_id.clone(), BulletinKind::Document)
            .await
        {
            Ok(_) => true,
            Err(bulletin::error::BulletinError::NotFound { .. }) => false,
            Err(e) => {
                return Err(StoreSecretError::Storage(format!(
                    "Failed to check existing post: {}",
                    e
                ))
                .into())
            }
        };

        if !post_exists {
            self.state
                .bulletin
                .post(BulletinKind::Document, payload_bytes.clone(), None)
                .await
                .map_err(|e| {
                    StoreSecretError::Storage(format!("Failed to post to bulletin: {}", e))
                })?;
        } else {
            tracing::debug!(
                object_id = %object_id,
                "Post already exists on bulletin, skipping post"
            );
        }

        let created_at = current_time as i64;

        tracing::info!(
            object_id = %object_id,
            ring_id = %req.ring_id,
            owner = %token.issuer_id,
            "Successfully stored encrypted secret"
        );

        let mut signature = "".to_string();

        if req.with_proof {
            // Construct the BulletinPost that was stored
            let bulletin_post = BulletinPost {
                id: object_id.clone(),
                payload: payload_bytes.clone(),
            };

            // Serialize BulletinPost to bytes for signing
            let message_to_sign: Vec<u8> = bulletin_post.try_into().map_err(|e| {
                StoreSecretError::Serialization(format!("Failed to serialize BulletinPost: {}", e))
            })?;

            // Generate random session id
            let session_id: u64 = rand::random();
            let coordinator = SignCoordinator::<D, S>::new(Arc::new(self.state.clone()));
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
                ring_pk_bytes,
                peer_ids,
                peer_node_keys: ring_payload.peer_node_keys,
                threshold: ring_payload.threshold as usize,
                total_participants,
                public_polynomial_hex: poly_state.public_polynomial,
            };
            let response_bytes = coordinator
                .initiate_signing(
                    session_id.to_string(),
                    ring,
                    message_to_sign,
                    SignContext::Bulletin,
                )
                .await
                .map_err(|e| StoreSecretError::Signing(format!("Signing failed: {}", e)))?;

            let sign_response: SignResponse =
                serde_json::from_slice(&response_bytes).map_err(|e| {
                    StoreSecretError::Signing(format!("Failed to parse sign response: {}", e))
                })?;
            signature = sign_response.signature;
        }

        metrics::record_store_secret_completed(start.elapsed().as_secs_f64());

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

/// Validates the encrypted document structure and enc_cmt.
///
/// This function performs structural validation to ensure the encrypted data
/// is well-formed before posting to the bulletin.
fn validate_encrypted_document(
    encrypted_document: &[u8],
    enc_cmt: &[u8],
) -> Result<Secret, StoreSecretError> {
    // 1. Parse the encrypted document as a Secret struct
    let secret: Secret = serde_json::from_slice(encrypted_document).map_err(|e| {
        StoreSecretError::Validation(format!(
            "Failed to parse encrypted_document as Secret: {}",
            e
        ))
    })?;

    // 3. Validate the enc_cmt in the Secret matches the provided enc_cmt
    if secret.enc_cmt != enc_cmt {
        return Err(StoreSecretError::Validation(
            "enc_cmt in encrypted_document does not match provided enc_cmt".to_string(),
        ));
    }

    // 4. Validate nonce is 12 bytes (AES-GCM standard)
    if secret.nonce.len() != 12 {
        return Err(StoreSecretError::Validation(format!(
            "Invalid nonce length: expected 12 bytes, got {}",
            secret.nonce.len()
        )));
    }

    Ok(secret)
}

fn validate_store_secret_claims(
    token: &BearerToken<StoreSecretClaims>,
    req: &StoreSecretRequest,
) -> Result<(), StoreSecretError> {
    let expected = Sha256::digest(&req.encrypted_document);
    if token.claims.encrypted_document_sha256 != expected.as_slice() {
        return Err(StoreSecretError::Unauthorized(
            "Token encrypted_document_sha256 does not match request encrypted_document".to_string(),
        ));
    }

    if token.claims.enc_cmt != req.enc_cmt {
        return Err(StoreSecretError::Unauthorized(
            "Token enc_cmt does not match request".to_string(),
        ));
    }

    if token.claims.ring_id != req.ring_id {
        return Err(StoreSecretError::Unauthorized(format!(
            "Token ring_id '{}' does not match request ring_id '{}'",
            token.claims.ring_id, req.ring_id
        )));
    }

    if token.claims.policy_id != req.policy_id {
        return Err(StoreSecretError::Unauthorized(format!(
            "Token policy_id '{}' does not match request policy_id '{}'",
            token.claims.policy_id, req.policy_id
        )));
    }

    if token.claims.resource != req.resource {
        return Err(StoreSecretError::Unauthorized(format!(
            "Token resource '{}' does not match request resource '{}'",
            token.claims.resource, req.resource
        )));
    }

    if token.claims.permission != req.permission {
        return Err(StoreSecretError::Unauthorized(format!(
            "Token permission '{}' does not match request permission '{}'",
            token.claims.permission, req.permission
        )));
    }

    if token.claims.shared_point != req.shared_point {
        return Err(StoreSecretError::Unauthorized(format!(
            "Token shared_point '{:?}' does not match request shared_point '{:?}'",
            token.claims.shared_point, req.shared_point
        )));
    }

    if token.claims.challenge != req.challenge {
        return Err(StoreSecretError::Unauthorized(format!(
            "Token challenge '{:?}' does not match request challenge '{:?}'",
            token.claims.challenge, req.challenge
        )));
    }

    if token.claims.response != req.response {
        return Err(StoreSecretError::Unauthorized(format!(
            "Token response '{:?}' does not match request response '{:?}'",
            token.claims.response, req.response
        )));
    }

    if token.claims.with_proof != req.with_proof {
        return Err(StoreSecretError::Unauthorized(format!(
            "Token with_proof '{:?}' does not match request with_proof '{:?}'",
            token.claims.with_proof, req.with_proof
        )));
    }

    if token.claims.tier != req.tier {
        return Err(StoreSecretError::Unauthorized(format!(
            "Token tier '{:?}' does not match request tier '{:?}'",
            token.claims.tier, req.tier
        )));
    }
    if token.claims.timestamp != req.timestamp {
        return Err(StoreSecretError::Unauthorized(format!(
            "Token timestamp '{:?}' does not match request timestamp '{:?}'",
            token.claims.timestamp, req.timestamp
        )));
    }

    Ok(())
}
