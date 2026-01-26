use crate::app_state::AppState;
use crate::constants::{BULLETIN_PLACEHOLDER_PROOF, BULLETIN_RING_NAMESPACE};
use crate::metrics;
use crate::store_secret::error::StoreSecretError;
use authn::{extract_bearer_token, resolve_jwt_did, BearerToken, StoreSecretClaims};
use bulletin::r#trait::{DocumentPayload, RingPayload};
use bulletin::sourcehub::SourceHubBulletin;
use crypto::bls12_381::pre::ThresholdDealerNode;
use crypto::r#trait::{CryptoDeserialize, Dkg, EncryptionProof, Secret, ThresholdDealer};
use proto::store_secret_service::{
    store_secret_service_server::StoreSecretService, StoreSecretRequest, StoreSecretResponse,
};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tonic::{Request, Response, Status};

/// Implementation of the StoreSecretService
///
/// This service acts as an authenticated relay for storing pre-encrypted secrets.
/// The node NEVER sees plaintext - users must encrypt locally before calling this service.
#[derive(Debug)]
pub struct StoreSecretServiceImpl<D>
where
    D: Dkg + Clone + 'static,
{
    pub state: AppState<D>,
}

impl<D> StoreSecretServiceImpl<D>
where
    D: Dkg + Clone + 'static,
{
    /// Create a new StoreSecretServiceImpl with shared application state
    pub fn new(state: AppState<D>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl<D> StoreSecretService for StoreSecretServiceImpl<D>
where
    D: Dkg<PublicKey = ark_bls12_381::G1Affine> + Clone + Send + Sync + 'static,
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
        let token: BearerToken<StoreSecretClaims> = resolve_jwt_did(token_str, current_time)
            .map_err(|e| StoreSecretError::Unauthorized(format!("JWT validation failed: {}", e)))?;

        let req = request.into_inner();

        // 2. Validate JWT claims match request
        validate_store_secret_claims(&token, &req)?;

        tracing::info!(
            ring_id = %req.ring_id,
            namespace = %req.namespace,
            issuer = %token.issuer_id,
            "Authenticated StoreSecret request"
        );

        // Get ring public_key from bulletin
        let ring_info = self
            .state
            .bulletin
            .read(BULLETIN_RING_NAMESPACE.to_string(), req.ring_id.clone())
            .await
            .map_err(|e| {
                StoreSecretError::Storage(format!("Failed to read ring '{}': {}", req.ring_id, e))
            })?;

        let ring_payload =
            serde_json::from_slice::<RingPayload>(&ring_info.payload).map_err(|e| {
                StoreSecretError::Deserialization(format!("Failed to parse ring payload: {}", e))
            })?;

        // 3. Validate the encrypted document structure
        let _encrypted_secret = validate_encrypted_document::<D>(
            &req.encrypted_document,
            &req.enc_cmt,
            &ring_payload.ring_pk,
            req.shared_point,
            req.challenge,
            req.response,
        )?;

        // 4. Create DocumentPayload with the pre-encrypted secret
        let document_payload = DocumentPayload {
            ring_id: req.ring_id.clone(),
            document: req.encrypted_document.clone(),
            policy_id: req.policy_id,
            resource: req.resource,
            permission: req.permission,
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

        // 5. Compute object_id before posting (deterministic hash)
        // Note: get_post_id expects the full namespace format "bulletin/{namespace}"
        let full_namespace = format!("bulletin/{}", req.namespace);
        let object_id = SourceHubBulletin::get_post_id(&full_namespace, &payload_bytes)
            .map_err(|e| StoreSecretError::Storage(format!("Failed to compute post ID: {}", e)))?;

        // 6. Post to bulletin
        let proof = BULLETIN_PLACEHOLDER_PROOF.to_vec();

        self.state
            .bulletin
            .post(req.namespace.clone(), payload_bytes, proof, None)
            .await
            .map_err(|e| StoreSecretError::Storage(format!("Failed to post to bulletin: {}", e)))?;

        let created_at = current_time as i64;

        tracing::info!(
            object_id = %object_id,
            ring_id = %req.ring_id,
            namespace = %req.namespace,
            owner = %token.issuer_id,
            "Successfully stored encrypted secret"
        );

        metrics::record_store_secret_completed(start.elapsed().as_secs_f64());

        Ok(Response::new(StoreSecretResponse {
            status: "success".to_string(),
            message: "Secret stored successfully".to_string(),
            created_at,
            object_id,
            ring_id: req.ring_id,
        }))
    }
}

/// Validates the encrypted document structure and enc_cmt.
///
/// This function performs structural validation to ensure the encrypted data
/// is well-formed before posting to the bulletin.
fn validate_encrypted_document<D>(
    encrypted_document: &str,
    enc_cmt_hex: &str,
    ring_key: &str,
    shared_point: Vec<u8>,
    challenge: Vec<u8>,
    response: Vec<u8>,
) -> Result<Secret, StoreSecretError>
where
    D: Dkg<PublicKey = ark_bls12_381::G1Affine>,
{
    // 1. Parse the encrypted document as a Secret struct
    let secret: Secret = serde_json::from_str(encrypted_document).map_err(|e| {
        StoreSecretError::Validation(format!(
            "Failed to parse encrypted_document as Secret: {}",
            e
        ))
    })?;

    // 2. Validate enc_cmt is a valid hex-encoded G1 point
    let enc_cmt_bytes = hex::decode(enc_cmt_hex).map_err(|e| {
        StoreSecretError::Validation(format!("Invalid enc_cmt hex encoding: {}", e))
    })?;

    // Validate it's a valid G1 point (48 bytes compressed)
    let enc_cmt_point = D::PublicKey::from_bytes(&enc_cmt_bytes).map_err(|e| {
        StoreSecretError::Validation(format!("enc_cmt is not a valid G1 curve point: {}", e))
    })?;

    // 2b. Parse ring_key from hex to G1 point
    let ring_key_bytes = hex::decode(ring_key).map_err(|e| {
        StoreSecretError::Validation(format!("Invalid ring_key hex encoding: {}", e))
    })?;
    let ring_key_point = D::PublicKey::from_bytes(&ring_key_bytes).map_err(|e| {
        StoreSecretError::Validation(format!("ring_key is not a valid G1 curve point: {}", e))
    })?;

    // 3. Validate the enc_cmt in the Secret matches the provided enc_cmt
    if secret.enc_cmt != enc_cmt_bytes {
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

    // 5. Validate Encryption of secret validity
    let proof = EncryptionProof {
        shared_point,
        challenge,
        response,
    };

    ThresholdDealerNode::verify_encryption(&ring_key_point, &enc_cmt_point, &proof).map_err(
        |e| StoreSecretError::Validation(format!("Failed to Validate secret encryption: {}", e)),
    )?;

    Ok(secret)
}

fn validate_store_secret_claims(
    token: &BearerToken<StoreSecretClaims>,
    req: &StoreSecretRequest,
) -> Result<(), StoreSecretError> {
    if token.claims.encrypted_document != req.encrypted_document {
        return Err(StoreSecretError::Unauthorized(
            "Token encrypted_document does not match request".to_string(),
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

    if token.claims.namespace != req.namespace {
        return Err(StoreSecretError::Unauthorized(format!(
            "Token namespace '{}' does not match request namespace '{}'",
            token.claims.namespace, req.namespace
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

    Ok(())
}
