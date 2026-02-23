use crate::app_state::AppState;
use crate::constants::{BULLETIN_PLACEHOLDER_PROOF, BULLETIN_RING_NAMESPACE};
use crate::metrics;
use crate::sign::coordinator::{SignCoordinator, SignResponse};
use crate::store_secret::error::StoreSecretError;
use authn::{extract_bearer_token, resolve_jwt_did, BearerToken, StoreSecretClaims};
use bulletin::r#trait::{BulletinPost, DocumentPayload, RingPayload};
use crypto::r#trait::{CryptoDeserialize, Dkg, EncryptionProof, Secret, ThresholdDealer};
use crypto::PreImpl as ThresholdDealerNode;
use proto::store_secret_service::{
    store_secret_service_server::StoreSecretService, StoreSecretRequest, StoreSecretResponse,
};
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

        // TODO: remove and pass the metadata hash
        let policy_metadata = ThresholdDealerNode::encode_metadata(
            &req.policy_id,
            &req.resource,
            &req.permission,
            req.tier.as_deref(),
            req.date.as_deref(),
            req.salt.as_deref(),
        );
        let proof = EncryptionProof {
            shared_point: req.shared_point,
            challenge: req.challenge,
            response: req.response,
            derived_pk: req.derived_pk,
        };

        // 3. Validate the encrypted document structure
        let _encrypted_secret = validate_encrypted_document::<D>(
            &req.encrypted_document,
            &req.enc_cmt,
            &ring_payload.ring_pk,
            proof.clone(),
            policy_metadata,
        )?;

        // 4. Create DocumentPayload with the pre-encrypted secret
        let document_payload = DocumentPayload {
            ring_id: req.ring_id.clone(),
            document: req.encrypted_document.clone(),
            proof: proof.try_into().map_err(|e: crypto::error::CryptoError| {
                StoreSecretError::Serialization(format!("Failed to serialize proof: {}", e))
            })?,
            policy_id: req.policy_id,
            resource: req.resource,
            permission: req.permission,
            tier: req.tier,
            date: req.date,
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
        let object_id = self
            .state
            .bulletin
            .get_post_id(&full_namespace, &payload_bytes)
            .map_err(|e| StoreSecretError::Storage(format!("Failed to compute post ID: {}", e)))?;

        // 6. Post to bulletin (only if it doesn't already exist)
        let proof = BULLETIN_PLACEHOLDER_PROOF.to_vec();

        // Check if the post already exists (read returns NotFound error if not found)
        let post_exists = match self
            .state
            .bulletin
            .read(req.namespace.clone(), object_id.clone())
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
                .post(
                    req.namespace.clone(),
                    payload_bytes.clone(),
                    proof.clone(),
                    None,
                )
                .await
                .map_err(|e| {
                    StoreSecretError::Storage(format!("Failed to post to bulletin: {}", e))
                })?;
        } else {
            tracing::debug!(
                object_id = %object_id,
                namespace = %req.namespace,
                "Post already exists on bulletin, skipping post"
            );
        }

        let created_at = current_time as i64;

        tracing::info!(
            object_id = %object_id,
            ring_id = %req.ring_id,
            namespace = %req.namespace,
            owner = %token.issuer_id,
            "Successfully stored encrypted secret"
        );

        let mut signature = "".to_string();

        if req.with_proof {
            // Construct the BulletinPost that was stored
            let bulletin_post = BulletinPost {
                id: object_id.clone(),
                namespace: req.namespace.clone(),
                payload: payload_bytes.clone(),
                proof: proof.clone(),
            };

            // Serialize BulletinPost to bytes for signing
            let message_to_sign: Vec<u8> = bulletin_post.try_into().map_err(|e| {
                StoreSecretError::Serialization(format!("Failed to serialize BulletinPost: {}", e))
            })?;

            // Generate random session id
            let session_id: u64 = rand::random();
            let coordinator = SignCoordinator::<D, S>::new(Arc::new(self.state.clone()));
            let response_bytes = coordinator
                .initiate_signing(
                    session_id.to_string(),
                    hex::decode(&ring_payload.ring_pk).map_err(|e| {
                        StoreSecretError::Validation(format!("Invalid ring_pk hex: {}", e))
                    })?,
                    message_to_sign,
                    &ring_payload.peer_ids,
                    ring_payload.threshold as usize,
                    ring_payload.peer_ids.len(),
                    &ring_payload.public_polynomial,
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
fn validate_encrypted_document<D>(
    encrypted_document: &str,
    enc_cmt_hex: &str,
    ring_key: &str,
    proof: EncryptionProof,
    policy_metadata: Vec<u8>,
) -> Result<Secret, StoreSecretError>
where
    D: Dkg<PublicKey = crypto::GroupAffine>,
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
    // The store service never has derivation bytes, so when proof.derived_pk is present
    // we use it directly as the effective key. The NIZK proves it was used correctly.
    // Derivation byte correctness (d * ring_pk == derived_pk) is enforced by the PRE
    // service via verify_encryption_binding, which does have the derivation bytes.
    let effective_key = if let Some(ref derived_pk_bytes) = proof.derived_pk {
        D::PublicKey::from_bytes(derived_pk_bytes).map_err(|e| {
            StoreSecretError::Validation(format!("derived_pk is not a valid curve point: {}", e))
        })?
    } else {
        ring_key_point
    };
    ThresholdDealerNode::verify_encryption(
        &effective_key,
        &enc_cmt_point,
        &proof,
        Some(&policy_metadata),
    )
    .map_err(|e| {
        StoreSecretError::Validation(format!("Failed to Validate secret encryption: {}", e))
    })?;

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

    if token.claims.derived_pk != req.derived_pk {
        return Err(StoreSecretError::Unauthorized(format!(
            "Token derived_pk '{:?}' does not match request derived_pk '{:?}'",
            token.claims.derived_pk, req.derived_pk
        )));
    }

    if token.claims.with_proof != req.with_proof {
        return Err(StoreSecretError::Unauthorized(format!(
            "Token with_proof '{:?}' does not match request with_proof '{:?}'",
            token.claims.with_proof, req.with_proof
        )));
    }
    // TODO; remove for metadata hash
    //  if token.claims.tier != req.tier {
    //     return Err(StoreSecretError::Unauthorized(format!(
    //         "Token tier '{:?}' does not match request tier '{:?}'",
    //         token.claims.tier, req.tier
    //     )));
    // }
    //  if token.claims.date != req.date {
    //     return Err(StoreSecretError::Unauthorized(format!(
    //         "Token date '{:?}' does not match request date '{:?}'",
    //         token.claims.date, req.date
    //     )));
    // }
    //  if token.claims.salt != req.salt {
    //     return Err(StoreSecretError::Unauthorized(format!(
    //         "Token salt '{:?}' does not match request salt '{:?}'",
    //         token.claims.salt, req.salt
    //     )));
    // }

    Ok(())
}
