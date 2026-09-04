use crate::app_state::AppState;
use crate::constants::{BULLETIN_RING_NAMESPACE, MAX_TOKEN_LIFETIME_SECS};
use crate::helpers::helpers::{validate_all_peer_ids, RingConfig};
use crate::sign::coordinator::{SignCoordinator, SignResponse};
use crate::sign::messages::SignContext;
use crate::utility::error::UtilityError;
use authn::{extract_bearer_token, resolve_jwt_did, BearerToken, SignClaims};
use authz::sourcehub::AccessCheckRequest;
use bulletin::r#trait::RingPayload;
use crypto::r#trait::{CryptoDeserialize, CryptoSerialize, Dkg, ThresholdSigner};
use proto::utility_service::{
    utility_service_server::UtilityService, DerivePublicKeyRequest, DerivePublicKeyResponse,
    SignAlgorithm, SignRequest, SignResponse as ProtoSignResponse,
};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tonic::{Request, Response, Status};

/// Map a ThresholdSigner::name() string to the proto SignAlgorithm enum.
fn signer_algorithm<S: ThresholdSigner>() -> SignAlgorithm {
    match S::name().as_str() {
        "threshold-bls-g2" => SignAlgorithm::Bls,
        "threshold-frost-decaf377" => SignAlgorithm::FrostDecaf377,
        _ => SignAlgorithm::Unspecified,
    }
}

/// Implementation of the UtilityService
///
/// Provides two RPCs:
/// - DerivePublicKey: derive a public key from a ring's master PK + label (unauthenticated)
/// - Sign: perform T-of-N threshold signing (authenticated)
#[derive(Debug)]
pub struct UtilityServiceImpl<D, S>
where
    D: Dkg + Clone + 'static,
    S: ThresholdSigner,
{
    pub state: AppState<D>,
    _phantom: std::marker::PhantomData<S>,
}

impl<D, S> UtilityServiceImpl<D, S>
where
    D: Dkg + Clone + 'static,
    S: ThresholdSigner,
{
    pub fn new(state: AppState<D>) -> Self {
        Self {
            state,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[tonic::async_trait]
impl<D, S> UtilityService for UtilityServiceImpl<D, S>
where
    D: Dkg<ShareValue = crypto::ScalarField, PublicKey = crypto::GroupAffine>
        + Clone
        + Send
        + Sync
        + 'static,
    S: ThresholdSigner<
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
    async fn derive_public_key(
        &self,
        request: Request<DerivePublicKeyRequest>,
    ) -> Result<Response<DerivePublicKeyResponse>, Status> {
        let req = request.into_inner();

        tracing::info!(
            ring_id = %req.ring_id,
            derivation_len = req.derivation.len(),
            "DerivePublicKey request"
        );

        // 1. Read ring info from bulletin
        let ring_info = self
            .state
            .bulletin
            .read(BULLETIN_RING_NAMESPACE.to_string(), req.ring_id.clone())
            .await
            .map_err(|e| {
                UtilityError::RingNotFound(format!("Failed to read ring '{}': {}", req.ring_id, e))
            })?;

        let ring_payload =
            serde_json::from_slice::<RingPayload>(&ring_info.payload).map_err(|e| {
                UtilityError::Deserialization(format!("Failed to parse ring payload: {}", e))
            })?;

        // 2. Parse ring_pk from hex -> G1Affine
        let ring_pk_bytes = hex::decode(&ring_payload.ring_pk)
            .map_err(|e| UtilityError::Deserialization(format!("Invalid ring_pk hex: {}", e)))?;
        let ring_pk = <D::PublicKey>::from_bytes(&ring_pk_bytes).map_err(|e| {
            UtilityError::Deserialization(format!("Invalid ring_pk curve point: {}", e))
        })?;

        // 3. Derive the public key threshold signatures under this derivation
        //    will actually carry.
        //
        //    There are two derivation scalars in the crypto crate: the PRE
        //    capability scalar (`Dkg::derive_public_key`, two arguments) and
        //    the signing scalar (`ThresholdSigner::derive_public_key`, which
        //    also takes metadata). This RPC exists to tell a client which key
        //    to publish for signature verification, so it must use the signing
        //    one. Using the capability scalar here returned a key no signature
        //    ever verifies under, and the mismatch surfaced only on a peer as
        //    `BLST_VERIFY_FAIL` when it merged an otherwise valid block.
        let derived_pk = <S as ThresholdSigner>::derive_public_key(&ring_pk, &req.derivation, None)
            .map_err(|e| UtilityError::Crypto(format!("Failed to derive public key: {}", e)))?;

        // 4. Serialize derived key
        let derived_pk_bytes = CryptoSerialize::to_bytes(&derived_pk).map_err(|e| {
            UtilityError::Crypto(format!("Failed to serialize derived public key: {}", e))
        })?;

        Ok(Response::new(DerivePublicKeyResponse {
            public_key: derived_pk_bytes,
            algorithm: signer_algorithm::<S>().into(),
        }))
    }

    #[tracing::instrument(skip_all, fields(request))]
    async fn sign(
        &self,
        request: Request<SignRequest>,
    ) -> Result<Response<ProtoSignResponse>, Status> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Status::internal(format!("Failed to get timestamp: {}", e)))?
            .as_secs();

        // 1. Authenticate: Extract and validate JWT
        let token_str = extract_bearer_token(&request)
            .map_err(|e| UtilityError::Unauthorized(e.to_string()))?;
        let jwt_string = token_str.to_string();
        let token: BearerToken<SignClaims> =
            resolve_jwt_did(token_str, current_time, MAX_TOKEN_LIFETIME_SECS)
                .map_err(|e| UtilityError::Unauthorized(format!("JWT validation failed: {}", e)))?;

        let req = request.into_inner();

        // 2. Algorithm guard
        let ring_algorithm = signer_algorithm::<S>();
        let requested =
            SignAlgorithm::try_from(req.algorithm).unwrap_or(SignAlgorithm::Unspecified);
        if requested != SignAlgorithm::Unspecified && requested != ring_algorithm {
            return Err(UtilityError::UnsupportedAlgorithm(format!(
                "requested algorithm {:?} but ring uses {:?}",
                requested.as_str_name(),
                ring_algorithm.as_str_name(),
            ))
            .into());
        }

        // 3. Validate JWT claims match request
        if token.claims.ring_id != req.ring_id {
            return Err(UtilityError::Unauthorized(format!(
                "Token ring_id '{}' does not match request ring_id '{}'",
                token.claims.ring_id, req.ring_id
            ))
            .into());
        }
        if token.claims.message != req.message {
            return Err(UtilityError::Unauthorized(
                "Token message does not match request".to_string(),
            )
            .into());
        }
        let req_derivation = if req.derivation.is_empty() {
            None
        } else {
            Some(req.derivation.clone())
        };
        if token.claims.derivation != req_derivation {
            return Err(UtilityError::Unauthorized(
                "Token derivation does not match request".to_string(),
            )
            .into());
        }

        // Mutual exclusivity: decision_id and policy_id cannot both be set
        if !req.decision_id.is_empty() && !req.policy_id.is_empty() {
            return Err(UtilityError::Unauthorized(
                "decision_id and policy_id are mutually exclusive".to_string(),
            )
            .into());
        }

        // ACP authorization: three-way branch
        if !req.decision_id.is_empty() {
            let light_client = self.state.acp_light_client.as_ref().ok_or_else(|| {
                UtilityError::Signing(
                    "decision_id provided but ACP light client not configured (--hub-rpc/--hub-ws)"
                        .to_string(),
                )
            })?;
            let result = light_client
                .check_access_decision(&req.decision_id)
                .await
                .map_err(|e| UtilityError::Signing(format!("ACP light client error: {}", e)))?;
            if !result.allowed {
                return Err(UtilityError::Unauthorized(format!(
                    "AccessDecision '{}' not authorized on-chain",
                    req.decision_id,
                ))
                .into());
            }
            tracing::info!(
                decision_id = %req.decision_id,
                verified_at_height = result.verified_at_height,
                "AccessDecision verified via light client"
            );
        } else if !req.policy_id.is_empty() {
            let permission_bytes = AccessCheckRequest::new(
                req.policy_id.clone(),
                req.resource.clone(),
                req.object_id.clone(),
                req.permission.clone(),
                None,
                None,
                None,
            )
            .to_bytes()
            .map_err(|e| {
                UtilityError::Signing(format!("Error formatting access request: {}", e))
            })?;
            let authorized = self
                .state
                .authz
                .check(permission_bytes, &token.issuer_id)
                .await
                .map_err(|e| UtilityError::Signing(format!("ACP authorization failed: {}", e)))?;
            if !authorized {
                return Err(UtilityError::Unauthorized(format!(
                    "ACP denied: {} not authorized for {}/{}/{}",
                    token.issuer_id, req.resource, req.object_id, req.permission,
                ))
                .into());
            }
        } else {
            tracing::warn!(
                ring_id = %req.ring_id,
                issuer = %token.issuer_id,
                "Sign request without ACP fields — authorization not enforced"
            );
        }

        tracing::info!(
            ring_id = %req.ring_id,
            message_len = req.message.len(),
            algorithm = %ring_algorithm.as_str_name(),
            issuer = %token.issuer_id,
            "Authenticated Sign request"
        );

        // 4. Read ring info from bulletin
        let ring_info = self
            .state
            .bulletin
            .read(BULLETIN_RING_NAMESPACE.to_string(), req.ring_id.clone())
            .await
            .map_err(|e| {
                UtilityError::RingNotFound(format!("Failed to read ring '{}': {}", req.ring_id, e))
            })?;

        let ring_payload =
            serde_json::from_slice::<RingPayload>(&ring_info.payload).map_err(|e| {
                UtilityError::Deserialization(format!("Failed to parse ring payload: {}", e))
            })?;

        // 5. Compute the public key that will verify this signature
        let ring_pk_bytes = hex::decode(&ring_payload.ring_pk)
            .map_err(|e| UtilityError::Deserialization(format!("Invalid ring_pk hex: {}", e)))?;
        let verification_pk = if req.derivation.is_empty() {
            ring_pk_bytes.clone()
        } else {
            let ring_pk = <D::PublicKey>::from_bytes(&ring_pk_bytes).map_err(|e| {
                UtilityError::Deserialization(format!("Invalid ring_pk curve point: {}", e))
            })?;
            // Same signing scalar the threshold signature is produced under,
            // not the PRE capability scalar; see `derive_public_key` above.
            let derived =
                <S as ThresholdSigner>::derive_public_key(&ring_pk, &req.derivation, None)
                    .map_err(|e| {
                        UtilityError::Crypto(format!("Failed to derive public key: {}", e))
                    })?;
            CryptoSerialize::to_bytes(&derived).map_err(|e| {
                UtilityError::Crypto(format!("Failed to serialize public key: {}", e))
            })?
        };

        // Validate peers
        if ring_payload.peer_ids.is_empty() {
            return Err(UtilityError::Signing("No peer IDs found for ring".to_string()).into());
        }
        if let Err((invalid_peer_id, validation_error)) =
            validate_all_peer_ids(&ring_payload.peer_ids)
        {
            return Err(UtilityError::Signing(format!(
                "Invalid peer ID '{}': {}",
                invalid_peer_id, validation_error
            ))
            .into());
        }

        // 6. Initiate threshold signing
        let ring = RingConfig {
            ring_pk_bytes,
            peer_ids: ring_payload.peer_ids.clone(),
            threshold: ring_payload.threshold as usize,
            total_participants: ring_payload.peer_ids.len(),
            public_polynomial_hex: ring_payload.public_polynomial,
        };

        let context = if !req.decision_id.is_empty() {
            SignContext::AccessDecision {
                jwt: jwt_string,
                ring_id: req.ring_id.clone(),
                decision_id: req.decision_id.clone(),
                derivation: req_derivation.clone(),
            }
        } else {
            SignContext::Authenticated {
                jwt: jwt_string,
                ring_id: req.ring_id.clone(),
                policy_id: req.policy_id.clone(),
                resource: req.resource.clone(),
                object_id: req.object_id.clone(),
                permission: req.permission.clone(),
                derivation: req_derivation.clone(),
            }
        };

        let request_id = rand::random::<u64>().to_string();
        let coordinator = SignCoordinator::<D, S>::new(Arc::new(self.state.clone()));
        let response_bytes = coordinator
            .initiate_signing(request_id, ring, req.message, context)
            .await
            .map_err(|e| UtilityError::Signing(format!("Signing failed: {}", e)))?;

        let sign_response: SignResponse = serde_json::from_slice(&response_bytes)
            .map_err(|e| UtilityError::Signing(format!("Failed to parse sign response: {}", e)))?;

        let signature_bytes = hex::decode(&sign_response.signature)
            .map_err(|e| UtilityError::Signing(format!("Failed to decode signature hex: {}", e)))?;

        Ok(Response::new(ProtoSignResponse {
            signature: signature_bytes,
            algorithm: ring_algorithm.into(),
            public_key: verification_pk,
            metadata: std::collections::HashMap::new(),
        }))
    }
}
