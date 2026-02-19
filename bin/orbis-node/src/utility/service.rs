use crate::app_state::AppState;
use crate::constants::BULLETIN_RING_NAMESPACE;
use crate::sign::coordinator::{SignCoordinator, SignResponse};
use crate::sign::messages::SignVerification;
use crate::utility::error::UtilityError;
use authn::{extract_bearer_token, resolve_jwt_did, BearerToken, SignClaims};
use authz::sourcehub::AccessCheckRequest;
use bulletin::r#trait::RingPayload;
use crypto::r#trait::{CryptoDeserialize, CryptoSerialize, Dkg, ThresholdDealer, ThresholdSigner};
use crypto::PreImpl as ThresholdDealerNode;
use proto::utility_service::{
    utility_service_server::UtilityService, DerivePublicKeyRequest, DerivePublicKeyResponse,
    SignAlgorithm, SignRequest, SignResponse as ProtoSignResponse,
};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tonic::{Request, Response, Status};

/// Map a ThresholdSigner::name() string to the proto SignAlgorithm enum.
///
/// This is the single mapping point between the compile-time crypto
/// implementation and the wire protocol. When a new signing scheme is
/// added, register its name() string here.
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
///
/// The signing algorithm is determined at compile time by the `S` type parameter
/// (BLS12-381 or FROST/Decaf377). The proto `SignAlgorithm` enum communicates
/// this to clients so they know how to verify signatures.
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
                UtilityError::RingNotFound(format!(
                    "Failed to read ring '{}': {}",
                    req.ring_id, e
                ))
            })?;

        let ring_payload =
            serde_json::from_slice::<RingPayload>(&ring_info.payload).map_err(|e| {
                UtilityError::Deserialization(format!("Failed to parse ring payload: {}", e))
            })?;

        // 2. Parse ring_pk from hex -> G1Affine
        let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).map_err(|e| {
            UtilityError::Deserialization(format!("Invalid ring_pk hex: {}", e))
        })?;
        let ring_pk = <D::PublicKey>::from_bytes(&ring_pk_bytes).map_err(|e| {
            UtilityError::Deserialization(format!("Invalid ring_pk curve point: {}", e))
        })?;

        // 3. Derive public key
        let derived_pk =
            ThresholdDealerNode::derive_public_key(&ring_pk, &req.derivation).map_err(|e| {
                UtilityError::Crypto(format!("Failed to derive public key: {}", e))
            })?;

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
        let jwt_string = token_str.to_string(); // Save for forwarding to responder nodes
        let token: BearerToken<SignClaims> = resolve_jwt_did(token_str, current_time)
            .map_err(|e| {
                UtilityError::Unauthorized(format!("JWT validation failed: {}", e))
            })?;

        let req = request.into_inner();

        // 2. Algorithm guard: if the client specified an algorithm, verify it matches
        let ring_algorithm = signer_algorithm::<S>();
        let requested = SignAlgorithm::try_from(req.algorithm).unwrap_or(SignAlgorithm::Unspecified);
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
            return Err(
                UtilityError::Unauthorized("Token message does not match request".to_string())
                    .into(),
            );
        }
        // Compare derivation: JWT has Option<Vec<u8>>, proto has Vec<u8> (empty = none)
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

        // Validate ACP claims match request
        if token.claims.policy_id != req.policy_id {
            return Err(UtilityError::Unauthorized(format!(
                "Token policy_id '{}' does not match request policy_id '{}'",
                token.claims.policy_id, req.policy_id
            ))
            .into());
        }
        if token.claims.resource != req.resource {
            return Err(UtilityError::Unauthorized(format!(
                "Token resource '{}' does not match request resource '{}'",
                token.claims.resource, req.resource
            ))
            .into());
        }
        if token.claims.object_id != req.object_id {
            return Err(UtilityError::Unauthorized(format!(
                "Token object_id '{}' does not match request object_id '{}'",
                token.claims.object_id, req.object_id
            ))
            .into());
        }
        if token.claims.permission != req.permission {
            return Err(UtilityError::Unauthorized(format!(
                "Token permission '{}' does not match request permission '{}'",
                token.claims.permission, req.permission
            ))
            .into());
        }

        // Check ACP authorization on SourceHub (if policy_id is provided)
        if !req.policy_id.is_empty() {
            let permission_bytes = AccessCheckRequest::new(
                &req.policy_id,
                &req.resource,
                &req.object_id,
                &req.permission,
            )
            .to_bytes()
            .map_err(|e| {
                UtilityError::Signing(format!("Error formatting access request: {}", e))
            })?;
            self.state
                .authz
                .check(permission_bytes, &token.issuer_id)
                .await
                .map_err(|e| UtilityError::Signing(format!("ACP authorization failed: {}", e)))?;
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
                UtilityError::RingNotFound(format!(
                    "Failed to read ring '{}': {}",
                    req.ring_id, e
                ))
            })?;

        let ring_payload =
            serde_json::from_slice::<RingPayload>(&ring_info.payload).map_err(|e| {
                UtilityError::Deserialization(format!("Failed to parse ring payload: {}", e))
            })?;

        // 5. Compute the public key that will verify this signature
        let ring_pk_bytes = hex::decode(&ring_payload.ring_pk).map_err(|e| {
            UtilityError::Deserialization(format!("Invalid ring_pk hex: {}", e))
        })?;
        let verification_pk = if req.derivation.is_empty() {
            ring_pk_bytes.clone()
        } else {
            let ring_pk = <D::PublicKey>::from_bytes(&ring_pk_bytes).map_err(|e| {
                UtilityError::Deserialization(format!("Invalid ring_pk curve point: {}", e))
            })?;
            let derived = ThresholdDealerNode::derive_public_key(&ring_pk, &req.derivation)
                .map_err(|e| UtilityError::Crypto(format!("Failed to derive public key: {}", e)))?;
            CryptoSerialize::to_bytes(&derived)
                .map_err(|e| UtilityError::Crypto(format!("Failed to serialize public key: {}", e)))?
        };

        // 6. Initiate threshold signing
        let session_id: u64 = rand::random();
        let coordinator = SignCoordinator::<D, S>::new(Arc::new(self.state.clone()));
        let response_bytes = coordinator
            .initiate_signing(
                session_id.to_string(),
                hex::decode(&ring_payload.ring_pk).map_err(|e| {
                    UtilityError::Deserialization(format!("Invalid ring_pk hex: {}", e))
                })?,
                req.message,
                &ring_payload.peer_ids,
                ring_payload.threshold as usize,
                ring_payload.peer_ids.len(),
                &ring_payload.public_polynomial,
                req.ring_id.clone(),
                SignVerification::Authenticated {
                    jwt: jwt_string,
                    policy_id: req.policy_id.clone(),
                    resource: req.resource.clone(),
                    object_id: req.object_id.clone(),
                    permission: req.permission.clone(),
                },
            )
            .await
            .map_err(|e| UtilityError::Signing(format!("Signing failed: {}", e)))?;

        let sign_response: SignResponse =
            serde_json::from_slice(&response_bytes).map_err(|e| {
                UtilityError::Signing(format!("Failed to parse sign response: {}", e))
            })?;

        let signature_bytes = hex::decode(&sign_response.signature).map_err(|e| {
            UtilityError::Signing(format!("Failed to decode signature hex: {}", e))
        })?;

        Ok(Response::new(ProtoSignResponse {
            signature: signature_bytes,
            algorithm: ring_algorithm.into(),
            public_key: verification_pk,
            metadata: std::collections::HashMap::new(),
        }))
    }
}
