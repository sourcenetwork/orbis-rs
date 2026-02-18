use crate::app_state::AppState;
use crate::constants::BULLETIN_RING_NAMESPACE;
use crate::sign::coordinator::{SignCoordinator, SignResponse};
use crate::utility::error::UtilityError;
use authn::{extract_bearer_token, resolve_jwt_did, BearerToken, SignClaims};
use bulletin::r#trait::RingPayload;
use crypto::r#trait::{CryptoDeserialize, CryptoSerialize, Dkg, ThresholdDealer};
use crypto::PreImpl as ThresholdDealerNode;
use proto::utility_service::{
    utility_service_server::UtilityService, DerivePublicKeyRequest, DerivePublicKeyResponse,
    SignRequest, SignResponse as ProtoSignResponse,
};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tonic::{Request, Response, Status};

/// Implementation of the UtilityService
///
/// Provides two RPCs:
/// - DerivePublicKey: derive a public key from a ring's master PK + label (unauthenticated)
/// - Sign: perform T-of-N threshold signing (authenticated)
#[derive(Debug)]
pub struct UtilityServiceImpl<D, S>
where
    D: Dkg + Clone + 'static,
    S: crypto::r#trait::ThresholdSigner,
{
    pub state: AppState<D>,
    _phantom: std::marker::PhantomData<S>,
}

impl<D, S> UtilityServiceImpl<D, S>
where
    D: Dkg + Clone + 'static,
    S: crypto::r#trait::ThresholdSigner,
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

        // 4. Serialize to hex
        let derived_pk_bytes = CryptoSerialize::to_bytes(&derived_pk).map_err(|e| {
            UtilityError::Crypto(format!("Failed to serialize derived public key: {}", e))
        })?;

        Ok(Response::new(DerivePublicKeyResponse {
            public_key: derived_pk_bytes,
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
        let token: BearerToken<SignClaims> = resolve_jwt_did(token_str, current_time)
            .map_err(|e| {
                UtilityError::Unauthorized(format!("JWT validation failed: {}", e))
            })?;

        let req = request.into_inner();

        // 2. Validate JWT claims match request
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

        tracing::info!(
            ring_id = %req.ring_id,
            message_len = req.message.len(),
            issuer = %token.issuer_id,
            "Authenticated Sign request"
        );

        // 3. Read ring info from bulletin
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

        // 4. Initiate threshold signing
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
        }))
    }
}
