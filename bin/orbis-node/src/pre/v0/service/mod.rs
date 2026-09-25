use crate::app_state::AppState;
use crate::helpers::auth::current_unix_time;
use crate::metrics;
use crate::pre::v0::error::PreError;
use crypto::r#trait::{
    DistKeyShare, Dkg, EncryptionProof, ReencryptReply, Secret, ThresholdDealer,
};
use proto::v0::pre::{pre_service_server::PreService, StartPreRequest, StartPreResponse};
use std::sync::Arc;
use tonic::{Request, Response, Status};

mod stages;
use stages::{encode_pre_response, validate_pre_request_size};

/// Converts a caller-supplied `InlineDocument` into the internal `DocumentPayload` shape,
/// validating the encrypted document's structure along the way. Does not check `object_id` —
/// that happens in `resolve_document_and_ring_payloads` via `check_document_id_binding` (after the
/// protocol-version gate), which every node (including cascaded committee members) independently
/// re-runs.
///
/// `pub(crate)` so `unsafe_testing::service` can reuse it to inject a
/// `PreRequestContext.document` for integration tests exercising the inline-document path.
pub(crate) fn document_payload_from_inline(
    inline: proto::v0::pre::InlineDocument,
) -> Result<bulletin::r#trait::DocumentPayload, PreError> {
    crate::helpers::encrypted_document::validate_encrypted_document(
        &inline.encrypted_document,
        &inline.enc_cmt,
    )
    .map_err(PreError::InvalidInput)?;

    let document = String::from_utf8(inline.encrypted_document).map_err(|e| {
        PreError::InvalidInput(format!("encrypted_document is not valid UTF-8: {}", e))
    })?;

    let proof: String = EncryptionProof {
        challenge: inline.challenge,
        response: inline.response,
    }
    .try_into()
    .map_err(|e: crypto::error::CryptoError| {
        PreError::Serialization(format!("Failed to serialize proof: {}", e))
    })?;

    let (pet_tag, pet_tag_proof) = match inline.pet_tag {
        Some(attachment) => {
            let (pet_tag, pet_tag_proof) =
                crate::helpers::pet_tag::pet_tag_attachment_to_document_fields(
                    attachment.ephemeral_point,
                    attachment.masked_fingerprint,
                    attachment.knowledge_proof_challenge,
                    attachment.knowledge_proof_response,
                )
                .map_err(PreError::InvalidInput)?;
            (Some(pet_tag), Some(pet_tag_proof))
        }
        None => (None, None),
    };

    Ok(bulletin::r#trait::DocumentPayload {
        ring_id: inline.ring_id,
        document,
        proof,
        policy_id: inline.policy_id,
        resource: inline.resource,
        permission: inline.permission,
        tier: inline.tier,
        timestamp: inline.timestamp,
        pet_tag,
        pet_tag_proof,
    })
}

/// Implementation of the v0 PreService.
///
/// Accepts requests only for rings whose effective protocol version is 0.
/// Once a ring's activation_time passes and its effective version becomes 1,
/// callers must switch to the v1 PreService endpoint.
///
/// `start_pre`'s request pipeline is a sequence of named stages defined in
/// `stages.rs` — see that module's docs for what each one does and the
/// security-sensitive ordering between the policy check and single-use JWT
/// enforcement.
#[derive(Debug)]
pub struct PreServiceImpl<D, T>
where
    D: Dkg + Clone + 'static,
    T: ThresholdDealer,
{
    pub state: Arc<AppState<D>>,
    pub routes: &'static network::ProtocolRoutes,
    _phantom: std::marker::PhantomData<T>,
}

impl<D, T> PreServiceImpl<D, T>
where
    D: Dkg + Clone + 'static,
    T: ThresholdDealer,
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
impl<D, T> PreService for PreServiceImpl<D, T>
where
    D: Dkg<
            ShareValue = crypto::ScalarField,
            PublicKey = crypto::GroupAffine,
            PolynomialCommitment = crypto::PolynomialCommitmentImpl,
            PubPoly = crypto::PubPolyImpl,
        > + Clone
        + Send
        + Sync
        + 'static,
    T: ThresholdDealer<
            ShareValue = crypto::ScalarField,
            PublicKey = crypto::GroupAffine,
            DistKeyShare = DistKeyShare<crypto::ScalarField>,
            Secret = Secret,
            ReencryptReply = ReencryptReply<crypto::ScalarField, crypto::GroupAffine>,
            PubPoly = D::PubPoly,
        > + Send
        + Sync
        + 'static,
{
    #[tracing::instrument(skip_all, fields(request))]
    async fn start_pre(
        &self,
        request: Request<StartPreRequest>,
    ) -> Result<Response<StartPreResponse>, Status> {
        let grpc_metrics = metrics::GrpcRequestGuard::new("pre", "start_pre");
        let request_metrics = metrics::track_pre_request();

        // Get current timestamp (needed for both auth and the response).
        let current_time = current_unix_time().map_err(|e| {
            tracing::error!("Failed to get current unix time: {}", e);
            PreError::SystemTime("Failed to get current timestamp".to_string())
        })?;

        validate_pre_request_size(&request)?;

        // 1. Authentication.
        let (authenticated, inline_document) =
            Self::authenticate_pre_request(request, current_time)?;

        // 2. Bulletin reads.
        let bulletin_state = self
            .resolve_pre_bulletin_state(
                &authenticated.object_id,
                inline_document,
                &authenticated.token,
            )
            .await?;

        // 3. Policy checks (ACP, then single-use JWT enforcement, then ciphertext-
        //    binding verification — see `stages::authorize_pre_request`'s docs for the
        //    security-sensitive ordering between the ACP check and the JWT check).
        let authorized = self
            .authorize_pre_request(authenticated, bulletin_state)
            .await?;
        let ciphertext_context = authorized.ciphertext_context.clone();

        // 3.5. PET check (no-op unless the ring requires it). The returned attestations are
        //      forwarded to every PRE peer so each one independently re-verifies the same
        //      check before releasing its share.
        let pet_attestations = self.check_pet_if_required(&authorized).await?;

        // 4. Relay setup.
        let setup = self.prepare_pre_relay(authorized, pet_attestations).await?;

        // 5. Coordination.
        let result = self.coordinate_pre_reencryption(setup).await?;

        // 6. Response encoding.
        let response = encode_pre_response(result, ciphertext_context, current_time as i64)?;

        request_metrics.complete();
        grpc_metrics.success();

        Ok(Response::new(response))
    }
}
