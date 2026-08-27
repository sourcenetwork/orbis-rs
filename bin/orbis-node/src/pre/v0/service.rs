use crate::app_state::AppState;
use crate::helpers::auth::{current_unix_time, extract_and_validate_jwt, request_actor};
use crate::helpers::identity::validate_all_peer_ids;
use crate::helpers::node_routes::{peer_ids_from_routes, resolve_node_routes};
use crate::helpers::ring::RingConfig;
use crate::metrics;
use crate::pre::v0::coordinator::{PreCoordinator, PreReportBinding};
use crate::pre::v0::error::PreError;
use crate::pre::v0::helpers::{
    check_policy_access, decode_ring_pk, deserialize_secret, resolve_document_and_ring_payloads,
    validate_pre_claims, verify_encryption_binding,
};
use crate::pre::v0::messages::PreRequestContext;
use crate::reporting::v0::types::ReportedDocumentEvidence;
use crate::reporting::v0::{build_signed_relay_statement, RelayStatementInputs};
use crate::ring_state::RingPolyState;
use authn::PreClaims;
use authz::vera::ValidWindow;
use bulletin::r#trait::DocumentPayload;
use crypto::r#trait::{
    DistKeyShare, Dkg, EncryptionProof, ReencryptReply, Secret, ThresholdDealer,
};
use crypto::PreImpl as ThresholdDealerNode;
use proto::v0::pre::{pre_service_server::PreService, StartPreRequest, StartPreResponse};
use std::sync::Arc;
use tonic::{Request, Response, Status};

/// Converts a caller-supplied `InlineDocument` into the internal `DocumentPayload` shape,
/// validating the encrypted document's structure along the way. Does not check `object_id` —
/// that happens in `resolve_document_and_ring_payloads` via `validate_inline_document_id`, which
/// every node (including cascaded committee members) independently re-runs.
///
/// `pub(crate)` so `unsafe_testing::service` can reuse it to inject a
/// `PreRequestContext.document` for integration tests exercising the inline-document path.
pub(crate) fn document_payload_from_inline(
    inline: proto::v0::pre::InlineDocument,
) -> Result<DocumentPayload, PreError> {
    crate::helpers::encrypted_document::validate_encrypted_document(
        &inline.encrypted_document,
        &inline.enc_cmt,
    )
    .map_err(PreError::InvalidInput)?;

    let document = String::from_utf8(inline.encrypted_document).map_err(|e| {
        PreError::InvalidInput(format!("encrypted_document is not valid UTF-8: {}", e))
    })?;

    let proof: String = EncryptionProof {
        shared_point: inline.shared_point,
        challenge: inline.challenge,
        response: inline.response,
    }
    .try_into()
    .map_err(|e: crypto::error::CryptoError| {
        PreError::Serialization(format!("Failed to serialize proof: {}", e))
    })?;

    Ok(DocumentPayload {
        ring_id: inline.ring_id,
        document,
        proof,
        policy_id: inline.policy_id,
        resource: inline.resource,
        permission: inline.permission,
        tier: inline.tier,
        timestamp: inline.timestamp,
    })
}
/// Implementation of the v0 PreService.
///
/// Accepts requests only for rings whose effective protocol version is 0.
/// Once a ring's activation_time passes and its effective version becomes 1,
/// callers must switch to the v1 PreService endpoint.
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

        // Get current timestamp (needed for both auth and response)
        let current_time = current_unix_time().map_err(|e| {
            tracing::error!("Failed to get current unix time: {}", e);
            PreError::SystemTime("Failed to get current timestamp".to_string())
        })?;

        // 1. Authenticate: Extract and validate JWT
        let (token_str, token) = extract_and_validate_jwt::<PreClaims, _>(&request, current_time)
            .map_err(PreError::Unauthorized)?;

        let mut req = request.into_inner();

        let valid_window = req.valid_window.map(|w| ValidWindow {
            start: w.start,
            end: w.end,
        });

        validate_pre_claims(
            &token,
            &req.rdr_pk,
            &req.object_id,
            &req.derivation,
            &req.salt,
        )?;

        // Resolve document and ring payloads. When the caller supplied `document` inline, it's
        // used directly instead of being read from the bulletin (validated against `object_id`
        // inside); otherwise this reads the document from the bulletin exactly as before.
        // Either way, ring_payload is always read live from the bulletin.
        // Validates that the ring's effective protocol version matches this service (v0).
        // Returns an error with version details if the ring has migrated to a newer version.
        let inline_document = req
            .document
            .take()
            .map(document_payload_from_inline)
            .transpose()?;
        let is_inline = inline_document.is_some();
        let (document_payload, ring_payload) = resolve_document_and_ring_payloads(
            &*self.state.bulletin,
            &req.object_id,
            self.routes.version,
            inline_document,
        )
        .await?;
        let ctx_document = is_inline.then(|| document_payload.clone());
        let document_evidence = ctx_document.as_ref().map(|doc| ReportedDocumentEvidence {
            document: doc.document.clone(),
            proof: doc.proof.clone(),
            policy_id: doc.policy_id.clone(),
            resource: doc.resource.clone(),
            permission: doc.permission.clone(),
            tier: doc.tier.clone(),
        });
        let actor_id = request_actor(&token, ring_payload.trusted_auth_relay_dids.as_deref())
            .map_err(PreError::Unauthorized)?;
        check_policy_access(
            &*self.state.authz,
            &document_payload,
            &req.object_id,
            &actor_id,
            valid_window.clone(),
        )
        .await?;

        // Validate metadata not tampered
        // Generate policy metadata for proof binding verification (before fields are moved)
        let policy_metadata = ThresholdDealerNode::encode_metadata(
            &document_payload.policy_id,
            &document_payload.resource,
            &document_payload.permission,
            document_payload.tier.clone().as_deref(),
            document_payload.timestamp,
            req.salt.as_deref(),
        );
        let (ring_pk_bytes, ring_pk) = decode_ring_pk(&ring_payload.ring_pk)?;
        let secret = deserialize_secret(&document_payload.document)?;

        verify_encryption_binding(
            &ring_pk,
            req.derivation.as_deref(),
            document_payload.proof,
            &secret.enc_cmt,
            &policy_metadata,
        )?;

        tracing::info!(
            ring_id = %document_payload.ring_id,
            ring_pk = %ring_payload.ring_pk,
            reader_pk = ?req.rdr_pk,
            peer_node_keys = ?ring_payload.peer_node_keys,
            issuer = %token.issuer_id,
            actor = %actor_id,
            "Authenticated StartPre request"
        );

        let created_at = current_time as i64;

        // 1. Parse inputs
        // Use original string bytes instead of re-serializing
        let secret_bytes = document_payload.document.as_bytes().to_vec();

        // 2. Validate we have peers
        if ring_payload.peer_node_keys.is_empty() {
            return Err(PreError::InvalidInput(
                "No peer node keys provided for reencryption".to_string(),
            )
            .into());
        }

        let routes = resolve_node_routes(&self.state.bulletin, &ring_payload.peer_node_keys)
            .await
            .map_err(PreError::InvalidInput)?;
        let peer_ids = peer_ids_from_routes(&routes);

        // 2b. Validate all peer IDs before attempting connections
        validate_all_peer_ids(&peer_ids).map_err(|(invalid_peer_id, validation_error)| {
            PreError::InvalidInput(format!(
                "Invalid peer ID '{}': {}",
                invalid_peer_id, validation_error
            ))
        })?;

        // 3. Generate unique request ID
        let request_id = rand::random::<u64>().to_string();

        // 4. Create coordinator and initiate reencryption
        // Per-peer connectivity is handled inside the coordinator via JoinSet tasks,
        // allowing threshold-of-n operation when some nodes are unreachable.
        let coordinator = PreCoordinator::<D, T>::with_routes(self.state.clone(), self.routes);
        let total_participants = peer_ids.len();
        let poly_state = RingPolyState::load(&self.state.local_storage, &ring_pk).map_err(|e| {
            tracing::error!("Failed to load ring polynomial state: {}", e);
            PreError::RingState("Failed to load ring polynomial state".to_string())
        })?;
        // Chain/ring binding for invalid-proof reporting, taken from the same
        // payloads that authorized this request (must be built before
        // `ring_payload.peer_node_keys` is moved into the RingConfig).
        let report_binding = PreReportBinding::from_ring(
            self.state.bulletin.chain_id(),
            document_payload.ring_id.clone(),
            &ring_payload,
            document_payload.timestamp,
            document_evidence,
        );
        // The relayer signs a record that it forwarded this request (after passing its own ACP
        // check above), so a peer whose re-check fails can attribute it via `unauthorized_request`.
        // `document_inline` (set above when this request's document was supplied inline) tells the
        // report verifier to expect the document out-of-band rather than read it from the
        // bulletin; the ciphertext itself is never signed into the statement.
        let (relay_statement, relay_signature) = build_signed_relay_statement(
            RelayStatementInputs {
                ring: ring_payload.clone(),
                ring_id: document_payload.ring_id.clone(),
                protocol_version: self.routes.version,
                chain_id: self.state.bulletin.chain_id(),
                request_id: request_id.clone(),
                origin_protocol: "pre".to_string(),
                relayer_node_key: self.state.node_key.clone(),
                actor_id: actor_id.clone(),
                object_id: req.object_id.clone(),
                user_signed_at: token.issued_time,
                acp_timestamp: document_payload.timestamp,
                valid_window: valid_window.clone(),
                document_inline: is_inline,
            },
            &self.state.local_storage,
        )
        .map_err(|e| PreError::Generic(format!("Failed to build relay statement: {}", e)))?;
        let relay_statement = Some(relay_statement);
        let ring = RingConfig {
            ring_id: document_payload.ring_id.clone(),
            ring_pk_bytes,
            peer_ids,
            peer_node_keys: ring_payload.peer_node_keys,
            threshold: ring_payload.threshold as usize,
            total_participants,
            public_polynomial_hex: poly_state.public_polynomial,
        };
        let ctx = PreRequestContext {
            rdr_pk_bytes: req.rdr_pk,
            object_id: req.object_id,
            token_string: token_str.to_string(),
            derivation: req.derivation,
            salt: req.salt,
            valid_window,
            relay_statement,
            relay_signature,
            document: ctx_document,
        };
        let result = coordinator
            .initiate_reencryption(request_id, ring, secret_bytes, ctx, report_binding)
            .await?;

        // 6. Parse result as PreResponse and encode as JSON
        let pre_response: crate::pre::v0::coordinator::PreResponse =
            serde_json::from_slice(&result).map_err(|e| {
                PreError::Deserialization(format!("Failed to parse PRE result: {}", e))
            })?;

        let encrypted_secret = serde_json::to_vec(&pre_response)
            .map_err(|e| PreError::Serialization(format!("Failed to serialize response: {}", e)))?;

        let response = StartPreResponse {
            status: "completed".to_string(),
            message: "PRE completed successfully".to_string(),
            created_at,
            encrypted_secret,
        };

        request_metrics.complete();
        grpc_metrics.success();

        Ok(Response::new(response))
    }
}
