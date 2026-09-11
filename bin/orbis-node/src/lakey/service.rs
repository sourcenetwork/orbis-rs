use super::worker;
use crate::{
    app_state::AppState,
    helpers::{
        auth::{current_unix_time, extract_and_validate_jwt, request_actor},
        identity::determine_session_node_id,
        protocol_version::read_ring_for_route,
    },
    sign::v0::helpers::validate_sign_claims,
};
use authn::SignClaims;
use authz::vera::AccessCheckRequest;
use bulletin::lakey::{committee_id, Evaluation};
use crypto::{
    lakey::{
        evaluation_request_bytes, registration_object_id, Identity, Operation, PublicShare,
        WorkerRequest,
    },
    r#trait::Dkg,
};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use proto::v0::sign::{EvaluateShielddAuditKeyRequest, EvaluateShielddAuditKeyResponse};
use tonic::{Request, Response, Status};

pub async fn evaluate<D>(
    state: &AppState<D>,
    version: u64,
    request: Request<EvaluateShielddAuditKeyRequest>,
) -> Result<Response<EvaluateShielddAuditKeyResponse>, Status>
where
    D: Dkg + Clone + Send + Sync + 'static,
{
    if request.get_ref().identity_json.len() > 8192 {
        return Err(Status::resource_exhausted("LaKey identity too large"));
    }
    let (raw_token, token) = extract_and_validate_jwt::<SignClaims, _>(
        &request,
        current_unix_time().map_err(Status::internal)?,
    )
    .map_err(Status::unauthenticated)?;
    let request = request.into_inner();
    let identity: Identity = serde_json::from_slice(&request.identity_json)
        .map_err(|_| Status::invalid_argument("invalid LaKey identity"))?;
    let session: [u8; 32] = request
        .session
        .as_slice()
        .try_into()
        .map_err(|_| Status::invalid_argument("invalid LaKey session"))?;
    let message = evaluation_request_bytes(&identity, &session)
        .map_err(|_| Status::invalid_argument("invalid LaKey evaluation request"))?;
    let object = registration_object_id(&identity)
        .map_err(|_| Status::invalid_argument("invalid LaKey registration identity"))?;
    validate_sign_claims(&token, &object, Some(&message))
        .map_err(|_| Status::permission_denied("LaKey authentication binding mismatch"))?;
    let ring = read_ring_for_route(&*state.bulletin, &identity.ring, version)
        .await
        .map_err(Status::failed_precondition)?;
    let committee =
        committee_id(&ring).map_err(|_| Status::failed_precondition("invalid LaKey committee"))?;
    let index = determine_session_node_id(&state.node_key, &ring.peer_node_keys)
        .ok_or_else(|| Status::permission_denied("node is not in the LaKey committee"))?;
    let actor = request_actor(&token, ring.trusted_auth_relay_dids.as_deref())
        .map_err(Status::permission_denied)?;
    // Registration authority is separate from audit readers. The policy comes
    // from the authoritative ring, never from the caller's request.
    let policy = ring
        .policy_id
        .as_ref()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| Status::failed_precondition("ring registration policy unavailable"))?;
    let access = AccessCheckRequest::new(
        policy.clone(),
        "audit_registration".into(),
        object,
        "derive".into(),
        None,
        None,
        None,
    )
    .to_bytes()
    .map_err(|_| Status::internal("invalid registration access check"))?;
    if !state
        .authz
        .check(access.clone(), &actor)
        .await
        .map_err(|_| Status::unavailable("ACP unavailable"))?
    {
        return Err(Status::permission_denied(
            "ACP denied LaKey registration evaluation",
        ));
    }
    state
        .jti_guard
        .check_and_record(
            &token.jwt_id,
            token.expiration_time,
            "evaluate_shieldd_audit_key",
        )
        .await
        .map_err(|_| Status::permission_denied("replayed LaKey evaluation request"))?;
    let bytes = worker::invoke(
        &WorkerRequest {
            identity: identity.clone(),
            session,
            operation: Operation::PublicKey,
        },
        index,
    )
    .await
    .map_err(|_| Status::unavailable("LaKey evaluation unavailable"))?;
    let share: PublicShare = serde_json::from_slice(&bytes)
        .map_err(|_| Status::failed_precondition("invalid LaKey evaluation output"))?;
    if share.index != index {
        return Err(Status::failed_precondition(
            "LaKey evaluation index mismatch",
        ));
    }
    let fresh_token = authn::resolve_jwt_did::<SignClaims>(
        &raw_token,
        current_unix_time().map_err(Status::internal)?,
        crate::constants::MAX_TOKEN_LIFETIME_SECS,
        crate::constants::MAX_JWT_BYTES,
        crate::constants::JWT_CLOCK_SKEW_LEEWAY_SECS,
    )
    .map_err(|_| Status::unauthenticated("LaKey authentication expired during evaluation"))?;
    let current_ring = read_ring_for_route(&*state.bulletin, &identity.ring, version)
        .await
        .map_err(Status::failed_precondition)?;
    if committee_id(&current_ring).ok() != Some(committee)
        || current_ring.policy_id != ring.policy_id
        || request_actor(
            &fresh_token,
            current_ring.trusted_auth_relay_dids.as_deref(),
        )
        .map_err(Status::permission_denied)?
            != actor
    {
        return Err(Status::permission_denied(
            "LaKey registration authority changed",
        ));
    }
    if !state
        .authz
        .check(access, &actor)
        .await
        .map_err(|_| Status::unavailable("ACP unavailable after evaluation"))?
    {
        return Err(Status::permission_denied(
            "ACP denied LaKey evaluation release",
        ));
    }
    let mut evaluation = Evaluation {
        identity,
        session,
        committee,
        index,
        public_share: share.public_share,
        signature: Vec::new(),
    };
    let bytes = evaluation
        .signing_bytes()
        .map_err(|_| Status::failed_precondition("invalid LaKey evaluation point"))?;
    let signing_key = state
        .local_storage
        .get_encrypted(LocalStorageKeys::NodeSigningKey)
        .map_err(|_| Status::unavailable("node attestation key unavailable"))?
        .ok_or_else(|| Status::unavailable("node attestation key missing"))?;
    let key = std::str::from_utf8(&signing_key)
        .map_err(|_| Status::internal("invalid node attestation key"))?;
    evaluation.signature = common::blockchain::sign_node_message_with_hex_key(key, &bytes)
        .map_err(|_| Status::internal("node evaluation signing failed"))?;
    common::blockchain::verify_node_message(&state.node_key, &bytes, &evaluation.signature)
        .map_err(|_| {
            Status::failed_precondition("node attestation key does not match ring identity")
        })?;
    Ok(Response::new(EvaluateShielddAuditKeyResponse {
        evaluation_json: serde_json::to_vec(&evaluation)
            .map_err(|_| Status::internal("evaluation serialization failed"))?,
    }))
}
