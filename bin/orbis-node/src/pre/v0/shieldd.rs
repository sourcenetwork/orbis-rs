//! Per-node PRE for selections resolved by the node's chosen Shieldd verifier.
use crate::helpers::shieldd_sdk::invoke;
use crate::{
    app_state::AppState,
    helpers::{
        auth::{current_unix_time, extract_and_validate_jwt, request_actor},
        protocol_version::read_ring_for_route,
    },
};
use authn::PreClaims;
use authz::vera::AccessCheckRequest;
use crypto::lakey::{Identity, Operation, PreShare, WorkerRequest};
use crypto::r#trait::{Dkg, PubShare, ReaderKeyProof, ReencryptReply, ThresholdDealer};
use crypto::{CryptoDeserialize, CryptoSerialize, GroupAffine, PreImpl, PubPolyImpl, ScalarField};
use proto::v0::pre::{ReencryptShielddRequest, ReencryptShielddResponse};
use serde::Deserialize;
use tonic::{Request, Response, Status};

const MAX_SELECTION: usize = 64 * 1024;
static CONCURRENCY: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

#[derive(Deserialize)]
struct Capabilities {
    protocol: u32,
    audit_ciphertext_version: u32,
}

#[derive(Deserialize)]
struct Policy {
    ring_id: String,
    policy_id: String,
    resource: String,
    permission: String,
}

#[derive(Deserialize)]
struct Selection {
    version: u32,
    policy: Policy,
}

#[derive(Deserialize)]
struct AcceptedSelection {
    selection: Selection,
    epk: [u8; 32],
    identity: Identity,
    object_id: String,
}

fn validate_session(
    token: &authn::BearerToken<PreClaims>,
    req: &ReencryptShielddRequest,
) -> Result<[u8; 32], Status> {
    let session: [u8; 32] = req
        .session
        .as_slice()
        .try_into()
        .map_err(|_| Status::invalid_argument("LaKey session must be 32 bytes"))?;
    if session == [0; 32] {
        return Err(Status::invalid_argument("missing LaKey session"));
    }
    super::helpers::validate_pre_claims(
        token,
        &req.rdr_pk,
        &req.object_id,
        &None,
        &Some(hex::encode(session)),
    )
    .map_err(|_| Status::permission_denied("PRE session or request claims mismatch"))?;
    Ok(session)
}

pub async fn reencrypt<D>(
    state: &AppState<D>,
    version: u64,
    request: Request<ReencryptShielddRequest>,
) -> Result<Response<ReencryptShielddResponse>, Status>
where
    D: Dkg + Clone + Send + Sync + 'static,
{
    let now = current_unix_time().map_err(Status::internal)?;
    let (raw_token, token) =
        extract_and_validate_jwt::<PreClaims, _>(&request, now).map_err(Status::unauthenticated)?;
    let _permit = CONCURRENCY
        .try_acquire()
        .map_err(|_| Status::resource_exhausted("Shieldd PRE busy"))?;
    let req = request.into_inner();
    if req.selection_json.is_empty()
        || req.selection_json.len() > MAX_SELECTION
        || req.object_id.len() > 4096
    {
        return Err(Status::invalid_argument("invalid Shieldd selection size"));
    }
    let session = validate_session(&token, &req)?;
    let session_binding = Some(hex::encode(session));
    if token.subject_id.as_deref().is_none_or(str::is_empty) {
        return Err(Status::permission_denied(
            "Shieldd PRE requires an approved intermediary",
        ));
    }
    let proof = req
        .rdr_pk_proof
        .ok_or_else(|| Status::invalid_argument("reader proof required"))?;
    let reader = GroupAffine::from_bytes(&req.rdr_pk)
        .map_err(|_| Status::invalid_argument("invalid reader key"))?;
    let proof = ReaderKeyProof {
        challenge: proof.challenge,
        response: proof.response,
    };
    PreImpl::verify_reader_key(&reader, &proof)
        .map_err(|_| Status::permission_denied("invalid reader proof"))?;
    let selection: Selection = serde_json::from_slice(&req.selection_json)
        .map_err(|_| Status::invalid_argument("invalid Shieldd selection"))?;
    if selection.version != 2 || selection.policy.ring_id.len() > 1024 {
        return Err(Status::invalid_argument("unsupported Shieldd selection"));
    }
    let ring = read_ring_for_route(&*state.bulletin, &selection.policy.ring_id, version)
        .await
        .map_err(Status::failed_precondition)?;
    if !ring
        .trusted_auth_relay_dids
        .as_ref()
        .is_some_and(|ids| ids.contains(&token.issuer_id))
    {
        return Err(Status::permission_denied(
            "intermediary is not approved for this ring",
        ));
    }
    let actor = request_actor(&token, ring.trusted_auth_relay_dids.as_deref())
        .map_err(Status::permission_denied)?;
    if !ring.peer_node_keys.contains(&state.node_key) {
        return Err(Status::permission_denied(
            "node is not a member of the selected ring",
        ));
    }
    state
        .jti_guard
        .check_and_record(&token.jwt_id, token.expiration_time, "reencrypt_shieldd")
        .await
        .map_err(|_| Status::permission_denied("replayed Shieldd PRE request"))?;

    let executable = std::env::var("SHIELDD_AUDIT_VERIFIER")
        .map_err(|_| Status::unavailable("Shieldd verifier is not configured"))?;
    let node = std::env::var("SHIELDD_AUDIT_NODE")
        .map_err(|_| Status::unavailable("chosen Shieldd node is not configured"))?;
    let capabilities: Capabilities =
        serde_json::from_slice(&invoke(&executable, &["disclosure", "capabilities"], &[]).await?)
            .map_err(|_| Status::failed_precondition("invalid verifier capabilities"))?;
    if capabilities.protocol != 1 || capabilities.audit_ciphertext_version != 2 {
        return Err(Status::failed_precondition("incompatible Shieldd verifier"));
    }
    let bytes = invoke(
        &executable,
        &["disclosure", "audit-ciphertext", "-", "--node", &node],
        &req.selection_json,
    )
    .await?;
    let accepted: AcceptedSelection = serde_json::from_slice(&bytes)
        .map_err(|_| Status::failed_precondition("invalid accepted selection"))?;
    if accepted.selection.version != 2
        || accepted.object_id != req.object_id
        || accepted.selection.policy.ring_id != selection.policy.ring_id
    {
        return Err(Status::failed_precondition("accepted selection mismatch"));
    }
    if accepted.identity.ring != selection.policy.ring_id || accepted.identity.encode().is_err() {
        return Err(Status::failed_precondition(
            "invalid accepted LaKey identity",
        ));
    }
    if session == [0; 32] || ring.threshold != 3 || ring.peer_node_keys.len() != 5 {
        return Err(Status::failed_precondition(
            "LaKey requires a fresh session and a five-node committee",
        ));
    }
    super::helpers::validate_pre_claims(
        &token,
        &req.rdr_pk,
        &accepted.object_id,
        &None,
        &session_binding,
    )
    .map_err(|_| Status::permission_denied("request claims mismatch"))?;
    let policy = accepted.selection.policy;
    let permission = AccessCheckRequest::new(
        policy.policy_id,
        policy.resource,
        accepted.object_id,
        policy.permission,
        None,
        None,
        None,
    )
    .to_bytes()
    .map_err(|_| Status::internal("invalid access request"))?;
    if !state
        .authz
        .check(permission.clone(), &actor)
        .await
        .map_err(|_| Status::unavailable("ACP unavailable"))?
    {
        return Err(Status::permission_denied("ACP denied Shieldd PRE"));
    }
    let ring_key =
        hex::decode(&ring.ring_pk).map_err(|_| Status::failed_precondition("invalid ring key"))?;
    let _ring_point = GroupAffine::from_bytes(&ring_key)
        .map_err(|_| Status::failed_precondition("invalid ring key"))?;
    // Verification can outlast a token or an intermediary's ring membership.
    let fresh_token = authn::resolve_jwt_did::<PreClaims>(
        &raw_token,
        current_unix_time().map_err(Status::internal)?,
        crate::constants::MAX_TOKEN_LIFETIME_SECS,
        crate::constants::MAX_JWT_BYTES,
        crate::constants::JWT_CLOCK_SKEW_LEEWAY_SECS,
    )
    .map_err(|_| Status::unauthenticated("PRE authentication expired during verification"))?;
    let current_ring = read_ring_for_route(&*state.bulletin, &selection.policy.ring_id, version)
        .await
        .map_err(Status::failed_precondition)?;
    if !current_ring
        .trusted_auth_relay_dids
        .as_ref()
        .is_some_and(|ids| ids.contains(&fresh_token.issuer_id))
        || !current_ring.peer_node_keys.contains(&state.node_key)
        || current_ring.ring_pk != ring.ring_pk
        || current_ring.peer_node_keys != ring.peer_node_keys
        || current_ring.threshold != ring.threshold
    {
        return Err(Status::permission_denied(
            "ring authorization changed during verification",
        ));
    }
    let index =
        crate::helpers::identity::determine_session_node_id(&state.node_key, &ring.peer_node_keys)
            .ok_or_else(|| Status::permission_denied("node is not in LaKey committee"))?;
    let output = crate::lakey::worker::invoke(
        &WorkerRequest {
            identity: accepted.identity,
            session,
            operation: Operation::Pre {
                epk: accepted.epk,
                reader: req.rdr_pk,
                reader_proof: proof,
            },
        },
        index,
    )
    .await
    .map_err(|_| Status::unavailable("LaKey derivation or PRE unavailable"))?;
    let share: PreShare = serde_json::from_slice(&output)
        .map_err(|_| Status::failed_precondition("invalid LaKey PRE output"))?;
    if share.index != index {
        return Err(Status::failed_precondition("LaKey PRE index mismatch"));
    }
    let public_share = GroupAffine::from_bytes(&share.public_share)
        .map_err(|_| Status::failed_precondition("invalid LaKey public share"))?;
    let reply = ReencryptReply {
        share: PubShare {
            i: index,
            v: GroupAffine::from_bytes(&share.ciphertext_share)
                .map_err(|_| Status::failed_precondition("invalid LaKey ciphertext share"))?,
        },
        challenge: ScalarField::from_bytes(&share.challenge)
            .map_err(|_| Status::failed_precondition("invalid LaKey challenge"))?,
        proof: ScalarField::from_bytes(&share.proof)
            .map_err(|_| Status::failed_precondition("invalid LaKey proof"))?,
    };
    let epk = GroupAffine::from_bytes(&accepted.epk)
        .map_err(|_| Status::failed_precondition("invalid accepted EPK"))?;
    PreImpl::new()
        .verify(
            &reader,
            &PubPolyImpl {
                commits: vec![public_share],
            },
            &epk,
            &reply,
            None,
        )
        .map_err(|_| Status::failed_precondition("invalid LaKey PRE evidence"))?;
    let fresh_token = authn::resolve_jwt_did::<PreClaims>(
        &raw_token,
        current_unix_time().map_err(Status::internal)?,
        crate::constants::MAX_TOKEN_LIFETIME_SECS,
        crate::constants::MAX_JWT_BYTES,
        crate::constants::JWT_CLOCK_SKEW_LEEWAY_SECS,
    )
    .map_err(|_| Status::unauthenticated("PRE authentication expired during derivation"))?;
    let current_ring = read_ring_for_route(&*state.bulletin, &selection.policy.ring_id, version)
        .await
        .map_err(Status::failed_precondition)?;
    if current_ring.peer_node_keys != ring.peer_node_keys
        || current_ring.ring_pk != ring.ring_pk
        || current_ring.threshold != ring.threshold
        || !current_ring
            .trusted_auth_relay_dids
            .as_ref()
            .is_some_and(|ids| ids.contains(&fresh_token.issuer_id))
    {
        return Err(Status::permission_denied(
            "ring authorization changed during derivation",
        ));
    }
    if !state
        .authz
        .check(permission, &actor)
        .await
        .map_err(|_| Status::unavailable("ACP unavailable after derivation"))?
    {
        return Err(Status::permission_denied(
            "ACP denied release of PRE result",
        ));
    }
    Ok(Response::new(ReencryptShielddResponse {
        accepted_selection_json: bytes,
        share_index: reply.share.i,
        share: reply
            .share
            .v
            .to_bytes()
            .map_err(|_| Status::internal("share encoding failed"))?,
        challenge: CryptoSerialize::to_bytes(&reply.challenge)
            .map_err(|_| Status::internal("challenge encoding failed"))?,
        proof: CryptoSerialize::to_bytes(&reply.proof)
            .map_err(|_| Status::internal("proof encoding failed"))?,
        public_share: share.public_share,
        ring_public_key: ring_key,
        threshold: ring.threshold,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_binding_rejects_substitution_before_mpc() {
        let mut request = ReencryptShielddRequest {
            object_id: "accepted-object".into(),
            rdr_pk: vec![7; 32],
            session: vec![1; 32],
            ..Default::default()
        };
        let token = authn::BearerToken {
            issuer_id: "intermediary".into(),
            subject_id: Some("auditor".into()),
            issued_time: 1,
            expiration_time: 2,
            not_before: None,
            jwt_id: "nonce".into(),
            claims: PreClaims {
                object_id: request.object_id.clone(),
                rdr_pk: request.rdr_pk.clone(),
                derivation: None,
                salt: Some(hex::encode(&request.session)),
            },
        };
        assert_eq!(validate_session(&token, &request).unwrap(), [1; 32]);
        request.session = vec![2; 32];
        assert!(validate_session(&token, &request).is_err());
        request.session = vec![0; 32];
        assert!(validate_session(&token, &request).is_err());
        request.session = vec![1; 31];
        assert!(validate_session(&token, &request).is_err());
        request.session = vec![1; 32];
        let mut unsigned = token.clone();
        unsigned.claims.salt = None;
        assert!(validate_session(&unsigned, &request).is_err());
        request.object_id.push('x');
        assert!(validate_session(&token, &request).is_err());
    }
}
