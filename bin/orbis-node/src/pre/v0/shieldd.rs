//! Per-node PRE for selections resolved by the node's chosen Shieldd verifier.
use crate::{
    app_state::AppState,
    helpers::{
        auth::{current_unix_time, extract_and_validate_jwt, request_actor},
        protocol_version::read_ring_for_route,
    },
    ring_state::RingShareBundle,
};
use authn::PreClaims;
use authz::vera::AccessCheckRequest;
use crypto::r#trait::{DistKeyShare, Dkg, PriShare, PubPoly, ReaderKeyProof, ThresholdDealer};
use crypto::{CryptoDeserialize, CryptoSerialize, GroupAffine, PreImpl, PubPolyImpl, ScalarField};
use proto::v0::pre::{ReencryptShielddRequest, ReencryptShielddResponse};
use serde::Deserialize;
use std::{process::Stdio, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tonic::{Request, Response, Status};

const MAX_SELECTION: usize = 64 * 1024;
const MAX_RESPONSE: u64 = 1024 * 1024;
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
    derivation: Option<Vec<u8>>,
    object_id: String,
}

async fn invoke(executable: &str, args: &[&str], input: &[u8]) -> Result<Vec<u8>, Status> {
    let mut child = tokio::process::Command::new(executable)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| Status::unavailable("Shieldd verifier unavailable"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| Status::internal("verifier stdin unavailable"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Status::internal("verifier stdout unavailable"))?;
    let work = async {
        stdin
            .write_all(input)
            .await
            .map_err(|_| Status::unavailable("verifier input failed"))?;
        drop(stdin);
        let mut bytes = Vec::new();
        stdout
            .take(MAX_RESPONSE + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| Status::unavailable("verifier output failed"))?;
        if bytes.len() as u64 > MAX_RESPONSE {
            return Err(Status::resource_exhausted("verifier output too large"));
        }
        let status = child
            .wait()
            .await
            .map_err(|_| Status::unavailable("verifier wait failed"))?;
        if !status.success() {
            return Err(Status::failed_precondition(
                "transaction verification or acceptance unavailable",
            ));
        }
        Ok(bytes)
    };
    tokio::time::timeout(Duration::from_secs(90), work)
        .await
        .map_err(|_| Status::deadline_exceeded("Shieldd verification timed out"))?
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
    if selection.version != 1 || selection.policy.ring_id.len() > 1024 {
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
    if capabilities.protocol != 1 || capabilities.audit_ciphertext_version != 1 {
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
    if accepted.selection.version != 1
        || accepted.object_id != req.object_id
        || accepted.selection.policy.ring_id != selection.policy.ring_id
    {
        return Err(Status::failed_precondition("accepted selection mismatch"));
    }
    if accepted.derivation.is_some() {
        return Err(Status::failed_precondition(
            "named-person PRE requires authenticated transaction association",
        ));
    }
    super::helpers::validate_pre_claims(
        &token,
        &req.rdr_pk,
        &accepted.object_id,
        &accepted.derivation,
        &None,
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
        .check(permission, &actor)
        .await
        .map_err(|_| Status::unavailable("ACP unavailable"))?
    {
        return Err(Status::permission_denied("ACP denied Shieldd PRE"));
    }
    let ring_key =
        hex::decode(&ring.ring_pk).map_err(|_| Status::failed_precondition("invalid ring key"))?;
    let ring_point = GroupAffine::from_bytes(&ring_key)
        .map_err(|_| Status::failed_precondition("invalid ring key"))?;
    let bundle = RingShareBundle::load(&state.local_storage, &ring_point)
        .map_err(|_| Status::unavailable("ring share unavailable"))?;
    let polynomial_bytes = hex::decode(&bundle.public_polynomial)
        .map_err(|_| Status::failed_precondition("invalid ring polynomial"))?;
    let polynomial = PubPolyImpl::from_bytes(&polynomial_bytes)
        .map_err(|_| Status::failed_precondition("invalid ring polynomial"))?;
    if polynomial.eval(0) != ring_point
        || polynomial.commits.len() != ring.threshold as usize
        || ring.threshold == 0
    {
        return Err(Status::failed_precondition("ring polynomial mismatch"));
    }
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
        || current_ring.threshold != ring.threshold
    {
        return Err(Status::permission_denied(
            "ring authorization changed during verification",
        ));
    }
    let pri_share = PriShare::<ScalarField>::from_bytes(&bundle.share_bytes)
        .map_err(|_| Status::failed_precondition("invalid ring share"))?;
    let dealer = PreImpl::new();
    let reply = dealer
        .reencrypt_commitment(
            &DistKeyShare { pri_share },
            &accepted.epk,
            &reader,
            &proof,
            accepted.derivation.as_deref(),
        )
        .map_err(|_| Status::failed_precondition("Shieldd PRE failed"))?;
    let epk = GroupAffine::from_bytes(&accepted.epk)
        .map_err(|_| Status::failed_precondition("invalid accepted EPK"))?;
    dealer
        .verify(
            &reader,
            &polynomial,
            &epk,
            &reply,
            accepted.derivation.as_deref(),
        )
        .map_err(|_| Status::failed_precondition("ring share does not match polynomial"))?;
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
        public_polynomial: polynomial_bytes,
        ring_public_key: ring_key,
        threshold: ring.threshold,
    }))
}
