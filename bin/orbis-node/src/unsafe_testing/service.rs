use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::app_state::AppState;
use crate::constants::RELAY_CHECK_MAX_DRIFT_SECS;
use crate::dkg::v0::coordinator::evidence::{
    build_and_store_commitment_evidence, queue_invalid_refresh_commitment_report,
    queue_or_relay_equivocation, queue_or_relay_invalid_share, share_evidence_proves_failure,
    verify_share_evidence,
};
use crate::dkg::v0::coordinator::reporting::report_abandoned_pss_session;
use crate::dkg::v0::coordinator::DkgCoordinator;
use crate::dkg::v0::helpers::{deserialize_wire_commitment, ring_payload_matches_ring_key};
use crate::dkg::v0::messages::{SessionKind, SignedDkgCommitment, SignedDkgShare};
use crate::dkg::v0::network::{
    contribution_ids, coordinate_refresh_as_claimed_leader, submit_public_contribution,
    RefreshStartOutcome,
};
use crate::dkg::v0::session_state::AbandonedPssSession;
use crate::dkg::v0::transport::{
    self, AttemptKey, CeremonyId, DkgPublicMessage, DkgPublicPayload, PhaseManifest, PublicPhase,
};
use crate::helpers::protocol_version::read_ring_for_route;
use crate::pre::v0::coordinator::PreCoordinator;
use crate::pre::v0::messages::{PreMessage, PreRequestContext, ReencryptRequest};
use crate::reporting::v0::types::RelayRequestStatement;
use crate::sign::v0::coordinator::SignCoordinator;
use crate::sign::v0::helpers::refresh_health_check_peer_node_keys_sha256;
use crate::sign::v0::messages::{
    NonceRequest, PolicyContext, RefreshHealthCheckStatement, SignContext, SignMessage,
    REFRESH_HEALTH_CHECK_DOMAIN,
};
use bulletin::r#trait::{BulletinKind, KeyDerivation};
use common::blockchain::verify_node_message;
use crypto::r#trait::{Dkg as _, PolynomialCommitment as _};
use crypto::{DkgImpl, PreImpl, SignImpl};
use local_storage::{
    r#trait::{LocalStorage, LocalStorageKeys},
    LocalStorageImpl,
};
use proto::unsafe_testing::{
    unsafe_testing_service_server::UnsafeTestingService, DeleteLocalStorageRequest,
    DeleteLocalStorageResponse, GetActivePssSessionRequest, GetActivePssSessionResponse,
    GetLocalStorageRequest, GetLocalStorageResponse, LocalStorageAccessMode, LocalStorageKey,
    LocalStorageKeyType, SetLocalStorageRequest, SetLocalStorageResponse,
    SubmitDkgEquivocationEvidenceRequest, SubmitDkgEquivocationEvidenceResponse,
    SubmitDkgInvalidRefreshCommitmentEvidenceRequest,
    SubmitDkgInvalidRefreshCommitmentEvidenceResponse, SubmitDkgInvalidShareEvidenceRequest,
    SubmitDkgInvalidShareEvidenceResponse, SubmitOrganicConflictingCommitmentRequest,
    SubmitOrganicConflictingCommitmentResponse, SubmitOrganicConflictingManifestRequest,
    SubmitOrganicConflictingManifestResponse, SubmitOrganicInvalidRefreshResultRequest,
    SubmitOrganicInvalidRefreshResultResponse, SubmitOrganicNoncanonicalPrepareRequest,
    SubmitOrganicNoncanonicalPrepareResponse, SubmitPssStallOfflineReportRequest,
    SubmitPssStallOfflineReportResponse, SubmitUnauthorizedRelayEvidenceRequest,
    SubmitUnauthorizedRelayEvidenceResponse,
};
use tonic::{Request, Response, Status};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct UnsafeTestingServiceImpl {
    local_storage: LocalStorageImpl,
    app_state: Option<Arc<AppState<DkgImpl>>>,
}

impl UnsafeTestingServiceImpl {
    #[cfg(test)]
    pub fn new(local_storage: LocalStorageImpl) -> Self {
        Self {
            local_storage,
            app_state: None,
        }
    }

    pub fn with_app_state(app_state: Arc<AppState<DkgImpl>>) -> Self {
        Self {
            local_storage: app_state.local_storage.clone(),
            app_state: Some(app_state),
        }
    }
}

fn parse_key(key: Option<LocalStorageKey>) -> Result<LocalStorageKeys, Status> {
    let key = key.ok_or_else(|| Status::invalid_argument("local storage key is required"))?;
    let key_type = LocalStorageKeyType::try_from(key.key_type)
        .map_err(|_| Status::invalid_argument("unknown local storage key type"))?;

    match key_type {
        LocalStorageKeyType::RingIndex => {
            reject_ring_key_value(&key.ring_key)?;
            Ok(LocalStorageKeys::RingIndex)
        }
        LocalStorageKeyType::RingKey => {
            if key.ring_key.trim().is_empty() {
                return Err(Status::invalid_argument(
                    "ring_key is required for RING_KEY",
                ));
            }
            Ok(LocalStorageKeys::RingKey(key.ring_key))
        }
        LocalStorageKeyType::NodeSecretKey => {
            reject_ring_key_value(&key.ring_key)?;
            Ok(LocalStorageKeys::NodeSecretKey)
        }
        LocalStorageKeyType::NodeSigningKey => {
            reject_ring_key_value(&key.ring_key)?;
            Ok(LocalStorageKeys::NodeSigningKey)
        }
        LocalStorageKeyType::Unspecified => Err(Status::invalid_argument(
            "local storage key type must be specified",
        )),
    }
}

fn reject_ring_key_value(ring_key: &str) -> Result<(), Status> {
    if ring_key.is_empty() {
        Ok(())
    } else {
        Err(Status::invalid_argument(
            "ring_key is only valid for RING_KEY",
        ))
    }
}

fn parse_access_mode(value: i32) -> Result<LocalStorageAccessMode, Status> {
    match LocalStorageAccessMode::try_from(value)
        .map_err(|_| Status::invalid_argument("unknown local storage access mode"))?
    {
        LocalStorageAccessMode::Plain => Ok(LocalStorageAccessMode::Plain),
        LocalStorageAccessMode::Encrypted => Ok(LocalStorageAccessMode::Encrypted),
        LocalStorageAccessMode::Unspecified => Err(Status::invalid_argument(
            "local storage access mode must be specified",
        )),
    }
}

fn storage_error(operation: &str, error: impl std::fmt::Display) -> Status {
    Status::internal(format!("failed to {operation} local storage: {error}"))
}

fn current_unix_time() -> Result<u64, Status> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| Status::internal(format!("system clock before unix epoch: {error}")))
}

#[tonic::async_trait]
impl UnsafeTestingService for UnsafeTestingServiceImpl {
    async fn get_local_storage(
        &self,
        request: Request<GetLocalStorageRequest>,
    ) -> Result<Response<GetLocalStorageResponse>, Status> {
        let request = request.into_inner();
        let key = parse_key(request.key)?;
        let value = match parse_access_mode(request.access_mode)? {
            LocalStorageAccessMode::Plain => self
                .local_storage
                .get(key)
                .map_err(|error| storage_error("get", error))?,
            LocalStorageAccessMode::Encrypted => self
                .local_storage
                .get_encrypted(key)
                .map_err(|error| storage_error("get encrypted", error))?
                .map(|value| value.to_vec()),
            LocalStorageAccessMode::Unspecified => unreachable!(),
        };

        Ok(Response::new(GetLocalStorageResponse {
            found: value.is_some(),
            value: value.unwrap_or_default(),
        }))
    }

    async fn set_local_storage(
        &self,
        request: Request<SetLocalStorageRequest>,
    ) -> Result<Response<SetLocalStorageResponse>, Status> {
        let request = request.into_inner();
        let key = parse_key(request.key)?;
        match parse_access_mode(request.access_mode)? {
            LocalStorageAccessMode::Plain => self
                .local_storage
                .set(key, request.value)
                .map_err(|error| storage_error("set", error))?,
            LocalStorageAccessMode::Encrypted => self
                .local_storage
                .set_encrypted(key, Zeroizing::new(request.value))
                .map_err(|error| storage_error("set encrypted", error))?,
            LocalStorageAccessMode::Unspecified => unreachable!(),
        }

        Ok(Response::new(SetLocalStorageResponse {}))
    }

    async fn delete_local_storage(
        &self,
        request: Request<DeleteLocalStorageRequest>,
    ) -> Result<Response<DeleteLocalStorageResponse>, Status> {
        let key = parse_key(request.into_inner().key)?;
        let existed = self
            .local_storage
            .contains(key.clone())
            .map_err(|error| storage_error("check", error))?;
        self.local_storage
            .delete(key)
            .map_err(|error| storage_error("delete", error))?;

        Ok(Response::new(DeleteLocalStorageResponse { existed }))
    }

    async fn get_active_pss_session(
        &self,
        request: Request<GetActivePssSessionRequest>,
    ) -> Result<Response<GetActivePssSessionResponse>, Status> {
        let ring_pk = request.into_inner().ring_pk;
        if ring_pk.trim().is_empty() {
            return Err(Status::invalid_argument("ring_pk is required"));
        }
        let app_state = self.app_state.clone().ok_or_else(|| {
            Status::failed_precondition("unsafe PSS session lookup requires app state")
        })?;
        let session_id = app_state
            .dkg_session_state
            .active_ring_pss_session(&ring_pk)
            .await;
        let activated = match session_id {
            Some(session_id) => {
                match app_state
                    .dkg_session_state
                    .transport_attempt(&session_id)
                    .await
                {
                    Some(attempt_id) => {
                        let attempt = AttemptKey::new(CeremonyId(session_id), attempt_id);
                        app_state
                            .dkg_session_state
                            .with_attempt_state(attempt, |state| state.transport.activated)
                            .await
                            .unwrap_or(false)
                    }
                    None => false,
                }
            }
            None => false,
        };
        Ok(Response::new(GetActivePssSessionResponse {
            found: session_id.is_some(),
            session_id: session_id.map(|id| id.to_string()).unwrap_or_default(),
            activated,
        }))
    }

    async fn submit_dkg_invalid_share_evidence(
        &self,
        request: Request<SubmitDkgInvalidShareEvidenceRequest>,
    ) -> Result<Response<SubmitDkgInvalidShareEvidenceResponse>, Status> {
        let request = request.into_inner();
        let session_id = request
            .session_id
            .parse::<u128>()
            .map_err(|error| Status::invalid_argument(format!("invalid session_id: {error}")))?;
        let evidence: SignedDkgShare =
            serde_json::from_slice(&request.signed_share_json).map_err(|error| {
                Status::invalid_argument(format!("invalid signed_share_json: {error}"))
            })?;
        let app_state = self.app_state.clone().ok_or_else(|| {
            Status::failed_precondition("unsafe DKG evidence injection requires app state")
        })?;
        let attempt_id = app_state
            .dkg_session_state
            .transport_attempt(&session_id)
            .await
            .ok_or_else(|| {
                Status::failed_precondition("DKG report evidence is not active for this session")
            })?;
        let attempt = AttemptKey::new(CeremonyId(session_id), attempt_id);
        let coordinator = DkgCoordinator::<DkgImpl>::with_routes(app_state, &network::V0);

        let from_node_id = evidence.statement.from_node_id;
        let to_node_id = evidence.statement.to_node_id;
        let share_value = evidence.statement.share_value.clone();
        let nonce = evidence.statement.nonce;
        let verified = verify_share_evidence::<DkgImpl>(
            &coordinator,
            attempt,
            from_node_id,
            to_node_id,
            &share_value,
            nonce,
            Some(evidence),
        )
        .await
        .map_err(|error| Status::failed_precondition(error.to_string()))?
        .ok_or_else(|| Status::failed_precondition("DKG report evidence is not active"))?;

        if !share_evidence_proves_failure(&verified) {
            return Err(Status::failed_precondition(
                "DKG share evidence does not prove a verification failure",
            ));
        }

        queue_or_relay_invalid_share::<DkgImpl>(&coordinator, attempt, verified)
            .await
            .map_err(|error| Status::failed_precondition(error.to_string()))?;

        Ok(Response::new(SubmitDkgInvalidShareEvidenceResponse {}))
    }

    async fn submit_dkg_equivocation_evidence(
        &self,
        request: Request<SubmitDkgEquivocationEvidenceRequest>,
    ) -> Result<Response<SubmitDkgEquivocationEvidenceResponse>, Status> {
        let request = request.into_inner();
        let session_id = request
            .session_id
            .parse::<u128>()
            .map_err(|error| Status::invalid_argument(format!("invalid session_id: {error}")))?;
        let commitment_a: SignedDkgCommitment = serde_json::from_slice(&request.commitment_a_json)
            .map_err(|error| {
                Status::invalid_argument(format!("invalid commitment_a_json: {error}"))
            })?;
        let commitment_b: SignedDkgCommitment = serde_json::from_slice(&request.commitment_b_json)
            .map_err(|error| {
                Status::invalid_argument(format!("invalid commitment_b_json: {error}"))
            })?;
        let app_state = self.app_state.clone().ok_or_else(|| {
            Status::failed_precondition("unsafe DKG evidence injection requires app state")
        })?;
        let attempt_id = app_state
            .dkg_session_state
            .transport_attempt(&session_id)
            .await
            .ok_or_else(|| {
                Status::failed_precondition("DKG report evidence is not active for this session")
            })?;
        let attempt = AttemptKey::new(CeremonyId(session_id), attempt_id);
        let coordinator = DkgCoordinator::<DkgImpl>::with_routes(app_state, &network::V0);

        queue_or_relay_equivocation::<DkgImpl>(&coordinator, attempt, commitment_a, commitment_b)
            .await
            .map_err(|error| Status::failed_precondition(error.to_string()))?;

        Ok(Response::new(SubmitDkgEquivocationEvidenceResponse {}))
    }

    async fn submit_dkg_invalid_refresh_commitment_evidence(
        &self,
        request: Request<SubmitDkgInvalidRefreshCommitmentEvidenceRequest>,
    ) -> Result<Response<SubmitDkgInvalidRefreshCommitmentEvidenceResponse>, Status> {
        let request = request.into_inner();
        let evidence: SignedDkgCommitment = serde_json::from_slice(&request.signed_commitment_json)
            .map_err(|error| {
                Status::invalid_argument(format!("invalid signed_commitment_json: {error}"))
            })?;
        let app_state = self.app_state.clone().ok_or_else(|| {
            Status::failed_precondition("unsafe DKG evidence injection requires app state")
        })?;

        // The report producer + co-signer validation are the real security boundary and need only
        // the ring and the signed statement — not a live DKG session — so this injects directly
        // rather than going through the node-local session pre-check (a healthy same-committee
        // refresh completes before an injection targeting its live session could land).
        if let Ok(commitment) = deserialize_wire_commitment(&evidence.statement.commitment) {
            if commitment.constant_term_is_identity() {
                return Err(Status::failed_precondition(
                    "DKG refresh commitment evidence has an identity constant term",
                ));
            }
        }

        queue_invalid_refresh_commitment_report::<DkgImpl>(app_state, &network::V0, evidence)
            .await
            .map_err(|error| Status::failed_precondition(error.to_string()))?;

        Ok(Response::new(
            SubmitDkgInvalidRefreshCommitmentEvidenceResponse {},
        ))
    }

    async fn submit_pss_stall_offline_report(
        &self,
        request: Request<SubmitPssStallOfflineReportRequest>,
    ) -> Result<Response<SubmitPssStallOfflineReportResponse>, Status> {
        let request = request.into_inner();
        let session_id = request
            .session_id
            .parse::<u128>()
            .map_err(|error| Status::invalid_argument(format!("invalid session_id: {error}")))?;
        let app_state = self.app_state.clone().ok_or_else(|| {
            Status::failed_precondition("unsafe PSS stall injection requires app state")
        })?;

        // Drive the real drain-worker path: a genuinely-abandoned refresh or reshare session
        // whose only silent dealer is `peer_id`. The accused must be stopped so the co-signer
        // reachability probe passes and the resulting node_offline report is accepted.
        let kind = if request.new_peer_node_keys.is_empty() {
            SessionKind::Refresh {
                ring_pk_hex: request.ring_pk_hex,
            }
        } else {
            SessionKind::Reshare {
                ring_pk_hex: request.ring_pk_hex,
                new_peer_node_keys: request.new_peer_node_keys,
                new_threshold: request.new_threshold,
                bulletin_post_id: request.bulletin_post_id,
            }
        };
        let event = AbandonedPssSession {
            session_id,
            kind,
            ring_id: request.ring_id,
            protocol_version: network::V0.version,
            missing_peer_ids: vec![request.peer_id],
        };
        report_abandoned_pss_session::<DkgImpl>(&app_state, event).await;

        Ok(Response::new(SubmitPssStallOfflineReportResponse {}))
    }

    async fn submit_unauthorized_relay_evidence(
        &self,
        request: Request<SubmitUnauthorizedRelayEvidenceRequest>,
    ) -> Result<Response<SubmitUnauthorizedRelayEvidenceResponse>, Status> {
        let request = request.into_inner();
        if request.relay_statement_canonical_bytes.is_empty() {
            return Err(Status::invalid_argument(
                "relay_statement_canonical_bytes is required",
            ));
        }
        if request.relay_signature.is_empty() {
            return Err(Status::invalid_argument("relay_signature is required"));
        }
        if request.target_peer_id.trim().is_empty() {
            return Err(Status::invalid_argument("target_peer_id is required"));
        }
        if request.token_string.trim().is_empty() {
            return Err(Status::invalid_argument("token_string is required"));
        }

        let statement =
            RelayRequestStatement::from_canonical_bytes(&request.relay_statement_canonical_bytes)
                .map_err(|error| {
                Status::invalid_argument(format!(
                    "invalid relay_statement_canonical_bytes: {error}"
                ))
            })?;

        let app_state = self.app_state.clone().ok_or_else(|| {
            Status::failed_precondition("unsafe unauthorized relay evidence requires app state")
        })?;
        if statement.relayer_node_key != app_state.node_key {
            return Err(Status::failed_precondition(format!(
                "relay statement relayer_node_key {} does not match this node {}",
                statement.relayer_node_key, app_state.node_key
            )));
        }

        let now = current_unix_time()?;
        let drift = now.abs_diff(statement.signed_at);
        if drift > RELAY_CHECK_MAX_DRIFT_SECS {
            return Err(Status::failed_precondition(format!(
                "relay statement is stale: signed_at drift {drift}s exceeds {RELAY_CHECK_MAX_DRIFT_SECS}s"
            )));
        }

        verify_node_message(
            &statement.relayer_node_key,
            &statement.canonical_bytes(),
            &request.relay_signature,
        )
        .map_err(|error| {
            Status::failed_precondition(format!("invalid relay request signature: {error}"))
        })?;

        match statement.origin_protocol.as_str() {
            "pre" => {
                forward_unauthorized_pre(
                    app_state,
                    request.target_peer_id,
                    statement,
                    request.relay_signature,
                    request.token_string,
                    request.pre_reader_pk,
                )
                .await?;
            }
            "sign" => {
                forward_unauthorized_sign(
                    app_state,
                    request.target_peer_id,
                    statement,
                    request.relay_signature,
                    request.token_string,
                )
                .await?;
            }
            other => {
                return Err(Status::invalid_argument(format!(
                    "unsupported relay origin_protocol {other}"
                )));
            }
        }

        Ok(Response::new(SubmitUnauthorizedRelayEvidenceResponse {}))
    }

    async fn submit_organic_conflicting_commitment(
        &self,
        request: Request<SubmitOrganicConflictingCommitmentRequest>,
    ) -> Result<Response<SubmitOrganicConflictingCommitmentResponse>, Status> {
        let request = request.into_inner();
        let session_id = request
            .session_id
            .parse::<u128>()
            .map_err(|error| Status::invalid_argument(format!("invalid session_id: {error}")))?;
        if request.commitment_bytes.is_empty() {
            return Err(Status::invalid_argument("commitment_bytes is required"));
        }
        let app_state = self.app_state.clone().ok_or_else(|| {
            Status::failed_precondition("unsafe DKG evidence injection requires app state")
        })?;
        let attempt_id = app_state
            .dkg_session_state
            .transport_attempt(&session_id)
            .await
            .ok_or_else(|| {
                Status::failed_precondition("DKG report evidence is not active for this session")
            })?;
        let attempt = AttemptKey::new(CeremonyId(session_id), attempt_id);
        let coordinator = DkgCoordinator::<DkgImpl>::with_routes(app_state, &network::V0);

        // This node's own node_id within the live attempt — the same identity
        // its real (already-broadcast) first commitment used, so the second
        // one lands as a conflict for the same origin rather than a new one.
        let node_id = coordinator
            .app_state
            .dkg_session_state
            .with_attempt_state(attempt, |state| state.node.node_id())
            .await
            .map_err(|error| Status::failed_precondition(format!("{error:?}")))?;

        let report_evidence = build_and_store_commitment_evidence(
            &coordinator,
            attempt,
            node_id,
            request.commitment_bytes.clone(),
        )
        .await
        .map_err(|error| Status::failed_precondition(error.to_string()))?;

        submit_public_contribution(
            &coordinator,
            attempt,
            DkgPublicPayload::Commitment {
                commitment: request.commitment_bytes,
                report_evidence: report_evidence.map(Box::new),
            },
        )
        .await
        .map_err(|error| Status::failed_precondition(error.to_string()))?;

        Ok(Response::new(SubmitOrganicConflictingCommitmentResponse {}))
    }

    async fn submit_organic_noncanonical_prepare(
        &self,
        request: Request<SubmitOrganicNoncanonicalPrepareRequest>,
    ) -> Result<Response<SubmitOrganicNoncanonicalPrepareResponse>, Status> {
        let request = request.into_inner();
        if request.ring_id.trim().is_empty() {
            return Err(Status::invalid_argument("ring_id is required"));
        }
        if request.ring_pk.trim().is_empty() {
            return Err(Status::invalid_argument("ring_pk is required"));
        }
        let app_state = self.app_state.clone().ok_or_else(|| {
            Status::failed_precondition("unsafe DKG evidence injection requires app state")
        })?;

        let ring = read_ring_for_route(&*app_state.bulletin, &request.ring_id, network::V0.version)
            .await
            .map_err(Status::failed_precondition)?;
        if !ring_payload_matches_ring_key(&request.ring_pk, &ring.ring_pk) {
            return Err(Status::failed_precondition(
                "ring_pk does not match SourceHub state",
            ));
        }

        // Skips the canonical-leader check `coordinate_refresh` itself does —
        // that check is exactly the fault this RPC exists to exercise.
        let outcome = coordinate_refresh_as_claimed_leader::<DkgImpl>(
            app_state,
            &network::V0,
            request.ring_id,
            request.ring_pk,
            ring,
        )
        .await
        .map_err(|error| Status::failed_precondition(error.to_string()))?;

        if !matches!(outcome, RefreshStartOutcome::Started(_, _)) {
            return Err(Status::failed_precondition(format!(
                "refresh Prepare was not sent as a fresh attempt: {outcome:?}"
            )));
        }

        Ok(Response::new(SubmitOrganicNoncanonicalPrepareResponse {}))
    }

    async fn submit_organic_conflicting_manifest(
        &self,
        request: Request<SubmitOrganicConflictingManifestRequest>,
    ) -> Result<Response<SubmitOrganicConflictingManifestResponse>, Status> {
        let request = request.into_inner();
        let session_id = request
            .session_id
            .parse::<u128>()
            .map_err(|error| Status::invalid_argument(format!("invalid session_id: {error}")))?;
        let app_state = self.app_state.clone().ok_or_else(|| {
            Status::failed_precondition("unsafe DKG evidence injection requires app state")
        })?;
        let attempt_id = app_state
            .dkg_session_state
            .transport_attempt(&session_id)
            .await
            .ok_or_else(|| {
                Status::failed_precondition("DKG report evidence is not active for this session")
            })?;
        let ceremony_id = CeremonyId(session_id);
        let phase = PublicPhase::Commitments;

        let items = app_state
            .dkg_session_state
            .public_contributions(&session_id, attempt_id, phase)
            .await
            .ok_or_else(|| {
                Status::failed_precondition("no retained public contributions for this phase")
            })?;
        if items.len() < 2 {
            return Err(Status::failed_precondition(
                "at least 2 retained contributions are required to construct a \
                 distinguishable conflicting manifest",
            ));
        }
        let ids = contribution_ids(&items);
        let root = transport::phase_root(ceremony_id, attempt_id, phase, &ids);
        // Same phase_root/contribution_ids as the real manifest (recomputed from
        // the same real retained contributions, so it passes the receiver's own
        // self-consistency recheck), but a different chunk_count — the one field
        // this node fully controls independent of the underlying signed
        // contributions, which can't be forged without a valid signature from
        // their original signer.
        let signed_at = current_unix_time()?;
        let real_chunk_count = transport::chunk_public_contributions(
            ceremony_id,
            attempt_id,
            phase,
            root,
            items,
            signed_at,
        )
        .map_err(Status::failed_precondition)?
        .len();
        let rogue_chunk_count = if real_chunk_count > 1 {
            real_chunk_count - 1
        } else if real_chunk_count < ids.len() {
            real_chunk_count + 1
        } else {
            return Err(Status::failed_precondition(
                "no distinguishable chunk_count is available for this contribution set",
            ));
        };

        let manifest = DkgPublicMessage::Manifest(PhaseManifest {
            ceremony_id,
            attempt_id,
            phase,
            phase_root: root,
            contribution_ids: ids,
            chunk_count: rogue_chunk_count as u32,
            complete: true,
            signed_at,
        });
        let encoded = transport::encode(&manifest)
            .map_err(|error| Status::failed_precondition(error.to_string()))?;

        let topic = app_state
            .dkg_session_state
            .transport_topic_for_attempt(&session_id, attempt_id)
            .await
            .ok_or_else(|| {
                Status::failed_precondition("transport topic is missing or attempt is stale")
            })?;
        topic
            .broadcast(bytes::Bytes::from(encoded))
            .await
            .map_err(|error| Status::failed_precondition(error.to_string()))?;

        Ok(Response::new(SubmitOrganicConflictingManifestResponse {}))
    }

    async fn submit_organic_invalid_refresh_result(
        &self,
        request: Request<SubmitOrganicInvalidRefreshResultRequest>,
    ) -> Result<Response<SubmitOrganicInvalidRefreshResultResponse>, Status> {
        let request = request.into_inner();
        let session_id = request
            .session_id
            .parse::<u128>()
            .map_err(|error| Status::invalid_argument(format!("invalid session_id: {error}")))?;
        let app_state = self.app_state.clone().ok_or_else(|| {
            Status::failed_precondition("unsafe DKG evidence injection requires app state")
        })?;
        let attempt_id = app_state
            .dkg_session_state
            .transport_attempt(&session_id)
            .await
            .ok_or_else(|| {
                Status::failed_precondition("DKG report evidence is not active for this session")
            })?;
        let candidate = app_state
            .dkg_session_state
            .refresh_health_check_candidate(&session_id)
            .await
            .ok_or_else(|| {
                Status::failed_precondition(
                    "no staged refresh health-check candidate — ceremony has not reached \
                     RefreshHealthCheck yet",
                )
            })?;

        // Every field matches this node's own real staged candidate except
        // public_polynomial_sha256, so it passes the receiver's coarse
        // candidate-identity check and is rejected specifically on content —
        // the "invalid result" this scenario targets, not "wrong ceremony".
        let statement = RefreshHealthCheckStatement {
            domain: REFRESH_HEALTH_CHECK_DOMAIN.to_string(),
            session_id,
            ring_pk: candidate.ring_pk_hex,
            public_polynomial_sha256: "0".repeat(64),
            peer_node_keys_sha256: refresh_health_check_peer_node_keys_sha256(
                &candidate.peer_node_keys,
            ),
            threshold: candidate.threshold as u32,
            total_participants: candidate.peer_ids.len() as u32,
        };

        let coordinator = DkgCoordinator::<DkgImpl>::with_routes(app_state, &network::V0);
        let attempt = AttemptKey::new(CeremonyId(session_id), attempt_id);
        submit_public_contribution(
            &coordinator,
            attempt,
            DkgPublicPayload::RefreshHealthCheckResult {
                statement,
                // A syntactically-present placeholder, not a real threshold
                // signature: `verify_result_signature`'s content-mismatch check
                // (network.rs/refresh_health_check.rs) rejects on the wrong
                // public_polynomial_sha256 before it ever parses this as a
                // real signature.
                signature: Some("00".repeat(96)),
            },
        )
        .await
        .map_err(|error| Status::failed_precondition(error.to_string()))?;

        Ok(Response::new(SubmitOrganicInvalidRefreshResultResponse {}))
    }
}

async fn forward_unauthorized_pre(
    app_state: Arc<AppState<DkgImpl>>,
    target_peer_id: String,
    statement: RelayRequestStatement,
    relay_signature: Vec<u8>,
    token_string: String,
    pre_reader_pk: Vec<u8>,
) -> Result<(), Status> {
    if pre_reader_pk.is_empty() {
        return Err(Status::invalid_argument(
            "pre_reader_pk is required for PRE relay evidence",
        ));
    }

    let request_id = statement.request_id.clone();
    let message = PreMessage::ReencryptRequest(Box::new(ReencryptRequest {
        request_id: request_id.clone(),
        from_node_id: statement.from_node_id,
        context: PreRequestContext {
            rdr_pk_bytes: pre_reader_pk,
            object_id: statement.object_id.clone(),
            token_string,
            derivation: None,
            salt: None,
            valid_window: None,
            relay_statement: Some(statement),
            relay_signature,
            document: None,
        },
    }));
    let coordinator = PreCoordinator::<DkgImpl, PreImpl>::with_routes(app_state, &network::V0);
    coordinator
        .send_request_and_receive_response(&target_peer_id, message, &request_id)
        .await
        .map_err(|error| {
            Status::failed_precondition(format!(
                "failed to forward PRE unauthorized relay evidence: {error}"
            ))
        })?;
    Ok(())
}

async fn forward_unauthorized_sign(
    app_state: Arc<AppState<DkgImpl>>,
    target_peer_id: String,
    statement: RelayRequestStatement,
    relay_signature: Vec<u8>,
    token_string: String,
) -> Result<(), Status> {
    let derivation_post = app_state
        .bulletin
        .read(statement.object_id.clone(), BulletinKind::KeyDerivation)
        .await
        .map_err(|error| {
            Status::failed_precondition(format!("failed to read key derivation: {error}"))
        })?;
    let key_derivation: KeyDerivation =
        serde_json::from_slice(&derivation_post.payload).map_err(|error| {
            Status::failed_precondition(format!("failed to parse key derivation: {error}"))
        })?;
    let ring_pk = hex::decode(&statement.ring_pk).map_err(|error| {
        Status::failed_precondition(format!("failed to decode relay ring_pk hex: {error}"))
    })?;

    let request_id = statement.request_id.clone();
    let message = SignMessage::NonceRequest(NonceRequest {
        request_id: request_id.clone(),
        from_node_id: statement.from_node_id,
        ring_pk,
        context: SignContext::Policy(Box::new(PolicyContext {
            token_string,
            derivation_id: statement.object_id.clone(),
            valid_window: None,
            key_derivation,
            relay_statement: Some(statement),
            relay_signature,
        })),
    });
    let coordinator = SignCoordinator::<DkgImpl, SignImpl>::with_routes(app_state, &network::V0);
    coordinator
        .send_request_and_receive_response(&target_peer_id, message, &request_id)
        .await
        .map_err(|error| {
            Status::failed_precondition(format!(
                "failed to forward Sign unauthorized relay evidence: {error}"
            ))
        })?;
    Ok(())
}
