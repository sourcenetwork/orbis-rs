use std::sync::Arc;

use crate::app_state::AppState;
use crate::dkg::v0::coordinator::evidence::{
    queue_invalid_refresh_commitment_report, queue_or_relay_equivocation,
    queue_or_relay_invalid_share, share_evidence_proves_failure, verify_share_evidence,
};
use crate::dkg::v0::coordinator::network::report_abandoned_pss_session;
use crate::dkg::v0::coordinator::DkgCoordinator;
use crate::dkg::v0::helpers::deserialize_wire_commitment;
use crate::dkg::v0::messages::{SessionKind, SignedDkgCommitment, SignedDkgShare};
use crate::dkg::v0::session_state::AbandonedPssSession;
use crypto::r#trait::PolynomialCommitment as _;
use crypto::DkgImpl;
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
    SubmitDkgInvalidShareEvidenceResponse, SubmitPssStallOfflineReportRequest,
    SubmitPssStallOfflineReportResponse,
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
        Ok(Response::new(GetActivePssSessionResponse {
            found: session_id.is_some(),
            session_id: session_id.map(|id| id.to_string()).unwrap_or_default(),
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
        let coordinator = DkgCoordinator::<DkgImpl>::with_routes(app_state, &network::V0);

        let from_node_id = evidence.statement.from_node_id;
        let to_node_id = evidence.statement.to_node_id;
        let share_value = evidence.statement.share_value.clone();
        let nonce = evidence.statement.nonce;
        let verified = verify_share_evidence::<DkgImpl>(
            &coordinator,
            session_id,
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

        queue_or_relay_invalid_share::<DkgImpl>(&coordinator, session_id, verified)
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
        let coordinator = DkgCoordinator::<DkgImpl>::with_routes(app_state, &network::V0);

        queue_or_relay_equivocation::<DkgImpl>(
            &coordinator,
            session_id,
            commitment_a,
            commitment_b,
        )
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

        // Drive the real drain-worker path: a genuinely-abandoned refresh session whose only
        // silent dealer is `peer_id`. The accused must be stopped so the co-signer reachability
        // probe passes and the resulting node_offline report is accepted.
        let event = AbandonedPssSession {
            session_id,
            kind: SessionKind::Refresh {
                ring_pk_hex: request.ring_pk_hex,
            },
            ring_id: request.ring_id,
            protocol_version: network::V0.version,
            missing_peer_ids: vec![request.peer_id],
        };
        report_abandoned_pss_session::<DkgImpl>(&app_state, event).await;

        Ok(Response::new(SubmitPssStallOfflineReportResponse {}))
    }
}
