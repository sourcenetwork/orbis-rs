use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bulletin::r#trait::{BulletinKind, NodeInfo, RingPayload};
use common::blockchain::{sign_node_message_with_hex_key, verify_node_message};
use crypto::r#trait::{CryptoDeserialize, Dkg, PolynomialCommitment as PolynomialCommitmentTrait};
use crypto::{ScalarField as Fr, SignImpl};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};

use crate::app_state::AppState;
use crate::dkg::v0::error::{DkgError, Result};
use crate::dkg::v0::helpers::deserialize_wire_commitment;
use crate::dkg::v0::messages::{
    ControlSignature, SessionKind, SignedDkgCommitment, SignedDkgShare,
};
use crate::dkg::v0::network::{
    relay_invalid_commitment_evidence, relay_public_origin_fault_evidence,
};
use crate::dkg::v0::session_state::DkgReportEvidenceBinding;
use crate::dkg::v0::transport::{self, AttemptKey, DkgPublicContribution, PrepareSession};
use crate::helpers::identity::extract_node_part;
use crate::helpers::node_routes::node_key_for_canonical_node_id;
use crate::reporting::v0::observation::{InvalidCryptoResponseObservation, ReportObservation};
use crate::reporting::v0::queue_report;
use crate::reporting::v0::types::{
    ring_state_sha256, CommitteeScope, ControlMessageArtifact, DkgCommitmentStatement,
    DkgControlMessageFaultKind, DkgControlMessageFaultStatement, DkgLeaderEquivocationStatement,
    DkgPublicOriginFaultKind, DkgPublicOriginFaultStatement, DkgShareStatement,
    EndpointSignedContribution, InvalidCryptoResponse, CHAIN_BLOCK_GRACE_SECS,
    DKG_COMMITMENT_DOMAIN, DKG_CONTROL_MESSAGE_FAULT_DOMAIN, DKG_LEADER_EQUIVOCATION_DOMAIN,
    DKG_PUBLIC_ORIGIN_FAULT_DOMAIN, DKG_SHARE_DOMAIN,
};

use super::{
    attempt_state_error,
    types::{CoordinatorDkg, CoordinatorReportSigner},
    DkgCoordinator,
};

pub(crate) struct DkgEvidenceBuildContext {
    binding: DkgReportEvidenceBinding,
    signing_key_hex: String,
    session_nonce: [u8; 16],
}

pub(crate) async fn evidence_build_context<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
) -> Result<Option<DkgEvidenceBuildContext>>
where
    D: CoordinatorDkg,
{
    let Some(binding) = evidence_binding(coord, attempt).await? else {
        return Ok(None);
    };
    let signing_key_hex = read_node_signing_key_hex(&coord.app_state)?;
    let session_nonce = coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |state| state.session_nonce)
        .await
        .map_err(|error| attempt_state_error(attempt, error))?;
    Ok(Some(DkgEvidenceBuildContext {
        binding,
        signing_key_hex,
        session_nonce,
    }))
}

pub(crate) fn build_commitment_evidence_with_context<D>(
    coord: &DkgCoordinator<D>,
    context: &DkgEvidenceBuildContext,
    from_node_id: u32,
    commitment: Vec<u8>,
) -> Result<SignedDkgCommitment>
where
    D: CoordinatorDkg,
{
    let binding = &context.binding;
    let signed_at = now_unix_secs()?;
    let statement = DkgCommitmentStatement {
        domain: DKG_COMMITMENT_DOMAIN.to_string(),
        chain_id: binding.chain_id.clone(),
        ring_id: binding.ring_id.clone(),
        ring_pk: binding.ring_pk.clone(),
        ring_state_sha256: binding.ring_state_sha256.clone(),
        protocol_version: binding.protocol_version,
        request_id: binding.request_id.clone(),
        signed_at,
        responder_node_key: coord.app_state.node_key.clone(),
        origin_protocol: binding.origin_protocol.clone(),
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        from_node_id,
        commitment,
        session_nonce: context.session_nonce,
        crypto_backend: D::name(),
    };
    let signature =
        sign_statement_with_key(&context.signing_key_hex, &statement.canonical_bytes())?;
    Ok(SignedDkgCommitment {
        statement,
        signature,
    })
}

pub async fn build_and_store_commitment_evidence<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    from_node_id: u32,
    commitment: Vec<u8>,
) -> Result<Option<SignedDkgCommitment>>
where
    D: CoordinatorDkg,
{
    let Some(context) = evidence_build_context(coord, attempt).await? else {
        return Ok(None);
    };
    let report_evidence = build_and_store_commitment_evidence_with_context(
        coord,
        attempt,
        &context,
        from_node_id,
        commitment,
    )
    .await?;
    Ok(Some(report_evidence))
}

pub(crate) async fn build_and_store_commitment_evidence_with_context<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    context: &DkgEvidenceBuildContext,
    from_node_id: u32,
    commitment: Vec<u8>,
) -> Result<SignedDkgCommitment>
where
    D: CoordinatorDkg,
{
    let report_evidence =
        build_commitment_evidence_with_context(coord, context, from_node_id, commitment)?;
    coord
        .app_state
        .dkg_session_state
        .with_attempt_state_mut(attempt, |state| {
            state.local_signed_commitment = Some(report_evidence.clone());
        })
        .await
        .map_err(|error| attempt_state_error(attempt, error))?;
    Ok(report_evidence)
}

pub(crate) fn build_share_evidence_with_context<D>(
    coord: &DkgCoordinator<D>,
    context: &DkgEvidenceBuildContext,
    from_node_id: u32,
    to_node_id: u32,
    share_value: Vec<u8>,
    nonce: [u8; 16],
    commitment_evidence: &SignedDkgCommitment,
) -> Result<SignedDkgShare>
where
    D: CoordinatorDkg,
{
    let binding = &context.binding;
    let receiver_node_key = binding
        .receiver_node_keys
        .get(to_node_id.saturating_sub(1) as usize)
        .ok_or_else(|| {
            DkgError::InvalidState(format!(
                "DKG share to_node_id {} is outside the receiver committee",
                to_node_id
            ))
        })?
        .clone();

    let signed_at = now_unix_secs()?;
    let statement = DkgShareStatement {
        domain: DKG_SHARE_DOMAIN.to_string(),
        chain_id: binding.chain_id.clone(),
        ring_id: binding.ring_id.clone(),
        ring_pk: binding.ring_pk.clone(),
        ring_state_sha256: binding.ring_state_sha256.clone(),
        protocol_version: binding.protocol_version,
        request_id: binding.request_id.clone(),
        signed_at,
        responder_node_key: coord.app_state.node_key.clone(),
        receiver_node_key,
        origin_protocol: binding.origin_protocol.clone(),
        accused_committee_scope: CommitteeScope::Current,
        signing_committee_scope: CommitteeScope::Current,
        from_node_id,
        to_node_id,
        commitment_statement: commitment_evidence.statement.clone(),
        commitment_signature: commitment_evidence.signature.clone(),
        share_value,
        nonce,
        crypto_backend: D::name(),
    };
    let signature =
        sign_statement_with_key(&context.signing_key_hex, &statement.canonical_bytes())?;
    Ok(SignedDkgShare {
        statement,
        signature,
    })
}

pub async fn verify_commitment_evidence<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    from_node_id: u32,
    commitment: &[u8],
    evidence: Option<SignedDkgCommitment>,
) -> Result<Option<SignedDkgCommitment>>
where
    D: CoordinatorDkg,
{
    let Some(binding) = evidence_binding(coord, attempt).await? else {
        return Ok(None);
    };
    let evidence = evidence.ok_or_else(|| {
        DkgError::Unauthorized("PSS DKG commitment is missing signed report evidence".to_string())
    })?;
    validate_commitment_statement::<D>(&binding, from_node_id, commitment, &evidence.statement)?;
    verify_node_message(
        &evidence.statement.responder_node_key,
        &evidence.statement.canonical_bytes(),
        &evidence.signature,
    )
    .map_err(|error| {
        DkgError::Unauthorized(format!(
            "invalid DKG commitment evidence signature: {error}"
        ))
    })?;
    Ok(Some(evidence))
}

pub async fn verify_share_evidence<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    from_node_id: u32,
    to_node_id: u32,
    share_value: &[u8],
    nonce: [u8; 16],
    evidence: Option<SignedDkgShare>,
) -> Result<Option<SignedDkgShare>>
where
    D: CoordinatorDkg,
{
    let Some(binding) = evidence_binding(coord, attempt).await? else {
        return Ok(None);
    };
    let evidence = evidence.ok_or_else(|| {
        DkgError::Unauthorized("PSS DKG share is missing signed report evidence".to_string())
    })?;
    validate_share_statement::<D>(
        &binding,
        from_node_id,
        to_node_id,
        share_value,
        nonce,
        &evidence.statement,
    )?;
    verify_node_message(
        &evidence.statement.responder_node_key,
        &evidence.statement.commitment_statement.canonical_bytes(),
        &evidence.statement.commitment_signature,
    )
    .map_err(|error| {
        DkgError::Unauthorized(format!("invalid nested DKG commitment signature: {error}"))
    })?;
    verify_node_message(
        &evidence.statement.responder_node_key,
        &evidence.statement.canonical_bytes(),
        &evidence.signature,
    )
    .map_err(|error| {
        DkgError::Unauthorized(format!("invalid DKG share evidence signature: {error}"))
    })?;
    Ok(Some(evidence))
}

pub fn share_evidence_proves_failure(evidence: &SignedDkgShare) -> bool {
    // A responder that signs share evidence whose commitment or share value cannot
    // be decoded distributed an unusable share; a decode failure is itself proof of
    // a bad share, so treat it the same as a share that fails verification. Registry
    // co-signers reach the same conclusion because deserialization is deterministic
    // (see `require_dkg_share_verification_failure`).
    let Ok(commitment) =
        deserialize_wire_commitment(&evidence.statement.commitment_statement.commitment)
    else {
        return true;
    };
    let Ok(share_value) = Fr::from_bytes(&evidence.statement.share_value) else {
        return true;
    };
    !commitment.verify_share(evidence.statement.to_node_id, &share_value)
}

/// Spawn a pending-new evidence relay so it never blocks the caller (a
/// protocol-response or ceremony-abort path). One fan-out attempt is
/// considered sufficient — there are many independent detection points and
/// co-signers across this reporting system, so a single relay attempt that
/// fails is an acceptable loss rather than something worth retrying.
fn spawn_evidence_relay<Fut>(session_id: u128, evidence_kind: &'static str, relay: Fut)
where
    Fut: std::future::Future<Output = Result<()>> + Send + 'static,
{
    tokio::spawn(async move {
        if let Err(error) = relay.await {
            tracing::warn!(
                session_id = session_id,
                evidence_kind,
                %error,
                "failed to relay evidence to a current-committee signer"
            );
        }
    });
}

pub async fn queue_or_relay_invalid_share<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    evidence: SignedDkgShare,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    if local_node_is_current_route_member(coord, attempt).await? {
        queue_invalid_share_report(coord.app_state.clone(), coord.routes, evidence).await
    } else if evidence.statement.origin_protocol == "pss_reshare" {
        let app_state = coord.app_state.clone();
        let routes = coord.routes;
        spawn_evidence_relay(attempt.session_id(), "dkg_share", async move {
            let coordinator = DkgCoordinator::with_routes(app_state, routes);
            relay_invalid_share_evidence(&coordinator, attempt, evidence).await
        });
        Ok(())
    } else {
        Err(DkgError::Unauthorized(
            "local node is not in the report signing committee".to_string(),
        ))
    }
}

pub async fn handle_invalid_share_evidence_relay<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    report_evidence: SignedDkgShare,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    if report_evidence.statement.origin_protocol != "pss_reshare" {
        return Err(DkgError::Unauthorized(
            "DKG bad-share evidence relay is only valid for reshare".to_string(),
        ));
    }
    verify_relay_is_current_signer(coord, attempt).await?;

    // A relayed report is otherwise unauthenticated network input, so re-run the
    // same checks the direct receiver path runs before spending a report attempt
    // on it: authenticate the evidence against this session (ring binding plus the
    // responder's commitment and share signatures) and confirm it actually proves a
    // verification failure. Without this a peer could relay altered evidence or
    // evidence for a perfectly valid share and force a bogus report.
    let from_node_id = report_evidence.statement.from_node_id;
    let to_node_id = report_evidence.statement.to_node_id;
    let share_value = report_evidence.statement.share_value.clone();
    let nonce = report_evidence.statement.nonce;
    let verified = verify_share_evidence(
        coord,
        attempt,
        from_node_id,
        to_node_id,
        &share_value,
        nonce,
        Some(report_evidence),
    )
    .await?
    .ok_or_else(|| {
        DkgError::Unauthorized(
            "relayed DKG bad-share evidence is not valid for this session".to_string(),
        )
    })?;
    if !share_evidence_proves_failure(&verified) {
        return Err(DkgError::Unauthorized(
            "relayed DKG share evidence does not prove a verification failure".to_string(),
        ));
    }

    queue_invalid_share_report(coord.app_state.clone(), coord.routes, verified).await?;
    Ok(())
}

/// Two commitments are equivocation iff the same dealer signed both for the same session
/// under the SAME per-attempt nonce with different bytes. Same nonce is what distinguishes
/// genuine equivocation from an honest retry (which uses a fresh nonce).
pub(crate) fn commitments_prove_equivocation(
    commitment_a: &SignedDkgCommitment,
    commitment_b: &SignedDkgCommitment,
) -> bool {
    commitment_a.statement.session_nonce == commitment_b.statement.session_nonce
        && commitment_a.statement.commitment != commitment_b.statement.commitment
        && commitment_a.statement.from_node_id == commitment_b.statement.from_node_id
}

pub async fn queue_or_relay_equivocation<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    commitment_a: SignedDkgCommitment,
    commitment_b: SignedDkgCommitment,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    if local_node_is_current_route_member(coord, attempt).await? {
        queue_equivocation_report(
            coord.app_state.clone(),
            coord.routes,
            commitment_a,
            commitment_b,
        )
        .await
    } else if commitment_a.statement.origin_protocol == "pss_reshare" {
        let app_state = coord.app_state.clone();
        let routes = coord.routes;
        spawn_evidence_relay(attempt.session_id(), "dkg_equivocation", async move {
            let coordinator = DkgCoordinator::with_routes(app_state, routes);
            relay_equivocation_evidence(&coordinator, attempt, commitment_a, commitment_b).await
        });
        Ok(())
    } else {
        Err(DkgError::Unauthorized(
            "local node is not in the report signing committee".to_string(),
        ))
    }
}

pub async fn queue_or_relay_public_origin_fault<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    fault_kind: DkgPublicOriginFaultKind,
    contribution_a: network::SignedPayload,
    contribution_b: Option<network::SignedPayload>,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    if local_node_is_current_route_member(coord, attempt).await? {
        queue_public_origin_fault_report(
            coord.app_state.clone(),
            coord.routes,
            attempt,
            fault_kind,
            contribution_a,
            contribution_b,
        )
        .await
    } else {
        let origin_protocol = evidence_binding(coord, attempt)
            .await?
            .ok_or_else(|| {
                DkgError::Unauthorized(
                    "Fresh DKG public-origin faults are not reportable".to_string(),
                )
            })?
            .origin_protocol;
        if origin_protocol != "pss_reshare" {
            return Err(DkgError::Unauthorized(
                "local node is not in the report signing committee".to_string(),
            ));
        }
        let app_state = coord.app_state.clone();
        let routes = coord.routes;
        spawn_evidence_relay(attempt.session_id(), "dkg_public_origin_fault", async move {
            let coordinator = DkgCoordinator::with_routes(app_state, routes);
            relay_public_origin_fault_evidence(
                &coordinator,
                attempt,
                fault_kind,
                contribution_a,
                contribution_b,
            )
            .await
        });
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn queue_or_relay_leader_equivocation<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    delivery_id_a: [u8; 16],
    delivery_a: network::SignedPayload,
    delivery_id_b: [u8; 16],
    delivery_b: network::SignedPayload,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    if local_node_is_current_route_member(coord, attempt).await? {
        queue_leader_equivocation_report(
            coord.app_state.clone(),
            coord.routes,
            attempt,
            delivery_id_a,
            delivery_a,
            delivery_id_b,
            delivery_b,
        )
        .await
    } else {
        let origin_protocol = evidence_binding(coord, attempt)
            .await?
            .ok_or_else(|| {
                DkgError::Unauthorized(
                    "Fresh DKG leader equivocation is not reportable".to_string(),
                )
            })?
            .origin_protocol;
        if origin_protocol != "pss_reshare" {
            return Err(DkgError::Unauthorized(
                "local node is not in the report signing committee".to_string(),
            ));
        }
        let app_state = coord.app_state.clone();
        let routes = coord.routes;
        spawn_evidence_relay(attempt.session_id(), "dkg_leader_equivocation", async move {
            let coordinator = DkgCoordinator::with_routes(app_state, routes);
            crate::dkg::v0::network::relay_leader_equivocation_evidence(
                &coordinator,
                attempt,
                delivery_id_a,
                delivery_a,
                delivery_id_b,
                delivery_b,
            )
            .await
        });
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn queue_or_relay_control_message_fault<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    accused_node_key: String,
    message_kind: String,
    fault_kind: DkgControlMessageFaultKind,
    artifact_a: ControlMessageArtifact,
    artifact_b: Option<ControlMessageArtifact>,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    if local_node_is_current_route_member(coord, attempt).await? {
        queue_control_message_fault_report(
            coord.app_state.clone(),
            coord.routes,
            attempt,
            accused_node_key,
            message_kind,
            fault_kind,
            artifact_a,
            artifact_b,
        )
        .await
    } else {
        let origin_protocol = evidence_binding(coord, attempt)
            .await?
            .ok_or_else(|| {
                DkgError::Unauthorized(
                    "Fresh DKG control-message faults are not reportable".to_string(),
                )
            })?
            .origin_protocol;
        if origin_protocol != "pss_reshare" {
            return Err(DkgError::Unauthorized(
                "local node is not in the report signing committee".to_string(),
            ));
        }
        let app_state = coord.app_state.clone();
        let routes = coord.routes;
        spawn_evidence_relay(attempt.session_id(), "dkg_control_message_fault", async move {
            let coordinator = DkgCoordinator::with_routes(app_state, routes);
            crate::dkg::v0::network::relay_control_message_fault_evidence(
                &coordinator,
                attempt,
                accused_node_key,
                message_kind,
                fault_kind,
                artifact_a,
                artifact_b,
            )
            .await
        });
        Ok(())
    }
}

pub async fn handle_public_origin_fault_evidence_relay<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    fault_kind: DkgPublicOriginFaultKind,
    contribution_a: network::SignedPayload,
    contribution_b: Option<network::SignedPayload>,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    verify_relay_is_current_signer(coord, attempt).await?;
    let binding = evidence_binding(coord, attempt).await?.ok_or_else(|| {
        DkgError::Unauthorized("Fresh DKG public-origin faults are not reportable".to_string())
    })?;
    if binding.origin_protocol != "pss_reshare" {
        return Err(DkgError::Unauthorized(
            "public-origin fault relay is only valid for Reshare".to_string(),
        ));
    }
    queue_public_origin_fault_report(
        coord.app_state.clone(),
        coord.routes,
        attempt,
        fault_kind,
        contribution_a,
        contribution_b,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_leader_equivocation_evidence_relay<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    delivery_id_a: [u8; 16],
    delivery_a: network::SignedPayload,
    delivery_id_b: [u8; 16],
    delivery_b: network::SignedPayload,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    verify_relay_is_current_signer(coord, attempt).await?;
    let binding = evidence_binding(coord, attempt).await?.ok_or_else(|| {
        DkgError::Unauthorized("Fresh DKG leader equivocation is not reportable".to_string())
    })?;
    if binding.origin_protocol != "pss_reshare" {
        return Err(DkgError::Unauthorized(
            "leader-equivocation evidence relay is only valid for Reshare".to_string(),
        ));
    }
    queue_leader_equivocation_report(
        coord.app_state.clone(),
        coord.routes,
        attempt,
        delivery_id_a,
        delivery_a,
        delivery_id_b,
        delivery_b,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_control_message_fault_evidence_relay<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    accused_node_key: String,
    message_kind: String,
    fault_kind: DkgControlMessageFaultKind,
    artifact_a: ControlMessageArtifact,
    artifact_b: Option<ControlMessageArtifact>,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    verify_relay_is_current_signer(coord, attempt).await?;
    let binding = evidence_binding(coord, attempt).await?.ok_or_else(|| {
        DkgError::Unauthorized("Fresh DKG control-message faults are not reportable".to_string())
    })?;
    if binding.origin_protocol != "pss_reshare" {
        return Err(DkgError::Unauthorized(
            "control-message fault evidence relay is only valid for Reshare".to_string(),
        ));
    }
    queue_control_message_fault_report(
        coord.app_state.clone(),
        coord.routes,
        attempt,
        accused_node_key,
        message_kind,
        fault_kind,
        artifact_a,
        artifact_b,
    )
    .await
}

async fn relay_equivocation_evidence<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    commitment_a: SignedDkgCommitment,
    commitment_b: SignedDkgCommitment,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    relay_invalid_commitment_evidence(coord, attempt, commitment_a, commitment_b).await
}

pub async fn handle_invalid_commitment_evidence_relay<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    commitment_a: SignedDkgCommitment,
    commitment_b: SignedDkgCommitment,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    if commitment_a.statement.origin_protocol != "pss_reshare" {
        return Err(DkgError::Unauthorized(
            "DKG equivocation evidence relay is only valid for reshare".to_string(),
        ));
    }
    verify_relay_is_current_signer(coord, attempt).await?;

    // Relayed evidence is otherwise unauthenticated input: re-authenticate both commitments
    // against this session (ring binding + the dealer's signature) and re-confirm they
    // actually prove equivocation before spending a report attempt on them.
    let from_node_id_a = commitment_a.statement.from_node_id;
    let commitment_bytes_a = commitment_a.statement.commitment.clone();
    let verified_a = verify_commitment_evidence(
        coord,
        attempt,
        from_node_id_a,
        &commitment_bytes_a,
        Some(commitment_a),
    )
    .await?
    .ok_or_else(|| {
        DkgError::Unauthorized(
            "relayed DKG equivocation commitment is not valid for this session".to_string(),
        )
    })?;
    let from_node_id_b = commitment_b.statement.from_node_id;
    let commitment_bytes_b = commitment_b.statement.commitment.clone();
    let verified_b = verify_commitment_evidence(
        coord,
        attempt,
        from_node_id_b,
        &commitment_bytes_b,
        Some(commitment_b),
    )
    .await?
    .ok_or_else(|| {
        DkgError::Unauthorized(
            "relayed DKG equivocation commitment is not valid for this session".to_string(),
        )
    })?;
    if !commitments_prove_equivocation(&verified_a, &verified_b) {
        return Err(DkgError::Unauthorized(
            "relayed DKG commitments do not prove equivocation".to_string(),
        ));
    }

    queue_equivocation_report(
        coord.app_state.clone(),
        coord.routes,
        verified_a,
        verified_b,
    )
    .await?;
    Ok(())
}

async fn evidence_binding<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
) -> Result<Option<DkgReportEvidenceBinding>>
where
    D: CoordinatorDkg,
{
    let session_id = attempt.session_id();
    if let Some(cached) = coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |state| state.report_evidence_binding.clone())
        .await
        .map_err(|error| attempt_state_error(attempt, error))?
    {
        return Ok(Some(cached));
    }

    let (kind, stored_ring_id, protocol_version, receiver_node_keys) = coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |state| {
            let receiver_node_keys = match &state.kind {
                SessionKind::Fresh => Vec::new(),
                SessionKind::Refresh { .. } => state.routing.peer_node_keys.clone(),
                SessionKind::Reshare {
                    new_peer_node_keys, ..
                } => new_peer_node_keys.clone(),
            };
            (
                state.kind.clone(),
                state.routing.ring_id.clone(),
                state.protocol_version,
                receiver_node_keys,
            )
        })
        .await
        .map_err(|error| attempt_state_error(attempt, error))?;

    let (origin_protocol, ring_id) = match kind {
        SessionKind::Fresh => return Ok(None),
        SessionKind::Refresh { .. } => ("pss_refresh", stored_ring_id),
        SessionKind::Reshare {
            bulletin_post_id, ..
        } => (
            "pss_reshare",
            if stored_ring_id.is_empty() {
                bulletin_post_id
            } else {
                stored_ring_id
            },
        ),
    };
    if ring_id.is_empty() {
        return Err(DkgError::InvalidState(
            "PSS DKG report evidence requires an authoritative ring ID".to_string(),
        ));
    }

    let ring_post = coord
        .app_state
        .bulletin
        .read(ring_id.clone(), BulletinKind::Ring)
        .await
        .map_err(|error| DkgError::Bulletin(error.to_string()))?;
    let ring = RingPayload::try_from(ring_post)
        .map_err(|error| DkgError::Deserialization(error.to_string()))?;

    let binding = DkgReportEvidenceBinding {
        ring_id,
        ring_pk: ring.ring_pk.clone(),
        ring_state_sha256: ring_state_sha256(&ring),
        chain_id: coord.app_state.bulletin.chain_id(),
        protocol_version,
        request_id: session_id.to_string(),
        origin_protocol: origin_protocol.to_string(),
        current_node_keys: ring.peer_node_keys.clone(),
        receiver_node_keys,
    };

    let binding = coord
        .app_state
        .dkg_session_state
        .with_attempt_state_mut(attempt, |state| {
            if state.report_evidence_binding.is_none() {
                state.report_evidence_binding = Some(binding.clone());
            }
            state.report_evidence_binding.clone()
        })
        .await
        .map_err(|error| attempt_state_error(attempt, error))?
        .ok_or_else(|| {
            DkgError::InvalidState("failed to cache DKG report evidence binding".to_string())
        })?;

    Ok(Some(binding))
}

/// Resolve report-evidence binding directly from a received `PrepareSession`
/// rather than from live session state, mirroring `evidence_binding`'s
/// bulletin-ring read exactly. A noncanonical-leader or route/digest-invalid
/// `Prepare` is rejected *before* any session is created (deliberately — we
/// do not want to commit local state for a bogus Prepare), so the usual
/// session-backed evidence path cannot be used for this one fault kind.
async fn evidence_binding_from_prepare<D>(
    app_state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: &PrepareSession,
) -> Result<Option<DkgReportEvidenceBinding>>
where
    D: Dkg + Clone + 'static,
{
    let (origin_protocol, ring_id, receiver_node_keys) = match &prepare.kind {
        SessionKind::Fresh => return Ok(None),
        SessionKind::Refresh { .. } => (
            "pss_refresh",
            prepare.ring_id.clone(),
            prepare.committees.current.node_keys.clone(),
        ),
        SessionKind::Reshare {
            bulletin_post_id,
            new_peer_node_keys,
            ..
        } => (
            "pss_reshare",
            if prepare.ring_id.is_empty() {
                bulletin_post_id.clone()
            } else {
                prepare.ring_id.clone()
            },
            new_peer_node_keys.clone(),
        ),
    };
    if ring_id.is_empty() {
        return Err(DkgError::InvalidState(
            "PSS DKG report evidence requires an authoritative ring ID".to_string(),
        ));
    }
    let ring_post = app_state
        .bulletin
        .read(ring_id.clone(), BulletinKind::Ring)
        .await
        .map_err(|error| DkgError::Bulletin(error.to_string()))?;
    let ring = RingPayload::try_from(ring_post)
        .map_err(|error| DkgError::Deserialization(error.to_string()))?;
    Ok(Some(DkgReportEvidenceBinding {
        ring_id,
        ring_pk: ring.ring_pk.clone(),
        ring_state_sha256: ring_state_sha256(&ring),
        chain_id: app_state.bulletin.chain_id(),
        protocol_version: routes.version,
        request_id: prepare.ceremony_id.0.to_string(),
        origin_protocol: origin_protocol.to_string(),
        current_node_keys: ring.peer_node_keys.clone(),
        receiver_node_keys,
    }))
}

/// Report a `Prepare` that is independently provable as invalid (noncanonical
/// leader, or routes/digest contradicting SourceHub) before any session is
/// created for it. Best-effort and queue-only: unlike the other control
/// evidence kinds, a pure pending-new reshare receiver that detects this
/// (rather than a current-committee member) cannot relay it in this pass —
/// relaying requires the current-committee routing that normally comes from
/// live session state, which by construction does not exist yet here. A
/// current-committee detector (every recipient for Fresh/Refresh, current
/// dealers/dealer-receivers for Reshare) is unaffected.
pub(crate) async fn report_leader_prepare_fault_best_effort<D>(
    app_state: &Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    prepare: &PrepareSession,
) where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let Some(signature) = prepare.report_signature.clone() else {
        return;
    };
    if verify_control_signature(
        prepare.ceremony_id,
        prepare.attempt_id,
        "prepare",
        prepare.config_digest,
        &prepare.leader_node_key,
        &signature,
    )
    .is_err()
    {
        return;
    }
    // A signature only covers `config_digest`, not the rest of the message.
    // Without also confirming the digest is self-consistent with the
    // fields actually present, a relay that tampers with `leader_node_key`
    // or `committees` post-signature while leaving the original digest
    // intact could produce a mismatch that looks attributable to the real
    // signer but isn't — the signer never endorsed the tampered content.
    // Only a self-consistent (and therefore untampered) `Prepare` is safe
    // to report.
    match transport::config_digest(prepare) {
        Ok(recomputed) if recomputed == prepare.config_digest => {}
        _ => return,
    }
    if !prepare
        .committees
        .current
        .node_keys
        .contains(&app_state.node_key)
    {
        // Not a current-committee member: cannot queue directly, and relay
        // is not built for this fault kind yet (see doc comment above).
        return;
    }
    let Ok(Some(binding)) = evidence_binding_from_prepare(app_state, routes, prepare).await else {
        return;
    };
    let Ok(data) = transport::encode(prepare) else {
        return;
    };
    crate::metrics::record_dkg_transport_event("control", "leader_prepare_fault_candidate");
    let accused_info = match read_node_info(app_state, &prepare.leader_node_key).await {
        Ok(info) => info,
        Err(error) => {
            tracing::warn!(
                session_id = prepare.ceremony_id.0,
                %error,
                "failed to resolve accused leader NodeInfo for Prepare-fault report"
            );
            return;
        }
    };
    let Ok(signed_at) = now_unix_secs() else {
        return;
    };
    let accused_committee_scope = if binding.origin_protocol == "pss_reshare" {
        CommitteeScope::PendingNew
    } else {
        CommitteeScope::Current
    };
    let statement = DkgControlMessageFaultStatement {
        domain: DKG_CONTROL_MESSAGE_FAULT_DOMAIN.to_string(),
        chain_id: binding.chain_id,
        ring_id: binding.ring_id.clone(),
        ring_pk: binding.ring_pk,
        ring_state_sha256: binding.ring_state_sha256,
        protocol_version: binding.protocol_version,
        request_id: binding.request_id,
        signed_at,
        responder_node_key: prepare.leader_node_key.clone(),
        origin_protocol: binding.origin_protocol,
        accused_committee_scope,
        signing_committee_scope: CommitteeScope::Current,
        attempt_id: prepare.attempt_id.0,
        message_kind: "prepare".to_string(),
        fault_kind: DkgControlMessageFaultKind::LeaderPrepareFault,
        artifact_a: ControlMessageArtifact {
            signature: signature.signature,
            data,
        },
        artifact_b: None,
    };
    let observation = InvalidCryptoResponseObservation {
        ring_id: binding.ring_id,
        accused_node_key: prepare.leader_node_key.clone(),
        accused_peer_id: accused_info.peer_id,
        observed_at: statement.signed_at.saturating_sub(CHAIN_BLOCK_GRACE_SECS),
        evidence: InvalidCryptoResponse::DkgControlMessageFault {
            statement: Box::new(statement),
        },
    };
    match queue_report::<D, SignImpl>(
        app_state.clone(),
        routes,
        ReportObservation::InvalidCryptoResponse(Box::new(observation)),
    )
    .await
    {
        Ok(_) => crate::metrics::record_dkg_transport_event(
            "control",
            "leader_prepare_fault_report_queued",
        ),
        Err(error) => {
            crate::metrics::record_dkg_transport_event(
                "control",
                "leader_prepare_fault_report_failed",
            );
            tracing::warn!(
                session_id = prepare.ceremony_id.0,
                attempt_id = %hex::encode(prepare.attempt_id.0),
                %error,
                "failed to queue authenticated leader-Prepare fault report"
            );
        }
    }
}

fn validate_commitment_statement<D>(
    binding: &DkgReportEvidenceBinding,
    from_node_id: u32,
    commitment: &[u8],
    statement: &DkgCommitmentStatement,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    if statement.domain != DKG_COMMITMENT_DOMAIN
        || statement.chain_id != binding.chain_id
        || statement.ring_id != binding.ring_id
        || statement.ring_pk != binding.ring_pk
        || statement.ring_state_sha256 != binding.ring_state_sha256
        || statement.protocol_version != binding.protocol_version
        || statement.request_id != binding.request_id
        || statement.origin_protocol != binding.origin_protocol
        || statement.accused_committee_scope != CommitteeScope::Current
        || statement.signing_committee_scope != CommitteeScope::Current
        || statement.from_node_id != from_node_id
        || statement.commitment != commitment
        || statement.crypto_backend != D::name()
    {
        return Err(DkgError::Unauthorized(
            "DKG commitment evidence does not match this session".to_string(),
        ));
    }
    if statement.responder_node_key.trim().is_empty() {
        return Err(DkgError::Unauthorized(
            "DKG commitment evidence responder cannot be empty".to_string(),
        ));
    }
    let expected_responder_node_key =
        node_key_for_canonical_node_id(from_node_id, &binding.current_node_keys).ok_or_else(
            || {
                DkgError::Unauthorized(format!(
                    "DKG commitment from_node_id {from_node_id} is outside the current committee"
                ))
            },
        )?;
    if statement.responder_node_key != expected_responder_node_key {
        return Err(DkgError::Unauthorized(
            "DKG commitment evidence responder does not match from_node_id".to_string(),
        ));
    }
    Ok(())
}

fn validate_share_statement<D>(
    binding: &DkgReportEvidenceBinding,
    from_node_id: u32,
    to_node_id: u32,
    share_value: &[u8],
    nonce: [u8; 16],
    statement: &DkgShareStatement,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    if statement.domain != DKG_SHARE_DOMAIN
        || statement.chain_id != binding.chain_id
        || statement.ring_id != binding.ring_id
        || statement.ring_pk != binding.ring_pk
        || statement.ring_state_sha256 != binding.ring_state_sha256
        || statement.protocol_version != binding.protocol_version
        || statement.request_id != binding.request_id
        || statement.origin_protocol != binding.origin_protocol
        || statement.accused_committee_scope != CommitteeScope::Current
        || statement.signing_committee_scope != CommitteeScope::Current
        || statement.from_node_id != from_node_id
        || statement.to_node_id != to_node_id
        || statement.share_value != share_value
        || statement.nonce != nonce
        || statement.crypto_backend != D::name()
    {
        return Err(DkgError::Unauthorized(
            "DKG share evidence does not match this session".to_string(),
        ));
    }
    let receiver_node_key = binding
        .receiver_node_keys
        .get(to_node_id.saturating_sub(1) as usize)
        .ok_or_else(|| {
            DkgError::Unauthorized(format!(
                "DKG share to_node_id {} is outside the receiver committee",
                to_node_id
            ))
        })?;
    if &statement.receiver_node_key != receiver_node_key {
        return Err(DkgError::Unauthorized(
            "DKG share evidence receiver does not match to_node_id".to_string(),
        ));
    }
    validate_commitment_statement::<D>(
        binding,
        from_node_id,
        &statement.commitment_statement.commitment,
        &statement.commitment_statement,
    )?;
    if statement.commitment_statement.responder_node_key != statement.responder_node_key
        || statement.commitment_statement.signed_at > statement.signed_at
    {
        return Err(DkgError::Unauthorized(
            "DKG share evidence has invalid nested commitment binding".to_string(),
        ));
    }
    Ok(())
}

fn read_node_signing_key_hex<D>(app_state: &Arc<AppState<D>>) -> Result<String>
where
    D: Dkg + Clone + 'static,
{
    let signing_key = app_state
        .local_storage
        .get_encrypted(LocalStorageKeys::NodeSigningKey)
        .map_err(|error| DkgError::Storage(format!("Failed to read node signing key: {error}")))?
        .ok_or_else(|| DkgError::Storage("Node signing key is not configured".to_string()))?;
    let signing_key_hex = String::from_utf8(signing_key.to_vec()).map_err(|error| {
        DkgError::Storage(format!("Stored node signing key is not UTF-8: {error}"))
    })?;
    Ok(signing_key_hex)
}

fn sign_statement_with_key(signing_key_hex: &str, message: &[u8]) -> Result<Vec<u8>> {
    sign_node_message_with_hex_key(signing_key_hex, message)
        .map_err(|error| DkgError::Crypto(format!("Failed to sign DKG evidence: {error}")))
}

fn now_unix_secs() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| DkgError::Generic(format!("Failed to get unix timestamp: {error}")))
}

/// Node-key sign one control-handshake message's existing digest field
/// (`config_digest`/`activation_digest`), binding it to
/// (ceremony_id, attempt_id, message_kind). Unconditional across every
/// `SessionKind` — Fresh DKG is excluded later, at report-build time
/// (`evidence_binding` returns `None`), not here; the signature itself is
/// cheap and this keeps signing uniform regardless of reportability.
pub(crate) fn sign_control_message<D>(
    app_state: &Arc<AppState<D>>,
    ceremony_id: transport::CeremonyId,
    attempt_id: transport::AttemptId,
    message_kind: &str,
    digest: [u8; 32],
) -> Result<ControlSignature>
where
    D: Dkg + Clone + 'static,
{
    let signing_key_hex = read_node_signing_key_hex(app_state)?;
    let signed_at = now_unix_secs()?;
    let message =
        transport::control_ack_signing_bytes(ceremony_id, attempt_id, message_kind, digest);
    let signature = sign_statement_with_key(&signing_key_hex, &message)?;
    Ok(ControlSignature {
        signer_node_key: app_state.node_key.clone(),
        signed_at,
        signature,
    })
}

/// Independently re-verify a `ControlSignature` against the claimed
/// digest/message-kind/attempt binding and the expected signer. Does not
/// trust `signature.signer_node_key` for identity — the caller supplies
/// `expected_signer_node_key` from its own authoritative source (e.g. the
/// committee route the message arrived on).
pub(crate) fn verify_control_signature(
    ceremony_id: transport::CeremonyId,
    attempt_id: transport::AttemptId,
    message_kind: &str,
    digest: [u8; 32],
    expected_signer_node_key: &str,
    signature: &ControlSignature,
) -> Result<()> {
    if signature.signer_node_key != expected_signer_node_key {
        return Err(DkgError::Unauthorized(format!(
            "control message signature claims signer {} but expected {}",
            signature.signer_node_key, expected_signer_node_key
        )));
    }
    let message =
        transport::control_ack_signing_bytes(ceremony_id, attempt_id, message_kind, digest);
    verify_node_message(expected_signer_node_key, &message, &signature.signature).map_err(|error| {
        DkgError::Unauthorized(format!("invalid control message signature: {error}"))
    })
}

async fn queue_invalid_share_report<D>(
    app_state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    evidence: SignedDkgShare,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let accused_node_key = evidence.statement.responder_node_key.clone();
    let accused_info = read_node_info(&app_state, &accused_node_key).await?;
    let observed_at = evidence
        .statement
        .signed_at
        .saturating_sub(CHAIN_BLOCK_GRACE_SECS);
    let observation = InvalidCryptoResponseObservation {
        ring_id: evidence.statement.ring_id.clone(),
        accused_node_key,
        accused_peer_id: accused_info.peer_id,
        observed_at,
        evidence: InvalidCryptoResponse::DkgShare {
            statement: Box::new(evidence.statement),
            response_signature: evidence.signature,
        },
    };

    queue_report::<D, SignImpl>(
        app_state,
        routes,
        ReportObservation::InvalidCryptoResponse(Box::new(observation)),
    )
    .await
    .map_err(|error| DkgError::Generic(error.to_string()))?;
    Ok(())
}

/// Report a refresh dealer whose signed commitment has a non-identity constant term.
/// Refresh keeps the same committee, so the detector is always a current-committee member —
/// this queues directly (no relay). Single self-incriminating statement.
pub async fn queue_invalid_refresh_commitment_report<D>(
    app_state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    commitment: SignedDkgCommitment,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let accused_node_key = commitment.statement.responder_node_key.clone();
    let accused_info = read_node_info(&app_state, &accused_node_key).await?;
    let observed_at = commitment
        .statement
        .signed_at
        .saturating_sub(CHAIN_BLOCK_GRACE_SECS);
    let observation = InvalidCryptoResponseObservation {
        ring_id: commitment.statement.ring_id.clone(),
        accused_node_key,
        accused_peer_id: accused_info.peer_id,
        observed_at,
        evidence: InvalidCryptoResponse::DkgInvalidRefreshCommitment {
            statement: Box::new(commitment.statement),
            response_signature: commitment.signature,
        },
    };

    queue_report::<D, SignImpl>(
        app_state,
        routes,
        ReportObservation::InvalidCryptoResponse(Box::new(observation)),
    )
    .await
    .map_err(|error| DkgError::Generic(error.to_string()))?;
    Ok(())
}

async fn queue_public_origin_fault_report<D>(
    app_state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    attempt: AttemptKey,
    fault_kind: DkgPublicOriginFaultKind,
    contribution_a: network::SignedPayload,
    contribution_b: Option<network::SignedPayload>,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let coordinator = DkgCoordinator::with_routes(app_state.clone(), routes);
    let binding = evidence_binding(&coordinator, attempt)
        .await?
        .ok_or_else(|| {
            DkgError::Unauthorized("Fresh DKG public-origin faults are not reportable".to_string())
        })?;
    let decoded: DkgPublicContribution = transport::decode(
        &contribution_a.data,
        transport::MAX_PUBLIC_ORIGIN_EVIDENCE_BYTES,
    )
    .map_err(DkgError::Deserialization)?;
    if decoded.ceremony_id != attempt.ceremony_id || decoded.attempt_id != attempt.attempt_id {
        return Err(DkgError::Unauthorized(
            "public-origin evidence does not target the active attempt".to_string(),
        ));
    }
    let evidence_signed_at = match fault_kind {
        DkgPublicOriginFaultKind::InvalidPayload => decoded.signed_at,
        DkgPublicOriginFaultKind::OriginEquivocation => {
            let contribution_b = contribution_b.as_ref().ok_or_else(|| {
                DkgError::InvalidInput(
                    "public-origin equivocation evidence requires two contributions".to_string(),
                )
            })?;
            let decoded_b: DkgPublicContribution = transport::decode(
                &contribution_b.data,
                transport::MAX_PUBLIC_ORIGIN_EVIDENCE_BYTES,
            )
            .map_err(DkgError::Deserialization)?;
            decoded.signed_at.max(decoded_b.signed_at)
        }
    };
    let (accused_committee_scope, node_keys) = match decoded.origin.scope {
        transport::CommitteeScope::Current => (CommitteeScope::Current, &binding.current_node_keys),
        transport::CommitteeScope::Next => {
            (CommitteeScope::PendingNew, &binding.receiver_node_keys)
        }
    };
    let accused_node_key = node_key_for_canonical_node_id(decoded.origin.node_id, node_keys)
        .ok_or_else(|| {
            DkgError::Unauthorized(
                "public-origin evidence participant is not in the bound committee".to_string(),
            )
        })?;
    let accused_info = read_node_info(&app_state, &accused_node_key).await?;
    let statement = DkgPublicOriginFaultStatement {
        domain: DKG_PUBLIC_ORIGIN_FAULT_DOMAIN.to_string(),
        chain_id: binding.chain_id,
        ring_id: binding.ring_id.clone(),
        ring_pk: binding.ring_pk,
        ring_state_sha256: binding.ring_state_sha256,
        protocol_version: binding.protocol_version,
        request_id: binding.request_id,
        signed_at: evidence_signed_at,
        responder_node_key: accused_node_key.clone(),
        origin_protocol: binding.origin_protocol,
        accused_committee_scope,
        signing_committee_scope: CommitteeScope::Current,
        attempt_id: attempt.attempt_id.0,
        phase: decoded.payload.phase().as_metric_label().to_string(),
        fault_kind,
        contribution_a: EndpointSignedContribution {
            origin: contribution_a.origin,
            signature: contribution_a.signature,
            data: contribution_a.data,
        },
        contribution_b: contribution_b.map(|contribution| EndpointSignedContribution {
            origin: contribution.origin,
            signature: contribution.signature,
            data: contribution.data,
        }),
    };
    let observation = InvalidCryptoResponseObservation {
        ring_id: binding.ring_id,
        accused_node_key,
        accused_peer_id: accused_info.peer_id,
        observed_at: statement.signed_at.saturating_sub(CHAIN_BLOCK_GRACE_SECS),
        evidence: InvalidCryptoResponse::DkgPublicOriginFault {
            statement: Box::new(statement),
        },
    };
    queue_report::<D, SignImpl>(
        app_state,
        routes,
        ReportObservation::InvalidCryptoResponse(Box::new(observation)),
    )
    .await
    .map_err(|error| DkgError::Generic(error.to_string()))?;
    Ok(())
}

/// The ceremony/attempt/phase a decoded leader delivery targets, or `None`
/// for `TopologyProbe`, which is never retained as leader-equivocation
/// evidence.
fn leader_delivery_attempt_and_phase(
    message: &transport::DkgPublicMessage,
) -> Option<(
    transport::CeremonyId,
    transport::AttemptId,
    transport::PublicPhase,
)> {
    match message {
        transport::DkgPublicMessage::Manifest(manifest) => {
            Some((manifest.ceremony_id, manifest.attempt_id, manifest.phase))
        }
        transport::DkgPublicMessage::Chunk {
            ceremony_id,
            attempt_id,
            phase,
            ..
        } => Some((*ceremony_id, *attempt_id, *phase)),
        transport::DkgPublicMessage::TopologyProbe { .. } => None,
    }
}

/// Package two conflicting endpoint-signed leader deliveries (a manifest, or
/// a chunk) into a report. This step does not itself re-prove they conflict
/// — that already happened structurally before this was called (direct
/// detection in `PublicBatchAssembler`), or will be independently re-checked
/// by every co-signer during threshold-signing (`registry.rs`'s anti-framing
/// verification) — a relayed claim is otherwise-unauthenticated input.
#[allow(clippy::too_many_arguments)]
async fn queue_leader_equivocation_report<D>(
    app_state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    attempt: AttemptKey,
    delivery_id_a: [u8; 16],
    delivery_a: network::SignedPayload,
    delivery_id_b: [u8; 16],
    delivery_b: network::SignedPayload,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let coordinator = DkgCoordinator::with_routes(app_state.clone(), routes);
    let binding = evidence_binding(&coordinator, attempt)
        .await?
        .ok_or_else(|| {
            DkgError::Unauthorized("Fresh DKG leader equivocation is not reportable".to_string())
        })?;
    let canonical_leader = transport::canonical_leader(&binding.receiver_node_keys)
        .ok_or_else(|| {
            DkgError::InvalidState(
                "leader-equivocation evidence has an empty committee".to_string(),
            )
        })?
        .to_string();
    let decoded_a: transport::DkgPublicMessage = transport::decode(
        &delivery_a.data,
        transport::MAX_PUBLIC_ORIGIN_EVIDENCE_BYTES,
    )
    .map_err(DkgError::Deserialization)?;
    let (ceremony_id, attempt_id, phase) = leader_delivery_attempt_and_phase(&decoded_a)
        .ok_or_else(|| {
            DkgError::InvalidInput("leader delivery is not a manifest or chunk".to_string())
        })?;
    if ceremony_id != attempt.ceremony_id || attempt_id != attempt.attempt_id {
        return Err(DkgError::Unauthorized(
            "leader-equivocation evidence does not target the active attempt".to_string(),
        ));
    }
    let signed_at = now_unix_secs()?;
    let accused_committee_scope = if binding.origin_protocol == "pss_reshare" {
        CommitteeScope::PendingNew
    } else {
        CommitteeScope::Current
    };
    let accused_info = read_node_info(&app_state, &canonical_leader).await?;
    let statement = DkgLeaderEquivocationStatement {
        domain: DKG_LEADER_EQUIVOCATION_DOMAIN.to_string(),
        chain_id: binding.chain_id,
        ring_id: binding.ring_id.clone(),
        ring_pk: binding.ring_pk,
        ring_state_sha256: binding.ring_state_sha256,
        protocol_version: binding.protocol_version,
        request_id: binding.request_id,
        signed_at,
        responder_node_key: canonical_leader.clone(),
        origin_protocol: binding.origin_protocol,
        accused_committee_scope,
        signing_committee_scope: CommitteeScope::Current,
        attempt_id: attempt.attempt_id.0,
        phase: phase.as_metric_label().to_string(),
        delivery_id_a,
        delivery_a: EndpointSignedContribution {
            origin: delivery_a.origin,
            signature: delivery_a.signature,
            data: delivery_a.data,
        },
        delivery_id_b,
        delivery_b: EndpointSignedContribution {
            origin: delivery_b.origin,
            signature: delivery_b.signature,
            data: delivery_b.data,
        },
    };
    let observation = InvalidCryptoResponseObservation {
        ring_id: binding.ring_id,
        accused_node_key: canonical_leader,
        accused_peer_id: accused_info.peer_id,
        observed_at: statement.signed_at.saturating_sub(CHAIN_BLOCK_GRACE_SECS),
        evidence: InvalidCryptoResponse::DkgLeaderEquivocation {
            statement: Box::new(statement),
        },
    };
    queue_report::<D, SignImpl>(
        app_state,
        routes,
        ReportObservation::InvalidCryptoResponse(Box::new(observation)),
    )
    .await
    .map_err(|error| DkgError::Generic(error.to_string()))?;
    Ok(())
}

/// Package a control-handshake fault into a report. Accepts the accused's
/// node key directly rather than re-deriving it, since which key that is
/// varies by fault kind (the claimed leader for `LeaderPrepareFault`, the
/// equivocating follower for `AckEquivocation`) and the caller already knows
/// it from the same logic that detected the fault. Like
/// `queue_leader_equivocation_report`, this does not itself re-verify the
/// signatures — direct detection already proved it structurally, and a
/// relayed claim is independently re-checked by every co-signer during
/// threshold-signing.
#[allow(clippy::too_many_arguments)]
async fn queue_control_message_fault_report<D>(
    app_state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    attempt: AttemptKey,
    accused_node_key: String,
    message_kind: String,
    fault_kind: DkgControlMessageFaultKind,
    artifact_a: ControlMessageArtifact,
    artifact_b: Option<ControlMessageArtifact>,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let coordinator = DkgCoordinator::with_routes(app_state.clone(), routes);
    let binding = evidence_binding(&coordinator, attempt)
        .await?
        .ok_or_else(|| {
            DkgError::Unauthorized(
                "Fresh DKG control-message faults are not reportable".to_string(),
            )
        })?;
    let accused_committee_scope = if binding.current_node_keys.contains(&accused_node_key) {
        CommitteeScope::Current
    } else if binding.receiver_node_keys.contains(&accused_node_key) {
        CommitteeScope::PendingNew
    } else {
        return Err(DkgError::Unauthorized(
            "control-message fault accused is not in the bound committee".to_string(),
        ));
    };
    let signed_at = now_unix_secs()?;
    let accused_info = read_node_info(&app_state, &accused_node_key).await?;
    let statement = DkgControlMessageFaultStatement {
        domain: DKG_CONTROL_MESSAGE_FAULT_DOMAIN.to_string(),
        chain_id: binding.chain_id,
        ring_id: binding.ring_id.clone(),
        ring_pk: binding.ring_pk,
        ring_state_sha256: binding.ring_state_sha256,
        protocol_version: binding.protocol_version,
        request_id: binding.request_id,
        signed_at,
        responder_node_key: accused_node_key.clone(),
        origin_protocol: binding.origin_protocol,
        accused_committee_scope,
        signing_committee_scope: CommitteeScope::Current,
        attempt_id: attempt.attempt_id.0,
        message_kind: message_kind.to_string(),
        fault_kind,
        artifact_a,
        artifact_b,
    };
    let observation = InvalidCryptoResponseObservation {
        ring_id: binding.ring_id,
        accused_node_key,
        accused_peer_id: accused_info.peer_id,
        observed_at: statement.signed_at.saturating_sub(CHAIN_BLOCK_GRACE_SECS),
        evidence: InvalidCryptoResponse::DkgControlMessageFault {
            statement: Box::new(statement),
        },
    };
    queue_report::<D, SignImpl>(
        app_state,
        routes,
        ReportObservation::InvalidCryptoResponse(Box::new(observation)),
    )
    .await
    .map_err(|error| DkgError::Generic(error.to_string()))?;
    Ok(())
}

async fn queue_equivocation_report<D>(
    app_state: Arc<AppState<D>>,
    routes: &'static network::ProtocolRoutes,
    commitment_a: SignedDkgCommitment,
    commitment_b: SignedDkgCommitment,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    // Both commitments name the same dealer. Anchor the envelope to the LATER
    // of the two signed_at values, not whichever happens to be "commitment_a"
    // (typically the earlier, already-retained one) — equivocation is only
    // detectable once the second, conflicting commitment arrives, which can
    // legitimately be well after the first within a long-running attempt.
    // Anchoring to the earlier one would let the report's TTL close before
    // the fault is even provable.
    let accused_node_key = commitment_a.statement.responder_node_key.clone();
    let accused_info = read_node_info(&app_state, &accused_node_key).await?;
    let observed_at = commitment_a
        .statement
        .signed_at
        .max(commitment_b.statement.signed_at)
        .saturating_sub(CHAIN_BLOCK_GRACE_SECS);
    let observation = InvalidCryptoResponseObservation {
        ring_id: commitment_a.statement.ring_id.clone(),
        accused_node_key,
        accused_peer_id: accused_info.peer_id,
        observed_at,
        evidence: InvalidCryptoResponse::DkgEquivocation {
            commitment_a: Box::new(commitment_a),
            commitment_b: Box::new(commitment_b),
        },
    };

    queue_report::<D, SignImpl>(
        app_state,
        routes,
        ReportObservation::InvalidCryptoResponse(Box::new(observation)),
    )
    .await
    .map_err(|error| DkgError::Generic(error.to_string()))?;
    Ok(())
}

async fn relay_invalid_share_evidence<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    evidence: SignedDkgShare,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    crate::dkg::v0::network::relay_invalid_share_evidence(coord, attempt, evidence).await
}

async fn local_node_is_current_route_member<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
) -> Result<bool>
where
    D: CoordinatorDkg,
{
    let local_peer_hex = hex::encode(coord.app_state.network.local_peer_id().as_bytes());
    coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |state| {
            state
                .routing
                .node_id_to_peer_id
                .values()
                .any(|peer_id| extract_node_part(peer_id) == local_peer_hex)
        })
        .await
        .map_err(|error| attempt_state_error(attempt, error))
}

async fn verify_relay_is_current_signer<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    if local_node_is_current_route_member(coord, attempt).await? {
        Ok(())
    } else {
        Err(DkgError::Unauthorized(
            "local node is not a current committee report signer".to_string(),
        ))
    }
}

async fn read_node_info<D>(app_state: &Arc<AppState<D>>, node_key: &str) -> Result<NodeInfo>
where
    D: Dkg + Clone + 'static,
{
    let post = app_state
        .bulletin
        .read(node_key.to_string(), BulletinKind::NodeInfo)
        .await
        .map_err(|error| DkgError::Bulletin(error.to_string()))?;
    NodeInfo::try_from(post).map_err(|error| DkgError::Deserialization(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::test_helpers::{cleanup_db, create_test_app_state_default, test_db_path};
    use crypto::r#trait::DkgRole;
    use crypto::DkgImpl;
    use std::sync::Arc;

    fn signed_share_with_origin(origin: &str) -> SignedDkgShare {
        let commitment_statement = DkgCommitmentStatement {
            domain: DKG_COMMITMENT_DOMAIN.to_string(),
            chain_id: "chain".to_string(),
            ring_id: "ring".to_string(),
            ring_pk: "pk".to_string(),
            ring_state_sha256: "00".repeat(32),
            protocol_version: 0,
            request_id: "session".to_string(),
            signed_at: 100,
            responder_node_key: "accused".to_string(),
            origin_protocol: origin.to_string(),
            accused_committee_scope: CommitteeScope::Current,
            signing_committee_scope: CommitteeScope::Current,
            from_node_id: 2,
            commitment: vec![1],
            session_nonce: [0u8; 16],
            crypto_backend: DkgImpl::name(),
        };
        SignedDkgShare {
            statement: DkgShareStatement {
                domain: DKG_SHARE_DOMAIN.to_string(),
                chain_id: "chain".to_string(),
                ring_id: "ring".to_string(),
                ring_pk: "pk".to_string(),
                ring_state_sha256: "00".repeat(32),
                protocol_version: 0,
                request_id: "session".to_string(),
                signed_at: 100,
                responder_node_key: "accused".to_string(),
                receiver_node_key: "receiver".to_string(),
                origin_protocol: origin.to_string(),
                accused_committee_scope: CommitteeScope::Current,
                signing_committee_scope: CommitteeScope::Current,
                from_node_id: 2,
                to_node_id: 1,
                commitment_statement,
                commitment_signature: vec![7; 64],
                share_value: vec![8],
                nonce: [9; 16],
                crypto_backend: DkgImpl::name(),
            },
            signature: vec![5; 64],
        }
    }

    fn evidence_binding_for_tests() -> DkgReportEvidenceBinding {
        DkgReportEvidenceBinding {
            ring_id: "ring".to_string(),
            ring_pk: "pk".to_string(),
            ring_state_sha256: "00".repeat(32),
            chain_id: "chain".to_string(),
            protocol_version: 0,
            request_id: "session".to_string(),
            origin_protocol: "pss_refresh".to_string(),
            current_node_keys: vec!["node-a".to_string(), "node-b".to_string()],
            receiver_node_keys: vec!["node-a".to_string(), "node-b".to_string()],
        }
    }

    fn commitment_statement_for_tests(responder_node_key: &str) -> DkgCommitmentStatement {
        DkgCommitmentStatement {
            domain: DKG_COMMITMENT_DOMAIN.to_string(),
            chain_id: "chain".to_string(),
            ring_id: "ring".to_string(),
            ring_pk: "pk".to_string(),
            ring_state_sha256: "00".repeat(32),
            protocol_version: 0,
            request_id: "session".to_string(),
            signed_at: 100,
            responder_node_key: responder_node_key.to_string(),
            origin_protocol: "pss_refresh".to_string(),
            accused_committee_scope: CommitteeScope::Current,
            signing_committee_scope: CommitteeScope::Current,
            from_node_id: 1,
            commitment: vec![1, 2, 3],
            session_nonce: [0u8; 16],
            crypto_backend: DkgImpl::name(),
        }
    }

    #[test]
    fn commitment_evidence_rejects_responder_not_bound_to_from_node_id() {
        let binding = evidence_binding_for_tests();
        let statement = commitment_statement_for_tests("node-b");

        let error = validate_commitment_statement::<DkgImpl>(&binding, 1, &[1, 2, 3], &statement)
            .unwrap_err();

        assert!(matches!(error, DkgError::Unauthorized(_)));
    }

    fn signed_commitment_for_equivocation(
        commitment: Vec<u8>,
        session_nonce: [u8; 16],
    ) -> SignedDkgCommitment {
        let mut statement = commitment_statement_for_tests("accused");
        statement.commitment = commitment;
        statement.session_nonce = session_nonce;
        SignedDkgCommitment {
            statement,
            signature: vec![1; 64],
        }
    }

    #[test]
    fn commitments_prove_equivocation_requires_same_nonce_and_different_bytes() {
        let nonce = [5u8; 16];
        let a = signed_commitment_for_equivocation(vec![1, 2, 3], nonce);

        // Same nonce, different bytes → equivocation.
        let b = signed_commitment_for_equivocation(vec![9, 9, 9], nonce);
        assert!(commitments_prove_equivocation(&a, &b));

        // Same nonce, identical bytes → not equivocation.
        let same = signed_commitment_for_equivocation(vec![1, 2, 3], nonce);
        assert!(!commitments_prove_equivocation(&a, &same));

        // Different nonce (honest retry), different bytes → not equivocation.
        let retry = signed_commitment_for_equivocation(vec![9, 9, 9], [6u8; 16]);
        assert!(!commitments_prove_equivocation(&a, &retry));

        // Different dealer → not equivocation.
        let mut other_dealer = signed_commitment_for_equivocation(vec![9, 9, 9], nonce);
        other_dealer.statement.from_node_id += 1;
        assert!(!commitments_prove_equivocation(&a, &other_dealer));
    }

    #[test]
    fn share_evidence_rejects_responder_not_bound_to_from_node_id() {
        let binding = evidence_binding_for_tests();
        let commitment_statement = commitment_statement_for_tests("node-b");
        let statement = DkgShareStatement {
            domain: DKG_SHARE_DOMAIN.to_string(),
            chain_id: "chain".to_string(),
            ring_id: "ring".to_string(),
            ring_pk: "pk".to_string(),
            ring_state_sha256: "00".repeat(32),
            protocol_version: 0,
            request_id: "session".to_string(),
            signed_at: 101,
            responder_node_key: "node-b".to_string(),
            receiver_node_key: "node-a".to_string(),
            origin_protocol: "pss_refresh".to_string(),
            accused_committee_scope: CommitteeScope::Current,
            signing_committee_scope: CommitteeScope::Current,
            from_node_id: 1,
            to_node_id: 1,
            commitment_statement,
            commitment_signature: vec![7; 64],
            share_value: vec![9],
            nonce: [8; 16],
            crypto_backend: DkgImpl::name(),
        };

        let error = validate_share_statement::<DkgImpl>(&binding, 1, 1, &[9], [8; 16], &statement)
            .unwrap_err();

        assert!(matches!(error, DkgError::Unauthorized(_)));
    }

    #[tokio::test]
    async fn current_signer_detection_uses_current_route_map_during_reshare() {
        let db_name = "evidence_current_signer_uses_current_routes";
        let db_path = test_db_path(db_name);
        cleanup_db(&db_path);
        let app_state = Arc::new(create_test_app_state_default(db_name).await);
        let local_peer_hex = hex::encode(app_state.network.local_peer_id().as_bytes());
        let coordinator = DkgCoordinator::with_routes(app_state, &::network::V0);
        let session_id = 7;

        coordinator
            .create_session(
                AttemptKey::test(session_id),
                1,
                2,
                3,
                DkgRole::Dealer,
                |state| {
                    state.kind = SessionKind::Reshare {
                        ring_pk_hex: "ring-pk".to_string(),
                        new_peer_node_keys: vec!["new-a".to_string(), "new-b".to_string()],
                        new_threshold: 2,
                        bulletin_post_id: "ring-id".to_string(),
                    };
                    // During reshare this field is the receiver/new committee; it must
                    // not be used to decide whether this node can sign current reports.
                    state.routing.peer_node_keys = vec!["new-a".to_string(), "new-b".to_string()];
                    state
                        .routing
                        .node_id_to_peer_id
                        .insert(1, format!("{local_peer_hex}@127.0.0.1:1234"));
                },
            )
            .await
            .expect("create reshare dealer session");

        assert!(
            local_node_is_current_route_member(&coordinator, AttemptKey::test(session_id))
                .await
                .expect("membership check")
        );
        cleanup_db(&db_path);
    }

    #[tokio::test]
    async fn pure_new_receiver_is_not_current_report_signer() {
        let db_name = "evidence_pure_new_not_current_signer";
        let db_path = test_db_path(db_name);
        cleanup_db(&db_path);
        let app_state = Arc::new(create_test_app_state_default(db_name).await);
        let local_node_key = app_state.node_key.clone();
        let local_peer_hex = hex::encode(app_state.network.local_peer_id().as_bytes());
        let coordinator = DkgCoordinator::with_routes(app_state, &::network::V0);
        let session_id = 8;

        coordinator
            .create_session(
                AttemptKey::test(session_id),
                1,
                1,
                1,
                DkgRole::Receiver,
                |state| {
                    state.kind = SessionKind::Reshare {
                        ring_pk_hex: "ring-pk".to_string(),
                        new_peer_node_keys: vec![local_node_key.clone()],
                        new_threshold: 1,
                        bulletin_post_id: "ring-id".to_string(),
                    };
                    // This simulates the pure-new receiver case that used to be
                    // misclassified because `peer_node_keys` names the new committee.
                    state.routing.peer_node_keys = vec![local_node_key];
                    state.routing.node_id_to_peer_id.insert(1, "a".repeat(64));
                    state
                        .routing
                        .reshare_new_node_id_to_peer_id
                        .insert(1, local_peer_hex);
                },
            )
            .await
            .expect("create reshare receiver session");

        assert!(
            !local_node_is_current_route_member(&coordinator, AttemptKey::test(session_id))
                .await
                .expect("membership check")
        );
        cleanup_db(&db_path);
    }

    /// A relayed report is unauthenticated network input; the handler must reject a
    /// non-reshare origin before doing any work, since the relay message only
    /// exists for reshare pending-new receivers.
    #[tokio::test]
    async fn relay_rejects_non_reshare_origin() {
        let db_name = "evidence_relay_rejects_non_reshare_origin";
        let db_path = test_db_path(db_name);
        cleanup_db(&db_path);
        let app_state = Arc::new(create_test_app_state_default(db_name).await);
        let coordinator = DkgCoordinator::with_routes(app_state, &::network::V0);

        let error = handle_invalid_share_evidence_relay(
            &coordinator,
            AttemptKey::test(1),
            signed_share_with_origin("pss_refresh"),
        )
        .await
        .unwrap_err();
        cleanup_db(&db_path);

        assert!(matches!(error, DkgError::Unauthorized(_)));
    }

    #[tokio::test]
    async fn public_origin_relay_rejects_refresh_session() {
        let db_name = "evidence_public_origin_relay_rejects_refresh";
        let db_path = test_db_path(db_name);
        cleanup_db(&db_path);
        let app_state = Arc::new(create_test_app_state_default(db_name).await);
        let local_peer_hex = hex::encode(app_state.network.local_peer_id().as_bytes());
        let coordinator = DkgCoordinator::with_routes(app_state, &::network::V0);
        let attempt = AttemptKey::test(9);
        coordinator
            .create_session(attempt, 1, 2, 3, DkgRole::Standard, |state| {
                state.kind = SessionKind::Refresh {
                    ring_pk_hex: "pk".to_string(),
                };
                state.routing.node_id_to_peer_id.insert(1, local_peer_hex);
                state.report_evidence_binding = Some(evidence_binding_for_tests());
            })
            .await
            .expect("create Refresh relay test session");

        let error = handle_public_origin_fault_evidence_relay(
            &coordinator,
            attempt,
            DkgPublicOriginFaultKind::InvalidPayload,
            network::SignedPayload {
                origin: vec![1; 32],
                signature: vec![2; 64],
                data: vec![3],
            },
            None,
        )
        .await
        .expect_err("public-origin relays are Reshare-only");
        cleanup_db(&db_path);

        assert!(matches!(error, DkgError::Unauthorized(_)));
    }

    /// A reshare-origin relay for a session this node is not currently signing is
    /// rejected before the evidence is queued.
    #[tokio::test]
    async fn relay_rejects_unknown_session() {
        let db_name = "evidence_relay_rejects_unknown_session";
        let db_path = test_db_path(db_name);
        cleanup_db(&db_path);
        let app_state = Arc::new(create_test_app_state_default(db_name).await);
        let coordinator = DkgCoordinator::with_routes(app_state, &::network::V0);

        let error = handle_invalid_share_evidence_relay(
            &coordinator,
            AttemptKey::test(999),
            signed_share_with_origin("pss_reshare"),
        )
        .await
        .unwrap_err();
        cleanup_db(&db_path);

        // No such session exists, so the current-signer check fails before queuing.
        assert!(matches!(
            error,
            DkgError::SessionNotFound(_)
                | DkgError::StaleAttempt { .. }
                | DkgError::Unauthorized(_)
        ));
    }
}
