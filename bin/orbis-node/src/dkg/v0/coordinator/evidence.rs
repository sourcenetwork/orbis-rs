use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bulletin::r#trait::{BulletinKind, NodeInfo, RingPayload};
use common::blockchain::{sign_node_message_with_hex_key, verify_node_message};
use crypto::r#trait::{CryptoDeserialize, Dkg, PolynomialCommitment as PolynomialCommitmentTrait};
use crypto::{ScalarField as Fr, SignImpl};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};

use crate::app_state::AppState;
use crate::dkg::v0::error::{DkgError, Result};
use crate::dkg::v0::helpers::{deserialize_wire_commitment, session_not_found};
use crate::dkg::v0::messages::{DkgMessage, SessionKind, SignedDkgCommitment, SignedDkgShare};
use crate::dkg::v0::session_state::DkgReportEvidenceBinding;
use crate::reporting::v0::observation::{InvalidCryptoResponseObservation, ReportObservation};
use crate::reporting::v0::queue_report;
use crate::reporting::v0::types::{
    ring_state_sha256, CommitteeScope, DkgCommitmentStatement, DkgShareStatement,
    InvalidCryptoResponse, CHAIN_BLOCK_GRACE_SECS, DKG_COMMITMENT_DOMAIN, DKG_SHARE_DOMAIN,
};

use super::{
    types::{CoordinatorDkg, CoordinatorReportSigner},
    DkgCoordinator,
};

pub(crate) struct DkgEvidenceBuildContext {
    binding: DkgReportEvidenceBinding,
    signing_key_hex: String,
}

pub(crate) async fn evidence_build_context<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
) -> Result<Option<DkgEvidenceBuildContext>>
where
    D: CoordinatorDkg,
{
    let Some(binding) = evidence_binding(coord, session_id).await? else {
        return Ok(None);
    };
    let signing_key_hex = read_node_signing_key_hex(&coord.app_state)?;
    Ok(Some(DkgEvidenceBuildContext {
        binding,
        signing_key_hex,
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
    session_id: u128,
    from_node_id: u32,
    commitment: Vec<u8>,
) -> Result<Option<SignedDkgCommitment>>
where
    D: CoordinatorDkg,
{
    let Some(context) = evidence_build_context(coord, session_id).await? else {
        return Ok(None);
    };
    let report_evidence = build_and_store_commitment_evidence_with_context(
        coord,
        session_id,
        &context,
        from_node_id,
        commitment,
    )
    .await?;
    Ok(Some(report_evidence))
}

pub(crate) async fn build_and_store_commitment_evidence_with_context<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
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
        .with_state_mut(&session_id, |state| {
            state.local_signed_commitment = Some(report_evidence.clone());
        })
        .await
        .ok_or_else(|| session_not_found(session_id))?;
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
    session_id: u128,
    from_node_id: u32,
    commitment: &[u8],
    evidence: Option<SignedDkgCommitment>,
) -> Result<Option<SignedDkgCommitment>>
where
    D: CoordinatorDkg,
{
    let Some(binding) = evidence_binding(coord, session_id).await? else {
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
    session_id: u128,
    from_node_id: u32,
    to_node_id: u32,
    share_value: &[u8],
    nonce: [u8; 16],
    evidence: Option<SignedDkgShare>,
) -> Result<Option<SignedDkgShare>>
where
    D: CoordinatorDkg,
{
    let Some(binding) = evidence_binding(coord, session_id).await? else {
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

pub async fn queue_or_relay_invalid_share<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    evidence: SignedDkgShare,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let is_current_member = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| {
            state
                .routing
                .peer_node_keys
                .iter()
                .any(|node_key| node_key == &coord.app_state.node_key)
        })
        .await
        .ok_or_else(|| session_not_found(session_id))?;

    if is_current_member {
        queue_invalid_share_report(coord.app_state.clone(), coord.routes, evidence).await
    } else if evidence.statement.origin_protocol == "pss_reshare" {
        relay_invalid_share_evidence(coord, session_id, evidence).await
    } else {
        Err(DkgError::Unauthorized(
            "local node is not in the report signing committee".to_string(),
        ))
    }
}

pub async fn handle_invalid_share_evidence_relay<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    report_evidence: SignedDkgShare,
) -> Result<Option<DkgMessage>>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    if report_evidence.statement.origin_protocol != "pss_reshare" {
        return Err(DkgError::Unauthorized(
            "DKG bad-share evidence relay is only valid for reshare".to_string(),
        ));
    }
    verify_relay_is_current_signer(coord, session_id).await?;

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
        session_id,
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
    Ok(None)
}

async fn evidence_binding<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
) -> Result<Option<DkgReportEvidenceBinding>>
where
    D: CoordinatorDkg,
{
    if let Some(cached) = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| state.report_evidence_binding.clone())
        .await
        .ok_or_else(|| session_not_found(session_id))?
    {
        return Ok(Some(cached));
    }

    let Some((kind, stored_ring_id, protocol_version, receiver_node_keys)) = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| {
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
    else {
        return Err(session_not_found(session_id));
    };

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
        receiver_node_keys,
    };

    let binding = coord
        .app_state
        .dkg_session_state
        .with_state_mut(&session_id, |state| {
            if state.report_evidence_binding.is_none() {
                state.report_evidence_binding = Some(binding.clone());
            }
            state.report_evidence_binding.clone()
        })
        .await
        .ok_or_else(|| session_not_found(session_id))?
        .ok_or_else(|| {
            DkgError::InvalidState("failed to cache DKG report evidence binding".to_string())
        })?;

    Ok(Some(binding))
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

async fn relay_invalid_share_evidence<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    evidence: SignedDkgShare,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let current_peer_ids = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| {
            state
                .routing
                .node_id_to_peer_id
                .values()
                .cloned()
                .collect::<Vec<_>>()
        })
        .await
        .ok_or_else(|| session_not_found(session_id))?;
    if current_peer_ids.is_empty() {
        return Err(DkgError::InvalidState(
            "cannot relay DKG bad-share evidence without current committee routes".to_string(),
        ));
    }

    let mut sent = 0usize;
    for peer_id in current_peer_ids {
        let msg = DkgMessage::DkgInvalidShareEvidence {
            session_id,
            receiver_node_id: evidence.statement.to_node_id,
            report_evidence: evidence.clone(),
        };
        if coord
            .send_message_to_peer(&peer_id, msg, Some(session_id))
            .await
            .inspect_err(|error| {
                tracing::warn!(
                    session_id = session_id,
                    peer_id = %peer_id,
                    error = %error,
                    "Failed to relay DKG bad-share evidence to current committee peer"
                );
            })
            .is_ok()
        {
            sent += 1;
        }
    }

    if sent == 0 {
        return Err(DkgError::NetworkCommunication(
            "failed to relay DKG bad-share evidence to any current committee peer".to_string(),
        ));
    }
    Ok(())
}

async fn verify_relay_is_current_signer<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let is_current_member = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| {
            state
                .routing
                .peer_node_keys
                .iter()
                .any(|node_key| node_key == &coord.app_state.node_key)
        })
        .await
        .ok_or_else(|| session_not_found(session_id))?;
    if is_current_member {
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
            1,
            signed_share_with_origin("pss_refresh"),
        )
        .await
        .unwrap_err();
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
            999,
            signed_share_with_origin("pss_reshare"),
        )
        .await
        .unwrap_err();
        cleanup_db(&db_path);

        // No such session exists, so the current-signer check fails before queuing.
        assert!(matches!(
            error,
            DkgError::SessionNotFound(_) | DkgError::Unauthorized(_)
        ));
    }
}
