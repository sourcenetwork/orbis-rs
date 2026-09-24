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
    DkgLeaderPublicFaultKind, DkgLeaderPublicFaultStatement, DkgPublicOriginFaultKind,
    DkgPublicOriginFaultStatement, DkgShareStatement, EndpointSignedContribution,
    InvalidCryptoResponse, CHAIN_BLOCK_GRACE_SECS, DKG_COMMITMENT_DOMAIN,
    DKG_CONTROL_MESSAGE_FAULT_DOMAIN, DKG_LEADER_BATCH_MISMATCH_DOMAIN,
    DKG_LEADER_EQUIVOCATION_DOMAIN, DKG_LEADER_PUBLIC_FAULT_DOMAIN, DKG_PUBLIC_ORIGIN_FAULT_DOMAIN,
    DKG_SHARE_DOMAIN,
};

use super::{
    attempt_state_error,
    types::{CoordinatorDkg, CoordinatorReportSigner},
    DkgCoordinator,
};

mod commitment;
mod control_message;
mod leader_batch_mismatch;
mod leader_equivocation;
mod leader_public_fault;
mod public_origin;
mod share;

// External API, re-exported unchanged so every existing
// `crate::dkg::v0::coordinator::evidence::<name>` call site keeps working
// regardless of which submodule now defines it. A re-export a distant
// module only reaches via its own `use crate::...::evidence::{...}` (rather
// than a local call in this file) can trip `unused_imports` even though it
// is genuinely load-bearing — same pattern as `reporting::v0::registry`'s
// submodule split.
pub use commitment::{
    build_and_store_commitment_evidence, handle_invalid_commitment_evidence_relay,
    queue_invalid_refresh_commitment_report, queue_or_relay_equivocation,
    verify_commitment_evidence,
};
#[allow(unused_imports)]
pub(crate) use commitment::{
    build_and_store_commitment_evidence_with_context, build_commitment_evidence_with_context,
    commitments_prove_equivocation,
};
pub use control_message::{
    handle_control_message_fault_evidence_relay, queue_or_relay_control_message_fault,
};
pub(crate) use control_message::{
    report_leader_prepare_fault_best_effort, sign_control_message, verify_control_signature,
};
pub use leader_batch_mismatch::{
    handle_leader_batch_mismatch_evidence_relay, queue_or_relay_leader_batch_mismatch,
};
pub use leader_equivocation::{
    handle_leader_equivocation_evidence_relay, queue_or_relay_leader_equivocation,
};
pub use leader_public_fault::{
    handle_leader_public_fault_evidence_relay, queue_or_relay_leader_public_fault,
};
pub use public_origin::{
    handle_public_origin_fault_evidence_relay, queue_or_relay_public_origin_fault,
};
pub(crate) use share::build_share_evidence_with_context;
pub use share::{
    handle_invalid_share_evidence_relay, queue_or_relay_invalid_share,
    share_evidence_proves_failure, verify_share_evidence,
};

// Internal cross-submodule glue: `validate_share_statement` (share.rs) calls
// `validate_commitment_statement` (commitment.rs), and the `tests` submodule
// below exercises both directly — both are `pub(super)` in their defining
// file, and re-exporting them here (private `use`, visible to this module's
// whole subtree) lets every sibling's `use super::*` resolve them.
use commitment::validate_commitment_statement;
#[allow(unused_imports)]
use share::validate_share_statement;

pub(crate) struct DkgEvidenceBuildContext {
    binding: DkgReportEvidenceBinding,
    signing_key_hex: String,
    session_nonce: [u8; 16],
    attempt_id: [u8; 32],
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
        attempt_id: attempt.attempt_id.0,
    }))
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
                SessionKind::Fresh | SessionKind::FreshPet { .. } => Vec::new(),
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
        SessionKind::Fresh | SessionKind::FreshPet { .. } => return Ok(None),
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
        SessionKind::Fresh | SessionKind::FreshPet { .. } => return Ok(None),
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
        match relay.await {
            Ok(()) => {
                crate::metrics::record_dkg_transport_event(
                    "private",
                    &format!("{evidence_kind}_relay_accepted"),
                );
            }
            Err(error) => {
                crate::metrics::record_dkg_transport_event(
                    "private",
                    &format!("{evidence_kind}_relay_exhausted"),
                );
                tracing::warn!(
                    session_id = session_id,
                    evidence_kind,
                    %error,
                    "failed to relay evidence to a current-committee signer"
                );
            }
        }
    });
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

pub(crate) fn now_unix_secs() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| DkgError::Generic(format!("Failed to get unix timestamp: {error}")))
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

/// When the leader claims to have constructed a decoded delivery, or `None`
/// for `TopologyProbe`. Used to anchor leader-fault reports to when the
/// fault actually happened instead of report-construction time — unlike
/// `DkgPublicContribution`/`DkgCommitmentStatement`, `PhaseManifest`/`Chunk`
/// only gained a `signed_at` field for this purpose; both are authenticated
/// by the same enclosing Gossip delivery signature every other field here
/// already relies on.
fn leader_delivery_signed_at(message: &transport::DkgPublicMessage) -> Option<u64> {
    match message {
        transport::DkgPublicMessage::Manifest(manifest) => Some(manifest.signed_at),
        transport::DkgPublicMessage::Chunk { signed_at, .. } => Some(*signed_at),
        transport::DkgPublicMessage::TopologyProbe { .. } => None,
    }
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
mod tests;
