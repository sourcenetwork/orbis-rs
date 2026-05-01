use crate::dkg::error::{DkgError, Result};
use crate::dkg::helpers::{
    persist_ring_bundle, serialize_commitment_coefficients, session_not_found,
};
use crate::dkg::messages::{DkgMessage, SessionKind};
use crate::dkg::session_state::DkgPhase;
use crate::helpers::helpers::is_self_peer_id;
use crate::metrics;
use crypto::r#trait::{DistKeyShare, DkgRole, PubShare, ThresholdSigner};
use crypto::{
    CryptoSerialize, GroupAffine as G1Affine, ScalarField as Fr, SigShareInner, SignImpl,
    SignaturePoint,
};
use std::time::{SystemTime, UNIX_EPOCH};

use super::reshare::selection::record_and_ack_valid_reshare_share;
use super::state_machine::{self, DkgCommand, DkgEvent, SessionSnapshot};
use super::types::CoordinatorDkg;
use super::{reshare, ring_storage, DkgCoordinator};

mod phase1;
mod phase2;
mod phase4;

pub(in crate::dkg::coordinator) use phase1::{
    check_and_trigger_phase2, initiate_phase1_commitments,
};
pub(in crate::dkg::coordinator) use phase2::initiate_phase2_shares;
pub(in crate::dkg::coordinator) use phase4::{
    check_and_trigger_phase4, initiate_phase4_completion,
};

pub(in crate::dkg::coordinator) async fn drive_event<D>(
    coord: &DkgCoordinator<D>,
    session_id: u64,
    event: DkgEvent,
    peer_ids: Option<&[String]>,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let (snapshot, transition) = claim_transition(coord, session_id, event).await?;
    log_transition_wait(session_id, event, &snapshot, &transition);
    execute_commands(coord, session_id, transition.commands, peer_ids).await
}

pub(in crate::dkg::coordinator) async fn drive_post_phase2_event<D>(
    coord: &DkgCoordinator<D>,
    session_id: u64,
    event: DkgEvent,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let (snapshot, transition) = claim_transition(coord, session_id, event).await?;
    log_transition_wait(session_id, event, &snapshot, &transition);
    execute_post_phase2_commands(coord, session_id, transition.commands).await
}

async fn claim_transition<D>(
    coord: &DkgCoordinator<D>,
    session_id: u64,
    event: DkgEvent,
) -> Result<(SessionSnapshot, state_machine::Transition)>
where
    D: CoordinatorDkg,
{
    coord
        .app_state
        .dkg_session_state
        .with_state_mut(&session_id, |state| {
            let evaluates_phase4 = event.evaluates_phase4();
            let snapshot = SessionSnapshot {
                kind: state.kind.clone(),
                phase: state.phase,
                role: state.node.role(),
                node_id: state.node.node_id(),
                total_nodes: state.node.total_nodes(),
                threshold: state.node.threshold(),
                has_polynomial: !state.node.commitment().coefficients.is_empty(),
                commitments_received: state.commitments_received,
                shares_received: state.shares_received,
                reshare_selected_dealers: state.reshare_selected_dealers.is_some(),
                secret_share_available: evaluates_phase4
                    && state.node.compute_secret_share().is_ok(),
                aggregate_public_key_available: evaluates_phase4
                    && state.node.compute_aggregate_public_key().is_ok(),
            };
            let transition = state_machine::transition(&snapshot, event);
            if let Some(next_phase) = transition.next_phase {
                state.phase = next_phase;
                state.phase_started_at = std::time::Instant::now();
            }
            (snapshot, transition)
        })
        .await
        .ok_or_else(|| session_not_found(session_id))
}

async fn execute_commands<D>(
    coord: &DkgCoordinator<D>,
    session_id: u64,
    commands: Vec<DkgCommand>,
    peer_ids: Option<&[String]>,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    for command in commands {
        match command {
            DkgCommand::InitiatePhase2Shares => {
                let peer_ids = peer_ids.ok_or_else(|| {
                    DkgError::ProtocolError(
                        "State machine requested Phase 2 without peer IDs".to_string(),
                    )
                })?;
                Box::pin(initiate_phase2_shares(coord, session_id, peer_ids)).await?;
            }
            DkgCommand::AckValidReshareShare { dealer_id } => {
                Box::pin(record_and_ack_valid_reshare_share(
                    coord, session_id, dealer_id,
                ))
                .await?;
            }
            DkgCommand::CompletePhase4 => {
                tracing::info!(
                    session_id = session_id,
                    "DKG Coordinator: State machine selected Phase 4 completion"
                );
                if let Err(e) = initiate_phase4_completion(coord, session_id).await {
                    coord.remove_session(session_id).await;
                    return Err(e);
                }
            }
        }
    }

    Ok(())
}

async fn execute_post_phase2_commands<D>(
    coord: &DkgCoordinator<D>,
    session_id: u64,
    commands: Vec<DkgCommand>,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    for command in commands {
        match command {
            DkgCommand::AckValidReshareShare { dealer_id } => {
                Box::pin(record_and_ack_valid_reshare_share(
                    coord, session_id, dealer_id,
                ))
                .await?;
            }
            DkgCommand::CompletePhase4 => {
                tracing::info!(
                    session_id = session_id,
                    "DKG Coordinator: State machine selected Phase 4 completion"
                );
                if let Err(e) = initiate_phase4_completion(coord, session_id).await {
                    coord.remove_session(session_id).await;
                    return Err(e);
                }
            }
            DkgCommand::InitiatePhase2Shares => {
                return Err(DkgError::ProtocolError(
                    "Post-Phase-2 state machine path tried to re-enter Phase 2".to_string(),
                ));
            }
        }
    }

    Ok(())
}

fn log_transition_wait(
    session_id: u64,
    event: DkgEvent,
    snapshot: &SessionSnapshot,
    transition: &state_machine::Transition,
) {
    if transition.commands.iter().any(|command| {
        matches!(
            command,
            DkgCommand::InitiatePhase2Shares | DkgCommand::CompletePhase4
        )
    }) {
        return;
    }

    if event == DkgEvent::CommitmentRecorded {
        if let Some(expected) = snapshot.phase1_expected_commitments() {
            if matches!(
                snapshot.phase,
                DkgPhase::Phase2Shares | DkgPhase::Phase4Completing | DkgPhase::Phase4Complete
            ) {
                return;
            }
            if snapshot.role != DkgRole::Receiver && !snapshot.has_polynomial {
                return;
            }
            if snapshot.commitments_received >= expected {
                if snapshot.role == DkgRole::Receiver {
                    tracing::info!(
                        received = snapshot.commitments_received,
                        expected = expected,
                        node_id = snapshot.node_id,
                        "Phase 1 complete: receiver waiting for shares"
                    );
                }
                return;
            }
            tracing::debug!(
                received = snapshot.commitments_received,
                expected = expected,
                node_id = snapshot.node_id,
                threshold = snapshot.threshold,
                "Phase 1 not complete yet"
            );
        }
    }

    if event.evaluates_phase4() {
        log_phase4_wait(snapshot, session_id);
    }
}

fn log_phase4_wait(snapshot: &SessionSnapshot, session_id: u64) {
    if matches!(
        snapshot.phase,
        DkgPhase::Phase4Completing | DkgPhase::Phase4Complete
    ) {
        return;
    }
    if snapshot.is_reshare() && matches!(snapshot.role, DkgRole::Receiver | DkgRole::DealerReceiver)
    {
        if !snapshot.reshare_selected_dealers {
            return;
        }
        if !snapshot.secret_share_available {
            tracing::debug!(
                session_id = session_id,
                "DKG Coordinator: selected reshare shares are not all locally available yet"
            );
            return;
        }
        if !snapshot.aggregate_public_key_available {
            tracing::warn!(
                session_id = session_id,
                "DKG Coordinator: selected reshare commitments are not all available yet"
            );
        }
        return;
    }

    if snapshot.shares_received >= snapshot.phase4_expected_shares()
        && !snapshot.aggregate_public_key_available
    {
        tracing::warn!(
            session_id = session_id,
            "DKG Coordinator: Not all commitments received yet, cannot proceed to Phase 4"
        );
    }
}
