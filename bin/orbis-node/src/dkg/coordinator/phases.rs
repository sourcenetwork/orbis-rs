use crate::constants::BULLETIN_RING_NAMESPACE;
use crate::dkg::error::{DkgError, Result};
use crate::dkg::helpers::{
    persist_ring_bundle, serialize_commitment_coefficients, session_not_found,
};
use crate::dkg::messages::{DkgMessage, SessionKind};
use crate::dkg::session_state::DkgPhase;
use crate::helpers::helpers::{extract_node_part, is_self_peer_id};
use crate::metrics;
use crate::ring_state::RingIndexEntry;
use bulletin::r#trait::RingPayload;
use crypto::r#trait::{Dkg, DkgRole};
use crypto::{
    CryptoSerialize, GroupAffine as G1Affine, PolynomialCommitmentImpl as PolynomialCommitment,
    ScalarField as Fr,
};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{message_handlers::record_and_ack_valid_reshare_share, DkgCoordinator};

/// Phase 1: Generate polynomial and broadcast commitment to all peers.
///
/// Called by the session initiator after `StartDkg`, or by the PSS scheduler.
pub(super) async fn initiate_phase1_commitments<D>(
    coord: &DkgCoordinator<D>,
    session_id: u64,
    peer_ids: &[String],
) -> Result<()>
where
    D: Dkg<ShareValue = Fr, PublicKey = G1Affine, PolynomialCommitment = PolynomialCommitment>
        + Clone
        + 'static,
{
    let already_started = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| {
            matches!(
                state.phase,
                DkgPhase::Phase2Shares | DkgPhase::Phase4Complete
            )
        })
        .await
        .ok_or_else(|| session_not_found(session_id))?;

    if already_started {
        tracing::debug!(
            session_id = session_id,
            "Phase 1 start requested after shares/completion; ignoring duplicate request"
        );
        return Ok(());
    }

    let is_reshare_receiver = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| {
            matches!(state.kind, SessionKind::Reshare { .. })
                && state.node.role() == DkgRole::Receiver
        })
        .await
        .ok_or_else(|| session_not_found(session_id))?;

    if is_reshare_receiver {
        tracing::debug!(
            session_id = session_id,
            "Reshare receiver does not generate Phase 1 commitments; ignoring start request"
        );
        return Ok(());
    }

    let (commitment_bytes, node_id, threshold, is_reshare, role) = coord
        .app_state
        .dkg_session_state
        .with_state_mut(&session_id, |state| {
            if state.node.commitment().coefficients.is_empty() {
                state.generate_polynomial()?;
            }
            let bytes = serialize_commitment_coefficients(&state.node.commitment().coefficients)?;
            Ok::<_, DkgError>((
                bytes,
                state.node.node_id(),
                state.node.threshold(),
                matches!(state.kind, SessionKind::Reshare { .. }),
                state.node.role(),
            ))
        })
        .await
        .ok_or_else(|| session_not_found(session_id))??;

    coord
        .app_state
        .dkg_session_state
        .update_phase(&session_id, DkgPhase::Phase1Commitments)
        .await;

    let mut peers_sent = 0;
    let mut expected_peers = 0;
    for peer_id_str in peer_ids {
        if is_self_peer_id(&coord.app_state.network, peer_id_str) {
            tracing::debug!(peer_id = %peer_id_str, "Skipping self when broadcasting commitment");
            continue;
        }
        expected_peers += 1;

        let commitment_msg = DkgMessage::Commitment {
            session_id,
            from_node_id: node_id,
            commitment: commitment_bytes.clone(),
        };

        if let Err(e) = coord
            .send_message_to_peer(peer_id_str, commitment_msg, Some(session_id))
            .await
        {
            tracing::error!(peer_id = %peer_id_str, error = %e, "Failed to send commitment to peer");
        } else {
            peers_sent += 1;
        }
    }

    tracing::info!(
        peers_sent = peers_sent,
        expected_peers = expected_peers,
        "Phase 1: Broadcasted commitment to peers"
    );

    if peers_sent < expected_peers && !is_reshare {
        tracing::error!(
            sent = peers_sent,
            expected = expected_peers,
            session_id = session_id,
            "DKG Coordinator: Could not broadcast commitment to all peers - failing DKG to preserve expected redundancy"
        );
        coord.remove_session(session_id).await;
        tracing::debug!(
            session_id = session_id,
            "Cleaned up session after Phase 1 broadcast failure"
        );
        return Err(DkgError::InsufficientPeers {
            successful: peers_sent,
            total: expected_peers,
            threshold,
        });
    }

    if peers_sent < expected_peers {
        tracing::warn!(
            sent = peers_sent,
            expected = expected_peers,
            session_id = session_id,
            "Reshare: commitment broadcast did not reach every new-committee peer; continuing until threshold selection or timeout"
        );
    }

    if is_reshare && role != DkgRole::Receiver {
        initiate_phase2_shares(coord, session_id, peer_ids).await?;
    }

    Ok(())
}

/// Check if Phase 1 is complete and trigger Phase 2 if so.
///
/// Called after each incoming commitment message.
pub(super) async fn check_and_trigger_phase2<D>(
    coord: &DkgCoordinator<D>,
    session_id: u64,
    peer_ids: &[String],
) -> Result<()>
where
    D: Dkg<ShareValue = Fr, PublicKey = G1Affine, PolynomialCommitment = PolynomialCommitment>
        + Clone
        + 'static,
{
    // Check phase, polynomial readiness, expected commitment count, and our role.
    let (phase, has_polynomial, expected_commitments, node_id, role) = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| {
            let role = state.node.role();
            if matches!(state.kind, SessionKind::Reshare { .. }) {
                return (state.phase, true, usize::MAX, state.node.node_id(), role);
            }
            // Receivers expect commitments from ALL old-committee dealers.
            // Dealers/DealerReceivers expect from all others (excluding self).
            let expected = match role {
                DkgRole::Receiver => state.node.total_nodes(),
                _ => state.node.total_nodes() - 1,
            };
            (
                state.phase,
                !state.node.commitment().coefficients.is_empty(),
                expected,
                state.node.node_id(),
                role,
            )
        })
        .await
        .ok_or_else(|| session_not_found(session_id))?;

    if expected_commitments == usize::MAX {
        return Ok(());
    }

    // Guard: Phase 2 (or later) is already running — don't trigger it again.
    if phase == DkgPhase::Phase2Shares || phase == DkgPhase::Phase4Complete {
        return Ok(());
    }

    // Receiver nodes never generate a polynomial — skip this gate for them.
    if role != DkgRole::Receiver && !has_polynomial {
        return Ok(());
    }

    let received_commitments = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| state.commitments_received)
        .await
        .ok_or_else(|| session_not_found(session_id))?;

    if received_commitments >= expected_commitments {
        tracing::info!(
            received = received_commitments,
            expected = expected_commitments,
            node_id = node_id,
            "Phase 1 complete: Starting Phase 2"
        );
        // Receiver nodes don't send shares — they just wait for incoming shares.
        if role != DkgRole::Receiver {
            initiate_phase2_shares(coord, session_id, peer_ids).await?;
        }
    } else {
        tracing::debug!(
            received = received_commitments,
            expected = expected_commitments,
            node_id = node_id,
            "Phase 1 not complete yet"
        );
    }

    Ok(())
}

/// Phase 2: Generate shares and send them to all peers.
///
/// Called when all commitments have been received.
pub(super) async fn initiate_phase2_shares<D>(
    coord: &DkgCoordinator<D>,
    session_id: u64,
    peer_ids: &[String],
) -> Result<()>
where
    D: Dkg<ShareValue = Fr, PublicKey = G1Affine, PolynomialCommitment = PolynomialCommitment>
        + Clone
        + 'static,
{
    let (shares, node_id, threshold, role, is_reshare, reshare_new_peer_ids) = coord
        .app_state
        .dkg_session_state
        .with_state_mut(&session_id, |state| {
            if state.node.commitment().coefficients.is_empty() {
                tracing::debug!(
                    node_id = state.node.node_id(),
                    "DKG Coordinator: Generating polynomial before Phase 2"
                );
                state.generate_polynomial()?;
            }

            tracing::debug!(
                node_id = state.node.node_id(),
                session_id = session_id,
                "DKG Coordinator: Generating shares"
            );
            let shares = state
                .node
                .generate_shares()
                .map_err(|e| DkgError::Crypto(format!("Failed to generate shares: {}", e)))?;

            tracing::debug!(
                share_count = shares.len(),
                "DKG Coordinator: Generated shares"
            );

            let reshare_peer_ids = state
                .reshare_params
                .as_ref()
                .map(|p| p.new_peer_ids.clone());
            Ok::<_, DkgError>((
                shares,
                state.node.node_id(),
                state.node.threshold(),
                state.node.role(),
                matches!(state.kind, SessionKind::Reshare { .. }),
                reshare_peer_ids,
            ))
        })
        .await
        .ok_or_else(|| session_not_found(session_id))??;

    coord
        .app_state
        .dkg_session_state
        .update_phase(&session_id, DkgPhase::Phase2Shares)
        .await;

    if peer_ids.is_empty() {
        tracing::error!("DKG Coordinator: No peer_ids available to send shares to");
        coord.remove_session(session_id).await;
        tracing::debug!(
            session_id = session_id,
            "Cleaned up session - no peer_ids available"
        );
        return Err(DkgError::InsufficientPeers {
            successful: 0,
            total: 0,
            threshold,
        });
    }

    tracing::debug!(
        share_count = shares.len(),
        node_id = node_id,
        "DKG Coordinator: Sending shares to peers"
    );

    // Send shares to peers.
    // For Reshare: route using reshare_new_peer_ids (sorted new committee, index = to_id - 1).
    // For Fresh/Refresh: use node_id_to_peer_id map, falling back to broadcast.
    let mut shares_sent = 0;
    let mut shares_skipped = 0;

    for share in shares.iter() {
        // Skip sending share to ourselves.
        // For DealerReceiver, their new-committee node_id may differ from old-committee
        // node_id — skip if to_id maps to our own new-committee peer_id.
        let skip = if let Some(ref new_peers) = reshare_new_peer_ids {
            // Reshare: to_id is a new-committee index; check if it points to self.
            new_peers
                .get((share.to_id - 1) as usize)
                .map(|p| is_self_peer_id(&coord.app_state.network, p))
                .unwrap_or(false)
        } else {
            share.to_id == node_id
        };
        if skip {
            shares_skipped += 1;
            continue;
        }

        // For Reshare, route directly via sorted new committee list.
        if let Some(ref new_peers) = reshare_new_peer_ids {
            let Some(target_peer_id) = new_peers.get((share.to_id - 1) as usize) else {
                tracing::error!(
                    to_node = share.to_id,
                    "Reshare: share to_id out of range for new committee"
                );
                continue;
            };
            let share_value_bytes = CryptoSerialize::to_bytes(&share.value).map_err(|e| {
                DkgError::Serialization(format!("Failed to serialize share value: {}", e))
            })?;
            let share_msg = DkgMessage::Share {
                session_id,
                from_node_id: node_id,
                to_node_id: share.to_id,
                share_value: share_value_bytes,
                nonce: share.nonce,
            };
            match coord
                .send_message_to_peer(target_peer_id, share_msg, Some(session_id))
                .await
            {
                Ok(_) => {
                    shares_sent += 1;
                    tracing::debug!(
                        from_node = node_id,
                        to_node = share.to_id,
                        peer_id = %target_peer_id,
                        "Reshare: Sent share to new committee member"
                    );
                }
                Err(e) => {
                    tracing::error!(
                        to_node = share.to_id,
                        peer_id = %target_peer_id,
                        error = %e,
                        "Reshare: Failed to send share"
                    );
                }
            }
            continue;
        }

        let share_value_bytes = CryptoSerialize::to_bytes(&share.value).map_err(|e| {
            DkgError::Serialization(format!("Failed to serialize share value: {}", e))
        })?;

        // Try to get specific peer_id for this node_id (O(1) lookup).
        if let Some(target_peer_id) = coord
            .app_state
            .dkg_session_state
            .get_peer_id_for_node(&session_id, share.to_id)
            .await
        {
            let share_msg = DkgMessage::Share {
                session_id,
                from_node_id: node_id,
                to_node_id: share.to_id,
                share_value: share_value_bytes.clone(),
                nonce: share.nonce,
            };
            match coord
                .send_message_to_peer(&target_peer_id, share_msg, Some(session_id))
                .await
            {
                Ok(_) => {
                    shares_sent += 1;
                    tracing::debug!(
                        from_node = node_id,
                        to_node = share.to_id,
                        peer_id = %target_peer_id,
                        "DKG Coordinator: Sent share"
                    );
                }
                Err(e) => {
                    tracing::error!(
                        to_node = share.to_id,
                        peer_id = %target_peer_id,
                        error = %e,
                        "Failed to send share"
                    );
                }
            }
        } else {
            // Fallback: broadcast to all peers (only if node_id → peer_id mapping not set up).
            let mut sent_count = 0;
            for peer_id_str in peer_ids {
                if is_self_peer_id(&coord.app_state.network, peer_id_str) {
                    continue;
                }

                let broadcast_share_msg = DkgMessage::Share {
                    session_id,
                    from_node_id: node_id,
                    to_node_id: share.to_id,
                    share_value: share_value_bytes.clone(),
                    nonce: share.nonce,
                };
                match coord
                    .send_message_to_peer(peer_id_str, broadcast_share_msg, Some(session_id))
                    .await
                {
                    Ok(_) => {
                        sent_count += 1;
                        tracing::debug!(
                            from_node = node_id,
                            to_node = share.to_id,
                            peer_id = %peer_id_str,
                            "DKG Coordinator: Sent share (broadcast)"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            peer_id = %peer_id_str,
                            error = %e,
                            "Failed to send share to peer"
                        );
                    }
                }
            }
            if sent_count > 0 {
                shares_sent += 1;
            } else {
                tracing::error!(
                    from_node = node_id,
                    to_node = share.to_id,
                    "DKG Coordinator: Failed to send share to any peer"
                );
            }
        }
    }

    // expected = total shares minus the ones we skipped (our own self-share).
    let expected_shares = shares.len() - shares_skipped;
    tracing::info!(
        sent = shares_sent,
        total = expected_shares,
        node_id = node_id,
        "Phase 2: Sent shares to peers"
    );

    if shares_sent < expected_shares && !is_reshare {
        tracing::error!(
            sent = shares_sent,
            expected = expected_shares,
            threshold = threshold,
            "DKG Coordinator: Could not send shares to all peers - failing DKG to preserve expected redundancy"
        );
        coord.remove_session(session_id).await;
        tracing::debug!(
            session_id = session_id,
            "Cleaned up session after Phase 2 share send failure"
        );
        return Err(DkgError::InsufficientPeers {
            successful: shares_sent,
            total: expected_shares,
            threshold,
        });
    }

    if shares_sent < expected_shares {
        tracing::warn!(
            sent = shares_sent,
            expected = expected_shares,
            threshold = threshold,
            "Reshare: share distribution did not reach every new peer; continuing until selector freezes a valid threshold subset or timeout"
        );
    }

    if role == DkgRole::DealerReceiver {
        record_and_ack_valid_reshare_share(coord, session_id, node_id).await?;
    }

    // Pure Dealer nodes (not in new committee) are done after distributing shares —
    // they won't receive any shares themselves, so Phase 4 must be triggered here
    // rather than from the share-receive path.
    if role == DkgRole::Dealer {
        tracing::info!(
            session_id = session_id,
            "Reshare Dealer: share distribution complete, triggering Phase 4 cleanup"
        );
        initiate_phase4_completion(coord, session_id).await?;
    }

    Ok(())
}

/// Check if Phase 2 is complete (all shares received) and trigger Phase 4 if so.
///
/// Called after each incoming share message.
pub(super) async fn check_and_trigger_phase4<D>(
    coord: &DkgCoordinator<D>,
    session_id: u64,
) -> Result<()>
where
    D: Dkg<ShareValue = Fr, PublicKey = G1Affine, PolynomialCommitment = PolynomialCommitment>
        + Clone
        + 'static,
{
    // Atomically claim Phase 4 — all conditions are checked and the phase
    // transition happens inside a single write-lock hold, so no two concurrent
    // share deliveries can both enter initiate_phase4_completion.
    //
    // Expected share count depends on role:
    //   Receiver           → total_nodes (one from each old dealer)
    //   Standard/DealerReceiver → total_nodes - 1 (excluding self)
    //   Dealer             → 0 (handled by initiate_phase2_shares, never reaches here)
    let claimed = coord
        .app_state
        .dkg_session_state
        .with_state_mut(&session_id, |state| {
            if state.phase == DkgPhase::Phase4Complete {
                return false;
            }
            if matches!(state.kind, SessionKind::Reshare { .. })
                && matches!(
                    state.node.role(),
                    DkgRole::Receiver | DkgRole::DealerReceiver
                )
            {
                if state.reshare_selected_dealers.is_none() {
                    return false;
                }
                if state.node.compute_secret_share().is_err() {
                    tracing::debug!(
                        "DKG Coordinator: selected reshare shares are not all locally available yet"
                    );
                    return false;
                }
                if state.node.compute_aggregate_public_key().is_err() {
                    tracing::warn!(
                        "DKG Coordinator: selected reshare commitments are not all available yet"
                    );
                    return false;
                }
                state.phase = DkgPhase::Phase4Complete;
                return true;
            }
            let expected = match state.node.role() {
                DkgRole::Receiver => state.node.total_nodes(),
                _ => state.node.total_nodes() - 1,
            };
            if state.shares_received < expected {
                return false;
            }
            if state.node.compute_aggregate_public_key().is_err() {
                tracing::warn!(
                    "DKG Coordinator: Not all commitments received yet, cannot proceed to Phase 4"
                );
                return false;
            }
            // Mark Phase4Complete now so any concurrent call returns early.
            state.phase = DkgPhase::Phase4Complete;
            true
        })
        .await
        .ok_or_else(|| session_not_found(session_id))?;

    if !claimed {
        return Ok(());
    }

    tracing::info!(
        session_id = session_id,
        "DKG Coordinator: All shares and commitments received, initiating Phase 4"
    );

    // Phase4Complete is already set. If Phase 4 fails, remove the session so
    // the cleanup worker clears the rings_pss flag and frees memory.
    if let Err(e) = initiate_phase4_completion(coord, session_id).await {
        coord.remove_session(session_id).await;
        return Err(e);
    }

    Ok(())
}

/// Phase 4: Compute final secret share and aggregate public key.
///
/// Handles all three session kinds:
/// - **Dealer** (Reshare leaving node): deletes local share and cleans up ring index.
/// - **Receiver / DealerReceiver / Standard**: computes and persists the new share bundle.
/// - **Fresh (node_id == 1)**: posts the `RingPayload` to the bulletin.
/// - **Reshare (new-committee node_id == 1)**: posts the updated `RingPayload`.
pub(super) async fn initiate_phase4_completion<D>(
    coord: &DkgCoordinator<D>,
    session_id: u64,
) -> Result<()>
where
    D: Dkg<ShareValue = Fr, PublicKey = G1Affine, PolynomialCommitment = PolynomialCommitment>
        + Clone
        + 'static,
{
    tracing::info!(
        session_id = session_id,
        "DKG Coordinator: Starting Phase 4 completion"
    );

    let (kind, pss_interval, dkg_role, reshare_new_peer_ids, reshare_bulletin_post_id) = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| {
            (
                state.kind.clone(),
                state.pss_interval,
                state.node.role(),
                state
                    .reshare_params
                    .as_ref()
                    .map(|p| p.new_peer_ids.clone()),
                state
                    .reshare_params
                    .as_ref()
                    .map(|p| p.bulletin_post_id.clone()),
            )
        })
        .await
        .ok_or_else(|| session_not_found(session_id))?;

    // Pure Dealer nodes don't compute a secret share — they just clean up.
    // Because they are leaving the ring, delete the local secret share and
    // remove the ring from the index so the PSS scheduler ignores it.
    if dkg_role == DkgRole::Dealer {
        let ring_key = kind.ring_key().map(|k| k.to_string());
        coord
            .app_state
            .dkg_session_state
            .update_phase(&session_id, DkgPhase::Phase4Complete)
            .await;
        let mut ring_index_result: Result<()> = Ok(());
        if let Some(key) = &ring_key {
            coord.app_state.dkg_session_state.unmark_ring_pss(key).await;

            if let Err(e) = coord
                .app_state
                .local_storage
                .delete(LocalStorageKeys::RingKey(key.clone()))
            {
                tracing::warn!(
                    session_id = session_id,
                    ring_key = %key,
                    error = %e,
                    "Reshare Dealer: failed to delete share bundle (already absent?)"
                );
            } else {
                tracing::info!(
                    session_id = session_id,
                    ring_key = %key,
                    "Reshare Dealer: deleted share bundle — node has left the ring"
                );
            }

            // Remove the ring from the local index so the PSS scheduler skips it.
            let _guard = coord.app_state.ring_index_lock.lock().await;
            let storage = &coord.app_state.local_storage;
            ring_index_result = (|| {
                let raw = match storage.get(LocalStorageKeys::RingIndex) {
                    Ok(Some(raw)) => raw,
                    Ok(None) => return Ok(()),
                    Err(e) => {
                        return Err(DkgError::Storage(format!(
                            "Reshare Dealer: failed to read RingIndex: {}",
                            e
                        )))
                    }
                };
                let mut index: Vec<RingIndexEntry> = serde_json::from_slice(&raw).map_err(|e| {
                    DkgError::Storage(format!(
                        "Reshare Dealer: failed to deserialize RingIndex: {}",
                        e
                    ))
                })?;
                index.retain(|e| e.ring_pk_str != *key);
                let bytes = serde_json::to_vec(&index).map_err(|e| {
                    DkgError::Serialization(format!(
                        "Reshare Dealer: failed to serialize RingIndex: {}",
                        e
                    ))
                })?;
                storage
                    .set(LocalStorageKeys::RingIndex, bytes)
                    .map_err(|e| {
                        DkgError::Storage(format!(
                            "Reshare Dealer: failed to write updated RingIndex: {}",
                            e
                        ))
                    })
            })();
        }
        coord.remove_session(session_id).await;
        metrics::record_dkg_session_completed();
        tracing::info!(
            session_id = session_id,
            "Reshare Dealer: Phase 4 complete (share distribution done, secret deleted)"
        );
        return ring_index_result;
    }

    // Compute final secret share, aggregate public key, and data for bulletin.
    let (node_id, aggregate_pk, final_share_bytes, threshold, pub_poly_bytes) = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| {
            tracing::debug!(
                node_id = state.node.node_id(),
                "DKG Coordinator: Computing secret share"
            );

            let final_share = state
                .node
                .compute_secret_share()
                .map_err(|e| DkgError::Crypto(format!("Failed to compute secret share: {}", e)))?;

            tracing::debug!(
                node_id = state.node.node_id(),
                "DKG Coordinator: Successfully computed secret share"
            );

            let aggregate_pk = state.node.compute_aggregate_public_key().map_err(|e| {
                DkgError::Crypto(format!("Failed to compute aggregate public key: {}", e))
            })?;

            tracing::debug!(
                node_id = state.node.node_id(),
                "DKG Coordinator: Computed aggregate public key"
            );

            let final_share_bytes = CryptoSerialize::to_bytes(&final_share).map_err(|e| {
                DkgError::Serialization(format!("Failed to serialize final share: {}", e))
            })?;

            let pub_poly = state.node.compute_public_polynomial().map_err(|e| {
                DkgError::Crypto(format!("Failed to compute public polynomial: {}", e))
            })?;
            let pub_poly_bytes = CryptoSerialize::to_bytes(&pub_poly).map_err(|e| {
                DkgError::Serialization(format!("Failed to serialize public polynomial: {}", e))
            })?;

            Ok::<_, DkgError>((
                state.node.node_id(),
                aggregate_pk,
                final_share_bytes,
                state.node.threshold(),
                pub_poly_bytes,
            ))
        })
        .await
        .ok_or_else(|| session_not_found(session_id))??;

    // Compute storage_key — the canonical local-storage key used by sign/pre for share lookup.
    // For Refresh and Reshare this is the ORIGINAL ring's key (unchanged secret → same pk).
    let storage_key = kind
        .ring_key()
        .map(|k| k.to_string())
        .unwrap_or_else(|| aggregate_pk.to_string());

    // Write share + polynomial as a single encrypted bundle.
    // Atomicity: both fields land in one set_encrypted call, so a crash leaves the
    // entry either fully written or absent — never partially updated.
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    persist_ring_bundle(
        &coord.app_state.local_storage,
        &kind,
        &final_share_bytes,
        &pub_poly_bytes,
        &aggregate_pk,
        now_secs,
        session_id,
        |old, delta| D::combine_pub_poly_bytes(old, delta).map_err(|e| e.to_string()),
    )?;

    tracing::debug!(
        session_id = session_id,
        "DKG Coordinator: Stored RingShareBundle (share + polynomial) atomically"
    );

    // For Reshare: write a RingIndexEntry so the PSS scheduler can discover this ring.
    // Receiver and DealerReceiver nodes use the bulletin_post_id carried in the SessionInit
    // (they had no prior index entry).  Dealers have already left and skip this entirely.
    if matches!(kind, SessionKind::Reshare { .. }) && dkg_role != DkgRole::Dealer {
        if let Some(post_id) = &reshare_bulletin_post_id {
            let _guard = coord.app_state.ring_index_lock.lock().await;
            let mut ring_index: Vec<RingIndexEntry> = coord
                .app_state
                .local_storage
                .get(LocalStorageKeys::RingIndex)
                .ok()
                .flatten()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or_default();
            if !ring_index.iter().any(|e| e.ring_pk_str == storage_key) {
                ring_index.push(RingIndexEntry {
                    ring_pk_str: storage_key.clone(),
                    bulletin_post_id: post_id.clone(),
                });
                let index_bytes = serde_json::to_vec(&ring_index).map_err(|e| {
                    DkgError::Serialization(format!("Failed to serialize RingIndex: {}", e))
                })?;
                coord
                    .app_state
                    .local_storage
                    .set(LocalStorageKeys::RingIndex, index_bytes)
                    .map_err(|e| DkgError::Storage(format!("Failed to store RingIndex: {}", e)))?;
                tracing::info!(
                    session_id = session_id,
                    ring_pk = %storage_key,
                    "Reshare: wrote RingIndexEntry for new-committee node"
                );
            }
        }
    }

    // For fresh DKG: cache the RingPayload locally and append a RingIndexEntry so the
    // PSS scheduler can discover this ring.
    //
    // For Refresh: bulletin entry is unchanged; polynomial updated in RingShareBundle above.
    // For Reshare: bulletin is updated below by new-committee node 1.
    if matches!(kind, SessionKind::Fresh) {
        let peer_ids = coord
            .app_state
            .dkg_session_state
            .get_peer_ids(&session_id)
            .await
            .unwrap_or_default();

        // Hex-encode the aggregate public key for byte-round-trip use in RingPayload.
        let ring_pk_hex_for_payload = CryptoSerialize::to_bytes(&aggregate_pk)
            .map(|b| hex::encode(&b))
            .map_err(|e| {
                DkgError::Serialization(format!(
                    "Failed to serialize aggregate_pk for RingPayload: {}",
                    e
                ))
            })?;

        let ring_payload_local = RingPayload {
            ring_pk: ring_pk_hex_for_payload.clone(),
            peer_ids,
            next_peer_ids: None,
            new_threshold: None,
            threshold: threshold as u32,
            pss_interval,
        };
        let ring_payload_bytes: Vec<u8> = ring_payload_local.try_into().map_err(|e| {
            DkgError::Serialization(format!(
                "Failed to serialize RingPayload for local cache: {}",
                e
            ))
        })?;

        // Compute the bulletin post_id deterministically. All nodes construct the
        // identical RingPayload so they all arrive at the same post_id.
        let bulletin_post_id = coord
            .app_state
            .bulletin
            .get_post_id(BULLETIN_RING_NAMESPACE, &ring_payload_bytes)
            .map_err(|e| {
                DkgError::Serialization(format!("Failed to compute bulletin post_id: {}", e))
            })?;

        // Append a RingIndexEntry to RingIndex.  Hold the lock for the entire
        // read-modify-write so concurrent Phase 4 completions don't overwrite each
        // other's appended entry.
        {
            let _guard = coord.app_state.ring_index_lock.lock().await;
            let mut ring_index: Vec<RingIndexEntry> = coord
                .app_state
                .local_storage
                .get(LocalStorageKeys::RingIndex)
                .ok()
                .flatten()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or_default();
            if !ring_index.iter().any(|e| e.ring_pk_str == storage_key) {
                ring_index.push(RingIndexEntry {
                    ring_pk_str: storage_key.clone(),
                    bulletin_post_id,
                });
                let index_bytes = serde_json::to_vec(&ring_index).map_err(|e| {
                    DkgError::Serialization(format!("Failed to serialize RingIndex: {}", e))
                })?;
                coord
                    .app_state
                    .local_storage
                    .set(LocalStorageKeys::RingIndex, index_bytes)
                    .map_err(|e| DkgError::Storage(format!("Failed to store RingIndex: {}", e)))?;
            }
        }
    }

    // Clear the in-progress ceremony flag now that Phase 4 has succeeded.
    // (Phase4Complete was already set by check_and_trigger_phase4 before this
    // function was called; no second update_phase needed here.)
    if let Some(ring_key) = kind.ring_key() {
        coord
            .app_state
            .dkg_session_state
            .unmark_ring_pss(ring_key)
            .await;
    }

    let ring_pk_bytes = CryptoSerialize::to_bytes(&aggregate_pk).map_err(|e| {
        DkgError::Serialization(format!("Failed to serialize aggregate public key: {}", e))
    })?;

    tracing::info!(
        aggregate_pk = ?aggregate_pk,
        ring_key_hex = hex::encode(&ring_pk_bytes),
        node_id = node_id,
        "Phase 4: DKG complete! Final share computed"
    );

    // Node 1 of the OLD committee posts the RingPayload for fresh DKG.
    if node_id == 1 && matches!(kind, SessionKind::Fresh) {
        let peer_ids = coord
            .app_state
            .dkg_session_state
            .get_peer_ids(&session_id)
            .await
            .ok_or(DkgError::Generic("Failed to get peer ids".to_string()))?;

        let ring_payload = RingPayload {
            ring_pk: hex::encode(&ring_pk_bytes),
            peer_ids,
            next_peer_ids: None,
            new_threshold: None,
            threshold: threshold as u32,
            pss_interval,
        };

        let payload_bytes: Vec<u8> = ring_payload.clone().try_into().map_err(|e| {
            DkgError::Serialization(format!("Failed to serialize RingPayload: {}", e))
        })?;

        coord
            .app_state
            .bulletin
            .post(
                BULLETIN_RING_NAMESPACE.to_string(),
                payload_bytes,
                Some(session_id.to_string()),
            )
            .await
            .map_err(|e| DkgError::Bulletin(format!("Failed to post RingPayload: {}", e)))?;

        tracing::info!(
            ring_pk = %ring_payload.ring_pk,
            namespace = BULLETIN_RING_NAMESPACE,
            "DKG Coordinator: Successfully posted RingPayload to bulletin"
        );
    }

    // For Reshare: node 1 of the NEW committee posts the updated RingPayload with the
    // new peer_ids and new threshold.  The ring_pk remains the same (same secret).
    if let SessionKind::Reshare {
        ring_pk_hex,
        next_peer_ids,
        new_threshold,
        ..
    } = &kind
    {
        let our_peer_id_hex = hex::encode(coord.app_state.network.local_peer_id().as_bytes());
        let our_node_part = extract_node_part(&our_peer_id_hex);
        // If 0 will skip trying to post (not in new group).
        let new_node_id = reshare_new_peer_ids
            .as_ref()
            .and_then(|peers| {
                peers
                    .iter()
                    .position(|p| extract_node_part(p) == our_node_part)
                    .map(|i| (i + 1) as u32)
            })
            .unwrap_or(0);
        // TODO: change to needing a threshold signature
        if new_node_id == 1 {
            // Use the sorted peer list from session state (same list used to derive
            // new_node_id above) so the bulletin payload has a canonical ordering.
            let sorted_new_peer_ids = reshare_new_peer_ids
                .clone()
                .unwrap_or_else(|| next_peer_ids.clone());
            let ring_payload = RingPayload {
                ring_pk: hex::encode(&ring_pk_bytes),
                peer_ids: sorted_new_peer_ids,
                next_peer_ids: None,
                new_threshold: None,
                threshold: *new_threshold,
                pss_interval,
            };
            let payload_bytes: Vec<u8> = ring_payload.clone().try_into().map_err(|e| {
                DkgError::Serialization(format!(
                    "Reshare: failed to serialize updated RingPayload: {}",
                    e
                ))
            })?;
            let bulletin_post_id = reshare_bulletin_post_id.as_ref().ok_or_else(|| {
                DkgError::Bulletin(
                    "Reshare: missing bulletin post id for updated RingPayload".to_string(),
                )
            })?;
            coord
                .app_state
                .bulletin
                .update(
                    BULLETIN_RING_NAMESPACE.to_string(),
                    bulletin_post_id.clone(),
                    payload_bytes,
                    Some(session_id.to_string()),
                )
                .await
                .map_err(|e| {
                    DkgError::Bulletin(format!("Reshare: failed to update RingPayload: {}", e))
                })?;

            tracing::info!(
                ring_pk = %ring_pk_hex,
                post_id = %bulletin_post_id,
                namespace = BULLETIN_RING_NAMESPACE,
                new_threshold = new_threshold,
                new_committee_size = next_peer_ids.len(),
                "Reshare: Successfully updated RingPayload on bulletin"
            );
        }
    }

    coord.remove_session(session_id).await;
    metrics::record_dkg_session_completed();

    tracing::info!(
        session_id = session_id,
        "DKG Coordinator: Session cleanup complete"
    );

    Ok(())
}
