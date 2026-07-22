use super::*;
use crate::dkg::v0::coordinator::evidence::{
    build_and_store_commitment_evidence_with_context, build_share_evidence_with_context,
    evidence_build_context,
};

pub async fn initiate_phase2_shares<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    peer_ids: &[String],
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let (
        shares,
        node_id,
        threshold,
        is_reshare,
        reshare_new_node_id_to_peer_id,
        commitment_bytes,
        stored_commitment_evidence,
    ) = coord
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
                .reshare
                .params
                .as_ref()
                .map(|_| state.routing.reshare_new_node_id_to_peer_id.clone());
            Ok::<_, DkgError>((
                shares,
                state.node.node_id(),
                state.node.threshold(),
                matches!(state.kind, SessionKind::Reshare { .. }),
                reshare_peer_ids,
                serialize_commitment_coefficients(&state.node.commitment().coefficients)?,
                state.local_signed_commitment.clone(),
            ))
        })
        .await
        .ok_or_else(|| session_not_found(session_id))??;

    coord
        .app_state
        .dkg_session_state
        .update_phase(&session_id, DkgPhase::Phase2Shares)
        .await;
    let evidence_context = evidence_build_context(coord, session_id).await?;
    let commitment_evidence = match stored_commitment_evidence {
        Some(evidence) => Some(evidence),
        None => match &evidence_context {
            Some(context) => Some(
                build_and_store_commitment_evidence_with_context(
                    coord,
                    session_id,
                    context,
                    node_id,
                    commitment_bytes,
                )
                .await?,
            ),
            None => None,
        },
    };

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

    if !is_reshare {
        if let Some((ceremony_id, attempt_id, _, _, activated)) = coord
            .app_state
            .dkg_session_state
            .hybrid_transport_info(&session_id)
            .await
        {
            if !activated {
                return Err(DkgError::ProtocolError(
                    "private shares generated before hybrid attempt activation".to_string(),
                ));
            }
            let mut outgoing = Vec::with_capacity(shares.len().saturating_sub(1));
            for share in &shares {
                if share.to_id == node_id {
                    continue;
                }
                let target_peer_id = coord
                    .app_state
                    .dkg_session_state
                    .get_peer_id_for_node(&session_id, share.to_id)
                    .await
                    .ok_or_else(|| {
                        DkgError::ProtocolError(format!(
                            "Missing peer mapping for node_id {}; refusing to route private share",
                            share.to_id
                        ))
                    })?;
                let share_value = CryptoSerialize::to_bytes(&share.value).map_err(|error| {
                    DkgError::Serialization(format!(
                        "Failed to serialize private share value: {error}"
                    ))
                })?;
                let report_evidence = match (&evidence_context, &commitment_evidence) {
                    (Some(context), Some(commitment_evidence)) => {
                        Some(build_share_evidence_with_context(
                            coord,
                            context,
                            node_id,
                            share.to_id,
                            share_value.clone(),
                            share.nonce,
                            commitment_evidence,
                        )?)
                    }
                    _ => None,
                };
                let message_id = crate::dkg::v0::transport::derive_private_message_id(
                    ceremony_id,
                    attempt_id,
                    node_id,
                    share.to_id,
                    &share_value,
                    &share.nonce,
                );
                let private = crate::dkg::v0::transport::DkgPrivateMessage::ShareDelivery {
                    ceremony_id,
                    attempt_id,
                    message_id,
                    from_node_id: node_id,
                    to_node_id: share.to_id,
                    share_value,
                    nonce: share.nonce,
                    report_evidence,
                };
                let exact_bytes =
                    crate::dkg::v0::transport::encode(&private).map_err(DkgError::Serialization)?;
                if coord
                    .app_state
                    .dkg_session_state
                    .cache_private_message(&session_id, message_id, exact_bytes.clone())
                    .await
                    != Some(true)
                {
                    return Err(DkgError::ProtocolError(
                        "private share retransmission bytes changed".to_string(),
                    ));
                }
                outgoing.push((share.to_id, target_peer_id, message_id, exact_bytes));
            }
            tracing::info!(
                session_id,
                node_id,
                pair_count = outgoing.len(),
                "Phase 2: cached exact private shares; starting bounded pair exchanges"
            );
            crate::dkg::v0::hybrid::exchange_private_shares(coord, session_id, outgoing).await?;
            return drive_post_phase2_event(
                coord,
                session_id,
                DkgEvent::Phase2SharesDistributed {
                    local_node_id: node_id,
                },
            )
            .await;
        }
    }

    // Send shares to peers.
    // For Reshare: route using the resolved new-committee node_id -> peer_id map.
    // For Fresh/Refresh: use node_id_to_peer_id map, falling back to broadcast.
    let mut shares_sent = 0;
    let mut shares_skipped = 0;

    for share in shares.iter() {
        // Skip sending share to ourselves.
        // For DealerReceiver, their new-committee node_id may differ from old-committee
        // node_id — skip if to_id maps to our own new-committee peer_id.
        let skip = if let Some(ref new_peers) = reshare_new_node_id_to_peer_id {
            // Reshare: to_id is a new-committee index; check if it points to self.
            new_peers
                .get(&share.to_id)
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
        if let Some(ref new_peers) = reshare_new_node_id_to_peer_id {
            let Some(target_peer_id) = new_peers.get(&share.to_id) else {
                tracing::error!(
                    to_node = share.to_id,
                    "Reshare: share to_id out of range for new committee"
                );
                continue;
            };
            let share_value_bytes = CryptoSerialize::to_bytes(&share.value).map_err(|e| {
                DkgError::Serialization(format!("Failed to serialize share value: {}", e))
            })?;
            let report_evidence = match (&evidence_context, &commitment_evidence) {
                (Some(context), Some(commitment_evidence)) => {
                    Some(build_share_evidence_with_context(
                        coord,
                        context,
                        node_id,
                        share.to_id,
                        share_value_bytes.clone(),
                        share.nonce,
                        commitment_evidence,
                    )?)
                }
                _ => None,
            };
            let share_msg = DkgMessage::Share {
                session_id,
                from_node_id: node_id,
                to_node_id: share.to_id,
                share_value: share_value_bytes,
                nonce: share.nonce,
                report_evidence,
            };
            if coord
                .send_message_to_peer(target_peer_id, share_msg, Some(session_id))
                .await
                .inspect_err(|error| {
                    tracing::error!(
                        to_node = share.to_id,
                        peer_id = %target_peer_id,
                        error = %error,
                        "Reshare: Failed to send share"
                    );
                })
                .is_ok()
            {
                shares_sent += 1;
                tracing::debug!(
                    from_node = node_id,
                    to_node = share.to_id,
                    peer_id = %target_peer_id,
                    "Reshare: Sent share to new committee member"
                );
            }
            continue;
        }

        let share_value_bytes = CryptoSerialize::to_bytes(&share.value).map_err(|e| {
            DkgError::Serialization(format!("Failed to serialize share value: {}", e))
        })?;
        let report_evidence = match (&evidence_context, &commitment_evidence) {
            (Some(context), Some(commitment_evidence)) => Some(build_share_evidence_with_context(
                coord,
                context,
                node_id,
                share.to_id,
                share_value_bytes.clone(),
                share.nonce,
                commitment_evidence,
            )?),
            _ => None,
        };

        // Private DKG shares must be sent only to their intended recipient.
        let target_peer_id = match coord
            .app_state
            .dkg_session_state
            .get_peer_id_for_node(&session_id, share.to_id)
            .await
        {
            Some(peer_id) => peer_id,
            None => {
                coord.remove_session(session_id).await;
                return Err(DkgError::ProtocolError(format!(
                    "Missing peer mapping for node_id {}; refusing to broadcast private share",
                    share.to_id
                )));
            }
        };

        let share_msg = DkgMessage::Share {
            session_id,
            from_node_id: node_id,
            to_node_id: share.to_id,
            share_value: share_value_bytes,
            nonce: share.nonce,
            report_evidence,
        };
        if coord
            .send_message_to_peer(&target_peer_id, share_msg, Some(session_id))
            .await
            .inspect_err(|error| {
                tracing::error!(
                    to_node = share.to_id,
                    peer_id = %target_peer_id,
                    error = %error,
                    "Failed to send share"
                );
            })
            .is_ok()
        {
            shares_sent += 1;
            tracing::debug!(
                from_node = node_id,
                to_node = share.to_id,
                peer_id = %target_peer_id,
                "DKG Coordinator: Sent share"
            );
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

    drive_post_phase2_event(
        coord,
        session_id,
        DkgEvent::Phase2SharesDistributed {
            local_node_id: node_id,
        },
    )
    .await?;

    Ok(())
}
