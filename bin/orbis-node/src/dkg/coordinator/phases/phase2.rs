use super::*;

pub(in crate::dkg::coordinator) async fn initiate_phase2_shares<D>(
    coord: &DkgCoordinator<D>,
    session_id: u64,
    peer_ids: &[String],
) -> Result<()>
where
    D: CoordinatorDkg,
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

        // Private DKG shares must be sent only to their intended recipient.
        let target_peer_id = coord
            .app_state
            .dkg_session_state
            .get_peer_id_for_node(&session_id, share.to_id)
            .await
            .ok_or_else(|| {
                DkgError::ProtocolError(format!(
                    "Missing peer mapping for node_id {}; refusing to broadcast private share",
                    share.to_id
                ))
            })?;

        let share_msg = DkgMessage::Share {
            session_id,
            from_node_id: node_id,
            to_node_id: share.to_id,
            share_value: share_value_bytes,
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
