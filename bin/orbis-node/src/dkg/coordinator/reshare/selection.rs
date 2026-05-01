use super::*;

pub(in crate::dkg::coordinator) async fn record_and_ack_valid_reshare_share<D>(
    coord: &DkgCoordinator<D>,
    session_id: u64,
    dealer_id: u32,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let ack = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| {
            if !matches!(state.kind, SessionKind::Reshare { .. })
                || !matches!(
                    state.node.role(),
                    DkgRole::Receiver | DkgRole::DealerReceiver
                )
            {
                return Ok::<_, DkgError>(None);
            }

            if state.reshare_valid_share_dealers.contains(&dealer_id) {
                return Ok(None);
            }

            let params = state.reshare_params.as_ref().ok_or_else(|| {
                DkgError::Generic(
                    "Reshare session is missing reshare_params while acking share".to_string(),
                )
            })?;
            let receiver_node_id = params.new_node_id.ok_or_else(|| {
                DkgError::Generic(
                    "Reshare receiver is missing new_node_id while acking share".to_string(),
                )
            })?;
            let selector_peer_id = params.new_peer_ids.first().cloned().ok_or_else(|| {
                DkgError::InvalidInput("Reshare new committee is empty".to_string())
            })?;

            Ok(Some((receiver_node_id, selector_peer_id)))
        })
        .await
        .ok_or_else(|| session_not_found(session_id))??;

    let Some((receiver_node_id, selector_peer_id)) = ack else {
        return Ok(());
    };

    if is_self_peer_id(&coord.app_state.network, &selector_peer_id) {
        handle_reshare_share_ack(coord, session_id, receiver_node_id, dealer_id).await?;
    } else {
        let ack_msg = DkgMessage::ReshareShareAck {
            session_id,
            receiver_node_id,
            dealer_id,
        };
        coord
            .send_message_to_peer(&selector_peer_id, ack_msg, Some(session_id))
            .await
            .map_err(|e| {
                DkgError::NetworkCommunication(format!(
                    "Reshare: failed to send valid-share acknowledgement to selector {}: {}",
                    selector_peer_id, e
                ))
            })?;
    }

    coord
        .app_state
        .dkg_session_state
        .with_state_mut(&session_id, |state| {
            state.reshare_valid_share_dealers.insert(dealer_id);
        })
        .await;

    Ok(())
}

pub(in crate::dkg::coordinator) async fn handle_reshare_share_ack<D>(
    coord: &DkgCoordinator<D>,
    session_id: u64,
    receiver_node_id: u32,
    dealer_id: u32,
) -> Result<Option<DkgMessage>>
where
    D: CoordinatorDkg,
{
    let selection = coord
        .app_state
        .dkg_session_state
        .with_state_mut(&session_id, |state| {
            let (new_peer_ids, local_new_node_id) = {
                let params = state.reshare_params.as_ref().ok_or_else(|| {
                    DkgError::Generic(
                        "Reshare ack received for session without reshare_params".to_string(),
                    )
                })?;
                (params.new_peer_ids.clone(), params.new_node_id.unwrap_or(0))
            };

            if local_new_node_id != 1 {
                return Err(DkgError::Unauthorized(
                    "ReshareShareAck delivered to a non-selector node".to_string(),
                ));
            }
            if receiver_node_id == 0 || receiver_node_id as usize > new_peer_ids.len() {
                return Err(DkgError::InvalidInput(format!(
                    "Invalid reshare receiver_node_id {} for new committee size {}",
                    receiver_node_id,
                    new_peer_ids.len()
                )));
            }
            if dealer_id == 0 || dealer_id as usize > state.node.total_nodes() {
                return Err(DkgError::InvalidInput(format!(
                    "Invalid reshare dealer_id {} for old committee size {}",
                    dealer_id,
                    state.node.total_nodes()
                )));
            }

            let inserted = state
                .reshare_share_acks
                .entry(dealer_id)
                .or_insert_with(HashSet::new)
                .insert(receiver_node_id);
            if !inserted {
                return Ok(None);
            }

            let complete = state
                .reshare_share_acks
                .get(&dealer_id)
                .map(|acks| acks.len() == new_peer_ids.len())
                .unwrap_or(false);
            if complete && !state.reshare_dealer_completion_order.contains(&dealer_id) {
                state.reshare_dealer_completion_order.push(dealer_id);
            }

            if let Some(selected) = &state.reshare_selected_dealers {
                return Ok(Some((selected.clone(), new_peer_ids, false)));
            }

            if state.reshare_selected_dealers.is_none()
                && state.reshare_dealer_completion_order.len() >= state.node.threshold()
            {
                let selected: Vec<u32> = state
                    .reshare_dealer_completion_order
                    .iter()
                    .copied()
                    .take(state.node.threshold())
                    .collect();
                state
                    .node
                    .select_reshare_participants(selected.clone())
                    .map_err(|e| {
                        DkgError::Crypto(format!("Failed to select reshare participants: {}", e))
                    })?;
                state.reshare_selected_dealers = Some(selected.clone());
                return Ok(Some((selected, new_peer_ids, true)));
            }

            Ok(None)
        })
        .await
        .ok_or_else(|| session_not_found(session_id))??;

    if let Some((selected_dealer_ids, new_peer_ids, newly_frozen)) = selection {
        if newly_frozen {
            tracing::info!(
                session_id = session_id,
                selected_dealers = ?selected_dealer_ids,
                "Reshare: selector froze participant set"
            );
        } else {
            tracing::debug!(
                session_id = session_id,
                selected_dealers = ?selected_dealer_ids,
                "Reshare: selector re-announcing frozen participant set"
            );
        }

        broadcast_reshare_participant_set(coord, session_id, &selected_dealer_ids, &new_peer_ids)
            .await?;

        phases::drive_event(
            coord,
            session_id,
            DkgEvent::ReshareParticipantSetAccepted,
            None,
        )
        .await?;
    }

    Ok(None)
}

async fn broadcast_reshare_participant_set<D>(
    coord: &DkgCoordinator<D>,
    session_id: u64,
    selected_dealer_ids: &[u32],
    new_peer_ids: &[String],
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let mut failures = Vec::new();

    for peer_id in new_peer_ids {
        if is_self_peer_id(&coord.app_state.network, peer_id) {
            continue;
        }

        let mut last_error = None;
        for attempt in 1..=RESHARE_PARTICIPANT_SET_SEND_ATTEMPTS {
            let msg = DkgMessage::ReshareParticipantSet {
                session_id,
                from_node_id: 1,
                selected_dealer_ids: selected_dealer_ids.to_vec(),
            };

            match coord
                .send_message_to_peer(peer_id, msg, Some(session_id))
                .await
            {
                Ok(()) => {
                    last_error = None;
                    break;
                }
                Err(e) => {
                    last_error = Some(e.to_string());
                    tracing::warn!(
                        session_id = session_id,
                        peer_id = %peer_id,
                        attempt = attempt,
                        max_attempts = RESHARE_PARTICIPANT_SET_SEND_ATTEMPTS,
                        error = %e,
                        "Reshare: failed to broadcast selected participant set"
                    );
                    if attempt < RESHARE_PARTICIPANT_SET_SEND_ATTEMPTS {
                        tokio::time::sleep(RESHARE_PARTICIPANT_SET_RETRY_DELAY).await;
                    }
                }
            }
        }

        if let Some(error) = last_error {
            failures.push(format!("{} ({})", peer_id, error));
        }
    }

    if !failures.is_empty() {
        return Err(DkgError::NetworkCommunication(format!(
            "Reshare: failed to broadcast selected participant set after {} attempts to: {}",
            RESHARE_PARTICIPANT_SET_SEND_ATTEMPTS,
            failures.join(", ")
        )));
    }

    Ok(())
}

pub(in crate::dkg::coordinator) async fn handle_reshare_participant_set<D>(
    coord: &DkgCoordinator<D>,
    session_id: u64,
    from_node_id: u32,
    selected_dealer_ids: Vec<u32>,
) -> Result<Option<DkgMessage>>
where
    D: CoordinatorDkg,
{
    let accepted = coord
        .app_state
        .dkg_session_state
        .with_state_mut(&session_id, |state| {
            if from_node_id != 1 {
                return Err(DkgError::Unauthorized(format!(
                    "ReshareParticipantSet must come from new committee node 1, got {}",
                    from_node_id
                )));
            }
            if !matches!(state.kind, SessionKind::Reshare { .. }) {
                return Err(DkgError::InvalidInput(
                    "ReshareParticipantSet received for non-reshare session".to_string(),
                ));
            }
            if !matches!(
                state.node.role(),
                DkgRole::Receiver | DkgRole::DealerReceiver
            ) {
                return Err(DkgError::InvalidInput(
                    "ReshareParticipantSet received by node outside new committee".to_string(),
                ));
            }
            if selected_dealer_ids.len() != state.node.threshold() {
                return Err(DkgError::InvalidInput(format!(
                    "ReshareParticipantSet has {} dealers, expected old threshold {}",
                    selected_dealer_ids.len(),
                    state.node.threshold()
                )));
            }

            let mut canonical = selected_dealer_ids.clone();
            canonical.sort_unstable();
            canonical.dedup();
            if canonical.len() != selected_dealer_ids.len() {
                return Err(DkgError::InvalidInput(
                    "ReshareParticipantSet contains duplicate dealer IDs".to_string(),
                ));
            }
            for dealer_id in &selected_dealer_ids {
                if *dealer_id == 0 || *dealer_id as usize > state.node.total_nodes() {
                    return Err(DkgError::InvalidInput(format!(
                        "ReshareParticipantSet dealer ID {} is outside old committee 1..={}",
                        dealer_id,
                        state.node.total_nodes()
                    )));
                }
            }

            if let Some(existing) = &state.reshare_selected_dealers {
                let mut existing_canonical = existing.clone();
                existing_canonical.sort_unstable();
                if existing_canonical == canonical {
                    return Ok(false);
                }
                return Err(DkgError::InvalidInput(format!(
                    "Conflicting ReshareParticipantSet: existing {:?}, new {:?}",
                    existing, selected_dealer_ids
                )));
            }

            state
                .node
                .select_reshare_participants(selected_dealer_ids.clone())
                .map_err(|e| {
                    DkgError::Crypto(format!("Failed to select reshare participants: {}", e))
                })?;
            state.reshare_selected_dealers = Some(selected_dealer_ids.clone());
            Ok(true)
        })
        .await
        .ok_or_else(|| session_not_found(session_id))??;

    coord
        .app_state
        .dkg_session_state
        .mark_message_processed(
            &session_id,
            from_node_id,
            DkgMessageType::ReshareParticipantSet,
        )
        .await;

    if accepted {
        tracing::info!(
            session_id = session_id,
            selected_dealers = ?selected_dealer_ids,
            "Reshare: accepted participant set"
        );
        phases::drive_event(
            coord,
            session_id,
            DkgEvent::ReshareParticipantSetAccepted,
            None,
        )
        .await?;
    }

    Ok(None)
}
