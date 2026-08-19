use super::*;

pub async fn record_and_ack_valid_reshare_share<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    dealer_id: u32,
) -> Result<()>
where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let ack = coord
        .app_state
        .dkg_session_state
        .with_attempt_state_mut(attempt, |state| {
            if !matches!(state.kind, SessionKind::Reshare { .. })
                || !matches!(
                    state.node.role(),
                    DkgRole::Receiver | DkgRole::DealerReceiver
                )
            {
                return Ok::<_, DkgError>(None);
            }

            if state.reshare.valid_share_dealers.contains(&dealer_id) {
                return Ok(None);
            }

            let params = state.reshare.params.as_ref().ok_or_else(|| {
                DkgError::Generic(
                    "Reshare session is missing reshare_params while acking share".to_string(),
                )
            })?;
            let receiver_node_id = params.new_node_id.ok_or_else(|| {
                DkgError::Generic(
                    "Reshare receiver is missing new_node_id while acking share".to_string(),
                )
            })?;
            let selector_peer_id = state
                .routing
                .reshare_new_node_id_to_peer_id
                .get(&1)
                .cloned()
                .ok_or_else(|| {
                    DkgError::InvalidInput("Reshare new committee is empty".to_string())
                })?;

            state.reshare.valid_share_dealers.insert(dealer_id);

            Ok(Some((receiver_node_id, selector_peer_id)))
        })
        .await
        .map_err(|error| attempt_state_error(attempt, error))??;

    let Some((receiver_node_id, selector_peer_id)) = ack else {
        return Ok(());
    };

    if is_self_peer_id(&coord.app_state.network, &selector_peer_id) {
        handle_reshare_share_ack(coord, attempt, receiver_node_id, dealer_id).await?;
    } else {
        spawn_reshare_share_ack_delivery(
            coord,
            attempt,
            receiver_node_id,
            dealer_id,
            selector_peer_id,
        );
    }

    Ok(())
}

fn spawn_reshare_share_ack_delivery<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    receiver_node_id: u32,
    dealer_id: u32,
    selector_peer_id: String,
) where
    D: CoordinatorDkg + Send + Sync,
    SignImpl: CoordinatorReportSigner<D>,
{
    let coord = DkgCoordinator::with_routes(coord.app_state.clone(), coord.routes);
    tokio::spawn(async move {
        deliver_reshare_share_ack_until_done(
            coord,
            attempt,
            receiver_node_id,
            dealer_id,
            selector_peer_id,
        )
        .await;
    });
}

async fn deliver_reshare_share_ack_until_done<D>(
    coord: DkgCoordinator<D>,
    attempt_key: AttemptKey,
    receiver_node_id: u32,
    dealer_id: u32,
    selector_peer_id: String,
) where
    D: CoordinatorDkg,
    SignImpl: CoordinatorReportSigner<D>,
{
    let session_id = attempt_key.session_id();
    let Some(hard_deadline) = coord
        .app_state
        .dkg_session_state
        .transport_hard_deadline(&session_id, attempt_key.attempt_id)
        .await
    else {
        return;
    };
    let mut delivery_attempt = 0usize;
    let mut last_failure_was_unreachable = false;
    let mut selector_proved_reachable = false;
    loop {
        if !reshare_share_ack_still_needed(&coord, attempt_key).await {
            return;
        }
        if Instant::now() >= hard_deadline {
            if last_failure_was_unreachable && !selector_proved_reachable {
                spawn_pss_offline_for_attempt(
                    &coord.app_state,
                    coord.routes,
                    attempt_key,
                    PssOfflineStage::ReshareShareAck,
                    [ParticipantRef::next(1)],
                )
                .await;
            }
            tracing::warn!(
                session_id,
                receiver_node_id,
                dealer_id,
                selector_peer_id = %selector_peer_id,
                "Reshare: share acknowledgement delivery reached the hard attempt deadline"
            );
            return;
        }

        delivery_attempt += 1;
        match send_reshare_share_ack(
            &coord,
            attempt_key,
            receiver_node_id,
            dealer_id,
            &selector_peer_id,
        )
        .await
        {
            Ok(()) => {
                tracing::debug!(
                    session_id = session_id,
                    receiver_node_id = receiver_node_id,
                    dealer_id = dealer_id,
                    selector_peer_id = %selector_peer_id,
                    attempt = delivery_attempt,
                    "Reshare: delivered valid-share acknowledgement to selector"
                );
                return;
            }
            Err(e) => {
                last_failure_was_unreachable = e.is_unreachable();
                selector_proved_reachable |= e.proves_reachable();
                tracing::warn!(
                    session_id = session_id,
                    receiver_node_id = receiver_node_id,
                    dealer_id = dealer_id,
                    selector_peer_id = %selector_peer_id,
                    attempt = delivery_attempt,
                    error = %e.error(),
                    "Reshare: failed to deliver valid-share acknowledgement to selector, retrying"
                );
            }
        }

        tokio::time::sleep(RESHARE_SHARE_ACK_RETRY_DELAY).await;
    }
}

async fn reshare_share_ack_still_needed<D>(coord: &DkgCoordinator<D>, attempt: AttemptKey) -> bool
where
    D: CoordinatorDkg,
{
    coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |state| {
            matches!(state.kind, SessionKind::Reshare { .. })
                && state.reshare.selected_dealers.is_none()
        })
        .await
        .unwrap_or(false)
}

pub async fn handle_reshare_share_ack<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    receiver_node_id: u32,
    dealer_id: u32,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let session_id = attempt.session_id();
    let selection = coord
        .app_state
        .dkg_session_state
        .with_attempt_state_mut(attempt, |state| {
            let (new_route_peer_ids, new_committee_size, local_new_node_id) = {
                let params = state.reshare.params.as_ref().ok_or_else(|| {
                    DkgError::Generic(
                        "Reshare ack received for session without reshare_params".to_string(),
                    )
                })?;
                let new_committee_size = params.new_peer_node_keys.len();
                let new_route_peer_ids = (1..=new_committee_size as u32)
                    .filter_map(|node_id| {
                        state
                            .routing
                            .reshare_new_node_id_to_peer_id
                            .get(&node_id)
                            .cloned()
                    })
                    .collect::<Vec<_>>();
                (
                    new_route_peer_ids,
                    new_committee_size,
                    params.new_node_id.unwrap_or(0),
                )
            };

            if local_new_node_id != 1 {
                return Err(DkgError::Unauthorized(
                    "ReshareShareAck delivered to a non-selector node".to_string(),
                ));
            }
            if new_route_peer_ids.len() != new_committee_size {
                return Err(DkgError::InvalidInput(format!(
                    "Reshare new committee routing map has {} entries, expected {}",
                    new_route_peer_ids.len(),
                    new_committee_size
                )));
            }
            if receiver_node_id == 0 || receiver_node_id as usize > new_committee_size {
                return Err(DkgError::InvalidInput(format!(
                    "Invalid reshare receiver_node_id {} for new committee size {}",
                    receiver_node_id, new_committee_size
                )));
            }
            if dealer_id == 0 || dealer_id as usize > state.node.total_nodes() {
                return Err(DkgError::InvalidInput(format!(
                    "Invalid reshare dealer_id {} for old committee size {}",
                    dealer_id,
                    state.node.total_nodes()
                )));
            }
            let dealer = ParticipantRef::current(dealer_id);
            if !state.transport.active_dealers.contains(&dealer) {
                return Err(DkgError::Unauthorized(format!(
                    "ReshareShareAck names inactive dealer {}",
                    dealer_id
                )));
            }

            let inserted = state
                .reshare
                .share_acks
                .entry(dealer_id)
                .or_insert_with(HashSet::new)
                .insert(receiver_node_id);
            if !inserted {
                return Ok(None);
            }

            let complete = state
                .reshare
                .share_acks
                .get(&dealer_id)
                .map(|acks| acks.len() == new_committee_size)
                .unwrap_or(false);
            if complete && !state.reshare.dealer_completion_order.contains(&dealer_id) {
                state.reshare.dealer_completion_order.push(dealer_id);
            }

            if let Some(selected) = &state.reshare.selected_dealers {
                return Ok(Some((selected.clone(), new_route_peer_ids, false)));
            }

            if state.reshare.selected_dealers.is_none()
                && state.reshare.dealer_completion_order.len() >= state.node.threshold()
            {
                let mut threshold_complete: Vec<u32> = state
                    .reshare
                    .share_acks
                    .iter()
                    .filter_map(|(dealer_id, receivers)| {
                        (receivers.len() == new_committee_size).then_some(*dealer_id)
                    })
                    .collect();
                threshold_complete.sort_unstable();
                let selected: Vec<u32> = threshold_complete
                    .into_iter()
                    .take(state.node.threshold())
                    .collect();
                state
                    .node
                    .select_reshare_participants(selected.clone())
                    .map_err(|e| {
                        DkgError::Crypto(format!("Failed to select reshare participants: {}", e))
                    })?;
                state.reshare.selected_dealers = Some(selected.clone());
                return Ok(Some((selected, new_route_peer_ids, true)));
            }

            Ok(None)
        })
        .await
        .map_err(|error| attempt_state_error(attempt, error))??;

    if let Some((selected_dealer_ids, _new_route_peer_ids, newly_frozen)) = selection {
        if !newly_frozen {
            // The participant set was already frozen and broadcast by an
            // earlier (threshold-reaching) ack; this ack is a late/redundant
            // arrival. Do not re-broadcast: `submit_public_contribution`
            // stamps a fresh `signed_at` on every call, so re-signing the
            // same logical selection would produce a distinct signed
            // message from this origin for the same phase, which the
            // leader's contribution ledger correctly treats as equivocation
            // and aborts the attempt over. Nodes that missed the original
            // broadcast recover it via completeness repair against the
            // retained bytes instead.
            tracing::debug!(
                session_id = session_id,
                selected_dealers = ?selected_dealer_ids,
                "Reshare: ignoring share ack after participant set already frozen"
            );
            return Ok(());
        }

        tracing::info!(
            session_id = session_id,
            selected_dealers = ?selected_dealer_ids,
            "Reshare: selector froze participant set"
        );

        broadcast_reshare_participant_set(coord, attempt, &selected_dealer_ids).await?;

        phases::drive_event(
            coord,
            attempt,
            DkgEvent::ReshareParticipantSetAccepted,
            None,
        )
        .await?;
    }

    Ok(())
}

async fn broadcast_reshare_participant_set<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    selected_dealer_ids: &[u32],
) -> Result<()>
where
    D: CoordinatorDkg,
{
    submit_public_contribution(
        coord,
        attempt,
        DkgPublicPayload::ReshareParticipantSet {
            selected_dealers: selected_dealer_ids
                .iter()
                .copied()
                .map(ParticipantRef::current)
                .collect(),
        },
    )
    .await
}

pub async fn handle_reshare_participant_set<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    from_node_id: u32,
    selected_dealer_ids: Vec<u32>,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let session_id = attempt.session_id();
    let accepted = coord
        .app_state
        .dkg_session_state
        .with_attempt_state_mut(attempt, |state| -> Result<bool> {
            let accepted =
                validate_reshare_participant_set_state(state, from_node_id, &selected_dealer_ids)?;
            if !accepted {
                return Ok(false);
            }
            state
                .node
                .select_reshare_participants(selected_dealer_ids.clone())
                .map_err(|e| {
                    DkgError::Crypto(format!("Failed to select reshare participants: {}", e))
                })?;
            state.reshare.selected_dealers = Some(selected_dealer_ids.clone());
            Ok(true)
        })
        .await
        .map_err(|error| attempt_state_error(attempt, error))??;

    if accepted {
        tracing::info!(
            session_id = session_id,
            selected_dealers = ?selected_dealer_ids,
            "Reshare: accepted participant set"
        );
        phases::drive_event(
            coord,
            attempt,
            DkgEvent::ReshareParticipantSetAccepted,
            None,
        )
        .await?;
    }

    Ok(())
}

pub(crate) async fn preflight_reshare_participant_set<D>(
    coord: &DkgCoordinator<D>,
    attempt: AttemptKey,
    from_node_id: u32,
    selected_dealer_ids: &[u32],
) -> Result<()>
where
    D: CoordinatorDkg,
{
    coord
        .app_state
        .dkg_session_state
        .with_attempt_state(attempt, |state| {
            validate_reshare_participant_set_state(state, from_node_id, selected_dealer_ids)
        })
        .await
        .map_err(|error| attempt_state_error(attempt, error))??;
    Ok(())
}

fn validate_reshare_participant_set_state<D>(
    state: &DkgSessionState<D>,
    from_node_id: u32,
    selected_dealer_ids: &[u32],
) -> Result<bool>
where
    D: CoordinatorDkg,
{
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

    let mut canonical = selected_dealer_ids.to_vec();
    canonical.sort_unstable();
    canonical.dedup();
    if canonical.len() != selected_dealer_ids.len() {
        return Err(DkgError::InvalidInput(
            "ReshareParticipantSet contains duplicate dealer IDs".to_string(),
        ));
    }
    for dealer_id in selected_dealer_ids {
        if *dealer_id == 0 || *dealer_id as usize > state.node.total_nodes() {
            return Err(DkgError::InvalidInput(format!(
                "ReshareParticipantSet dealer ID {} is outside old committee 1..={}",
                dealer_id,
                state.node.total_nodes()
            )));
        }
        let dealer = ParticipantRef::current(*dealer_id);
        if !state.transport.active_dealers.contains(&dealer) {
            return Err(DkgError::Unauthorized(format!(
                "ReshareParticipantSet contains inactive dealer {}",
                dealer_id
            )));
        }
        if !state.reshare.valid_share_dealers.contains(dealer_id) {
            return Err(DkgError::InvalidState(format!(
                "ReshareParticipantSet selected dealer {} before this receiver accepted its commitment and share",
                dealer_id
            )));
        }
    }

    if let Some(existing) = &state.reshare.selected_dealers {
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

    let mut node_probe = state.node.clone();
    node_probe
        .select_reshare_participants(selected_dealer_ids.to_vec())
        .map_err(|e| DkgError::Crypto(format!("Failed to select reshare participants: {}", e)))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::v0::session_state::ReshareParams;
    use crate::helpers::test_helpers::create_test_app_state_default;
    use crypto::r#trait::Dkg as _;
    use crypto::DkgImpl;
    use std::sync::Arc;

    /// Build a receiver-role coordinator with a reshare session already
    /// configured with a given `active_dealers`/`valid_share_dealers` state,
    /// as if Phase 1 (commitment relay) and Phase 3 (share acceptance) had
    /// already run for those dealers. `handle_reshare_participant_set` never
    /// touches the node's crypto state on the rejection paths this exercises,
    /// so a bare `DkgImpl::new` receiver node is sufficient — no full reshare
    /// ceremony is required.
    async fn reshare_receiver_test_coordinator(
        db_name: &str,
        session_id: u128,
        active_dealers: Vec<u32>,
        valid_share_dealers: Vec<u32>,
    ) -> (DkgCoordinator<DkgImpl>, String) {
        let db_path = crate::helpers::test_helpers::test_db_path(db_name);
        let state = Arc::new(create_test_app_state_default(db_name).await);
        let node = *DkgImpl::new(1, 1, 2, 0, DkgRole::Receiver)
            .expect("construct receiver DkgImpl for test session");
        assert_eq!(
            state
                .dkg_session_state
                .create_session(session_id, node, 2, |_| {})
                .await,
            CreateSessionOutcome::Created
        );
        {
            let mut states = state.dkg_session_state.states.write().await;
            let session = states
                .get_mut(&session_id)
                .expect("session was just created");
            let attempt = AttemptKey::test(session_id);
            session.transport.ceremony_id = Some(attempt.ceremony_id);
            session.transport.attempt_id = Some(attempt.attempt_id);
            session.kind = SessionKind::Reshare {
                ring_pk_hex: "test-ring".to_string(),
                new_peer_node_keys: vec!["node-a".to_string(), "node-b".to_string()],
                new_threshold: 1,
                bulletin_post_id: "test-ring-post".to_string(),
            };
            session.transport.active_dealers = active_dealers
                .into_iter()
                .map(ParticipantRef::current)
                .collect();
            session.reshare.valid_share_dealers = valid_share_dealers.into_iter().collect();
        }
        (DkgCoordinator::with_routes(state, &::network::V0), db_path)
    }

    #[tokio::test]
    async fn rejects_dealer_not_in_active_dealers() {
        let (coord, db_path) = reshare_receiver_test_coordinator(
            "reshare_participant_set_rejects_inactive_dealer",
            1001,
            vec![],  // no active dealers at all
            vec![1], // dealer 1 already gave a valid share, but was never marked active
        )
        .await;

        let error = handle_reshare_participant_set(&coord, AttemptKey::test(1001), 1, vec![1])
            .await
            .expect_err("a dealer outside active_dealers must be rejected");
        assert!(matches!(error, DkgError::Unauthorized(_)));
        assert!(error.to_string().contains("inactive dealer"));
        crate::helpers::test_helpers::cleanup_db(&db_path);
    }

    #[tokio::test]
    async fn rejects_dealer_without_a_previously_accepted_valid_share() {
        let (coord, db_path) = reshare_receiver_test_coordinator(
            "reshare_participant_set_rejects_no_valid_share",
            1002,
            vec![1], // dealer 1 is active
            vec![],  // ...but this receiver never validated a commitment/share from it
        )
        .await;

        let error =
            handle_reshare_participant_set(&coord, AttemptKey::test(1002), 1, vec![1])
            .await
            .expect_err(
                "a dealer this receiver never independently validated a share from must be rejected",
            );
        assert!(matches!(error, DkgError::InvalidState(_)));
        assert!(error.to_string().contains("before this receiver accepted"));
        crate::helpers::test_helpers::cleanup_db(&db_path);
    }

    #[tokio::test]
    async fn rejects_participant_set_from_a_non_leader_sender() {
        let (coord, db_path) = reshare_receiver_test_coordinator(
            "reshare_participant_set_rejects_non_leader",
            1003,
            vec![1],
            vec![1],
        )
        .await;

        // Only new-committee node 1 may send ReshareParticipantSet; this must
        // be rejected before the active_dealers/valid_share_dealers checks
        // are even reached.
        let error = handle_reshare_participant_set(&coord, AttemptKey::test(1003), 2, vec![1])
            .await
            .expect_err("a non-leader sender must be rejected");
        assert!(matches!(error, DkgError::Unauthorized(_)));
        crate::helpers::test_helpers::cleanup_db(&db_path);
    }

    #[tokio::test]
    async fn accepts_dealer_that_is_both_active_and_share_validated() {
        let (coord, db_path) = reshare_receiver_test_coordinator(
            "reshare_participant_set_accepts_valid_dealer",
            1004,
            vec![1],
            vec![1],
        )
        .await;

        handle_reshare_participant_set(&coord, AttemptKey::test(1004), 1, vec![1])
            .await
            .expect("a dealer that is both active and share-validated must be accepted");
        crate::helpers::test_helpers::cleanup_db(&db_path);
    }

    /// Build a new-committee-node-1 (selector) coordinator with a reshare
    /// session configured to accept `ReshareShareAck` messages: `reshare.params`
    /// names this node as new-committee node 1, and the new-committee routing
    /// map is fully populated. `active_dealers` is the frozen old-committee
    /// dealer set the selector should check acks against.
    async fn reshare_selector_test_coordinator(
        db_name: &str,
        session_id: u128,
        active_dealers: Vec<u32>,
    ) -> (DkgCoordinator<DkgImpl>, String) {
        let (coord, db_path) =
            reshare_receiver_test_coordinator(db_name, session_id, active_dealers, vec![]).await;
        {
            let mut states = coord.app_state.dkg_session_state.states.write().await;
            let session = states
                .get_mut(&session_id)
                .expect("session was just created");
            session.reshare.params = Some(ReshareParams {
                old_share: None,
                participating_ids: vec![1, 2],
                new_threshold: 1,
                new_total_nodes: 2,
                new_peer_node_keys: vec!["node-a".to_string(), "node-b".to_string()],
                new_node_id: Some(1),
                bulletin_post_id: "test-ring-post".to_string(),
            });
            session
                .routing
                .reshare_new_node_id_to_peer_id
                .insert(1, "peer-a".to_string());
            session
                .routing
                .reshare_new_node_id_to_peer_id
                .insert(2, "peer-b".to_string());
        }
        (coord, db_path)
    }

    #[tokio::test]
    async fn rejects_share_ack_for_inactive_dealer() {
        let (coord, db_path) = reshare_selector_test_coordinator(
            "reshare_share_ack_rejects_inactive_dealer",
            2001,
            vec![], // no active dealers at all: dealer 1 was never frozen in
        )
        .await;

        let error = handle_reshare_share_ack(&coord, AttemptKey::test(2001), 2, 1)
            .await
            .expect_err("an ack naming a dealer outside active_dealers must be rejected");
        assert!(matches!(error, DkgError::Unauthorized(_)));
        assert!(error.to_string().contains("inactive dealer"));
        crate::helpers::test_helpers::cleanup_db(&db_path);
    }

    #[tokio::test]
    async fn accepts_share_ack_for_active_dealer() {
        let (coord, db_path) = reshare_selector_test_coordinator(
            "reshare_share_ack_accepts_active_dealer",
            2002,
            vec![1], // dealer 1 is frozen into the active set
        )
        .await;

        handle_reshare_share_ack(&coord, AttemptKey::test(2002), 2, 1)
            .await
            .expect("an ack naming an active dealer must be accepted");
        crate::helpers::test_helpers::cleanup_db(&db_path);
    }
}
