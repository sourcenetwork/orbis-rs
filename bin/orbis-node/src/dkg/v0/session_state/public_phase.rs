use super::*;

impl<D: Dkg + 'static> SessionStateManager<D> {
    pub(crate) async fn record_public_contribution(
        &self,
        session_id: &u128,
        attempt_id: AttemptId,
        phase: PublicPhase,
        origin: ParticipantRef,
        contribution: network::SignedPayload,
    ) -> PublicContributionRecordOutcome {
        self.with_state_mut(session_id, |state| {
            if state.transport.attempt_id != Some(attempt_id) {
                return PublicContributionRecordOutcome::StaleAttempt;
            }
            let transport = &mut state.transport;
            match transport
                .public_contributions
                .get(&phase)
                .and_then(|contributions| contributions.get(&origin))
            {
                Some(existing) if existing == &contribution => {
                    PublicContributionRecordOutcome::DuplicateSame
                }
                Some(existing) => PublicContributionRecordOutcome::ConflictingDuplicate {
                    retained: existing.clone(),
                    conflicting: contribution,
                },
                None => {
                    transport
                        .public_phase_started_at
                        .entry(phase)
                        .or_insert_with(Instant::now);
                    transport
                        .public_contributions
                        .entry(phase)
                        .or_default()
                        .insert(origin, contribution);
                    if transport
                        .public_repairs
                        .get(&phase)
                        .is_some_and(|repair| !repair.in_flight)
                    {
                        transport.public_repairs.remove(&phase);
                    }
                    transport.last_progress_at = Instant::now();
                    transport.peer_no_progress.remove(&origin.node_id);
                    PublicContributionRecordOutcome::Recorded
                }
            }
        })
        .await
        .unwrap_or(PublicContributionRecordOutcome::MissingSession)
    }

    /// Atomically retain a manifest-validated public batch.
    ///
    /// Every existing contribution is checked before any new item is inserted,
    /// so an equivocating origin cannot leave a partially recorded batch behind.
    pub(crate) async fn record_public_batch(
        &self,
        session_id: &u128,
        attempt_id: AttemptId,
        phase: PublicPhase,
        contributions: BTreeMap<ParticipantRef, network::SignedPayload>,
    ) -> PublicBatchRecordOutcome {
        self.with_state_mut(session_id, |state| {
            let transport = &mut state.transport;
            if transport.attempt_id != Some(attempt_id) {
                return PublicBatchRecordOutcome::StaleAttempt;
            }

            let retained = transport.public_contributions.entry(phase).or_default();
            for (origin, contribution) in &contributions {
                if let Some(existing) = retained
                    .get(origin)
                    .filter(|existing| *existing != contribution)
                {
                    return PublicBatchRecordOutcome::ConflictingDuplicate {
                        origin: *origin,
                        retained: existing.clone(),
                        conflicting: contribution.clone(),
                    };
                }
            }

            let mut newly_recorded_origins: Vec<ParticipantRef> = Vec::new();
            for (origin, contribution) in contributions {
                if let std::collections::btree_map::Entry::Vacant(entry) = retained.entry(origin) {
                    entry.insert(contribution);
                    newly_recorded_origins.push(origin);
                }
            }
            if !newly_recorded_origins.is_empty() {
                transport
                    .public_phase_started_at
                    .entry(phase)
                    .or_insert_with(Instant::now);
                if transport
                    .public_repairs
                    .get(&phase)
                    .is_some_and(|repair| !repair.in_flight)
                {
                    transport.public_repairs.remove(&phase);
                }
                transport.last_progress_at = Instant::now();
                for origin in newly_recorded_origins {
                    transport.peer_no_progress.remove(&origin.node_id);
                }
                PublicBatchRecordOutcome::Recorded
            } else {
                PublicBatchRecordOutcome::DuplicateSame
            }
        })
        .await
        .unwrap_or(PublicBatchRecordOutcome::MissingSession)
    }

    pub(crate) async fn public_contributions(
        &self,
        session_id: &u128,
        attempt_id: AttemptId,
        phase: PublicPhase,
    ) -> Option<BTreeMap<ParticipantRef, network::SignedPayload>> {
        self.with_state(session_id, |state| {
            (state.transport.attempt_id == Some(attempt_id)).then(|| {
                state
                    .transport
                    .public_contributions
                    .get(&phase)
                    .cloned()
                    .unwrap_or_default()
            })
        })
        .await
        .flatten()
    }

    pub(crate) async fn public_phase_collection_elapsed(
        &self,
        session_id: &u128,
        attempt_id: AttemptId,
        phase: PublicPhase,
    ) -> Option<std::time::Duration> {
        self.with_state(session_id, |state| {
            (state.transport.attempt_id == Some(attempt_id))
                .then(|| {
                    state
                        .transport
                        .public_phase_started_at
                        .get(&phase)
                        .map(Instant::elapsed)
                })
                .flatten()
        })
        .await
        .flatten()
    }

    pub(crate) async fn claim_public_phase_publish(
        &self,
        session_id: &u128,
        attempt_id: AttemptId,
        phase: PublicPhase,
        expected: usize,
    ) -> bool {
        self.with_state_mut(session_id, |state| {
            let transport = &mut state.transport;
            if transport.attempt_id != Some(attempt_id)
                || transport
                    .public_contributions
                    .get(&phase)
                    .map_or(0, BTreeMap::len)
                    != expected
                || transport.publishing_public_phases.contains(&phase)
                || transport.published_public_phases.contains(&phase)
            {
                return false;
            }
            transport.publishing_public_phases.insert(phase);
            true
        })
        .await
        .unwrap_or(false)
    }

    pub(crate) async fn finish_public_phase_publish(
        &self,
        session_id: &u128,
        attempt_id: AttemptId,
        phase: PublicPhase,
        published: bool,
    ) -> bool {
        self.with_state_mut(session_id, |state| {
            let transport = &mut state.transport;
            if transport.attempt_id != Some(attempt_id)
                || !transport.publishing_public_phases.remove(&phase)
            {
                return false;
            }
            if published {
                transport.published_public_phases.insert(phase);
            }
            true
        })
        .await
        .unwrap_or(false)
    }

    pub(crate) async fn claim_public_messages_publish(
        &self,
        session_id: &u128,
        attempt_id: AttemptId,
        message_ids: &[MessageId],
    ) -> Vec<MessageId> {
        self.with_state_mut(session_id, |state| {
            let transport = &mut state.transport;
            if transport.attempt_id != Some(attempt_id) {
                return Vec::new();
            }
            let claimed = message_ids
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .filter(|message_id| {
                    !transport.publishing_public_messages.contains(message_id)
                        && !transport.published_public_messages.contains(message_id)
                })
                .collect::<Vec<_>>();
            transport
                .publishing_public_messages
                .extend(claimed.iter().copied());
            claimed
        })
        .await
        .unwrap_or_default()
    }

    pub(crate) async fn finish_public_messages_publish(
        &self,
        session_id: &u128,
        attempt_id: AttemptId,
        message_ids: &[MessageId],
        published: bool,
    ) -> bool {
        self.with_state_mut(session_id, |state| {
            let transport = &mut state.transport;
            if transport.attempt_id != Some(attempt_id)
                || message_ids
                    .iter()
                    .any(|message_id| !transport.publishing_public_messages.contains(message_id))
            {
                return false;
            }
            for message_id in message_ids {
                transport.publishing_public_messages.remove(message_id);
            }
            if published {
                transport
                    .published_public_messages
                    .extend(message_ids.iter().copied());
            }
            true
        })
        .await
        .unwrap_or(false)
    }

    pub(crate) async fn transport_active_dealers(
        &self,
        session_id: &u128,
    ) -> Option<Vec<ParticipantRef>> {
        self.with_state(session_id, |state| state.transport.active_dealers.clone())
            .await
    }

    pub(crate) async fn transport_info(
        &self,
        session_id: &u128,
    ) -> Option<(CeremonyId, AttemptId, [u8; 32], String, bool)> {
        self.with_state(session_id, |state| {
            let transport = &state.transport;
            Some((
                transport.ceremony_id?,
                transport.attempt_id?,
                transport.committee_digest?,
                transport.leader_node_key.clone()?,
                transport.activated,
            ))
        })
        .await
        .flatten()
    }

    pub(crate) async fn transport_participant_routes(
        &self,
        session_id: &u128,
    ) -> Option<Vec<String>> {
        self.with_state(session_id, |state| {
            state.transport.participant_routes.clone()
        })
        .await
    }

    pub(crate) async fn transport_leader_route(&self, session_id: &u128) -> Option<String> {
        self.with_state(session_id, |state| {
            state.transport.leader_peer_route.clone()
        })
        .await
        .flatten()
    }

    pub(crate) async fn transport_repair_due(
        &self,
        session_id: &u128,
        attempt_id: AttemptId,
        stall_interval: std::time::Duration,
    ) -> bool {
        self.with_state(session_id, |state| {
            let transport = &state.transport;
            transport.attempt_id == Some(attempt_id)
                && transport.activated
                && transport.last_progress_at.elapsed() >= stall_interval
        })
        .await
        .unwrap_or(false)
    }

    pub(crate) async fn claim_public_phase_repair(
        &self,
        session_id: &u128,
        attempt_id: AttemptId,
        phase: PublicPhase,
    ) -> PublicRepairClaimOutcome {
        self.with_state_mut(session_id, |state| {
            let transport = &mut state.transport;
            if transport.attempt_id != Some(attempt_id) {
                return PublicRepairClaimOutcome::StaleAttempt;
            }
            let now = Instant::now();
            match transport.public_repairs.get_mut(&phase) {
                Some(repair) if repair.in_flight => PublicRepairClaimOutcome::InFlight,
                Some(repair) if repair.next_allowed_at > now => PublicRepairClaimOutcome::Backoff,
                Some(repair) => {
                    repair.in_flight = true;
                    PublicRepairClaimOutcome::Claimed
                }
                None => {
                    transport.public_repairs.insert(
                        phase,
                        PublicRepairState {
                            in_flight: true,
                            next_allowed_at: now,
                        },
                    );
                    PublicRepairClaimOutcome::Claimed
                }
            }
        })
        .await
        .unwrap_or(PublicRepairClaimOutcome::StaleAttempt)
    }

    pub(crate) async fn finish_public_phase_repair(
        &self,
        session_id: &u128,
        attempt_id: AttemptId,
        phase: PublicPhase,
        made_progress: bool,
        no_progress_backoff: std::time::Duration,
    ) -> bool {
        self.with_state_mut(session_id, |state| {
            let transport = &mut state.transport;
            if transport.attempt_id != Some(attempt_id) {
                return false;
            }
            if made_progress {
                transport.public_repairs.remove(&phase);
                return true;
            }
            let repair = transport
                .public_repairs
                .entry(phase)
                .or_insert(PublicRepairState {
                    in_flight: false,
                    next_allowed_at: Instant::now(),
                });
            repair.in_flight = false;
            repair.next_allowed_at = Instant::now() + no_progress_backoff;
            true
        })
        .await
        .unwrap_or(false)
    }
}
