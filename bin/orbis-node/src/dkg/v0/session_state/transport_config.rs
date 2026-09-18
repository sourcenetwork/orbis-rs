use super::*;

impl<D: Dkg + 'static> SessionStateManager<D> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn configure_transport(
        &self,
        session_id: &u128,
        ceremony_id: CeremonyId,
        attempt_id: AttemptId,
        committee_digest: [u8; 32],
        config_digest: [u8; 32],
        topic_id: network::TopicId,
        leader_node_key: String,
        leader_peer_route: String,
        participant_routes: Vec<String>,
        committees: CeremonyConfig,
        topic: Arc<dyn network::Topic>,
    ) -> TransportConfigureOutcome {
        let attempt = AttemptKey::new(ceremony_id, attempt_id);
        self.with_state_mut(session_id, |state| {
            if let Some(existing) = state.transport.attempt() {
                if existing != attempt {
                    return TransportConfigureOutcome::ConflictingAttempt;
                }
            }
            // A late-arriving duplicate Configure is tolerated for a matching-digest
            // retry even after this attempt has moved on to Activated/Begun (`configured()`
            // is `Some` for all three), not just while still `Configured`.
            if let Some(configured) = state.transport.configured() {
                return if configured.config_digest == config_digest {
                    TransportConfigureOutcome::AlreadyConfigured
                } else {
                    TransportConfigureOutcome::ConflictingAttempt
                };
            }
            // `Unset` (no prior reservation -- harmless, the original code tolerated
            // this too) or `Reserved` matching this attempt: configure now.
            let now = Instant::now();
            state.transport.lifecycle = TransportLifecycle::Configured {
                attempt,
                transport: ConfiguredTransport {
                    committee_digest,
                    config_digest,
                    topic_id,
                    leader_node_key,
                    leader_peer_route,
                    participant_routes,
                    committees,
                    topic,
                    prepared_at: now,
                    hard_deadline: now + crate::constants::DKG_ATTEMPT_TIMEOUT,
                },
            };
            state.transport.last_progress_at = now;
            TransportConfigureOutcome::Configured
        })
        .await
        .unwrap_or(TransportConfigureOutcome::MissingSession)
    }

    pub(crate) async fn activate_transport(
        &self,
        session_id: &u128,
        attempt_id: AttemptId,
        activation_digest: [u8; 32],
        active_dealers: Vec<ParticipantRef>,
    ) -> TransportActivationOutcome {
        self.with_state_mut(session_id, |state| {
            if state.transport.attempt_id() != Some(attempt_id) {
                return TransportActivationOutcome::StaleAttempt;
            }
            let current =
                std::mem::replace(&mut state.transport.lifecycle, TransportLifecycle::Unset);
            match current {
                TransportLifecycle::Configured { attempt, transport } => {
                    if let Some(params) = state.reshare.params.as_mut() {
                        params.participating_ids =
                            active_dealers.iter().map(|dealer| dealer.node_id).collect();
                    }
                    state.transport.lifecycle = TransportLifecycle::Activated {
                        attempt,
                        transport,
                        activation: ActivatedTransport {
                            activation_digest,
                            active_dealers,
                        },
                    };
                    state.transport.last_progress_at = Instant::now();
                    TransportActivationOutcome::Activated
                }
                TransportLifecycle::Activated {
                    attempt,
                    transport,
                    activation,
                } => {
                    let outcome = if activation.activation_digest == activation_digest
                        && activation.active_dealers == active_dealers
                    {
                        TransportActivationOutcome::AlreadyActivated
                    } else {
                        TransportActivationOutcome::StaleAttempt
                    };
                    state.transport.lifecycle = TransportLifecycle::Activated {
                        attempt,
                        transport,
                        activation,
                    };
                    outcome
                }
                TransportLifecycle::Begun {
                    attempt,
                    transport,
                    activation,
                } => {
                    // A retried Activate after Begin already happened is accepted the
                    // same way a retry before Begin would be (matches the original
                    // code, which only ever checked the `activated` flag).
                    let outcome = if activation.activation_digest == activation_digest
                        && activation.active_dealers == active_dealers
                    {
                        TransportActivationOutcome::AlreadyActivated
                    } else {
                        TransportActivationOutcome::StaleAttempt
                    };
                    state.transport.lifecycle = TransportLifecycle::Begun {
                        attempt,
                        transport,
                        activation,
                    };
                    outcome
                }
                other => {
                    // `Reserved` matching `attempt_id` (not yet configured). Not
                    // reachable in production -- every caller confirms
                    // `transport_configuration` succeeded before activating -- but
                    // fail closed rather than activating without a topic/committee.
                    state.transport.lifecycle = other;
                    TransportActivationOutcome::StaleAttempt
                }
            }
        })
        .await
        .unwrap_or(TransportActivationOutcome::MissingSession)
    }

    /// Claim the one transition from an activated transport barrier into
    /// cryptographic work. The claim is attempt-scoped so a retransmitted
    /// `Begin` request can be acknowledged without regenerating contributions
    /// or private shares.
    pub(crate) async fn begin_transport(
        &self,
        session_id: &u128,
        attempt_id: AttemptId,
        activation_digest: [u8; 32],
    ) -> TransportBeginOutcome {
        self.with_state_mut(session_id, |state| {
            if state.transport.attempt_id() != Some(attempt_id) {
                return TransportBeginOutcome::StaleAttempt;
            }
            let current =
                std::mem::replace(&mut state.transport.lifecycle, TransportLifecycle::Unset);
            match current {
                TransportLifecycle::Activated {
                    attempt,
                    transport,
                    activation,
                } => {
                    if activation.activation_digest != activation_digest {
                        state.transport.lifecycle = TransportLifecycle::Activated {
                            attempt,
                            transport,
                            activation,
                        };
                        return TransportBeginOutcome::StaleAttempt;
                    }
                    state.transport.lifecycle = TransportLifecycle::Begun {
                        attempt,
                        transport,
                        activation,
                    };
                    state.transport.last_progress_at = Instant::now();
                    TransportBeginOutcome::Begun
                }
                TransportLifecycle::Begun {
                    attempt,
                    transport,
                    activation,
                } => {
                    let outcome = if activation.activation_digest == activation_digest {
                        TransportBeginOutcome::AlreadyBegun
                    } else {
                        TransportBeginOutcome::StaleAttempt
                    };
                    state.transport.lifecycle = TransportLifecycle::Begun {
                        attempt,
                        transport,
                        activation,
                    };
                    outcome
                }
                other => {
                    // `Reserved`/`Configured` matching `attempt_id`: not yet activated.
                    state.transport.lifecycle = other;
                    TransportBeginOutcome::NotActivated
                }
            }
        })
        .await
        .unwrap_or(TransportBeginOutcome::MissingSession)
    }

    pub(crate) async fn transport_configuration(
        &self,
        session_id: &u128,
    ) -> Option<(CeremonyId, AttemptId, [u8; 32])> {
        self.with_state(session_id, |state| {
            let attempt = state.transport.attempt()?;
            let configured = state.transport.configured()?;
            Some((
                attempt.ceremony_id,
                attempt.attempt_id,
                configured.config_digest,
            ))
        })
        .await
        .flatten()
    }

    pub(crate) async fn transport_attempt(&self, session_id: &u128) -> Option<AttemptId> {
        self.with_state(session_id, |state| state.transport.attempt_id())
            .await
            .flatten()
    }

    pub(crate) async fn transport_hard_deadline(
        &self,
        session_id: &u128,
        attempt_id: AttemptId,
    ) -> Option<Instant> {
        self.with_state(session_id, |state| {
            (state.transport.attempt_id() == Some(attempt_id))
                .then(|| state.transport.configured().map(|c| c.hard_deadline))
                .flatten()
        })
        .await
        .flatten()
    }

    pub(crate) async fn transport_preparation_deadline(
        &self,
        session_id: &u128,
        attempt_id: AttemptId,
    ) -> Option<Instant> {
        self.with_state(session_id, |state| {
            (state.transport.attempt_id() == Some(attempt_id))
                .then(|| {
                    state
                        .transport
                        .configured()
                        .map(|c| c.prepared_at + crate::constants::DKG_PREPARATION_TIMEOUT)
                })
                .flatten()
        })
        .await
        .flatten()
    }

    pub(crate) async fn transport_topic(
        &self,
        session_id: &u128,
    ) -> Option<Arc<dyn network::Topic>> {
        self.with_state(session_id, |state| {
            state.transport.configured().map(|c| c.topic.clone())
        })
        .await
        .flatten()
    }

    pub(crate) async fn transport_topic_for_attempt(
        &self,
        session_id: &u128,
        attempt_id: AttemptId,
    ) -> Option<Arc<dyn network::Topic>> {
        self.with_state(session_id, |state| {
            (state.transport.attempt_id() == Some(attempt_id))
                .then(|| state.transport.configured().map(|c| c.topic.clone()))
                .flatten()
        })
        .await
        .flatten()
    }

    pub(crate) async fn transport_committees(&self, session_id: &u128) -> Option<CeremonyConfig> {
        self.with_state(session_id, |state| {
            state.transport.configured().map(|c| c.committees.clone())
        })
        .await
        .flatten()
    }

    pub(crate) async fn replace_transport_topic(
        &self,
        session_id: &u128,
        attempt_id: AttemptId,
        topic: Arc<dyn network::Topic>,
    ) -> Option<bool> {
        self.with_state_mut(session_id, |state| {
            if state.transport.attempt_id() != Some(attempt_id) {
                return false;
            }
            let replaced = match &mut state.transport.lifecycle {
                TransportLifecycle::Configured { transport, .. }
                | TransportLifecycle::Activated { transport, .. }
                | TransportLifecycle::Begun { transport, .. } => {
                    transport.topic = topic;
                    true
                }
                TransportLifecycle::Unset | TransportLifecycle::Reserved { .. } => false,
            };
            if replaced {
                state.transport.last_progress_at = Instant::now();
            }
            replaced
        })
        .await
    }

    pub(crate) async fn set_transport_topic_task(
        &self,
        session_id: &u128,
        task: tokio::task::AbortHandle,
    ) -> Option<()> {
        self.with_state_mut(session_id, |state| {
            if let Some(previous) = state.transport.topic_task.replace(task) {
                previous.abort();
            }
        })
        .await
    }

    pub(crate) async fn begin_topology_probe(
        &self,
        session_id: &u128,
        attempt_id: AttemptId,
        nonce: [u8; 32],
        self_peer: String,
    ) -> Option<Arc<Notify>> {
        self.with_state_mut(session_id, |state| {
            let transport = &mut state.transport;
            if transport.attempt_id() != Some(attempt_id) {
                return None;
            }
            transport.topology_probe_nonce = Some(nonce);
            transport.topology_probe_acknowledgements.clear();
            transport.topology_probe_responses.clear();
            transport
                .topology_probe_acknowledgements
                .insert(self_peer.clone());
            transport.topology_probe_responses.insert(self_peer);
            transport.last_progress_at = Instant::now();
            Some(transport.topology_probe_notify.clone())
        })
        .await
        .flatten()
    }

    pub(crate) async fn record_topology_probe(
        &self,
        session_id: &u128,
        attempt_id: AttemptId,
        nonce: [u8; 32],
    ) -> Option<bool> {
        self.with_state_mut(session_id, |state| {
            if state.transport.attempt_id() != Some(attempt_id) {
                return false;
            }
            if state
                .transport
                .topology_probe_nonce
                .is_some_and(|existing| existing != nonce)
            {
                return false;
            }
            state.transport.topology_probe_nonce = Some(nonce);
            state.transport.last_progress_at = Instant::now();
            true
        })
        .await
    }

    pub(crate) async fn record_topology_probe_ack(
        &self,
        session_id: &u128,
        attempt_id: AttemptId,
        nonce: [u8; 32],
        peer: String,
    ) -> TopologyAckRecordOutcome {
        self.with_state_mut(session_id, |state| {
            let transport = &mut state.transport;
            if transport.attempt_id() != Some(attempt_id) {
                return TopologyAckRecordOutcome::StaleAttempt;
            }
            transport.topology_probe_responses.insert(peer.clone());
            if transport.topology_probe_nonce != Some(nonce) {
                return TopologyAckRecordOutcome::WrongNonce;
            }
            if !transport.topology_probe_acknowledgements.insert(peer) {
                return TopologyAckRecordOutcome::Duplicate;
            }
            transport.last_progress_at = Instant::now();
            transport.topology_probe_notify.notify_waiters();
            TopologyAckRecordOutcome::Recorded
        })
        .await
        .unwrap_or(TopologyAckRecordOutcome::MissingSession)
    }

    pub(crate) async fn topology_probe_acknowledgements(
        &self,
        session_id: &u128,
        attempt_id: AttemptId,
        nonce: [u8; 32],
    ) -> Option<BTreeSet<String>> {
        self.with_state(session_id, |state| {
            let transport = &state.transport;
            (transport.attempt_id() == Some(attempt_id)
                && transport.topology_probe_nonce == Some(nonce))
            .then(|| transport.topology_probe_acknowledgements.clone())
        })
        .await
        .flatten()
    }

    pub(crate) async fn topology_probe_responses(
        &self,
        session_id: &u128,
        attempt_id: AttemptId,
    ) -> Option<BTreeSet<String>> {
        self.with_state(session_id, |state| {
            let transport = &state.transport;
            (transport.attempt_id() == Some(attempt_id))
                .then(|| transport.topology_probe_responses.clone())
        })
        .await
        .flatten()
    }
}
