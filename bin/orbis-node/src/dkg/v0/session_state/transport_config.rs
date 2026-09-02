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
        self.with_state_mut(session_id, |state| {
            let transport = &mut state.transport;
            if let Some(existing) = transport.attempt_id {
                if existing == attempt_id
                    && transport.ceremony_id == Some(ceremony_id)
                    && transport.config_digest.is_none()
                {
                    // `handle_session_init` reserves the concrete attempt
                    // before the Gossip topic has been joined. Finish filling
                    // the transport configuration below.
                } else {
                    return if existing == attempt_id
                        && transport.ceremony_id == Some(ceremony_id)
                        && transport.config_digest == Some(config_digest)
                    {
                        TransportConfigureOutcome::AlreadyConfigured
                    } else {
                        TransportConfigureOutcome::ConflictingAttempt
                    };
                }
            }
            let now = Instant::now();
            transport.ceremony_id = Some(ceremony_id);
            transport.attempt_id = Some(attempt_id);
            transport.committee_digest = Some(committee_digest);
            transport.config_digest = Some(config_digest);
            transport.topic_id = Some(topic_id);
            transport.leader_node_key = Some(leader_node_key);
            transport.leader_peer_route = Some(leader_peer_route);
            transport.participant_routes = participant_routes;
            transport.committees = Some(committees);
            transport.topic = Some(topic);
            transport.prepared_at = Some(now);
            transport.last_progress_at = now;
            transport.hard_deadline = Some(now + crate::constants::DKG_ATTEMPT_TIMEOUT);
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
            if state.transport.attempt_id != Some(attempt_id) {
                return TransportActivationOutcome::StaleAttempt;
            }
            if state.transport.activated {
                return if state.transport.activation_digest == Some(activation_digest)
                    && state.transport.active_dealers == active_dealers
                {
                    TransportActivationOutcome::AlreadyActivated
                } else {
                    TransportActivationOutcome::StaleAttempt
                };
            }
            if let Some(params) = state.reshare.params.as_mut() {
                params.participating_ids =
                    active_dealers.iter().map(|dealer| dealer.node_id).collect();
            }
            state.transport.activated = true;
            state.transport.activation_digest = Some(activation_digest);
            state.transport.active_dealers = active_dealers;
            state.transport.last_progress_at = Instant::now();
            TransportActivationOutcome::Activated
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
            let transport = &mut state.transport;
            if transport.attempt_id != Some(attempt_id) {
                return TransportBeginOutcome::StaleAttempt;
            }
            if !transport.activated {
                return TransportBeginOutcome::NotActivated;
            }
            if transport.activation_digest != Some(activation_digest) {
                return TransportBeginOutcome::StaleAttempt;
            }
            if transport.begun {
                return TransportBeginOutcome::AlreadyBegun;
            }
            transport.begun = true;
            transport.last_progress_at = Instant::now();
            TransportBeginOutcome::Begun
        })
        .await
        .unwrap_or(TransportBeginOutcome::MissingSession)
    }

    pub(crate) async fn transport_configuration(
        &self,
        session_id: &u128,
    ) -> Option<(CeremonyId, AttemptId, [u8; 32])> {
        self.with_state(session_id, |state| {
            let transport = &state.transport;
            Some((
                transport.ceremony_id?,
                transport.attempt_id?,
                transport.config_digest?,
            ))
        })
        .await
        .flatten()
    }

    pub(crate) async fn transport_attempt(&self, session_id: &u128) -> Option<AttemptId> {
        self.with_state(session_id, |state| state.transport.attempt_id)
            .await
            .flatten()
    }

    pub(crate) async fn transport_hard_deadline(
        &self,
        session_id: &u128,
        attempt_id: AttemptId,
    ) -> Option<Instant> {
        self.with_state(session_id, |state| {
            (state.transport.attempt_id == Some(attempt_id))
                .then_some(state.transport.hard_deadline)
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
            let transport = &state.transport;
            (transport.attempt_id == Some(attempt_id))
                .then(|| {
                    transport
                        .prepared_at
                        .map(|prepared_at| prepared_at + crate::constants::DKG_PREPARATION_TIMEOUT)
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
        self.with_state(session_id, |state| state.transport.topic.clone())
            .await
            .flatten()
    }

    pub(crate) async fn transport_topic_for_attempt(
        &self,
        session_id: &u128,
        attempt_id: AttemptId,
    ) -> Option<Arc<dyn network::Topic>> {
        self.with_state(session_id, |state| {
            (state.transport.attempt_id == Some(attempt_id))
                .then(|| state.transport.topic.clone())
                .flatten()
        })
        .await
        .flatten()
    }

    pub(crate) async fn transport_committees(&self, session_id: &u128) -> Option<CeremonyConfig> {
        self.with_state(session_id, |state| state.transport.committees.clone())
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
            if state.transport.attempt_id != Some(attempt_id) {
                return false;
            }
            state.transport.topic = Some(topic);
            state.transport.last_progress_at = Instant::now();
            true
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
            if transport.attempt_id != Some(attempt_id) {
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
            if state.transport.attempt_id != Some(attempt_id) {
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
            if transport.attempt_id != Some(attempt_id) {
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
            (transport.attempt_id == Some(attempt_id)
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
            (transport.attempt_id == Some(attempt_id))
                .then(|| transport.topology_probe_responses.clone())
        })
        .await
        .flatten()
    }
}
