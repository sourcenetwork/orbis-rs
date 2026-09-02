use super::*;

impl<D: Dkg + 'static> SessionStateManager<D> {
    #[cfg(test)]
    pub(crate) async fn cache_private_message(
        &self,
        session_id: &u128,
        message_id: MessageId,
        exact_bytes: Vec<u8>,
    ) -> Option<bool> {
        self.with_state_mut(session_id, |state| {
            match state.transport.outbound_private_messages.get(&message_id) {
                Some(existing) => existing == &exact_bytes,
                None => {
                    state
                        .transport
                        .outbound_private_messages
                        .insert(message_id, exact_bytes);
                    true
                }
            }
        })
        .await
    }

    pub(crate) async fn cache_private_message_for_attempt(
        &self,
        attempt: AttemptKey,
        message_id: MessageId,
        exact_bytes: Vec<u8>,
    ) -> std::result::Result<bool, AttemptStateError> {
        self.with_attempt_state_mut(attempt, |state| {
            match state.transport.outbound_private_messages.get(&message_id) {
                Some(existing) => existing == &exact_bytes,
                None => {
                    state
                        .transport
                        .outbound_private_messages
                        .insert(message_id, exact_bytes);
                    true
                }
            }
        })
        .await
    }

    pub(crate) async fn acknowledge_private_message(
        &self,
        session_id: &u128,
        attempt_id: AttemptId,
        message_id: MessageId,
    ) -> Option<bool> {
        self.with_state_mut(session_id, |state| {
            if state.transport.attempt_id != Some(attempt_id) {
                return false;
            }
            state
                .transport
                .acknowledged_private_messages
                .insert(message_id);
            state.transport.last_progress_at = Instant::now();
            true
        })
        .await
    }

    #[cfg(test)]
    pub(crate) async fn private_message(
        &self,
        session_id: &u128,
        message_id: MessageId,
    ) -> Option<Vec<u8>> {
        self.with_state(session_id, |state| {
            state
                .transport
                .outbound_private_messages
                .get(&message_id)
                .cloned()
        })
        .await
        .flatten()
    }

    pub(crate) async fn private_message_for_recipient(
        &self,
        session_id: &u128,
        recipient: ParticipantRef,
    ) -> Option<Vec<u8>> {
        self.with_state(session_id, |state| {
            state
                .transport
                .outbound_private_messages
                .values()
                .find(|bytes| {
                    decode::<DkgPrivateMessage>(bytes, 2 * 1024 * 1024).is_ok_and(|message| {
                        matches!(
                            message,
                            DkgPrivateMessage::ShareDelivery {
                                to,
                                ..
                            } if to == recipient
                        )
                    })
                })
                .cloned()
        })
        .await
        .flatten()
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) async fn private_message_acknowledged(
        &self,
        session_id: &u128,
        message_id: MessageId,
    ) -> bool {
        self.with_state(session_id, |state| {
            state
                .transport
                .acknowledged_private_messages
                .contains(&message_id)
        })
        .await
        .unwrap_or(false)
    }

    pub(crate) async fn private_message_acknowledged_for_attempt(
        &self,
        attempt: AttemptKey,
        message_id: MessageId,
    ) -> std::result::Result<bool, AttemptStateError> {
        self.with_attempt_state(attempt, |state| {
            state
                .transport
                .acknowledged_private_messages
                .contains(&message_id)
        })
        .await
    }

    pub(crate) async fn record_private_peer_response(
        &self,
        attempt: AttemptKey,
        participant: ParticipantRef,
    ) -> std::result::Result<(), AttemptStateError> {
        self.with_attempt_state_mut(attempt, |state| {
            state.transport.private_peer_responses.insert(participant);
        })
        .await
    }

    pub(crate) async fn private_peer_responses_for_attempt(
        &self,
        attempt: AttemptKey,
    ) -> std::result::Result<BTreeSet<ParticipantRef>, AttemptStateError> {
        self.with_attempt_state(attempt, |state| {
            state.transport.private_peer_responses.clone()
        })
        .await
    }

    pub(crate) async fn claim_transport_message(
        &self,
        attempt: AttemptKey,
        message_id: MessageId,
    ) -> MessageProcessingClaim {
        match self
            .with_attempt_state_mut(attempt, |state| {
                let transport = &mut state.transport;
                if transport.processed_message_ids.contains(&message_id) {
                    MessageProcessingClaim::AlreadyProcessed
                } else if !transport.processing_message_ids.insert(message_id) {
                    MessageProcessingClaim::AlreadyProcessing
                } else {
                    MessageProcessingClaim::Claimed
                }
            })
            .await
        {
            Ok(claim) => claim,
            Err(AttemptStateError::MissingSession) => MessageProcessingClaim::MissingSession,
            Err(AttemptStateError::StaleAttempt) => MessageProcessingClaim::StaleAttempt,
        }
    }

    pub(crate) async fn finish_transport_message(
        &self,
        attempt: AttemptKey,
        message_id: MessageId,
        success: bool,
    ) {
        let _ = self
            .with_attempt_state_mut(attempt, |state| {
                let transport = &mut state.transport;
                transport.processing_message_ids.remove(&message_id);
                if success {
                    transport.processed_message_ids.insert(message_id);
                }
            })
            .await;
    }
}
