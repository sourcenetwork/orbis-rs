use super::*;

impl<D: Dkg + 'static> SessionStateManager<D> {
    /// Remove a session and free its memory.
    ///
    /// Called after DKG Phase 4 completes. The session data is no longer needed
    /// since the private share is stored in local storage and ring info is on
    /// the bulletin.
    ///
    /// Listener-owned topic and acknowledgement tasks are cancelled here. Pair
    /// streams are ceremony-scoped and close after their delivery contract is
    /// acknowledged; bounded pooled peer connections remain available.
    #[cfg(test)]
    pub async fn remove_session(&self, session_id: &u128) {
        self.remove_session_with_outcome(session_id, false).await;
    }

    /// Remove a successfully completed session and balance its active metrics.
    #[cfg(test)]
    #[allow(dead_code)]
    pub async fn complete_session(&self, session_id: &u128) {
        self.remove_session_with_outcome(session_id, true).await;
    }

    /// Abort one exact transport attempt.
    ///
    /// A topic listener must detach its own abort handle before returning; other
    /// callers abort the listener immediately. The session is removed while the
    /// state lock is held, so no later protocol message can advance it.
    pub(crate) async fn abort_transport_attempt(
        &self,
        attempt: AttemptKey,
        topic_task: TopicTaskDisposition,
    ) -> bool {
        self.remove_transport_attempt(attempt, topic_task, false)
            .await
    }

    /// Complete one exact transport attempt without allowing a stale phase-4
    /// task to remove a newer retry of the same deterministic ceremony.
    pub(crate) async fn complete_transport_attempt(
        &self,
        attempt: AttemptKey,
        topic_task: TopicTaskDisposition,
    ) -> bool {
        self.remove_transport_attempt(attempt, topic_task, true)
            .await
    }

    async fn remove_transport_attempt(
        &self,
        attempt: AttemptKey,
        topic_task: TopicTaskDisposition,
        completed: bool,
    ) -> bool {
        let session_id = attempt.session_id();
        let mut state = {
            let mut states = self.states.write().await;
            if !states.get(&session_id).is_some_and(|state| {
                state.transport.ceremony_id == Some(attempt.ceremony_id)
                    && state.transport.attempt_id == Some(attempt.attempt_id)
            }) {
                return false;
            }
            states
                .remove(&session_id)
                .expect("the matching transport session was checked above")
        };
        if !completed {
            let _ = state.transport.attempt_cancel_tx.send(true);
        }
        if let Some(task) = state.transport.topic_task.take() {
            if topic_task == TopicTaskDisposition::Abort {
                task.abort();
            }
        }
        self.finish_removed_session(&session_id, state, completed)
            .await;
        true
    }

    /// Remove preparation state only when it is still unconfigured or belongs
    /// to the exact failed attempt. A stale coordinator must not erase a
    /// different attempt that won transport configuration for the same
    /// deterministic ceremony ID.
    pub(crate) async fn abort_transport_preparation(
        &self,
        session_id: &u128,
        attempt_id: AttemptId,
        topic_task: TopicTaskDisposition,
    ) -> bool {
        let mut state = {
            let mut states = self.states.write().await;
            let Some(existing) = states.get(session_id) else {
                return false;
            };
            if existing
                .transport
                .attempt_id
                .is_some_and(|configured| configured != attempt_id)
            {
                return false;
            }
            states
                .remove(session_id)
                .expect("the matching preparation session was checked above")
        };
        if let Some(task) = state.transport.topic_task.take() {
            if topic_task == TopicTaskDisposition::Abort {
                task.abort();
            }
        }
        self.finish_removed_session(session_id, state, false).await;
        true
    }

    #[cfg(test)]
    async fn remove_session_with_outcome(&self, session_id: &u128, completed: bool) {
        let mut state = {
            let mut states = self.states.write().await;
            let Some(state) = states.remove(session_id) else {
                return;
            };
            state
        };
        if let Some(task) = state.transport.topic_task.take() {
            task.abort();
        }
        self.finish_removed_session(session_id, state, completed)
            .await;
    }

    async fn finish_removed_session(
        &self,
        session_id: &u128,
        mut state: DkgSessionState<D>,
        completed: bool,
    ) {
        if let Some(guard) = state.metrics_guard.take() {
            if completed {
                guard.complete();
            } else {
                guard.abandon();
            }
        }
        tracing::debug!(
            session_id = session_id,
            "SessionStateManager: Removed session"
        );
        let ring_key_to_clear = state.kind.ring_key().map(str::to_string);
        let removed_attempt = state
            .transport
            .attempt_id
            .map(|attempt_id| AttemptKey::new(CeremonyId(*session_id), attempt_id));

        // Clear the in-progress PSS claim so future ceremonies can proceed.
        if let Some(key) = ring_key_to_clear {
            if let Some(attempt) = removed_attempt {
                self.unmark_ring_pss_for_attempt(&key, attempt).await;
            } else {
                self.unmark_ring_pss_if_matches(&key, *session_id).await;
            }
            tracing::debug!(
                session_id = session_id,
                ring_key = %key,
                "SessionStateManager: Cleared in-progress PSS claim on remove_session"
            );
        }

        // A successfully completed attempt's readiness marker must survive
        // this cleanup: `validate_ring_reshare_update_statement` needs it to
        // accept a late or retried co-signer sign request after this node's
        // own transport attempt is gone (e.g. `wait_for_reshare_bulletin_finalized`
        // already called `complete_transport_attempt` once its local bulletin
        // poll confirmed finalization, which can race ahead of a delayed sign
        // request from the selector). Only an aborted attempt's marker, if
        // any, is cleared here — there is nothing valid to sign for a
        // ceremony that never finished.
        if !completed {
            self.reshare_signature_ready.write().await.retain(|k, _| {
                removed_attempt.is_none_or(|attempt| {
                    k.session_id != attempt.session_id() || k.attempt_id != attempt.attempt_id
                })
            });
        }
    }
}
