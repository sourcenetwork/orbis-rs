use super::*;

impl<D: Dkg + 'static> SessionStateManager<D> {
    /// Stop and join the manager's background cleanup workers.
    pub async fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
        let tasks = self
            .background_tasks
            .lock()
            .expect("session background task mutex poisoned")
            .drain(..)
            .collect::<Vec<_>>();
        for task in tasks {
            let _ = task.await;
        }
    }

    /// Execute a function with read-only access to a session state
    pub async fn with_state<F, R>(&self, session_id: &u128, f: F) -> Option<R>
    where
        F: FnOnce(&DkgSessionState<D>) -> R,
    {
        let states = self.states.read().await;
        states.get(session_id).map(f)
    }

    /// Execute a function with mutable access to a session state
    pub async fn with_state_mut<F, R>(&self, session_id: &u128, f: F) -> Option<R>
    where
        F: FnOnce(&mut DkgSessionState<D>) -> R,
    {
        let mut states = self.states.write().await;
        states.get_mut(session_id).map(f)
    }

    /// Execute a read only when `attempt` still owns the deterministic
    /// ceremony ID. The ownership comparison and read happen under the same
    /// state-map lock, so a retry cannot replace the session between them.
    pub(crate) async fn with_attempt_state<F, R>(
        &self,
        attempt: AttemptKey,
        f: F,
    ) -> std::result::Result<R, AttemptStateError>
    where
        F: FnOnce(&DkgSessionState<D>) -> R,
    {
        let states = self.states.read().await;
        let Some(state) = states.get(&attempt.session_id()) else {
            return Err(AttemptStateError::MissingSession);
        };
        if state.transport.ceremony_id != Some(attempt.ceremony_id)
            || state.transport.attempt_id != Some(attempt.attempt_id)
        {
            return Err(AttemptStateError::StaleAttempt);
        }
        Ok(f(state))
    }

    /// Execute a mutation only when `attempt` still owns the deterministic
    /// ceremony ID. A stale task can therefore never mutate a replacement
    /// attempt, even if it resumes after an arbitrary `.await`.
    pub(crate) async fn with_attempt_state_mut<F, R>(
        &self,
        attempt: AttemptKey,
        f: F,
    ) -> std::result::Result<R, AttemptStateError>
    where
        F: FnOnce(&mut DkgSessionState<D>) -> R,
    {
        let mut states = self.states.write().await;
        let Some(state) = states.get_mut(&attempt.session_id()) else {
            return Err(AttemptStateError::MissingSession);
        };
        if state.transport.ceremony_id != Some(attempt.ceremony_id)
            || state.transport.attempt_id != Some(attempt.attempt_id)
        {
            return Err(AttemptStateError::StaleAttempt);
        }
        Ok(f(state))
    }

    pub(crate) async fn attempt_cancellation(
        &self,
        attempt: AttemptKey,
    ) -> std::result::Result<watch::Receiver<bool>, AttemptStateError> {
        self.with_attempt_state(attempt, |state| {
            state.transport.attempt_cancel_tx.subscribe()
        })
        .await
    }

    /// Create a new DKG session.
    ///
    /// Returns:
    /// - `CreateSessionOutcome::Created` on success.
    /// - `CreateSessionOutcome::AlreadyExists` if a concurrent handler already created
    ///   the session (safe to ignore).
    /// - `CreateSessionOutcome::LimitReached` if `MAX_DKG_SESSIONS` is already at
    ///   capacity (must NOT be silently ignored — callers that marked a ring as
    ///   in-progress PSS before calling this must unmark it on this outcome).
    ///
    /// Create a new DKG session, optionally initializing it via `init_fn` before
    /// the write lock is released.
    ///
    /// `init_fn` is called on the newly created state while the map's write lock is
    /// still held, so the session is never visible to other tasks in a
    /// partially-initialized state (e.g. with `kind = Fresh` and `reshare_params = None`
    /// when this is actually a Reshare session). Pass `|_| {}` when no extra
    /// initialization is needed.
    pub async fn create_session<F>(
        &self,
        session_id: u128,
        node: D,
        total_participants: usize,
        init_fn: F,
    ) -> CreateSessionOutcome
    where
        F: FnOnce(&mut DkgSessionState<D>),
    {
        if total_participants == 0 {
            tracing::warn!(
                session_id = session_id,
                "Cannot create DKG session with zero participants"
            );
            return CreateSessionOutcome::InvalidParticipantCount;
        }

        let mut states = self.states.write().await;

        // Check if session already exists to avoid overwriting existing state
        if states.contains_key(&session_id) {
            tracing::debug!(
                session_id = session_id,
                "DKG session already exists for session_id"
            );
            return CreateSessionOutcome::AlreadyExists;
        }

        // Enforce maximum concurrent session limit to prevent resource exhaustion
        if states.len() >= MAX_DKG_SESSIONS {
            tracing::warn!(
                session_id = session_id,
                active_sessions = states.len(),
                max_sessions = MAX_DKG_SESSIONS,
                "DKG session limit reached, rejecting new session"
            );
            return CreateSessionOutcome::LimitReached;
        }

        let mut new_state = DkgSessionState::new(node, total_participants);
        init_fn(&mut new_state);
        let ceremony_kind = new_state.ceremony_kind();
        new_state.metrics_guard = Some(metrics::DkgSessionMetricsGuard::new(ceremony_kind));
        states.insert(session_id, new_state);
        CreateSessionOutcome::Created
    }

    /// Check if a session exists
    pub async fn session_exists(&self, session_id: &u128) -> bool {
        self.states.read().await.contains_key(session_id)
    }

    #[cfg(test)]
    pub async fn set_peer_ids(&self, session_id: &u128, peer_ids: Vec<String>) {
        self.with_state_mut(session_id, |s| s.routing.peer_ids = peer_ids)
            .await;
    }

    #[cfg(test)]
    pub async fn set_peer_node_keys(&self, session_id: &u128, peer_node_keys: Vec<String>) {
        self.with_state_mut(session_id, |s| s.routing.peer_node_keys = peer_node_keys)
            .await;
    }

    /// Stage a refresh bundle while waiting for the post-refresh health-check result.
    #[cfg(test)]
    pub async fn set_refresh_health_check_candidate(
        &self,
        session_id: &u128,
        candidate: RefreshHealthCheckCandidate,
    ) {
        self.with_state_mut(session_id, |s| s.refresh.candidate = Some(candidate))
            .await;
    }

    /// Load the staged refresh bundle, if this session still has one.
    pub async fn refresh_health_check_candidate(
        &self,
        session_id: &u128,
    ) -> Option<RefreshHealthCheckCandidate> {
        self.with_state(session_id, |s| s.refresh.candidate.clone())
            .await
            .flatten()
    }

    /// Discard any staged refresh bundle for this session.
    #[cfg(test)]
    #[allow(dead_code)]
    pub async fn clear_refresh_health_check_candidate(&self, session_id: &u128) {
        self.with_state_mut(session_id, |s| s.refresh.candidate = None)
            .await;
    }

    /// Store a refresh health-check result that arrived before Phase 4 staged its candidate.
    #[cfg(test)]
    pub async fn store_pending_refresh_health_check_result(
        &self,
        session_id: &u128,
        result: PendingRefreshHealthCheckResult,
    ) -> Option<bool> {
        self.with_state_mut(session_id, |state| {
            if state.refresh.pending_result.is_some() {
                return false;
            }
            state.refresh.pending_result = Some(result);
            true
        })
        .await
    }

    /// Remove and return an early refresh health-check result, if one was queued.
    #[cfg(test)]
    pub async fn take_pending_refresh_health_check_result(
        &self,
        session_id: &u128,
    ) -> Option<PendingRefreshHealthCheckResult> {
        self.with_state_mut(session_id, |s| s.refresh.pending_result.take())
            .await
            .flatten()
    }

    /// Store the PSS refresh interval for this session so Phase 4 can persist it.
    pub async fn get_peer_ids(&self, session_id: &u128) -> Option<Vec<String>> {
        self.with_state(session_id, |s| s.routing.peer_ids.clone())
            .await
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub async fn get_peer_node_keys(&self, session_id: &u128) -> Option<Vec<String>> {
        self.with_state(session_id, |s| s.routing.peer_node_keys.clone())
            .await
    }

    pub async fn ring_id_for_session(&self, session_id: &u128) -> Option<String> {
        self.with_state(session_id, |s| s.routing.ring_id.clone())
            .await
    }
}
