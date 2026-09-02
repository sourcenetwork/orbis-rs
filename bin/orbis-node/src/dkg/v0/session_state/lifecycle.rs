use super::*;

impl<D: Dkg + 'static> SessionStateManager<D> {
    /// Create a new SessionStateManager and spawn background tasks
    pub fn new() -> Self {
        let states = Arc::new(RwLock::new(HashMap::new()));
        let rings_pss = Arc::new(RwLock::new(HashMap::new()));
        let reshare_signature_ready = Arc::new(RwLock::new(HashMap::new()));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut background_tasks = Vec::new();

        // Spawn background expiration task (handles abandoned sessions). It owns the sole
        // sender for the stall-report channel, so the receiver stays open for the worker's life.
        // Bounded rather than unbounded: if the drain worker (or whoever holds the receiver)
        // stalls, this caps how much memory queued-but-unprocessed events can hold rather than
        // growing without bound. A full channel just drops the newest event (see
        // `expiration_worker`) and counts it, rather than blocking the expiration sweep.
        let (stall_report_tx, stall_report_rx) = mpsc::channel(256);
        // Bounded for the same reason as `stall_report_tx`: caps queued-but-unprocessed
        // soft-stall events rather than growing without bound if the drain worker stalls.
        let (soft_stall_tx, soft_stall_rx) = mpsc::channel(256);
        let failed_sessions = Arc::new(RwLock::new(HashMap::new()));
        let states_clone = states.clone();
        let pss_clone = rings_pss.clone();
        let ready_clone = reshare_signature_ready.clone();
        let failed_sessions_clone = failed_sessions.clone();
        background_tasks.push(tokio::spawn(async move {
            Self::expiration_worker(
                states_clone,
                pss_clone,
                ready_clone,
                failed_sessions_clone,
                shutdown_rx,
                stall_report_tx,
                soft_stall_tx,
            )
            .await;
        }));

        Self {
            states,
            rings_pss,
            reshare_signature_ready,
            shutdown_tx,
            background_tasks: StdMutex::new(background_tasks),
            stall_report_rx: StdMutex::new(Some(stall_report_rx)),
            ceremony_start_locks: Arc::new(TokioMutex::new(HashMap::new())),
            public_commit_receipts: TokioMutex::new(HashMap::new()),
            offline_relay_receipts: TokioMutex::new(HashMap::new()),
            offline_candidate_dedup: StdMutex::new(HashMap::new()),
            private_exchange_permits: Arc::new(tokio::sync::Semaphore::new(
                DKG_PRIVATE_EXCHANGE_CONCURRENCY,
            )),
            soft_stall_rx: StdMutex::new(Some(soft_stall_rx)),
            failed_sessions,
        }
    }

    /// Take the receiver for stalled-PSS-session offline-report attribution. Returns `Some`
    /// exactly once (the first caller); subsequent calls return `None`. Called at node startup
    /// to spawn the drain worker. If no one takes it, the sweep's published events accumulate
    /// unread in the channel until it fills, after which further events are dropped and counted
    /// (see `expiration_worker`) — never fatal, just never turned into reports.
    pub fn take_stall_report_receiver(&self) -> Option<mpsc::Receiver<AbandonedPssSession>> {
        self.stall_report_rx
            .lock()
            .expect("stall_report_rx mutex poisoned")
            .take()
    }

    /// Take the receiver for soft-stalled Fresh DKG attempts. Returns `Some` exactly once
    /// (the first caller); subsequent calls return `None`. Called at node startup to spawn
    /// `spawn_dkg_soft_stall_worker`. If no one takes it, published events accumulate unread
    /// in the channel until it fills, after which further events are dropped and counted
    /// (see `expiration_worker`) — never fatal, just never turned into an early abort.
    pub fn take_soft_stall_receiver(&self) -> Option<mpsc::Receiver<SoftStalledDkgAttempt>> {
        self.soft_stall_rx
            .lock()
            .expect("soft_stall_rx mutex poisoned")
            .take()
    }

    /// Record a repair/private-exchange retry failure against `node_id` for the soft-stall
    /// gate. A no-op if the attempt is no longer current (stale task, already torn down).
    pub(crate) async fn record_peer_no_progress(&self, attempt: AttemptKey, node_id: u32) {
        let _ = self
            .with_attempt_state_mut(attempt, |state| {
                let entry =
                    state
                        .transport
                        .peer_no_progress
                        .entry(node_id)
                        .or_insert(PeerNoProgressInfo {
                            first_failure_at: Instant::now(),
                            consecutive_failures: 0,
                        });
                entry.consecutive_failures += 1;
            })
            .await;
    }

    /// Clear any soft-stall failure streak against `node_id` once its contribution or share
    /// is recorded. A no-op if the attempt is no longer current.
    pub(crate) async fn clear_peer_no_progress(&self, attempt: AttemptKey, node_id: u32) {
        let _ = self
            .with_attempt_state_mut(attempt, |state| {
                state.transport.peer_no_progress.remove(&node_id);
            })
            .await;
    }

    /// Write (or overwrite) the queryable failure record for a Fresh DKG attempt.
    pub(crate) async fn record_failed_session(&self, record: FailedDkgSessionRecord) {
        self.failed_sessions
            .write()
            .await
            .insert(record.session_id, (record, Instant::now()));
    }

    /// Read the queryable failure record for a Fresh DKG attempt, if one is still retained
    /// (see `DKG_FAILED_SESSION_RECORD_TTL`).
    pub(crate) async fn failed_session(&self, session_id: &u128) -> Option<FailedDkgSessionRecord> {
        self.failed_sessions
            .read()
            .await
            .get(session_id)
            .map(|(record, _)| record.clone())
    }

    /// Background task that periodically removes expired sessions
    ///
    /// Active sessions are removed only at their hard attempt deadline. Completed
    /// sessions are retained only for `DKG_COMPLETED_SESSION_TTL`.
    async fn expiration_worker(
        states: Arc<RwLock<HashMap<u128, DkgSessionState<D>>>>,
        rings_pss: Arc<RwLock<HashMap<String, RingPssOwner>>>,
        reshare_signature_ready: Arc<
            RwLock<HashMap<ReshareSignatureReadyKey, ReshareSignatureReadyMaterial>>,
        >,
        failed_sessions: Arc<RwLock<HashMap<u128, (FailedDkgSessionRecord, Instant)>>>,
        mut shutdown_rx: watch::Receiver<bool>,
        stall_report_tx: mpsc::Sender<AbandonedPssSession>,
        soft_stall_tx: mpsc::Sender<SoftStalledDkgAttempt>,
    ) {
        let mut interval = tokio::time::interval(SESSION_EXPIRATION_CHECK_INTERVAL);
        let mut soft_stall_interval = tokio::time::interval(DKG_SOFT_STALL_CHECK_INTERVAL);

        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                    continue;
                }
                _ = soft_stall_interval.tick() => {
                    Self::soft_stall_scan(&states, &soft_stall_tx).await;
                    continue;
                }
                _ = interval.tick() => {}
            }

            let now = Instant::now();
            let mut states = states.write().await;
            let initial_count = states.len();

            // Collect session IDs to remove (expired or stalled)
            let mut to_remove_ids: Vec<u128> = Vec::new();
            let mut completed_ids: HashSet<u128> = HashSet::new();
            let mut fresh_failures: Vec<FailedDkgSessionRecord> = Vec::new();
            for (session_id, state) in states.iter() {
                let phase_age = now.duration_since(state.phase_started_at);
                if state.phase == DkgPhase::Phase4Complete {
                    if phase_age >= DKG_COMPLETED_SESSION_TTL {
                        tracing::warn!(
                            session_id = session_id,
                            completed_age_secs = phase_age.as_secs(),
                            "SessionStateManager: Removing retained completed DKG session"
                        );
                        to_remove_ids.push(*session_id);
                        completed_ids.insert(*session_id);
                    }
                    continue;
                }
                let hard_deadline = state
                    .transport
                    .hard_deadline
                    .unwrap_or(state.created_at + DKG_ATTEMPT_TIMEOUT);
                if now >= hard_deadline {
                    tracing::warn!(
                        session_id = session_id,
                        phase = ?state.phase,
                        attempt_id = ?state.transport.attempt_id,
                        "SessionStateManager: Removing DKG attempt at hard deadline"
                    );
                    to_remove_ids.push(*session_id);

                    // A refresh/reshare that stalled while collecting commitments or shares
                    // means one or more dealers went silent. Publish the dealers we never heard
                    // from so the stall-report worker can attempt `node_offline` reports (the
                    // co-signer reachability probe filters to dealers that are actually unreachable).
                    //
                    // A pure reshare Receiver never generates commitments, so
                    // `initiate_phase1_commitments` deliberately skips it and its `phase`
                    // never leaves `Initializing` for the entire ceremony — even though it
                    // is, in every meaningful sense, waiting on dealers' Phase 2 shares the
                    // whole time. Classify by role/obligation, not only by phase: treat that
                    // case the same as an explicit `Phase2Shares` stall. `missing_dealer_peer_ids`
                    // itself is phase-parameterized, not role-gated (its own `Dealer`
                    // exclusion for `Phase2Shares` doesn't apply to `Receiver`), so this reuses
                    // its existing `received_shares` tracking rather than adding a new one.
                    let stalled_phase = match state.phase {
                        DkgPhase::Phase1Commitments | DkgPhase::Phase2Shares => Some(state.phase),
                        DkgPhase::Initializing
                            if matches!(state.kind, SessionKind::Reshare { .. })
                                && state.node.role() == DkgRole::Receiver =>
                        {
                            Some(DkgPhase::Phase2Shares)
                        }
                        _ => None,
                    };
                    if let Some(stalled_phase) = stalled_phase {
                        let missing_peer_ids = state.missing_dealer_peer_ids(stalled_phase);
                        if !missing_peer_ids.is_empty() {
                            if let Err(error) = stall_report_tx.try_send(AbandonedPssSession {
                                session_id: *session_id,
                                kind: state.kind.clone(),
                                ring_id: state.routing.ring_id.clone(),
                                protocol_version: state.protocol_version,
                                missing_peer_ids,
                            }) {
                                crate::metrics::record_dkg_transport_event(
                                    "pss_stall_report",
                                    "dropped",
                                );
                                tracing::warn!(
                                    session_id = session_id,
                                    %error,
                                    "SessionStateManager: stall-report channel full or closed; dropping offline-attribution event"
                                );
                            }
                        }
                    }

                    // Safety net for a stalled Fresh DKG attempt the soft-stall scan didn't
                    // catch (e.g. a follower whose leader vanished before ever broadcasting
                    // Abort, or a session stuck in `Initializing` past `Begin`). Client-facing
                    // diagnostic only — not wired into the on-chain reporting pipeline above.
                    if matches!(state.kind, SessionKind::Fresh) {
                        let stage = match state.phase {
                            DkgPhase::Phase0CommitmentHashes => DkgFailureStage::CommitmentHashes,
                            DkgPhase::Phase1Commitments => DkgFailureStage::Commitments,
                            DkgPhase::Phase2Shares => DkgFailureStage::ShareExchange,
                            _ => DkgFailureStage::Unknown,
                        };
                        fresh_failures.push(FailedDkgSessionRecord {
                            session_id: *session_id,
                            ring_id: state.routing.ring_id.clone(),
                            attempt_id: state.transport.attempt_id,
                            stage,
                            missing: state.missing_fresh_participants(),
                            reason:
                                "attempt reached the 15-minute hard deadline without completing"
                                    .to_string(),
                            failed_at: SystemTime::now(),
                        });
                    }
                }
            }

            if !fresh_failures.is_empty() {
                let mut failed = failed_sessions.write().await;
                let inserted_at = Instant::now();
                for record in fresh_failures {
                    failed.insert(record.session_id, (record, inserted_at));
                }
            }

            // Remove sessions (connections are per-peer and never closed here)
            let mut ring_claims_to_clear: Vec<(String, RingPssOwner)> = Vec::new();
            let mut removed_ids: HashSet<u128> = HashSet::new();
            let mut removed_attempts: HashSet<(u128, AttemptId)> = HashSet::new();
            let mut removed_unconfigured_ids: HashSet<u128> = HashSet::new();
            for session_id in to_remove_ids {
                if let Some(mut state) = states.remove(&session_id) {
                    removed_ids.insert(session_id);
                    let _ = state.transport.attempt_cancel_tx.send(true);
                    if let Some(task) = state.transport.topic_task.take() {
                        task.abort();
                    }
                    if let Some(guard) = state.metrics_guard.take() {
                        if completed_ids.contains(&session_id) {
                            guard.complete();
                        } else {
                            guard.abandon();
                        }
                    }
                    if let Some(k) = state.kind.ring_key() {
                        ring_claims_to_clear.push((
                            k.to_string(),
                            RingPssOwner {
                                session_id,
                                attempt_id: state.transport.attempt_id,
                            },
                        ));
                    }
                    if let Some(attempt_id) = state.transport.attempt_id {
                        removed_attempts.insert((session_id, attempt_id));
                    } else {
                        removed_unconfigured_ids.insert(session_id);
                    }
                }
            }

            // Clear in-progress PSS claims for expired sessions.
            if !ring_claims_to_clear.is_empty() {
                let mut pss = rings_pss.write().await;
                for (key, owner) in &ring_claims_to_clear {
                    if pss.get(key).copied() == Some(*owner) {
                        pss.remove(key);
                        tracing::debug!(
                            ring_key = %key,
                            session_id = owner.session_id,
                            "SessionStateManager: Cleared in-progress PSS claim on expiration"
                        );
                    }
                }
            }

            if !removed_ids.is_empty() {
                reshare_signature_ready.write().await.retain(|k, _| {
                    !removed_attempts.contains(&(k.session_id, k.attempt_id))
                        && !removed_unconfigured_ids.contains(&k.session_id)
                });
            }

            // Markers for a *successfully completed* attempt are deliberately not
            // cleared above (or in `finish_removed_session`) so a late or retried
            // co-signer sign request still validates after this node's own
            // transport attempt is gone — see `reshare_signature_ready_material`.
            // That session is no longer in `states` by then, so nothing else ever
            // revisits its marker. Age those out independently, on the same TTL
            // used to bound retained completed sessions, so this set can't grow
            // without bound over a node's lifetime.
            reshare_signature_ready.write().await.retain(|_, material| {
                now.duration_since(material.marked_at()) < DKG_COMPLETED_SESSION_TTL
            });

            // Failure records are decoupled from `states` (see `FailedDkgSessionRecord`), so
            // they're aged out on their own TTL rather than tied to any session's lifecycle.
            failed_sessions.write().await.retain(|_, (_, inserted_at)| {
                now.duration_since(*inserted_at) < DKG_FAILED_SESSION_RECORD_TTL
            });

            let removed = initial_count - states.len();
            if removed > 0 {
                tracing::info!(
                    removed = removed,
                    remaining = states.len(),
                    "SessionStateManager: Expired session cleanup complete"
                );
            }
        }
    }

    /// Leader-only scan for Fresh DKG crypto phases that have genuinely
    /// stopped making progress against a specific peer. Runs on its own
    /// (shorter) tick from `expiration_worker`, independent of the
    /// hard-deadline sweep. Only detects and publishes — the drain worker
    /// spawned via `take_soft_stall_receiver` does the actual abort + record
    /// write, since it needs full `AppState` access this task doesn't have.
    async fn soft_stall_scan(
        states: &Arc<RwLock<HashMap<u128, DkgSessionState<D>>>>,
        soft_stall_tx: &mpsc::Sender<SoftStalledDkgAttempt>,
    ) {
        // Write lock (not read): a successfully-queued attempt gets marked
        // `soft_stall_reported` below, under the same lock as the scan itself, so a
        // still-alive attempt awaiting drain-worker processing can't be re-published on
        // every subsequent tick.
        let mut states = states.write().await;
        for (session_id, state) in states.iter_mut() {
            if !matches!(state.kind, SessionKind::Fresh) {
                continue;
            }
            if state.transport.soft_stall_reported {
                continue;
            }
            if !matches!(
                state.phase,
                DkgPhase::Phase0CommitmentHashes
                    | DkgPhase::Phase1Commitments
                    | DkgPhase::Phase2Shares
            ) {
                continue;
            }
            if !state.is_local_leader() {
                continue;
            }
            let Some(attempt_id) = state.transport.attempt_id else {
                continue;
            };
            let stalled_ids = state.soft_stalled_peer_ids(
                DKG_SOFT_STALL_NO_PROGRESS_THRESHOLD,
                DKG_SOFT_STALL_MIN_REPAIR_ATTEMPTS,
            );
            if stalled_ids.is_empty() {
                continue;
            }
            // Only report peers that are both "missing" (per the phase-specific
            // diff) and "soft-stalled" (per the repair-retry gate), so a peer
            // whose contribution simply hasn't been repair-attempted yet is
            // never attributed.
            let missing: Vec<MissingDkgParticipant> = state
                .missing_fresh_participants()
                .into_iter()
                .filter(|participant| stalled_ids.contains(&participant.node_id))
                .collect();
            if missing.is_empty() {
                continue;
            }
            let stage = match state.phase {
                DkgPhase::Phase0CommitmentHashes => DkgFailureStage::CommitmentHashes,
                DkgPhase::Phase1Commitments => DkgFailureStage::Commitments,
                DkgPhase::Phase2Shares => DkgFailureStage::ShareExchange,
                _ => DkgFailureStage::Unknown,
            };
            match soft_stall_tx.try_send(SoftStalledDkgAttempt {
                session_id: *session_id,
                attempt_id,
                ring_id: state.routing.ring_id.clone(),
                protocol_version: state.protocol_version,
                missing,
                stage,
            }) {
                // Only mark reported once the event is actually queued — if the channel is
                // full or closed, leave the flag unset so a later tick can retry once the
                // drain worker (or a fresh one) catches up, rather than getting permanently
                // stuck unreported.
                Ok(()) => state.transport.soft_stall_reported = true,
                Err(error) => {
                    crate::metrics::record_dkg_transport_event("dkg_soft_stall", "dropped");
                    tracing::warn!(
                        session_id = session_id,
                        %error,
                        "SessionStateManager: soft-stall channel full or closed; dropping early-abort event"
                    );
                }
            }
        }
    }
}
