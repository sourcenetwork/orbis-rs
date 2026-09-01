use super::*;

impl<D: Dkg + 'static> SessionStateManager<D> {
    /// Clone of the ceremony-start singleflight lock registry, for
    /// `CeremonyStartGuard`'s independent `Drop`-time cleanup task.
    pub(crate) fn ceremony_start_locks(
        &self,
    ) -> Arc<TokioMutex<HashMap<u128, Arc<TokioMutex<()>>>>> {
        self.ceremony_start_locks.clone()
    }

    /// Clone of the node-wide private DKG pair-exchange concurrency permit.
    pub(crate) fn private_exchange_permits(&self) -> Arc<tokio::sync::Semaphore> {
        self.private_exchange_permits.clone()
    }

    /// Look up a retained `CommitRefreshResult` receipt for `key`, pruning
    /// expired entries first. Returns the recorded leader peer bytes if a
    /// live receipt exists.
    pub(crate) async fn public_commit_receipt(
        &self,
        key: (CeremonyId, AttemptId, MessageId),
    ) -> Option<Vec<u8>> {
        let now = Instant::now();
        let mut receipts = self.public_commit_receipts.lock().await;
        receipts
            .retain(|_, (_, recorded_at)| now.duration_since(*recorded_at) <= DKG_ATTEMPT_TIMEOUT);
        receipts
            .get(&key)
            .map(|(leader_peer, _)| leader_peer.clone())
    }

    /// Record a completed `CommitRefreshResult` receipt for `key`, evicting the
    /// oldest entry first if the bounded cache is full.
    pub(crate) async fn record_public_commit_receipt(
        &self,
        key: (CeremonyId, AttemptId, MessageId),
        leader_peer: Vec<u8>,
    ) {
        let now = Instant::now();
        let mut receipts = self.public_commit_receipts.lock().await;
        if receipts.len() >= MAX_PUBLIC_COMMIT_RECEIPTS {
            if let Some(oldest) = receipts
                .iter()
                .min_by_key(|(_, (_, recorded_at))| *recorded_at)
                .map(|(key, _)| *key)
            {
                receipts.remove(&oldest);
            }
        }
        receipts.insert(key, (leader_peer, now));
    }

    /// Look up a retained offline-relay receipt for `attempt`, pruning expired
    /// entries first.
    pub(crate) async fn offline_relay_receipt(
        &self,
        attempt: AttemptKey,
    ) -> Option<DkgOfflineRelayReceipt> {
        let now = tokio::time::Instant::now();
        let mut receipts = self.offline_relay_receipts.lock().await;
        receipts
            .retain(|_, receipt| now.duration_since(receipt.recorded_at) <= DKG_ATTEMPT_TIMEOUT);
        receipts.get(&attempt).cloned()
    }

    /// Claim `idempotency_key` against the retained offline-relay receipt for
    /// `attempt`. Returns `None` if the receipt has already expired, was
    /// never recorded, or its bounded set of processed keys is full —
    /// callers must treat this the same as "unavailable", not as a
    /// duplicate: `Some(false)` is reserved exclusively for a key that was
    /// genuinely already claimed. Returns `Some(true)` on a new claim.
    ///
    /// Re-checks `recorded_at` here (not just in `offline_relay_receipt`,
    /// which callers typically call first) because the two are separate
    /// lock acquisitions with real async work — e.g. a chain read in
    /// `validate_offline_relay_transition` — in between; a receipt that was
    /// still fresh at that first check can cross `DKG_ATTEMPT_TIMEOUT`
    /// before this call runs.
    pub(crate) async fn claim_offline_relay_idempotency(
        &self,
        attempt: AttemptKey,
        idempotency_key: MessageId,
    ) -> Option<bool> {
        let now = tokio::time::Instant::now();
        let mut receipts = self.offline_relay_receipts.lock().await;
        let expired = receipts
            .get(&attempt)
            .is_some_and(|receipt| now.duration_since(receipt.recorded_at) > DKG_ATTEMPT_TIMEOUT);
        if expired {
            receipts.remove(&attempt);
            return None;
        }
        let receipt = receipts.get_mut(&attempt)?;
        if receipt.processed.contains(&idempotency_key) {
            return Some(false);
        }
        if receipt.processed.len() >= MAX_OFFLINE_RELAY_RECEIPT_PROCESSED_KEYS {
            return None;
        }
        receipt.processed.insert(idempotency_key);
        Some(true)
    }

    /// Record a fresh offline-relay receipt for `attempt`, pruning expired
    /// entries and other attempts of the same ceremony first, then evicting
    /// the oldest entry if the bounded cache is still full.
    pub(crate) async fn record_offline_relay_receipt(
        &self,
        attempt: AttemptKey,
        receipt: DkgOfflineRelayReceipt,
    ) {
        let now = tokio::time::Instant::now();
        let mut receipts = self.offline_relay_receipts.lock().await;
        receipts.retain(|existing, r| {
            now.duration_since(r.recorded_at) <= DKG_ATTEMPT_TIMEOUT
                && (existing.ceremony_id != attempt.ceremony_id
                    || existing.attempt_id == attempt.attempt_id)
        });
        if receipts.len() >= MAX_OFFLINE_RELAY_RECEIPTS {
            if let Some(oldest) = receipts
                .iter()
                .min_by_key(|(_, r)| r.recorded_at)
                .map(|(attempt, _)| *attempt)
            {
                receipts.remove(&oldest);
            }
        }
        receipts.insert(attempt, receipt);
    }

    /// Prune expired terminal-boundary offline-candidate claims. Called once
    /// before a batch of [`SessionStateManager::claim_offline_candidate`] calls
    /// rather than on every call, since the caller iterates a whole candidate set
    /// under one logical dedup pass.
    pub(crate) fn prune_offline_candidate_claims(&self) {
        let now = Instant::now();
        let mut claims = self
            .offline_candidate_dedup
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        claims.retain(|_, recorded_at| now.duration_since(*recorded_at) <= DKG_ATTEMPT_TIMEOUT);
    }

    /// Claim `(ceremony_id, subject)` as an offline-candidate observation.
    /// Returns `true` for a new claim (caller should keep the candidate) or
    /// `false` if it was already claimed recently, refreshing its timestamp
    /// (caller should drop it). Evicts the oldest claim first if the bounded
    /// cache is full.
    pub(crate) fn claim_offline_candidate(&self, ceremony_id: CeremonyId, subject: String) -> bool {
        let now = Instant::now();
        let mut claims = self
            .offline_candidate_dedup
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let key = (ceremony_id, subject);
        if let Some(recorded_at) = claims.get_mut(&key) {
            *recorded_at = now;
            return false;
        }
        if claims.len() >= MAX_OFFLINE_CANDIDATE_CLAIMS {
            if let Some(oldest) = claims
                .iter()
                .min_by_key(|(_, recorded_at)| **recorded_at)
                .map(|(key, _)| key.clone())
            {
                claims.remove(&oldest);
            }
        }
        claims.insert(key, now);
        true
    }

    #[cfg(test)]
    pub(crate) fn offline_candidate_claim_count(&self) -> usize {
        self.offline_candidate_dedup
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    #[cfg(all(test, feature = "fault-injection"))]
    pub(crate) fn offline_candidate_subjects_for_ceremony(&self, ceremony_id: u128) -> Vec<String> {
        self.offline_candidate_dedup
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .keys()
            .filter_map(|(candidate_ceremony, subject)| {
                (candidate_ceremony.0 == ceremony_id).then_some(subject.clone())
            })
            .collect()
    }

    /// Record a follower's signed control-plane ack for `(follower_node_key,
    /// message_kind)` within `attempt`. Returns `Some((existing_digest,
    /// existing_signature))` when a *different* digest was already recorded
    /// for this exact request — provable equivocation — or `None` when this
    /// is either the first sighting (now recorded) or a duplicate of the
    /// already-recorded digest (nothing to do). Also `None` if the attempt no
    /// longer owns the session, matching this call's best-effort semantics.
    pub(crate) async fn record_control_ack(
        &self,
        attempt: AttemptKey,
        follower_node_key: String,
        message_kind: &'static str,
        digest: [u8; 32],
        signature: &ControlSignature,
    ) -> Option<([u8; 32], ControlSignature)> {
        self.with_attempt_state_mut(attempt, |state| {
            let key = (follower_node_key, message_kind);
            match state.transport.control_ack_receipts.get(&key) {
                Some((existing_digest, existing_signature)) if *existing_digest != digest => {
                    Some((*existing_digest, existing_signature.clone()))
                }
                Some(_) => None,
                None => {
                    state
                        .transport
                        .control_ack_receipts
                        .insert(key, (digest, signature.clone()));
                    None
                }
            }
        })
        .await
        .ok()
        .flatten()
    }
}
