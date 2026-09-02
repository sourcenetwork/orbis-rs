use super::*;

impl<D: Dkg + 'static> SessionStateManager<D> {
    /// Store a share whose sender commitment has not arrived yet.
    ///
    /// Returns `Some(true)` when this is the first pending share for the sender,
    /// `Some(false)` when a pending share from that sender already exists, and
    /// `None` when the session is gone.
    #[cfg(test)]
    pub async fn store_pending_share_waiting_for_commitment(
        &self,
        session_id: &u128,
        share: DistributedShare<D::ShareValue>,
        report_evidence: Option<SignedDkgShare>,
    ) -> Option<bool> {
        self.with_state_mut(session_id, |state| {
            let from_node_id = share.from_id;
            if state
                .pending
                .pending_shares_waiting_for_commitment
                .contains_key(&from_node_id)
            {
                return false;
            }
            state.pending.pending_shares_waiting_for_commitment.insert(
                from_node_id,
                PendingDkgShare {
                    share,
                    report_evidence,
                },
            );
            true
        })
        .await
    }

    pub(crate) async fn store_pending_share_for_attempt(
        &self,
        attempt: AttemptKey,
        share: DistributedShare<D::ShareValue>,
        report_evidence: Option<SignedDkgShare>,
    ) -> std::result::Result<bool, AttemptStateError> {
        self.with_attempt_state_mut(attempt, |state| {
            let from_node_id = share.from_id;
            if state
                .pending
                .pending_shares_waiting_for_commitment
                .contains_key(&from_node_id)
            {
                return false;
            }
            state.pending.pending_shares_waiting_for_commitment.insert(
                from_node_id,
                PendingDkgShare {
                    share,
                    report_evidence,
                },
            );
            true
        })
        .await
    }

    /// Remove and return a pending share that was waiting on `from_node_id`'s commitment.
    #[cfg(test)]
    pub async fn take_pending_share_waiting_for_commitment(
        &self,
        session_id: &u128,
        from_node_id: u32,
    ) -> Option<PendingDkgShare<D::ShareValue>> {
        self.with_state_mut(session_id, |s| {
            s.pending
                .pending_shares_waiting_for_commitment
                .remove(&from_node_id)
        })
        .await
        .flatten()
    }

    pub(crate) async fn take_pending_share_for_attempt(
        &self,
        attempt: AttemptKey,
        from_node_id: u32,
    ) -> std::result::Result<Option<PendingDkgShare<D::ShareValue>>, AttemptStateError> {
        self.with_attempt_state_mut(attempt, |state| {
            state
                .pending
                .pending_shares_waiting_for_commitment
                .remove(&from_node_id)
        })
        .await
    }

    #[cfg(test)]
    pub async fn record_commitment_hash(
        &self,
        session_id: &u128,
        from_node_id: u32,
        commitment_hash: [u8; 32],
    ) -> Option<CommitmentHashRecordOutcome> {
        self.with_state_mut(session_id, |state| {
            match state.commit_reveal.received_hashes.get(&from_node_id) {
                Some(existing) if existing == &commitment_hash => {
                    CommitmentHashRecordOutcome::DuplicateSame
                }
                Some(existing) => CommitmentHashRecordOutcome::Mismatch {
                    existing: *existing,
                },
                None => {
                    state
                        .commit_reveal
                        .received_hashes
                        .insert(from_node_id, commitment_hash);
                    CommitmentHashRecordOutcome::Recorded
                }
            }
        })
        .await
    }

    #[cfg(test)]
    pub async fn get_commitment_hash(
        &self,
        session_id: &u128,
        from_node_id: u32,
    ) -> Option<[u8; 32]> {
        self.with_state(session_id, |state| {
            state
                .commit_reveal
                .received_hashes
                .get(&from_node_id)
                .copied()
        })
        .await
        .flatten()
    }

    #[cfg(test)]
    pub async fn mark_commitment_hash_broadcast_complete(&self, session_id: &u128) {
        self.with_state_mut(session_id, |state| {
            state.commit_reveal.own_hash_broadcast_complete = true;
        })
        .await;
    }

    pub(crate) async fn mark_commitment_hash_broadcast_complete_for_attempt(
        &self,
        attempt: AttemptKey,
    ) -> std::result::Result<(), AttemptStateError> {
        self.with_attempt_state_mut(attempt, |state| {
            state.commit_reveal.own_hash_broadcast_complete = true;
        })
        .await
    }

    /// Refresh/reshare only: remember the signed commitment received from `dealer_id`
    /// so it can be revealed if the ceremony later fails an equivocation-consistent check.
    #[cfg(test)]
    pub async fn store_received_commitment(
        &self,
        session_id: &u128,
        dealer_id: u32,
        signed_commitment: SignedDkgCommitment,
    ) {
        self.with_state_mut(session_id, |state| {
            state
                .commitment_audit
                .received_commitments
                .insert(dealer_id, signed_commitment);
        })
        .await;
    }

    /// Snapshot of every signed commitment this node received, for the on-failure
    /// equivocation-audit reveal broadcast.
    #[cfg(test)]
    #[allow(dead_code)]
    pub async fn received_commitments_snapshot(
        &self,
        session_id: &u128,
    ) -> Option<Vec<SignedDkgCommitment>> {
        self.with_state(session_id, |state| {
            state
                .commitment_audit
                .received_commitments
                .values()
                .cloned()
                .collect()
        })
        .await
    }

    /// Compare peer-revealed commitments against what we received: return the first
    /// dealer for which a revealed commitment's bytes differ from ours (equivocation).
    /// Dealers we never received a commitment from are ignored.
    /// Return the two conflicting commitments (`ours`, `reveal`) for the first dealer that
    /// equivocated, so the caller can build an equivocation report. Equivocation requires
    /// the SAME per-attempt nonce with different bytes; a different nonce means an honest
    /// retry (or evasion), not equivocation.
    #[cfg(test)]
    pub async fn find_conflicting_commitment_pair(
        &self,
        session_id: &u128,
        revealed: &[SignedDkgCommitment],
    ) -> Option<(u32, SignedDkgCommitment, SignedDkgCommitment)> {
        self.with_state(session_id, |state| {
            revealed.iter().find_map(|reveal| {
                let dealer_id = reveal.statement.from_node_id;
                let ours = state
                    .commitment_audit
                    .received_commitments
                    .get(&dealer_id)?;
                commitments_prove_equivocation(ours, reveal)
                    .then(|| (dealer_id, ours.clone(), reveal.clone()))
            })
        })
        .await
        .flatten()
    }

    pub(crate) async fn find_conflicting_commitment_pair_for_attempt(
        &self,
        attempt: AttemptKey,
        revealed: &[SignedDkgCommitment],
    ) -> std::result::Result<
        Option<(u32, SignedDkgCommitment, SignedDkgCommitment)>,
        AttemptStateError,
    > {
        self.with_attempt_state(attempt, |state| {
            revealed.iter().find_map(|reveal| {
                let dealer_id = reveal.statement.from_node_id;
                let ours = state
                    .commitment_audit
                    .received_commitments
                    .get(&dealer_id)?;
                commitments_prove_equivocation(ours, reveal)
                    .then(|| (dealer_id, ours.clone(), reveal.clone()))
            })
        })
        .await
    }

    #[cfg(test)]
    pub async fn store_pending_commitment_waiting_for_hash(
        &self,
        session_id: &u128,
        from_node_id: u32,
        commitment: Vec<u8>,
        report_evidence: Option<SignedDkgCommitment>,
    ) -> Option<bool> {
        self.with_state_mut(session_id, |state| {
            if state
                .pending
                .pending_commitments_waiting_for_hash
                .contains_key(&from_node_id)
            {
                return false;
            }
            state.pending.pending_commitments_waiting_for_hash.insert(
                from_node_id,
                PendingDkgCommitment {
                    commitment,
                    report_evidence,
                },
            );
            true
        })
        .await
    }

    #[cfg(test)]
    pub async fn take_pending_commitment_waiting_for_hash(
        &self,
        session_id: &u128,
        from_node_id: u32,
    ) -> Option<PendingDkgCommitment> {
        self.with_state_mut(session_id, |state| {
            state
                .pending
                .pending_commitments_waiting_for_hash
                .remove(&from_node_id)
        })
        .await
        .flatten()
    }

    #[cfg(test)]
    pub async fn update_phase(&self, session_id: &u128, phase: DkgPhase) {
        self.with_state_mut(session_id, |state| {
            state.transition_phase(phase);
        })
        .await;
    }

    pub(crate) async fn update_phase_for_attempt(
        &self,
        attempt: AttemptKey,
        phase: DkgPhase,
    ) -> std::result::Result<(), AttemptStateError> {
        self.with_attempt_state_mut(attempt, |state| {
            state.transition_phase(phase);
        })
        .await
    }

    #[cfg(test)]
    pub async fn increment_commitments(&self, session_id: &u128) {
        self.with_state_mut(session_id, |s| s.commitments_received += 1)
            .await;
    }

    #[cfg(test)]
    pub async fn increment_shares(&self, session_id: &u128) {
        self.with_state_mut(session_id, |s| s.shares_received += 1)
            .await;
    }

    /// Record a successfully verified Phase 2 share from `dealer_id`.
    #[cfg(test)]
    pub async fn record_received_share(&self, session_id: &u128, dealer_id: u32) {
        self.with_state_mut(session_id, |state| {
            if state.commitment_audit.received_shares.insert(dealer_id) {
                state.shares_received += 1;
            }
        })
        .await;
    }

    pub(crate) async fn record_received_share_for_attempt(
        &self,
        attempt: AttemptKey,
        dealer_id: u32,
    ) -> std::result::Result<(), AttemptStateError> {
        self.with_attempt_state_mut(attempt, |state| {
            if state.commitment_audit.received_shares.insert(dealer_id) {
                state.shares_received += 1;
            }
            state.transport.peer_no_progress.remove(&dealer_id);
        })
        .await
    }
}
