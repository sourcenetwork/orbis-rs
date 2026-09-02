use super::*;

impl<D: Dkg + 'static> SessionStateManager<D> {
    /// Atomically claim the active PSS session for a ring.
    ///
    /// This lets concurrent refresh/reshare starters converge on one session ID:
    /// callers racing to start the same deterministic session get
    /// `AlreadyClaimedBySameSession`, while genuinely conflicting ceremonies get
    /// `Conflict`.
    #[cfg(test)]
    pub async fn claim_ring_pss_session(
        &self,
        ring_pk_hex: &str,
        session_id: u128,
    ) -> RingPssClaimOutcome {
        let mut claims = self.rings_pss.write().await;
        match claims.get(ring_pk_hex).copied() {
            None => {
                claims.insert(
                    ring_pk_hex.to_string(),
                    RingPssOwner {
                        session_id,
                        attempt_id: None,
                    },
                );
                RingPssClaimOutcome::Claimed
            }
            Some(existing) if existing.session_id == session_id => {
                RingPssClaimOutcome::AlreadyClaimedBySameSession
            }
            Some(existing) => RingPssClaimOutcome::Conflict {
                active_session_id: existing.session_id,
            },
        }
    }

    pub(crate) async fn claim_ring_pss_attempt(
        &self,
        ring_pk_hex: &str,
        attempt: AttemptKey,
    ) -> RingPssClaimOutcome {
        let owner = RingPssOwner {
            session_id: attempt.session_id(),
            attempt_id: Some(attempt.attempt_id),
        };
        let mut claims = self.rings_pss.write().await;
        match claims.get(ring_pk_hex).copied() {
            None => {
                claims.insert(ring_pk_hex.to_string(), owner);
                RingPssClaimOutcome::Claimed
            }
            Some(existing) if existing == owner => RingPssClaimOutcome::AlreadyClaimedBySameSession,
            // Upgrade a pre-transport deterministic claim to the concrete
            // attempt that now owns it.
            Some(existing)
                if existing.session_id == owner.session_id && existing.attempt_id.is_none() =>
            {
                claims.insert(ring_pk_hex.to_string(), owner);
                RingPssClaimOutcome::AlreadyClaimedBySameSession
            }
            Some(existing) => RingPssClaimOutcome::Conflict {
                active_session_id: existing.session_id,
            },
        }
    }

    /// Returns `true` if a PSS ceremony is currently in progress for this ring.
    pub async fn is_ring_pss_active(&self, ring_pk_key: &str) -> bool {
        self.rings_pss.read().await.contains_key(ring_pk_key)
    }

    /// Return the deterministic session currently claiming this ring, if any.
    /// The production scheduler uses this to distinguish a new refresh from a
    /// harmless tick that observes the already-active attempt.
    pub async fn active_ring_pss_session(&self, ring_pk_key: &str) -> Option<u128> {
        self.rings_pss
            .read()
            .await
            .get(ring_pk_key)
            .map(|owner| owner.session_id)
    }

    /// Mark one exact reshare bulletin update as ready to sign, already
    /// promoted (bundle on disk) — test-only convenience for tests that only
    /// care about readiness/key lifecycle, not the staged-material path.
    #[cfg(test)]
    pub async fn mark_reshare_signature_ready(&self, key: ReshareSignatureReadyKey) {
        self.reshare_signature_ready.write().await.insert(
            key,
            ReshareSignatureReadyMaterial::Promoted {
                marked_at: Instant::now(),
            },
        );
    }

    /// Mark one exact reshare bulletin update as ready to sign, staging
    /// `bundle` (the newly computed, not-yet-persisted share) as the material
    /// co-signers should sign with until this node's own bulletin-confirmation
    /// poll promotes it to disk.
    pub(crate) async fn mark_reshare_signature_ready_for_attempt(
        &self,
        attempt: AttemptKey,
        key: ReshareSignatureReadyKey,
        bundle: RingShareBundle,
    ) -> bool {
        if self.with_attempt_state(attempt, |_| ()).await.is_err() {
            return false;
        }
        self.reshare_signature_ready.write().await.insert(
            key.clone(),
            ReshareSignatureReadyMaterial::Staged {
                bundle,
                marked_at: Instant::now(),
            },
        );
        if self.with_attempt_state(attempt, |_| ()).await.is_ok() {
            true
        } else {
            self.reshare_signature_ready.write().await.remove(&key);
            false
        }
    }

    /// Returns true iff this node has locally completed the exact reshare update.
    #[cfg(test)]
    pub async fn is_reshare_signature_ready(&self, key: &ReshareSignatureReadyKey) -> bool {
        self.reshare_signature_ready.read().await.contains_key(key)
    }

    /// Returns the share material to sign a reshare finalize statement with,
    /// matched without requiring the live transport attempt to still exist.
    /// The bulletin pre/post-state hashes already bind readiness to one exact
    /// ceremony result (see [`ReshareSignatureReadyKey`]'s docs), so a late or
    /// retried sign request does not need to look up an `attempt_id` via
    /// `transport_attempt` — which may already be gone once this node's own
    /// ceremony work finished successfully and its transport attempt was
    /// cleaned up.
    ///
    /// Returns `None` if no marker matches (not ready — caller should treat
    /// this as `ReshareInProgress`). Returns `Some(None)` if a marker matches
    /// but the bundle has already been promoted to disk (caller should read
    /// disk). Returns `Some(Some(bundle))` if a marker matches and the bundle
    /// is still only staged (caller must sign with `bundle`, not disk — disk
    /// still holds the old, pre-reshare share).
    pub(crate) async fn reshare_signature_ready_material(
        &self,
        ring_key: &str,
        session_id: u128,
        ring_id: &str,
        current_ring_sha256: &str,
        finalized_ring_sha256: &str,
    ) -> Option<Option<RingShareBundle>> {
        self.reshare_signature_ready
            .read()
            .await
            .iter()
            .find(|(key, _)| {
                key.ring_key == ring_key
                    && key.session_id == session_id
                    && key.ring_id == ring_id
                    && key.current_ring_sha256 == current_ring_sha256
                    && key.finalized_ring_sha256 == finalized_ring_sha256
            })
            .map(|(_, material)| match material {
                ReshareSignatureReadyMaterial::Staged { bundle, .. } => Some(bundle.clone()),
                ReshareSignatureReadyMaterial::Promoted { .. } => None,
            })
    }

    /// Clone out the staged bundle for `key`, if any, without mutating the
    /// map. Used by `wait_for_reshare_bulletin_finalized` to obtain the bytes
    /// to write to disk; the entry is only flipped to `Promoted` afterward,
    /// via `mark_reshare_promoted`, once that write has actually succeeded —
    /// so a disk-write failure never loses the only copy of the material.
    pub(crate) async fn peek_staged_reshare_bundle(
        &self,
        key: &ReshareSignatureReadyKey,
    ) -> Option<RingShareBundle> {
        match self.reshare_signature_ready.read().await.get(key)? {
            ReshareSignatureReadyMaterial::Staged { bundle, .. } => Some(bundle.clone()),
            ReshareSignatureReadyMaterial::Promoted { .. } => None,
        }
    }

    /// Flip `key`'s material from `Staged` to `Promoted` after its bundle has
    /// been successfully written to disk. The entry itself is kept (not
    /// removed) so a late/retried finalize-sign request continues to
    /// authorize and correctly falls back to disk.
    pub(crate) async fn mark_reshare_promoted(&self, key: &ReshareSignatureReadyKey) {
        let mut ready = self.reshare_signature_ready.write().await;
        if let Some(material) = ready.get(key) {
            let marked_at = material.marked_at();
            ready.insert(
                key.clone(),
                ReshareSignatureReadyMaterial::Promoted { marked_at },
            );
        }
    }

    /// Clear the in-progress PSS claim for a ring (called on setup failure before a
    /// session exists, or when force-clearing state).
    #[cfg(test)]
    pub async fn unmark_ring_pss(&self, ring_pk_hex: &str) {
        self.rings_pss.write().await.remove(ring_pk_hex);
    }

    /// Clear the in-progress PSS claim only if this exact session still owns it.
    pub async fn unmark_ring_pss_if_matches(&self, ring_pk_hex: &str, session_id: u128) {
        let mut claims = self.rings_pss.write().await;
        if claims
            .get(ring_pk_hex)
            .is_some_and(|owner| owner.session_id == session_id)
        {
            claims.remove(ring_pk_hex);
        }
    }

    pub(crate) async fn unmark_ring_pss_for_attempt(&self, ring_pk_hex: &str, attempt: AttemptKey) {
        let mut claims = self.rings_pss.write().await;
        if claims.get(ring_pk_hex).copied()
            == Some(RingPssOwner {
                session_id: attempt.session_id(),
                attempt_id: Some(attempt.attempt_id),
            })
        {
            claims.remove(ring_pk_hex);
        }
    }
}
