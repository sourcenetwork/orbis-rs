use std::sync::Arc;

use bulletin::r#trait::{BulletinKind, RingPayload};
use crypto::r#trait::Dkg;

use crate::app_state::AppState;
use crate::constants::{RESHARE_BULLETIN_CONFIRM_POLL_INTERVAL, RESHARE_BULLETIN_CONFIRM_TIMEOUT};
use crate::dkg::v0::helpers::peer_node_keys_match;
use crate::dkg::v0::session_state::TopicTaskDisposition;
use crate::dkg::v0::transport::AttemptKey;

use super::bulletin_update::ReshareReadinessInfo;

/// What kind of node is waiting for this reshare to finalize on the bulletin,
/// and what it should do once that's observed (or times out).
pub(crate) enum ReshareCleanupOutcome {
    /// A pure old-committee node being replaced out. Its old material is
    /// deleted once its exclusion from the finalized committee is confirmed
    /// — unaffected by this fix, unchanged from the prior behavior.
    DepartingDealer,
    /// A continuing or newly-joining member of the new committee, holding a
    /// staged (not-yet-persisted) `RingShareBundle`. Promoted to disk only if
    /// the bulletin confirms with exactly the expected new committee/threshold;
    /// otherwise discarded without ever touching disk.
    ContinuingCommittee(ReshareReadinessInfo),
}

pub fn spawn_bulletin_finalized_cleanup<D>(
    app_state: Arc<AppState<D>>,
    ring_key: Option<String>,
    attempt: AttemptKey,
    bulletin_post_id: Option<String>,
    outcome: ReshareCleanupOutcome,
) where
    D: Dkg + Clone + Send + Sync + 'static,
{
    tokio::spawn(async move {
        wait_for_reshare_bulletin_finalized(
            app_state,
            ring_key,
            attempt,
            bulletin_post_id,
            outcome,
        )
        .await;
    });
}

/// Holds the PSS ring claim until node 1 has posted the updated `RingPayload`,
/// then releases the claim and removes the session.
async fn wait_for_reshare_bulletin_finalized<D>(
    app_state: Arc<AppState<D>>,
    ring_key: Option<String>,
    attempt: AttemptKey,
    bulletin_post_id: Option<String>,
    outcome: ReshareCleanupOutcome,
) where
    D: Dkg + Clone + Send + Sync + 'static,
{
    let session_id = attempt.session_id();
    let mut finalized_payload = None;
    if let Some(post_id) = bulletin_post_id {
        let deadline = tokio::time::Instant::now() + RESHARE_BULLETIN_CONFIRM_TIMEOUT;
        loop {
            if app_state
                .dkg_session_state
                .with_attempt_state(attempt, |_| ())
                .await
                .is_err()
            {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                tracing::warn!(
                    session_id = session_id,
                    "Reshare: timed out waiting for bulletin confirmation, releasing PSS claim"
                );
                break;
            }
            match app_state
                .bulletin
                .read(post_id.clone(), BulletinKind::Ring)
                .await
            {
                Ok(post) => {
                    if let Ok(payload) = serde_json::from_slice::<RingPayload>(&post.payload)
                        .inspect_err(|error| {
                            tracing::warn!(
                                session_id = session_id,
                                error = %error,
                                "Reshare: failed to deserialize bulletin payload while waiting for confirmation"
                            );
                        })
                    {
                        if payload.new_peer_node_keys.is_none() && payload.new_threshold.is_none() {
                            tracing::debug!(
                                session_id = session_id,
                                "Reshare: bulletin confirmed updated, releasing PSS claim"
                            );
                            finalized_payload = Some(payload);
                            break;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        session_id = session_id,
                        error = %e,
                        "Reshare: failed to read bulletin while waiting for confirmation"
                    );
                }
            }
            tokio::time::sleep(RESHARE_BULLETIN_CONFIRM_POLL_INTERVAL).await;
        }
    }

    if let Some(key) = ring_key {
        if app_state
            .dkg_session_state
            .with_attempt_state(attempt, |_| ())
            .await
            .is_err()
        {
            return;
        }
        match outcome {
            ReshareCleanupOutcome::DepartingDealer => {
                let finalized_exclusion = finalized_payload.as_ref().is_some_and(|payload| {
                    !payload
                        .peer_node_keys
                        .iter()
                        .any(|node_key| node_key == &app_state.node_key)
                });
                if finalized_exclusion {
                    if let Err(error) = super::super::ring_storage::delete_departed_ring_material(
                        &app_state, session_id, &key,
                    )
                    .await
                    {
                        tracing::error!(
                            session_id,
                            ring_key = %key,
                            %error,
                            "Reshare Dealer: failed finalized stale-material cleanup"
                        );
                    }
                } else {
                    tracing::warn!(
                        session_id,
                        ring_key = %key,
                        "Reshare Dealer: final committee exclusion was not observed; preserving old material"
                    );
                }
                app_state
                    .dkg_session_state
                    .unmark_ring_pss_for_attempt(&key, attempt)
                    .await;
                app_state
                    .dkg_session_state
                    .complete_transport_attempt(attempt, TopicTaskDisposition::DetachCurrent)
                    .await;
            }
            ReshareCleanupOutcome::ContinuingCommittee(info) => {
                // Both a successful finalize AND a (future) cancel clear
                // `new_peer_node_keys`/`new_threshold` identically — the only
                // way to tell them apart is whether the resulting committee
                // and threshold actually match what this node staged.
                let should_promote = finalized_payload.as_ref().is_some_and(|payload| {
                    peer_node_keys_match(&payload.peer_node_keys, &info.expected_new_committee)
                        && payload.threshold == info.expected_new_threshold
                });
                if should_promote {
                    match app_state
                        .dkg_session_state
                        .peek_staged_reshare_bundle(&info.ready_key)
                        .await
                    {
                        Some(bundle) => {
                            match bundle.save_by_ring_key(&app_state.local_storage, &key) {
                                Ok(()) => {
                                    app_state
                                        .dkg_session_state
                                        .mark_reshare_promoted(&info.ready_key)
                                        .await;
                                    tracing::info!(
                                        session_id,
                                        ring_key = %key,
                                        "Reshare: promoted staged bundle after chain confirmation"
                                    );
                                }
                                Err(error) => {
                                    // Chain confirmed the reshare, but the local write failed:
                                    // this node is now locally-stale-but-chain-confirmed. No
                                    // automatic retry — matches the existing Fresh-DKG precedent
                                    // of preferring a diagnosable gap over new retry machinery.
                                    // The map entry is deliberately left `Staged` (not marked
                                    // promoted) so this isn't silently reported as resolved.
                                    tracing::error!(
                                        session_id,
                                        ring_key = %key,
                                        %error,
                                        "Reshare: chain confirmed but writing the promoted bundle to \
                                         local storage failed; this node's local share is now stale \
                                         relative to the chain-recognized committee. Operator \
                                         investigation required."
                                    );
                                }
                            }
                        }
                        None => {
                            tracing::error!(
                                session_id,
                                ring_key = %key,
                                "Reshare: chain confirmed but no staged bundle was found to \
                                 promote (already promoted, or an internal invariant was violated)"
                            );
                        }
                    }
                } else {
                    tracing::warn!(
                        session_id,
                        ring_key = %key,
                        "Reshare: bulletin confirmation did not match this node's expected new \
                         committee/threshold (or timed out); discarding staged bundle, old share \
                         on disk is preserved"
                    );
                }
                app_state
                    .dkg_session_state
                    .unmark_ring_pss_for_attempt(&key, attempt)
                    .await;
                if should_promote {
                    app_state
                        .dkg_session_state
                        .complete_transport_attempt(attempt, TopicTaskDisposition::DetachCurrent)
                        .await;
                } else {
                    // completed=false reuses `finish_removed_session`'s existing prune of
                    // this exact `reshare_signature_ready` entry, and correctly records
                    // this outcome as abandoned rather than completed in metrics.
                    app_state
                        .dkg_session_state
                        .abort_transport_attempt(attempt, TopicTaskDisposition::DetachCurrent)
                        .await;
                }
            }
        }
        return;
    }
    app_state
        .dkg_session_state
        .complete_transport_attempt(attempt, TopicTaskDisposition::DetachCurrent)
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::v0::session_state::ReshareSignatureReadyKey;
    use crate::helpers::test_helpers::{
        cleanup_db, create_test_app_state_with_bulletin, test_db_path,
    };
    use crate::ring_state::RingShareBundle;
    use bulletin::dummy::DummyBulletin;
    use crypto::r#trait::DkgRole;
    use crypto::DkgImpl;
    use zeroize::Zeroizing;

    const RING_KEY: &str = "test-ring-pk";
    const POST_ID: &str = "test-ring-post";

    fn old_bundle() -> RingShareBundle {
        RingShareBundle {
            share_bytes: Zeroizing::new(vec![1, 1, 1]),
            public_polynomial: "old-poly".to_string(),
            last_pss: 1,
        }
    }

    fn staged_new_bundle() -> RingShareBundle {
        RingShareBundle {
            share_bytes: Zeroizing::new(vec![2, 2, 2]),
            public_polynomial: "new-poly".to_string(),
            last_pss: 2,
        }
    }

    fn ready_key(session_id: u128) -> ReshareSignatureReadyKey {
        ReshareSignatureReadyKey {
            ring_key: RING_KEY.to_string(),
            session_id,
            attempt_id: AttemptKey::test(session_id).attempt_id,
            ring_id: POST_ID.to_string(),
            current_ring_sha256: "current".to_string(),
            finalized_ring_sha256: "finalized".to_string(),
        }
    }

    fn ring_payload(
        peer_node_keys: Vec<String>,
        threshold: u32,
        new_peer_node_keys: Option<Vec<String>>,
        new_threshold: Option<u32>,
    ) -> RingPayload {
        RingPayload {
            upgrade_info: Default::default(),
            ring_pk: RING_KEY.to_string(),
            peer_node_keys,
            new_peer_node_keys,
            new_threshold,
            threshold,
            pss_interval: 0,
            block_number_nonce: 0,
            policy_id: None,
            trusted_auth_relay_dids: None,
            reporting: Default::default(),
        }
    }

    /// Builds a live, attempt-registered session with `staged_new_bundle()`
    /// already staged under `ready_key(session_id)`, and `old_bundle()`
    /// pre-seeded on disk under `RING_KEY` — mirroring exactly the state a
    /// continuing (DealerReceiver) node is in right after Phase 4 stages its
    /// new share but before chain confirmation. Returns the concrete
    /// `DummyBulletin` handle too, so tests can seed `RingPayload`s directly
    /// via `set_ring` (the trait-object `AppState::bulletin` field doesn't
    /// expose that test-only method).
    async fn setup(
        db_name: &str,
        session_id: u128,
    ) -> (Arc<AppState<DkgImpl>>, Arc<DummyBulletin>, String) {
        let db_path = test_db_path(db_name);
        let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("dummy bulletin"));
        let app_state = Arc::new(
            create_test_app_state_with_bulletin(true, dummy_bulletin.clone(), db_name).await,
        );

        let attempt = AttemptKey::test(session_id);
        let node = *DkgImpl::new(1, 1, 2, 0, DkgRole::DealerReceiver)
            .expect("construct DealerReceiver DkgImpl for test session");
        assert_eq!(
            app_state
                .dkg_session_state
                .create_session(session_id, node, 2, |state| {
                    state.transport.ceremony_id = Some(attempt.ceremony_id);
                    state.transport.attempt_id = Some(attempt.attempt_id);
                })
                .await,
            crate::dkg::v0::session_state::CreateSessionOutcome::Created
        );

        old_bundle()
            .save_by_ring_key(&app_state.local_storage, RING_KEY)
            .expect("seed old bundle on disk");

        let key = ready_key(session_id);
        assert!(
            app_state
                .dkg_session_state
                .mark_reshare_signature_ready_for_attempt(attempt, key, staged_new_bundle())
                .await,
            "staging the new bundle against a live attempt must succeed"
        );

        (app_state, dummy_bulletin, db_path)
    }

    fn disk_bundle(app_state: &AppState<DkgImpl>) -> RingShareBundle {
        RingShareBundle::load_by_ring_key(&app_state.local_storage, RING_KEY)
            .expect("bundle must still be present on disk")
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_discards_staged_bundle_and_preserves_old_one() {
        let session_id = 9001;
        let (app_state, dummy_bulletin, db_path) =
            setup("reshare_cleanup_timeout_discard", session_id).await;
        let attempt = AttemptKey::test(session_id);

        // The bulletin never clears new_peer_node_keys/new_threshold — this
        // reshare simply never gets chain-confirmed within the timeout.
        dummy_bulletin
            .set_ring(
                POST_ID.to_string(),
                ring_payload(
                    vec!["old-a".to_string()],
                    1,
                    Some(vec!["old-a".to_string(), "new-b".to_string()]),
                    Some(1),
                ),
            )
            .expect("seed pending ring payload");

        let info = ReshareReadinessInfo {
            ready_key: ready_key(session_id),
            expected_new_committee: vec!["old-a".to_string(), "new-b".to_string()],
            expected_new_threshold: 1,
        };
        wait_for_reshare_bulletin_finalized(
            app_state.clone(),
            Some(RING_KEY.to_string()),
            attempt,
            Some(POST_ID.to_string()),
            ReshareCleanupOutcome::ContinuingCommittee(info.clone()),
        )
        .await;

        assert_eq!(disk_bundle(&app_state).public_polynomial, "old-poly");
        assert!(
            app_state
                .dkg_session_state
                .reshare_signature_ready_material(
                    &info.ready_key.ring_key,
                    info.ready_key.session_id,
                    &info.ready_key.ring_id,
                    &info.ready_key.current_ring_sha256,
                    &info.ready_key.finalized_ring_sha256,
                )
                .await
                .is_none(),
            "a discarded (timed-out) marker must not authorize a later sign request"
        );

        cleanup_db(&db_path);
    }

    #[tokio::test]
    async fn mismatched_confirmation_discards_staged_bundle_and_preserves_old_one() {
        let session_id = 9002;
        let (app_state, dummy_bulletin, db_path) =
            setup("reshare_cleanup_mismatch_discard", session_id).await;
        let attempt = AttemptKey::test(session_id);

        // Bulletin clears the pending fields, but reverts to the OLD
        // committee — exactly what a cancel (or a superseded reshare) would
        // produce. This must resolve on the very first poll, no timeout wait.
        dummy_bulletin
            .set_ring(
                POST_ID.to_string(),
                ring_payload(vec!["old-a".to_string()], 1, None, None),
            )
            .expect("seed cancelled-back-to-old ring payload");

        let info = ReshareReadinessInfo {
            ready_key: ready_key(session_id),
            expected_new_committee: vec!["old-a".to_string(), "new-b".to_string()],
            expected_new_threshold: 1,
        };
        wait_for_reshare_bulletin_finalized(
            app_state.clone(),
            Some(RING_KEY.to_string()),
            attempt,
            Some(POST_ID.to_string()),
            ReshareCleanupOutcome::ContinuingCommittee(info),
        )
        .await;

        assert_eq!(disk_bundle(&app_state).public_polynomial, "old-poly");

        cleanup_db(&db_path);
    }

    #[tokio::test]
    async fn matching_confirmation_promotes_staged_bundle() {
        let session_id = 9003;
        let (app_state, dummy_bulletin, db_path) =
            setup("reshare_cleanup_promote", session_id).await;
        let attempt = AttemptKey::test(session_id);

        dummy_bulletin
            .set_ring(
                POST_ID.to_string(),
                ring_payload(
                    vec!["old-a".to_string(), "new-b".to_string()],
                    1,
                    None,
                    None,
                ),
            )
            .expect("seed confirmed new-committee ring payload");

        let info = ReshareReadinessInfo {
            ready_key: ready_key(session_id),
            expected_new_committee: vec!["old-a".to_string(), "new-b".to_string()],
            expected_new_threshold: 1,
        };
        wait_for_reshare_bulletin_finalized(
            app_state.clone(),
            Some(RING_KEY.to_string()),
            attempt,
            Some(POST_ID.to_string()),
            ReshareCleanupOutcome::ContinuingCommittee(info.clone()),
        )
        .await;

        assert_eq!(disk_bundle(&app_state).public_polynomial, "new-poly");

        // A late/retried co-signer request for the same statement must still
        // authorize after promotion, now correctly falling back to disk.
        let material = app_state
            .dkg_session_state
            .reshare_signature_ready_material(
                &info.ready_key.ring_key,
                info.ready_key.session_id,
                &info.ready_key.ring_id,
                &info.ready_key.current_ring_sha256,
                &info.ready_key.finalized_ring_sha256,
            )
            .await
            .expect("promoted marker must still authorize a late sign request");
        assert!(
            material.is_none(),
            "a promoted marker must signal disk fallback, not a stale staged bundle"
        );

        cleanup_db(&db_path);
    }
}
