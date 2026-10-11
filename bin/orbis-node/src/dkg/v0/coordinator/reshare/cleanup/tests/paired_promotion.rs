use super::*;

async fn setup_pet(
    name: &str,
    session_id: u128,
) -> (Arc<AppState<DkgImpl>>, ReshareReadinessInfo, String) {
    let (app_state, bulletin, db_path) = setup(name, session_id).await;
    old_bundle()
        .save_by_pet_ring_key(&app_state.local_storage, POST_ID)
        .expect("seed old PET bundle");
    let mut payload = ring_payload(
        vec!["old-a".to_string(), "new-b".to_string()],
        1,
        None,
        None,
    );
    payload.requires_pet = true;
    payload.pet_pk = Some("test-pet-pk".to_string());
    bulletin
        .set_ring(POST_ID.to_string(), payload)
        .expect("seed finalized paired committee");
    let info = ReshareReadinessInfo {
        ready_key: ready_key(session_id),
        expected_new_committee: vec!["old-a".to_string(), "new-b".to_string()],
        expected_new_threshold: 1,
    };
    (app_state, info, db_path)
}

fn pending_pet(info: &ReshareReadinessInfo) -> PendingReshareBundle {
    PendingReshareBundle {
        bundle: staged_new_bundle(),
        bulletin_post_id: POST_ID.to_string(),
        expected_new_committee: info.expected_new_committee.clone(),
        expected_new_threshold: info.expected_new_threshold,
    }
}

fn assert_active_pair(app_state: &AppState<DkgImpl>, polynomial: &str) {
    assert_eq!(disk_bundle(app_state).public_polynomial, polynomial);
    assert_eq!(
        RingShareBundle::load_by_pet_ring_key(&app_state.local_storage, POST_ID)
            .expect("load active PET bundle")
            .public_polynomial,
        polynomial
    );
}

#[tokio::test(start_paused = true)]
async fn confirmation_waits_for_this_members_pet_bundle() {
    let session_id = 9011;
    let (app_state, info, db_path) = setup_pet("reshare_late_pet", session_id).await;
    let pending = pending_pet(&info);
    let cleanup = tokio::spawn(wait_for_reshare_bulletin_finalized(
        app_state.clone(),
        Some(RING_KEY.to_string()),
        AttemptKey::test(session_id),
        Some(POST_ID.to_string()),
        ReshareCleanupOutcome::ContinuingCommittee(info),
    ));
    tokio::task::yield_now().await;
    assert!(
        !cleanup.is_finished(),
        "confirmation must wait for local PET staging"
    );
    assert_active_pair(&app_state, "old-poly");
    assert_pending_bundle_retained(&app_state);

    pending
        .save_pet(&app_state.local_storage, POST_ID)
        .expect("stage late PET bundle");
    cleanup.await.expect("cleanup task");
    assert_active_pair(&app_state, "new-poly");
    assert_pending_bundle_cleared(&app_state);
    assert!(
        PendingReshareBundle::load_pet(&app_state.local_storage, POST_ID)
            .expect("read pending PET bundle")
            .is_none()
    );
    cleanup_db(&db_path);
}

#[tokio::test(start_paused = true)]
async fn unavailable_pet_preserves_both_active_and_pending_main_bundles() {
    let session_id = 9012;
    let (app_state, info, db_path) = setup_pet("reshare_missing_pet", session_id).await;
    wait_for_reshare_bulletin_finalized(
        app_state.clone(),
        Some(RING_KEY.to_string()),
        AttemptKey::test(session_id),
        Some(POST_ID.to_string()),
        ReshareCleanupOutcome::ContinuingCommittee(info),
    )
    .await;
    assert_active_pair(&app_state, "old-poly");
    assert_pending_bundle_retained(&app_state);
    cleanup_db(&db_path);
}

#[tokio::test(start_paused = true)]
async fn unrelated_pet_bundles_cannot_promote_a_confirmed_main_bundle() {
    for mismatch in 0..3 {
        let session_id = 9020 + mismatch;
        let (app_state, info, db_path) =
            setup_pet(&format!("reshare_wrong_pet_{mismatch}"), session_id).await;
        let mut pending = pending_pet(&info);
        match mismatch {
            0 => pending.bulletin_post_id = "different-ring".to_string(),
            1 => pending.expected_new_committee = vec!["different-member".to_string()],
            _ => pending.expected_new_threshold = 2,
        }
        pending
            .save_pet(&app_state.local_storage, POST_ID)
            .expect("seed unrelated pending PET bundle");
        wait_for_reshare_bulletin_finalized(
            app_state.clone(),
            Some(RING_KEY.to_string()),
            AttemptKey::test(session_id),
            Some(POST_ID.to_string()),
            ReshareCleanupOutcome::ContinuingCommittee(info),
        )
        .await;
        assert_active_pair(&app_state, "old-poly");
        assert_pending_bundle_retained(&app_state);
        assert!(
            PendingReshareBundle::load_pet(&app_state.local_storage, POST_ID)
                .expect("read unrelated pending PET bundle")
                .is_some()
        );
        cleanup_db(&db_path);
    }
}
