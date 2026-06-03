use std::sync::Arc;

use bulletin::r#trait::{BulletinKind, RingPayload};
use crypto::r#trait::Dkg;

use crate::app_state::AppState;
use crate::constants::{RESHARE_BULLETIN_CONFIRM_POLL_INTERVAL, RESHARE_BULLETIN_CONFIRM_TIMEOUT};
use crate::metrics;

pub(in crate::dkg::coordinator) fn spawn_bulletin_finalized_cleanup<D>(
    app_state: Arc<AppState<D>>,
    ring_key: Option<String>,
    session_id: u128,
    bulletin_post_id: Option<String>,
) where
    D: Dkg + Clone + Send + Sync + 'static,
{
    tokio::spawn(async move {
        wait_for_reshare_bulletin_finalized(app_state, ring_key, session_id, bulletin_post_id)
            .await;
    });
}

/// Holds the PSS ring claim until node 1 has posted the updated `RingPayload`,
/// then releases the claim and removes the session.
async fn wait_for_reshare_bulletin_finalized<D>(
    app_state: Arc<AppState<D>>,
    ring_key: Option<String>,
    session_id: u128,
    bulletin_post_id: Option<String>,
) where
    D: Dkg + Clone + Send + Sync + 'static,
{
    if let Some(post_id) = bulletin_post_id {
        let deadline = tokio::time::Instant::now() + RESHARE_BULLETIN_CONFIRM_TIMEOUT;
        loop {
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
                    if let Ok(payload) = serde_json::from_slice::<RingPayload>(&post.payload) {
                        if payload.new_peer_node_keys.is_none() && payload.new_threshold.is_none() {
                            tracing::debug!(
                                session_id = session_id,
                                "Reshare: bulletin confirmed updated, releasing PSS claim"
                            );
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
        app_state.dkg_session_state.unmark_ring_pss(&key).await;
    }
    app_state
        .dkg_session_state
        .remove_session(&session_id)
        .await;
    metrics::record_dkg_session_completed();
    metrics::record_reshare_session_completed();
}
