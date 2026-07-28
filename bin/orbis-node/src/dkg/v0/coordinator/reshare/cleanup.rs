use std::sync::Arc;

use bulletin::r#trait::{BulletinKind, RingPayload};
use crypto::r#trait::Dkg;

use crate::app_state::AppState;
use crate::constants::{RESHARE_BULLETIN_CONFIRM_POLL_INTERVAL, RESHARE_BULLETIN_CONFIRM_TIMEOUT};

pub fn spawn_bulletin_finalized_cleanup<D>(
    app_state: Arc<AppState<D>>,
    ring_key: Option<String>,
    session_id: u128,
    bulletin_post_id: Option<String>,
    delete_departed_material: bool,
) where
    D: Dkg + Clone + Send + Sync + 'static,
{
    tokio::spawn(async move {
        wait_for_reshare_bulletin_finalized(
            app_state,
            ring_key,
            session_id,
            bulletin_post_id,
            delete_departed_material,
        )
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
    delete_departed_material: bool,
) where
    D: Dkg + Clone + Send + Sync + 'static,
{
    let mut finalized_payload = None;
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
        if delete_departed_material {
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
        }
        app_state.dkg_session_state.unmark_ring_pss(&key).await;
    }
    app_state
        .dkg_session_state
        .complete_session(&session_id)
        .await;
}
