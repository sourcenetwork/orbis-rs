use crate::app_state::AppState;
use crate::constants::{
    FINALIZATION_COMPLETION_TIMEOUT, FINALIZATION_PERSISTENCE_RETRY_CAP,
    FINALIZATION_PERSISTENCE_RETRY_INITIAL, FINALIZATION_PERSISTENCE_RETRY_LIMIT,
    FINALIZATION_STATUS_POLL_INTERVAL, MAX_LOCAL_RINGS_PER_NODE,
};
use crate::dkg::v0::error::{DkgError, Result};
use crate::dkg::v0::messages::SessionKind;
use crate::dkg::v0::session_state::DkgPhase;
use crate::helpers::auth::current_unix_time;
use crate::ring_state::RingIndexEntry;
use bulletin::r#trait::{Bulletin, BulletinWriteKind, RingFinalizationPayload};
use crypto::r#trait::Dkg;
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use std::sync::Arc;
use tokio::time::{sleep, Instant};

use super::{types::CoordinatorDkg, DkgCoordinator};

pub async fn cleanup_departing_dealer<D>(
    coord: &DkgCoordinator<D>,
    session_id: u128,
    ring_key: Option<String>,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let bulletin_post_id = coord
        .app_state
        .dkg_session_state
        .with_state(&session_id, |state| {
            state
                .reshare
                .params
                .as_ref()
                .map(|params| params.bulletin_post_id.clone())
                .or_else(|| match &state.kind {
                    SessionKind::Reshare {
                        bulletin_post_id, ..
                    } => Some(bulletin_post_id.clone()),
                    _ => None,
                })
        })
        .await;
    coord
        .app_state
        .dkg_session_state
        .update_phase(&session_id, DkgPhase::Phase4Complete)
        .await;
    super::reshare::cleanup::spawn_bulletin_finalized_cleanup(
        coord.app_state.clone(),
        ring_key,
        session_id,
        bulletin_post_id.flatten(),
        true,
    );
    tracing::info!(
        session_id = session_id,
        "Reshare Dealer: share distribution complete; retaining old material until SourceHub finalization"
    );

    Ok(())
}

pub(crate) async fn delete_departed_ring_material<D>(
    app_state: &Arc<AppState<D>>,
    session_id: u128,
    ring_key: &str,
) -> Result<()>
where
    D: Dkg + Clone + 'static,
{
    let _guard = app_state.ring_index_lock.lock().await;
    app_state
        .local_storage
        .delete(LocalStorageKeys::RingKey(ring_key.to_string()))
        .map_err(|error| {
            DkgError::Storage(format!(
                "Reshare Dealer: failed to delete finalized departed share bundle for ring {ring_key}: {error}"
            ))
        })?;
    remove_ring_index_entry(&app_state.local_storage, ring_key)?;
    tracing::info!(
        session_id,
        ring_key,
        "Reshare Dealer: removed stale material after finalized committee exclusion"
    );
    Ok(())
}

pub async fn add_ring_index_entry<D>(
    app_state: &Arc<AppState<D>>,
    storage_key: &str,
    bulletin_post_id: String,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let _guard = app_state.ring_index_lock.lock().await;

    let mut ring_index = read_ring_index(&app_state.local_storage, "RingIndex")?;
    let now_secs = current_unix_time().map_err(DkgError::SystemTime)?;

    // Upsert: update bulletin_post_id on an existing entry (e.g. DealerReceiver after reshare),
    // or push a new one for first-time entries.
    if let Some(entry) = ring_index.iter_mut().find(|e| e.ring_pk_str == storage_key) {
        entry.bulletin_post_id = bulletin_post_id;
    } else {
        ensure_local_ring_capacity(&ring_index, storage_key)?;
        // This push is where the node's managed-ring count increases:
        // `RingIndex.len()` is the durable count PSS scans and the cap bounds.
        ring_index.push(RingIndexEntry {
            ring_pk_str: storage_key.to_string(),
            bulletin_post_id,
            indexed_at_secs: now_secs,
        });
    }

    let index_bytes = serde_json::to_vec(&ring_index)
        .map_err(|e| DkgError::Serialization(format!("Failed to serialize RingIndex: {}", e)))?;
    app_state
        .local_storage
        .set(LocalStorageKeys::RingIndex, index_bytes)
        .map_err(|e| DkgError::Storage(format!("Failed to store RingIndex: {}", e)))?;

    Ok(())
}

pub async fn preflight_new_ring_capacity<D>(
    app_state: &Arc<AppState<D>>,
    storage_key: &str,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let _guard = app_state.ring_index_lock.lock().await;
    let ring_index = read_ring_index(&app_state.local_storage, "RingIndex")?;
    ensure_local_ring_capacity(&ring_index, storage_key)
}

/// Confirm the completed fresh ring against the pre-created ring on the bulletin.
pub async fn post_fresh_ring_finalization<D>(
    coord: &DkgCoordinator<D>,
    ring_id: &str,
    ring_pk_bytes: &[u8],
) -> Result<()>
where
    D: Dkg + Clone + 'static,
{
    let ring_pk = hex::encode(ring_pk_bytes);

    let payload = RingFinalizationPayload {
        ring_id: ring_id.to_string(),
        ring_pk: ring_pk.clone(),
    };
    let payload_bytes: Vec<u8> = payload.try_into().map_err(|e| {
        DkgError::Serialization(format!(
            "Failed to serialize fresh ring finalization payload: {}",
            e
        ))
    })?;

    let persistence_retries = post_and_verify_fresh_ring_finalization(
        coord.app_state.bulletin.as_ref(),
        &coord.app_state.node_key,
        ring_id,
        &ring_pk,
        payload_bytes,
    )
    .await?;

    tracing::info!(
        ring_pk = %ring_pk,
        ring_id = %ring_id,
        persistence_retries = persistence_retries,
        "DKG Coordinator: Successfully confirmed fresh DKG on bulletin"
    );

    Ok(())
}

async fn post_and_verify_fresh_ring_finalization(
    bulletin: &(dyn Bulletin + Send + Sync),
    node_key: &str,
    ring_id: &str,
    ring_pk: &str,
    payload_bytes: Vec<u8>,
) -> Result<usize> {
    let mut post_error = bulletin
        .post(BulletinWriteKind::Finalize, payload_bytes.clone())
        .await
        .err()
        .map(|e| DkgError::Bulletin(format!("Failed to finalize ring: {}", e)));

    let mut persistence_retries = 0usize;
    let mut status_retries = 0usize;
    let mut retry_delay = FINALIZATION_PERSISTENCE_RETRY_INITIAL;
    let deadline = Instant::now() + FINALIZATION_COMPLETION_TIMEOUT;
    let mut persisted_confirmations = 0usize;
    loop {
        if Instant::now() >= deadline {
            return Err(DkgError::Bulletin(format!(
                "Ring {ring_id} did not collect every FinalizeRing confirmation within {} seconds; last observed {persisted_confirmations} confirmations",
                FINALIZATION_COMPLETION_TIMEOUT.as_secs()
            )));
        }

        match bulletin.ring_finalization_status(ring_id.to_string()).await {
            Ok(status) if status.ring_pk == ring_pk => break,
            Ok(status) if !status.ring_pk.is_empty() => {
                return Err(DkgError::Bulletin(format!(
                    "Ring {ring_id} finalized with conflicting public key {}",
                    status.ring_pk
                )));
            }
            Ok(status) => {
                status_retries = 0;
                let Some(confirmation_node_keys) = status.confirmation_node_keys else {
                    if let Some(error) = post_error {
                        return Err(error);
                    }
                    break;
                };
                persisted_confirmations = confirmation_node_keys.len();

                if confirmation_node_keys
                    .iter()
                    .any(|confirmed_node_key| confirmed_node_key == node_key)
                {
                    // Seeing our own confirmation is not enough. A later concurrent
                    // FinalizeRing transaction can expose an older confirmation set,
                    // so every participant keeps observing the pending ring until the
                    // chain publishes the final public key. If our confirmation
                    // disappears, the next pass reposts the exact same payload.
                    post_error = None;
                    retry_delay = FINALIZATION_PERSISTENCE_RETRY_INITIAL;
                    sleep(FINALIZATION_STATUS_POLL_INTERVAL).await;
                    continue;
                }
                if persistence_retries >= FINALIZATION_PERSISTENCE_RETRY_LIMIT {
                    if let Some(error) = post_error {
                        return Err(error);
                    }
                    return Err(DkgError::Bulletin(format!(
                        "SourceHub did not persist this node's FinalizeRing confirmation for ring {ring_id} after {persistence_retries} retries"
                    )));
                }

                persistence_retries += 1;
                tracing::warn!(
                    ring_id = %ring_id,
                    node_key = %node_key,
                    retry = persistence_retries,
                    persisted_confirmations = confirmation_node_keys.len(),
                    "FinalizeRing transaction succeeded but this node's confirmation is absent on-chain; retrying identical confirmation"
                );
                sleep(retry_delay).await;
                retry_delay = retry_delay
                    .saturating_mul(2)
                    .min(FINALIZATION_PERSISTENCE_RETRY_CAP);
                post_error = bulletin
                    .post(BulletinWriteKind::Finalize, payload_bytes.clone())
                    .await
                    .err()
                    .map(|e| DkgError::Bulletin(format!("Failed to finalize ring: {}", e)));
            }
            Err(error) => {
                if status_retries >= FINALIZATION_PERSISTENCE_RETRY_LIMIT {
                    if let Some(post_error) = post_error {
                        return Err(post_error);
                    }
                    return Err(DkgError::Bulletin(format!(
                        "Failed to verify FinalizeRing persistence for ring {ring_id}: {error}"
                    )));
                }
                status_retries += 1;
                tracing::warn!(
                    ring_id = %ring_id,
                    retry = status_retries,
                    error = %error,
                    "Failed to read FinalizeRing persistence; retrying status query"
                );
                sleep(retry_delay).await;
                retry_delay = retry_delay
                    .saturating_mul(2)
                    .min(FINALIZATION_PERSISTENCE_RETRY_CAP);
            }
        }
    }

    Ok(persistence_retries)
}

fn remove_ring_index_entry(storage: &impl LocalStorage, ring_key: &str) -> Result<()> {
    let mut index = read_ring_index(storage, "Reshare Dealer: RingIndex")?;
    if index.is_empty() {
        return Ok(());
    }

    index.retain(|e| e.ring_pk_str != ring_key);
    let bytes = serde_json::to_vec(&index).map_err(|e| {
        DkgError::Serialization(format!(
            "Reshare Dealer: failed to serialize RingIndex: {}",
            e
        ))
    })?;
    storage
        .set(LocalStorageKeys::RingIndex, bytes)
        .map_err(|e| {
            DkgError::Storage(format!(
                "Reshare Dealer: failed to write updated RingIndex: {}",
                e
            ))
        })
}

fn read_ring_index(storage: &impl LocalStorage, context: &str) -> Result<Vec<RingIndexEntry>> {
    // Fail closed on read/parse errors: silently falling back to an empty Vec
    // would overwrite all existing ring mappings if storage hiccups.
    match storage.get(LocalStorageKeys::RingIndex) {
        Ok(None) => Ok(Vec::new()),
        Ok(Some(bytes)) => serde_json::from_slice(&bytes)
            .map_err(|e| DkgError::Storage(format!("Failed to deserialize {}: {}", context, e))),
        Err(e) => Err(DkgError::Storage(format!(
            "Failed to read {}: {}",
            context, e
        ))),
    }
}

fn ensure_local_ring_capacity(ring_index: &[RingIndexEntry], storage_key: &str) -> Result<()> {
    if ring_index.iter().any(|e| e.ring_pk_str == storage_key) {
        return Ok(());
    }

    if ring_index.len() >= MAX_LOCAL_RINGS_PER_NODE {
        return Err(DkgError::MaxLocalRingsReached {
            current: ring_index.len(),
            max: MAX_LOCAL_RINGS_PER_NODE,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::test_helpers::{cleanup_db, create_test_app_state_default, test_db_path};
    use bulletin::error::BulletinError;
    use bulletin::r#trait::{
        BulletinKind, BulletinPost, BulletinReportSubmission, RingFinalizationStatus,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;

    #[tokio::test]
    async fn departed_bundle_deletion_waits_for_ring_index_lock() {
        let db_name = "departed_bundle_deletion_lock_order";
        let db_path = test_db_path(db_name);
        let state = Arc::new(create_test_app_state_default(db_name).await);
        let ring_key = "departed-ring";
        state
            .local_storage
            .set(
                LocalStorageKeys::RingKey(ring_key.to_string()),
                vec![1, 2, 3],
            )
            .unwrap();
        state
            .local_storage
            .set(
                LocalStorageKeys::RingIndex,
                serde_json::to_vec(&vec![RingIndexEntry {
                    ring_pk_str: ring_key.to_string(),
                    bulletin_post_id: "ring-post".to_string(),
                    indexed_at_secs: 0,
                }])
                .unwrap(),
            )
            .unwrap();

        let ring_index_guard = state.ring_index_lock.clone().lock_owned().await;
        let delete_state = state.clone();
        let deletion =
            tokio::spawn(
                async move { delete_departed_ring_material(&delete_state, 7, ring_key).await },
            );
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert_eq!(
            state
                .local_storage
                .get(LocalStorageKeys::RingKey(ring_key.to_string()))
                .unwrap(),
            Some(vec![1, 2, 3]),
            "bundle deletion must not race ahead of the ring-index lock"
        );

        drop(ring_index_guard);
        deletion.await.unwrap().unwrap();
        assert_eq!(
            state
                .local_storage
                .get(LocalStorageKeys::RingKey(ring_key.to_string()))
                .unwrap(),
            None
        );

        drop(state);
        cleanup_db(&db_path);
    }

    #[derive(Default)]
    struct LostFirstConfirmationBulletin {
        posts: AtomicUsize,
        payloads: Mutex<Vec<Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl Bulletin for LostFirstConfirmationBulletin {
        async fn post(
            &self,
            _kind: BulletinWriteKind,
            payload: Vec<u8>,
        ) -> bulletin::error::Result<String> {
            self.payloads.lock().unwrap().push(payload);
            self.posts.fetch_add(1, Ordering::SeqCst);
            Ok("ring".to_string())
        }

        async fn update(
            &self,
            _id: String,
            _signature_scheme: String,
            _signature: Vec<u8>,
        ) -> bulletin::error::Result<()> {
            Ok(())
        }

        async fn read(
            &self,
            id: String,
            _kind: BulletinKind,
        ) -> bulletin::error::Result<BulletinPost> {
            Err(BulletinError::NotFound { id })
        }

        async fn ring_finalization_status(
            &self,
            _id: String,
        ) -> bulletin::error::Result<RingFinalizationStatus> {
            let persisted = self.posts.load(Ordering::SeqCst) >= 2;
            let confirmation_node_keys = if persisted {
                vec!["node-key".to_string()]
            } else {
                Vec::new()
            };
            Ok(RingFinalizationStatus {
                ring_pk: if persisted {
                    "pk".to_string()
                } else {
                    String::new()
                },
                confirmation_node_keys: Some(confirmation_node_keys),
            })
        }

        async fn submit_report(
            &self,
            _submission: BulletinReportSubmission,
        ) -> bulletin::error::Result<()> {
            Ok(())
        }

        fn chain_id(&self) -> String {
            "test-chain".to_string()
        }

        fn ring_reshare_finalize_sign_bytes(
            &self,
            _chain_id: &str,
            _ring_id: &str,
            _ring_pk: &str,
            _current_ring_sha256: Vec<u8>,
            _finalized_ring_sha256: Vec<u8>,
            _block_number_nonce: u64,
        ) -> bulletin::error::Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }

    #[tokio::test]
    async fn retries_identical_finalization_when_successful_write_is_absent() {
        let bulletin = LostFirstConfirmationBulletin::default();
        let payload = br#"{"ring_id":"ring","ring_pk":"pk"}"#.to_vec();

        let retries = post_and_verify_fresh_ring_finalization(
            &bulletin,
            "node-key",
            "ring",
            "pk",
            payload.clone(),
        )
        .await
        .unwrap();

        assert_eq!(retries, 1);
        let payloads = bulletin.payloads.lock().unwrap();
        assert_eq!(payloads.len(), 2);
        assert_eq!(payloads[0], payload);
        assert_eq!(payloads[1], payload);
    }

    #[derive(Default)]
    struct OverwrittenConfirmationBulletin {
        posts: AtomicUsize,
        status_reads: AtomicUsize,
        payloads: Mutex<Vec<Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl Bulletin for OverwrittenConfirmationBulletin {
        async fn post(
            &self,
            _kind: BulletinWriteKind,
            payload: Vec<u8>,
        ) -> bulletin::error::Result<String> {
            self.payloads.lock().unwrap().push(payload);
            self.posts.fetch_add(1, Ordering::SeqCst);
            Ok("ring".to_string())
        }

        async fn update(
            &self,
            _id: String,
            _signature_scheme: String,
            _signature: Vec<u8>,
        ) -> bulletin::error::Result<()> {
            Ok(())
        }

        async fn read(
            &self,
            id: String,
            _kind: BulletinKind,
        ) -> bulletin::error::Result<BulletinPost> {
            Err(BulletinError::NotFound { id })
        }

        async fn ring_finalization_status(
            &self,
            _id: String,
        ) -> bulletin::error::Result<RingFinalizationStatus> {
            let read = self.status_reads.fetch_add(1, Ordering::SeqCst);
            let posts = self.posts.load(Ordering::SeqCst);
            Ok(match (read, posts) {
                // The first transaction appears persisted, then is overwritten
                // by a concurrent stale confirmation set.
                (0, _) => RingFinalizationStatus {
                    ring_pk: String::new(),
                    confirmation_node_keys: Some(vec!["node-key".to_string()]),
                },
                (_, 1) => RingFinalizationStatus {
                    ring_pk: String::new(),
                    confirmation_node_keys: Some(Vec::new()),
                },
                _ => RingFinalizationStatus {
                    ring_pk: "pk".to_string(),
                    confirmation_node_keys: Some(vec!["node-key".to_string()]),
                },
            })
        }

        async fn submit_report(
            &self,
            _submission: BulletinReportSubmission,
        ) -> bulletin::error::Result<()> {
            Ok(())
        }

        fn chain_id(&self) -> String {
            "test-chain".to_string()
        }

        fn ring_reshare_finalize_sign_bytes(
            &self,
            _chain_id: &str,
            _ring_id: &str,
            _ring_pk: &str,
            _current_ring_sha256: Vec<u8>,
            _finalized_ring_sha256: Vec<u8>,
            _block_number_nonce: u64,
        ) -> bulletin::error::Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }

    #[tokio::test]
    async fn reposts_identical_finalization_if_a_visible_confirmation_disappears() {
        let bulletin = OverwrittenConfirmationBulletin::default();
        let payload = br#"{"ring_id":"ring","ring_pk":"pk"}"#.to_vec();

        let retries = post_and_verify_fresh_ring_finalization(
            &bulletin,
            "node-key",
            "ring",
            "pk",
            payload.clone(),
        )
        .await
        .unwrap();

        assert_eq!(retries, 1);
        let payloads = bulletin.payloads.lock().unwrap();
        assert_eq!(payloads.as_slice(), [payload.clone(), payload].as_slice());
    }
}
