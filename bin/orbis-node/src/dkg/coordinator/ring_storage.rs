use crate::app_state::AppState;
use crate::constants::MAX_LOCAL_RINGS_PER_NODE;
use crate::dkg::error::{DkgError, Result};
use crate::metrics;
use crate::ring_state::RingIndexEntry;
use bulletin::r#trait::{BulletinWriteKind, RingFinalizationPayload};
use crypto::r#trait::Dkg;
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use std::sync::Arc;

use super::{types::CoordinatorDkg, DkgCoordinator};

pub(in crate::dkg::coordinator) async fn cleanup_departing_dealer<D>(
    coord: &DkgCoordinator<D>,
    session_id: u64,
    ring_key: Option<String>,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    if let Some(key) = &ring_key {
        coord
            .app_state
            .local_storage
            .delete(LocalStorageKeys::RingKey(key.clone()))
            .map_err(|e| {
                DkgError::Storage(format!(
                    "Reshare Dealer: failed to delete share bundle for ring {}: {}",
                    key, e
                ))
            })?;

        tracing::info!(
            session_id = session_id,
            ring_key = %key,
            "Reshare Dealer: deleted share bundle - node has left the ring"
        );

        let _guard = coord.app_state.ring_index_lock.lock().await;
        if let Err(e) = remove_ring_index_entry(&coord.app_state.local_storage, key) {
            tracing::error!(
                session_id = session_id,
                ring_key = %key,
                error = %e,
                "Reshare Dealer: failed to remove ring index entry"
            );
            return Err(e);
        }

        // All storage operations succeeded; release the PSS lock so future
        // ceremonies are not blocked by a departed dealer.
        coord.app_state.dkg_session_state.unmark_ring_pss(key).await;
    }

    coord.remove_session(session_id).await;
    metrics::record_dkg_session_completed();
    tracing::info!(
        session_id = session_id,
        "Reshare Dealer: Phase 4 complete (share distribution done, secret deleted)"
    );

    Ok(())
}

pub(in crate::dkg::coordinator) async fn add_ring_index_entry<D>(
    app_state: &Arc<AppState<D>>,
    storage_key: &str,
    bulletin_post_id: String,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let _guard = app_state.ring_index_lock.lock().await;

    let mut ring_index = read_ring_index(&app_state.local_storage, "RingIndex")?;

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

pub(in crate::dkg::coordinator) async fn preflight_new_ring_capacity<D>(
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
pub(in crate::dkg::coordinator) async fn post_fresh_ring_finalization<D>(
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

    coord
        .app_state
        .bulletin
        .post(BulletinWriteKind::Finalize, payload_bytes)
        .await
        .map_err(|e| DkgError::Bulletin(format!("Failed to finalize ring: {}", e)))?;

    tracing::info!(
        ring_pk = %ring_pk,
        ring_id = %ring_id,
        "DKG Coordinator: Successfully confirmed fresh DKG on bulletin"
    );

    Ok(())
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
