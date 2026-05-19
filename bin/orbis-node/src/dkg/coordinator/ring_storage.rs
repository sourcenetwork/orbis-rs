use crate::app_state::AppState;
use crate::constants::MAX_LOCAL_RINGS_PER_NODE;
use crate::dkg::error::{DkgError, Result};
use crate::metrics;
use crate::ring_state::RingIndexEntry;
use bulletin::r#trait::RingPayload;
use crypto::r#trait::Dkg;
use crypto::{CryptoSerialize, GroupAffine as G1Affine};
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
    bulletin_namespace: String,
) -> Result<()>
where
    D: CoordinatorDkg,
{
    let _guard = app_state.ring_index_lock.lock().await;

    let mut ring_index = read_ring_index(&app_state.local_storage, "RingIndex")?;

    // Upsert: update bulletin_post_id and bulletin_namespace on an existing entry
    // (e.g. DealerReceiver after reshare), or push a new one for first-time entries.
    if let Some(entry) = ring_index.iter_mut().find(|e| e.ring_pk_str == storage_key) {
        entry.bulletin_post_id = bulletin_post_id;
        entry.bulletin_namespace = bulletin_namespace;
    } else {
        ensure_local_ring_capacity(&ring_index, storage_key)?;
        // This push is where the node's managed-ring count increases:
        // `RingIndex.len()` is the durable count PSS scans and the cap bounds.
        ring_index.push(RingIndexEntry {
            ring_pk_str: storage_key.to_string(),
            bulletin_post_id,
            bulletin_namespace,
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

/// Post the fresh ring payload to the bulletin and return the chain-assigned ring_id.
///
/// Uses [`Bulletin::post_ring`] which, for `SourceHubBulletin`, decodes the ring_id
/// directly from the `MsgCreateRingResponse` ABCI data rather than recomputing it
/// locally — guaranteeing that the stored `bulletin_post_id` matches the chain's ID.
pub(in crate::dkg::coordinator) async fn post_fresh_ring_payload<D>(
    coord: &DkgCoordinator<D>,
    session_id: u64,
    ring_pk_bytes: &[u8],
    threshold: usize,
    pss_interval: Option<u64>,
    policy_id: Option<String>,
    bulletin_namespace: &str,
) -> Result<String>
where
    D: Dkg + Clone + 'static,
{
    let peer_ids = coord
        .app_state
        .dkg_session_state
        .get_peer_ids(&session_id)
        .await
        .ok_or(DkgError::Generic("Failed to get peer ids".to_string()))?;

    let ring_payload = RingPayload {
        ring_pk: hex::encode(ring_pk_bytes),
        peer_ids,
        new_peer_ids: None,
        new_threshold: None,
        threshold: threshold as u32,
        pss_interval,
        policy_id,
        // setting to 0 is fine since 0 can act as the first nonce, subsequent nonces set on update
        block_number_nonce: 0,
    };

    let payload_bytes: Vec<u8> = ring_payload
        .clone()
        .try_into()
        .map_err(|e| DkgError::Serialization(format!("Failed to serialize RingPayload: {}", e)))?;

    let ring_id = coord
        .app_state
        .bulletin
        .post_ring(
            bulletin_namespace.to_string(),
            payload_bytes,
            Some(session_id.to_string()),
        )
        .await
        .map_err(|e| DkgError::Bulletin(format!("Failed to post RingPayload: {}", e)))?;

    tracing::info!(
        ring_pk = %ring_payload.ring_pk,
        ring_id = %ring_id,
        namespace = bulletin_namespace,
        "DKG Coordinator: Successfully posted RingPayload to bulletin"
    );

    Ok(ring_id)
}

pub(in crate::dkg::coordinator) fn fresh_ring_index_post_id<D>(
    app_state: &AppState<D>,
    aggregate_pk: &G1Affine,
    peer_ids: Vec<String>,
    threshold: usize,
    pss_interval: Option<u64>,
    policy_id: Option<String>,
    bulletin_namespace: &str,
) -> Result<String>
where
    D: Dkg + Clone + 'static,
{
    let ring_pk_hex_for_payload = CryptoSerialize::to_bytes(aggregate_pk)
        .map(|b| hex::encode(&b))
        .map_err(|e| {
            DkgError::Serialization(format!(
                "Failed to serialize aggregate_pk for RingPayload: {}",
                e
            ))
        })?;

    app_state
        .bulletin
        .get_ring_id(
            bulletin_namespace,
            &ring_pk_hex_for_payload,
            &peer_ids,
            threshold as u32,
            pss_interval,
            policy_id.as_deref().unwrap_or(""),
        )
        .map_err(|e| DkgError::Serialization(format!("Failed to compute ring_id: {}", e)))
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
