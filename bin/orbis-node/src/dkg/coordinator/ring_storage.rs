use crate::app_state::AppState;
use crate::constants::BULLETIN_RING_NAMESPACE;
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
    let mut ring_index_result: Result<()> = Ok(());
    if let Some(key) = &ring_key {
        coord.app_state.dkg_session_state.unmark_ring_pss(key).await;

        if let Err(e) = coord
            .app_state
            .local_storage
            .delete(LocalStorageKeys::RingKey(key.clone()))
        {
            tracing::warn!(
                session_id = session_id,
                ring_key = %key,
                error = %e,
                "Reshare Dealer: failed to delete share bundle (already absent?)"
            );
        } else {
            tracing::info!(
                session_id = session_id,
                ring_key = %key,
                "Reshare Dealer: deleted share bundle - node has left the ring"
            );
        }

        let _guard = coord.app_state.ring_index_lock.lock().await;
        ring_index_result = remove_ring_index_entry(&coord.app_state.local_storage, key);
    }

    coord.remove_session(session_id).await;
    metrics::record_dkg_session_completed();
    tracing::info!(
        session_id = session_id,
        "Reshare Dealer: Phase 4 complete (share distribution done, secret deleted)"
    );

    ring_index_result
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
    let mut ring_index: Vec<RingIndexEntry> = app_state
        .local_storage
        .get(LocalStorageKeys::RingIndex)
        .ok()
        .flatten()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();

    if !ring_index.iter().any(|e| e.ring_pk_str == storage_key) {
        ring_index.push(RingIndexEntry {
            ring_pk_str: storage_key.to_string(),
            bulletin_post_id,
        });
        let index_bytes = serde_json::to_vec(&ring_index).map_err(|e| {
            DkgError::Serialization(format!("Failed to serialize RingIndex: {}", e))
        })?;
        app_state
            .local_storage
            .set(LocalStorageKeys::RingIndex, index_bytes)
            .map_err(|e| DkgError::Storage(format!("Failed to store RingIndex: {}", e)))?;
    }

    Ok(())
}

pub(in crate::dkg::coordinator) async fn post_fresh_ring_payload<D>(
    coord: &DkgCoordinator<D>,
    session_id: u64,
    ring_pk_bytes: &[u8],
    threshold: usize,
    pss_interval: Option<u64>,
) -> Result<()>
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
        next_peer_ids: None,
        new_threshold: None,
        threshold: threshold as u32,
        pss_interval,
    };

    let payload_bytes: Vec<u8> = ring_payload
        .clone()
        .try_into()
        .map_err(|e| DkgError::Serialization(format!("Failed to serialize RingPayload: {}", e)))?;

    coord
        .app_state
        .bulletin
        .post(
            BULLETIN_RING_NAMESPACE.to_string(),
            payload_bytes,
            Some(session_id.to_string()),
        )
        .await
        .map_err(|e| DkgError::Bulletin(format!("Failed to post RingPayload: {}", e)))?;

    tracing::info!(
        ring_pk = %ring_payload.ring_pk,
        namespace = BULLETIN_RING_NAMESPACE,
        "DKG Coordinator: Successfully posted RingPayload to bulletin"
    );

    Ok(())
}

pub(in crate::dkg::coordinator) fn fresh_ring_index_post_id<D>(
    app_state: &AppState<D>,
    aggregate_pk: &G1Affine,
    peer_ids: Vec<String>,
    threshold: usize,
    pss_interval: Option<u64>,
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

    let ring_payload_local = RingPayload {
        ring_pk: ring_pk_hex_for_payload,
        peer_ids,
        next_peer_ids: None,
        new_threshold: None,
        threshold: threshold as u32,
        pss_interval,
    };
    let ring_payload_bytes: Vec<u8> = ring_payload_local.try_into().map_err(|e| {
        DkgError::Serialization(format!(
            "Failed to serialize RingPayload for local cache: {}",
            e
        ))
    })?;

    app_state
        .bulletin
        .get_post_id(BULLETIN_RING_NAMESPACE, &ring_payload_bytes)
        .map_err(|e| DkgError::Serialization(format!("Failed to compute bulletin post_id: {}", e)))
}

fn remove_ring_index_entry(storage: &impl LocalStorage, ring_key: &str) -> Result<()> {
    let raw = match storage.get(LocalStorageKeys::RingIndex) {
        Ok(Some(raw)) => raw,
        Ok(None) => return Ok(()),
        Err(e) => {
            return Err(DkgError::Storage(format!(
                "Reshare Dealer: failed to read RingIndex: {}",
                e
            )))
        }
    };
    let mut index: Vec<RingIndexEntry> = serde_json::from_slice(&raw).map_err(|e| {
        DkgError::Storage(format!(
            "Reshare Dealer: failed to deserialize RingIndex: {}",
            e
        ))
    })?;
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
