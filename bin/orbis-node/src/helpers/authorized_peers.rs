//! Authorized-peer oracle for the network layer's reserved ingress capacity.
//!
//! `crates/network` holds back `authorized_reserve_percent` of every shared
//! inbound budget for peers this returns `true` for, so a flood of cheap
//! self-issued endpoint keys cannot starve the committee. The authorized set is
//! the union of every committee member (current + pending reshare) across:
//!
//! * every ring in the local `RingIndex` (completed ceremonies), and
//! * every `ring_id` in this node's own published `NodeInfo.whitelisted_ring_ids`
//!   — so a ring created on-chain whose fresh-DKG / reshare ceremony has **not**
//!   finished (and therefore has no `RingIndex` entry yet) is still covered, and
//!   the leader's `Prepare` / `SessionInit` traffic is not refused under flood
//!   before the ceremony can create that entry.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bulletin::error::BulletinError;
use bulletin::r#trait::{Bulletin, BulletinKind, NodeInfo, RingPayload};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use local_storage::LocalStorageImpl;
use tokio::task::JoinHandle;

use crate::helpers::identity::extract_node_part;
use crate::ring_state::RingIndexEntry;

/// Lowercase-hex endpoint-key node parts of every authorized peer, swapped
/// atomically by the background refresh. Reads are lock-brief and sit on the
/// connection-accept path.
pub struct RingAuthorizedPeers {
    keys: RwLock<Arc<HashSet<String>>>,
}

impl RingAuthorizedPeers {
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(Arc::new(HashSet::new())),
        }
    }

    fn store(&self, keys: HashSet<String>) {
        *self
            .keys
            .write()
            .unwrap_or_else(|poison| poison.into_inner()) = Arc::new(keys);
    }

    pub(crate) fn authorized_count(&self) -> usize {
        self.keys
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
            .len()
    }
}

impl Default for RingAuthorizedPeers {
    fn default() -> Self {
        Self::new()
    }
}

impl network::AuthorizedPeers for RingAuthorizedPeers {
    fn is_authorized(&self, peer: &network::PeerId) -> bool {
        let hex = hex::encode(peer.as_bytes());
        self.keys
            .read()
            .map(|keys| keys.contains(&hex))
            .unwrap_or(false)
    }
}

/// Rebuild the authorized-peer set from the local `RingIndex`, this node's own
/// `NodeInfo` ring whitelist, and the bulletin.
///
/// Returns `Err` when the rebuild could not be completed **authoritatively** — a
/// local `RingIndex` read/decode failure, or a bulletin read that failed for a
/// reason other than the post genuinely not existing. The caller must then keep
/// the previous snapshot rather than replace it with a partial one, so a
/// transient bulletin outage never strips the committee out of the reserve
/// exactly when reconnect capacity is needed. A `NotFound` on a whitelisted ring
/// (not created yet) or a committee member's `NodeInfo` (not published yet) is a
/// confirmed absence, not a transient failure, and is skipped. `Ok(set)` —
/// possibly empty — is authoritative and may be stored.
pub async fn rebuild_authorized_peer_set(
    node_key: &str,
    local_storage: &LocalStorageImpl,
    bulletin: &Arc<dyn Bulletin + Send + Sync>,
) -> Result<HashSet<String>, String> {
    let ring_index: Vec<RingIndexEntry> = match local_storage.get(LocalStorageKeys::RingIndex) {
        Ok(None) => Vec::new(), // no rings indexed yet — authoritative empty
        Ok(Some(bytes)) => serde_json::from_slice(&bytes)
            .map_err(|error| format!("RingIndex is corrupt: {error}"))?,
        Err(error) => return Err(format!("RingIndex read failed: {error}")),
    };

    // Ring identifiers to inspect: completed rings by their bulletin post id,
    // plus this node's whitelisted ring ids (a ring may be created on-chain long
    // before its ceremony finishes and writes a `RingIndex` entry).
    let mut ring_refs: Vec<String> = ring_index
        .iter()
        .map(|e| e.bulletin_post_id.clone())
        .collect();
    ring_refs.extend(read_own_whitelisted_ring_ids(node_key, bulletin).await?);
    ring_refs.sort();
    ring_refs.dedup();

    let mut node_keys: Vec<String> = Vec::new();
    for ring_ref in &ring_refs {
        match bulletin.read(ring_ref.clone(), BulletinKind::Ring).await {
            Ok(post) => {
                let payload = RingPayload::try_from(post)
                    .map_err(|error| format!("ring {ring_ref} payload is malformed: {error}"))?;
                node_keys.extend(payload.peer_node_keys);
                if let Some(new_committee) = payload.new_peer_node_keys {
                    node_keys.extend(new_committee);
                }
            }
            Err(BulletinError::NotFound { .. }) => tracing::debug!(
                ring = %ring_ref,
                "authorized-peer refresh: ring not present on the bulletin yet"
            ),
            Err(error) => return Err(format!("ring {ring_ref} read failed: {error}")),
        }
    }
    node_keys.sort();
    node_keys.dedup();

    let mut authorized = HashSet::new();
    for member in node_keys {
        match bulletin.read(member.clone(), BulletinKind::NodeInfo).await {
            Ok(post) => {
                let info = NodeInfo::try_from(post)
                    .map_err(|error| format!("NodeInfo for {member} is malformed: {error}"))?;
                authorized.insert(extract_node_part(&info.peer_id).to_lowercase());
            }
            Err(BulletinError::NotFound { .. }) => tracing::debug!(
                member = %member,
                "authorized-peer refresh: committee member has not published NodeInfo yet"
            ),
            Err(error) => return Err(format!("NodeInfo for {member} read failed: {error}")),
        }
    }
    Ok(authorized)
}

/// This node's own `NodeInfo.whitelisted_ring_ids`. A `NotFound` (node not
/// registered yet) yields an empty list; any other read error is fatal so a
/// transient outage does not shrink the set.
async fn read_own_whitelisted_ring_ids(
    node_key: &str,
    bulletin: &Arc<dyn Bulletin + Send + Sync>,
) -> Result<Vec<String>, String> {
    match bulletin
        .read(node_key.to_string(), BulletinKind::NodeInfo)
        .await
    {
        Ok(post) => {
            let info = NodeInfo::try_from(post)
                .map_err(|error| format!("own NodeInfo is malformed: {error}"))?;
            Ok(info.whitelisted_ring_ids)
        }
        Err(BulletinError::NotFound { .. }) => Ok(Vec::new()),
        Err(error) => Err(format!("own NodeInfo read failed: {error}")),
    }
}

/// Spawn the periodic refresh. Rebuilds once immediately, then every `interval`.
/// An incomplete rebuild (transient I/O) keeps the last-known-good set. The
/// returned handle is aborted at node shutdown.
pub fn spawn_authorized_peer_refresh(
    oracle: Arc<RingAuthorizedPeers>,
    node_key: String,
    local_storage: LocalStorageImpl,
    bulletin: Arc<dyn Bulletin + Send + Sync>,
    interval: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            // The first tick fires immediately, so the set is populated at
            // startup and then rebuilt every `interval`.
            ticker.tick().await;
            match rebuild_authorized_peer_set(&node_key, &local_storage, &bulletin).await {
                Ok(authorized) => {
                    let count = authorized.len();
                    oracle.store(authorized);
                    tracing::debug!(count, "authorized-peer set refreshed");
                }
                Err(error) => tracing::warn!(
                    %error,
                    retained = oracle.authorized_count(),
                    "authorized-peer refresh incomplete; keeping last-known-good set"
                ),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use network::AuthorizedPeers;

    #[test]
    fn is_authorized_matches_hex_of_endpoint_key() {
        let oracle = RingAuthorizedPeers::new();
        let authorized = network::PeerId::from_bytes(&[0xAB; 32]);
        let unknown = network::PeerId::from_bytes(&[0xCD; 32]);

        assert!(!oracle.is_authorized(&authorized));
        assert_eq!(oracle.authorized_count(), 0);

        oracle.store([hex::encode(authorized.as_bytes())].into_iter().collect());

        assert!(oracle.is_authorized(&authorized));
        assert!(!oracle.is_authorized(&unknown));
        assert_eq!(oracle.authorized_count(), 1);

        // A refresh that resolves nothing clears the set.
        oracle.store(HashSet::new());
        assert!(!oracle.is_authorized(&authorized));
    }
}
