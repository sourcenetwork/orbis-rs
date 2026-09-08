//! Authorized-peer oracle for the network layer's reserved connection capacity.
//!
//! `crates/network` sets aside `authorized_connection_reserve` inbound
//! connection slots for peers this returns `true` for, so a flood of cheap
//! self-issued endpoint keys cannot deny the committee a connection slot. The
//! authorized set is the union of every current and pending-reshare committee
//! member across every ring this node indexes, rebuilt periodically from the
//! bulletin.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bulletin::r#trait::{Bulletin, BulletinKind, RingPayload};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use local_storage::LocalStorageImpl;
use tokio::task::JoinHandle;

use crate::helpers::identity::extract_node_part;
use crate::helpers::node_routes::resolve_node_routes;
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

    #[cfg(test)]
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

/// Rebuild the authorized-peer set from the local `RingIndex` and the bulletin.
///
/// Fails open per ring and per node key: an unresolvable ring payload or a
/// missing `NodeInfo` just leaves that peer out of the set (it competes in the
/// shared connection pool) rather than erroring the whole refresh.
pub async fn rebuild_authorized_peer_set(
    local_storage: &LocalStorageImpl,
    bulletin: &Arc<dyn Bulletin + Send + Sync>,
) -> HashSet<String> {
    let ring_index: Vec<RingIndexEntry> = local_storage
        .get(LocalStorageKeys::RingIndex)
        .ok()
        .flatten()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();

    let mut node_keys: Vec<String> = Vec::new();
    for entry in &ring_index {
        match bulletin
            .read(entry.bulletin_post_id.clone(), BulletinKind::Ring)
            .await
            .map_err(|error| error.to_string())
            .and_then(|post| RingPayload::try_from(post).map_err(|error| error.to_string()))
        {
            Ok(payload) => {
                node_keys.extend(payload.peer_node_keys);
                if let Some(new_committee) = payload.new_peer_node_keys {
                    node_keys.extend(new_committee);
                }
            }
            Err(error) => tracing::debug!(
                ring = %entry.ring_pk_str,
                %error,
                "authorized-peer refresh: skipping ring whose payload did not resolve"
            ),
        }
    }
    node_keys.sort();
    node_keys.dedup();

    let mut authorized = HashSet::new();
    for node_key in node_keys {
        match resolve_node_routes(bulletin, std::slice::from_ref(&node_key)).await {
            Ok(routes) => {
                for route in routes {
                    authorized.insert(extract_node_part(&route.peer_id).to_lowercase());
                }
            }
            Err(error) => tracing::debug!(
                %node_key,
                %error,
                "authorized-peer refresh: NodeInfo did not resolve"
            ),
        }
    }
    authorized
}

/// Spawn the periodic refresh. Rebuilds once immediately, then every `interval`.
/// The returned handle is aborted at node shutdown.
pub fn spawn_authorized_peer_refresh(
    oracle: Arc<RingAuthorizedPeers>,
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
            let authorized = rebuild_authorized_peer_set(&local_storage, &bulletin).await;
            let count = authorized.len();
            oracle.store(authorized);
            tracing::debug!(count, "authorized-peer set refreshed");
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
