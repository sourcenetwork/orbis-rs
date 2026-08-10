use crate::dkg::v0::messages::SessionKind;
use crate::dkg::v0::session_state::SessionStateManager;
use crate::dkg::v0::transport::{CeremonyConfig, MessageId};
use crate::pre::v0::response_state::PreResponseManager;
use crate::reporting::v0::state::ReportingState;
use crate::sign::v0::response_state::SignResponseManager;
use authz::r#trait::Authz;
use bulletin::r#trait::Bulletin;
use crypto::r#trait::Dkg;
use local_storage::LocalStorageImpl;
use network::{Connection, Network};
use network::{PeerConnection, PeerId};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::constants::MAX_CACHED_PEER_CONNECTIONS;

/// Global per-peer, per-protocol connection pool.
///
/// Each entry is keyed by `(peer_id_str, protocol_bytes)` and holds one
/// persistent QUIC connection. Callers open lightweight QUIC streams via
/// [`PeerConnection::open_stream`] for individual requests or DKG sessions,
/// so concurrent sessions to the same peer run on independent streams with no
/// head-of-line blocking. Entries are bounded and evicted least-recently-used.
pub struct PeerConnectionPool {
    connections: Mutex<HashMap<(String, Vec<u8>), PoolEntry>>,
    max_entries: usize,
    access_clock: AtomicU64,
}

struct PoolEntry {
    connection: Arc<dyn PeerConnection>,
    last_used: u64,
}

/// Short-lived authenticated snapshot retained across DKG attempt teardown so
/// an offline-candidate relay already in flight can still be validated and
/// converted into a report. It contains only public ceremony metadata.
#[derive(Clone)]
pub(crate) struct DkgOfflineRelayReceipt {
    pub kind: SessionKind,
    pub ring_id: String,
    pub protocol_version: u64,
    pub committees: CeremonyConfig,
    pub leader_node_key: String,
    pub recorded_at: Instant,
    pub processed: HashSet<MessageId>,
}

impl Default for PeerConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerConnectionPool {
    pub fn new() -> Self {
        Self::with_capacity(MAX_CACHED_PEER_CONNECTIONS)
    }

    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            connections: Mutex::new(HashMap::new()),
            max_entries: max_entries.max(1),
            access_clock: AtomicU64::new(0),
        }
    }

    fn next_access(&self) -> u64 {
        self.access_clock.fetch_add(1, Ordering::Relaxed)
    }

    pub async fn get(&self, peer_id: &str, protocol: &[u8]) -> Option<Arc<dyn PeerConnection>> {
        let mut connections = self.connections.lock().await;
        let entry = connections.get_mut(&(peer_id.to_string(), protocol.to_vec()))?;
        entry.last_used = self.next_access();
        Some(entry.connection.clone())
    }

    /// Evict and close the cached connection only if it is still the connection
    /// observed by the caller. A concurrent reconnect may already have installed
    /// a healthy replacement, which must not be removed by a late timeout from an
    /// older stream attempt.
    pub(crate) async fn invalidate_if_same(
        &self,
        peer_id: &str,
        protocol: &[u8],
        expected: &Arc<dyn PeerConnection>,
    ) -> bool {
        let key = (peer_id.to_string(), protocol.to_vec());
        let removed = {
            let mut connections = self.connections.lock().await;
            let is_same = connections
                .get(&key)
                .is_some_and(|entry| Arc::ptr_eq(&entry.connection, expected));
            is_same.then(|| connections.remove(&key)).flatten()
        };
        if let Some(entry) = removed {
            let _ = entry.connection.close().await;
            true
        } else {
            false
        }
    }

    /// Get a cached connection for `(peer_id, protocol)`, or open and cache a new one.
    ///
    /// The optimistic read avoids taking the write lock on the hot path. If two
    /// tasks race through the read-miss simultaneously, both will open a connection,
    /// but only one will be stored — the loser's connection is dropped harmlessly
    /// and the winner's is returned to both callers.
    pub async fn get_or_connect(
        &self,
        network: &Arc<dyn Network>,
        peer_id_str: &str,
        protocol: &[u8],
    ) -> Result<Arc<dyn PeerConnection>, network::error::NetworkError> {
        if let Some(cached) = self.get(peer_id_str, protocol).await {
            return Ok(cached);
        }
        let peer_id_obj = PeerId::new(peer_id_str.as_bytes().to_vec());
        let new_conn: Arc<dyn PeerConnection> =
            Arc::from(network.connect(&peer_id_obj, protocol).await?);
        let key = (peer_id_str.to_string(), protocol.to_vec());
        Ok(self.cache_connection(key, new_conn).await)
    }

    async fn cache_connection(
        &self,
        key: (String, Vec<u8>),
        new_conn: Arc<dyn PeerConnection>,
    ) -> Arc<dyn PeerConnection> {
        let mut map = self.connections.lock().await;
        // Re-check under the write lock: another task may have inserted while we
        // were connecting. Prefer the existing entry to avoid displacing it.
        if let Some(existing) = map.get_mut(&key) {
            existing.last_used = self.next_access();
            let existing = existing.connection.clone();
            drop(map);
            let _ = new_conn.close().await;
            return existing;
        }
        let evicted = if map.len() >= self.max_entries {
            map.iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone())
                .and_then(|key| map.remove(&key))
        } else {
            None
        };
        map.insert(
            key,
            PoolEntry {
                connection: new_conn.clone(),
                last_used: self.next_access(),
            },
        );
        drop(map);
        if let Some(evicted) = evicted {
            let _ = evicted.connection.close().await;
        }
        new_conn
    }

    /// Open a QUIC stream and return the parent pooled connection used for it.
    /// The parent identity lets request protocols invalidate precisely the stale
    /// connection whose stream timed out after `open_stream` itself succeeded.
    pub(crate) async fn open_stream_with_connection(
        &self,
        network: &Arc<dyn Network>,
        peer_id_str: &str,
        protocol: &[u8],
    ) -> Result<(Box<dyn Connection>, Arc<dyn PeerConnection>), network::error::NetworkError> {
        let conn = self.get_or_connect(network, peer_id_str, protocol).await?;
        match conn.open_stream().await {
            Ok(stream) => Ok((stream, conn)),
            Err(_) => {
                self.invalidate_if_same(peer_id_str, protocol, &conn).await;
                let fresh = self.get_or_connect(network, peer_id_str, protocol).await?;
                let stream = fresh.open_stream().await?;
                Ok((stream, fresh))
            }
        }
    }

    /// Open a QUIC stream to a peer, evicting and reconnecting if the cached
    /// connection is already known to be dead while opening the stream.
    pub async fn open_stream(
        &self,
        network: &Arc<dyn Network>,
        peer_id_str: &str,
        protocol: &[u8],
    ) -> Result<Box<dyn Connection>, network::error::NetworkError> {
        self.open_stream_with_connection(network, peer_id_str, protocol)
            .await
            .map(|(stream, _)| stream)
    }

    #[cfg(test)]
    pub async fn len(&self) -> usize {
        self.connections.lock().await.len()
    }
}

#[cfg(test)]
mod peer_connection_pool_tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::AtomicBool;

    struct FakePeerConnection {
        peer_id: PeerId,
        closed: Arc<AtomicBool>,
    }

    #[async_trait]
    impl PeerConnection for FakePeerConnection {
        async fn open_stream(&self) -> network::Result<Box<dyn Connection>> {
            Err(network::NetworkError::Connection(
                "unused fake connection".into(),
            ))
        }

        fn peer_id(&self) -> &PeerId {
            &self.peer_id
        }

        async fn close(&self) -> network::Result<()> {
            self.closed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    fn fake(name: &str) -> (Arc<dyn PeerConnection>, Arc<AtomicBool>) {
        let closed = Arc::new(AtomicBool::new(false));
        (
            Arc::new(FakePeerConnection {
                peer_id: PeerId::from_bytes(name.as_bytes()),
                closed: closed.clone(),
            }),
            closed,
        )
    }

    #[tokio::test]
    async fn bounded_pool_evicts_and_closes_least_recently_used_connection() {
        let pool = PeerConnectionPool::with_capacity(2);
        let (a, a_closed) = fake("a");
        let (b, b_closed) = fake("b");
        let (c, c_closed) = fake("c");
        pool.cache_connection(("a".into(), b"p".to_vec()), a).await;
        pool.cache_connection(("b".into(), b"p".to_vec()), b).await;
        assert!(pool.get("a", b"p").await.is_some());
        pool.cache_connection(("c".into(), b"p".to_vec()), c).await;

        assert_eq!(pool.len().await, 2);
        assert!(pool.get("a", b"p").await.is_some());
        assert!(pool.get("b", b"p").await.is_none());
        assert!(pool.get("c", b"p").await.is_some());
        assert!(!a_closed.load(Ordering::SeqCst));
        assert!(b_closed.load(Ordering::SeqCst));
        assert!(!c_closed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn invalidation_closes_only_the_connection_observed_by_the_caller() {
        let pool = PeerConnectionPool::with_capacity(2);
        let (stale, stale_closed) = fake("stale");
        let (replacement, replacement_closed) = fake("replacement");
        pool.cache_connection(("peer".into(), b"p".to_vec()), stale.clone())
            .await;

        assert!(pool.invalidate_if_same("peer", b"p", &stale).await);
        assert!(stale_closed.load(Ordering::SeqCst));
        assert_eq!(pool.len().await, 0);

        pool.cache_connection(("peer".into(), b"p".to_vec()), replacement.clone())
            .await;
        assert!(!pool.invalidate_if_same("peer", b"p", &stale).await);
        assert!(pool.get("peer", b"p").await.is_some());
        assert!(!replacement_closed.load(Ordering::SeqCst));
    }
}

/// Shared application state accessible by all gRPC endpoints
#[derive(Clone)]
pub struct AppState<D>
where
    D: Dkg + Clone + 'static,
{
    /// Public key for this node's SourceHub signing key.
    pub node_key: String,
    /// Network for node-to-node communication
    pub network: Arc<dyn Network>,
    /// Local Storage implementation for storing items locally
    pub local_storage: LocalStorageImpl,
    /// DKG session state manager - handles both crypto state and protocol tracking
    pub dkg_session_state: Arc<SessionStateManager<D>>,
    /// PRE response state manager - handles PRE response collection
    pub pre_response_state: Arc<PreResponseManager>,
    /// Sign response state manager - handles threshold signing response collection
    /// and FROST nonce state between Round 1 and Round 2
    pub sign_response_state: Arc<SignResponseManager>,
    /// Authz implementation
    pub authz: Arc<dyn Authz + Send + Sync>,
    /// Bulletin implementation
    pub bulletin: Arc<dyn Bulletin + Send + Sync>,
    /// Serializes concurrent RingIndex read-modify-write operations in Phase 4.
    /// Without this, two simultaneous DKG completions can each read the same
    /// index and one will overwrite the other's appended entry.
    pub ring_index_lock: Arc<Mutex<()>>,
    /// Global per-peer, per-protocol connection pool shared across DKG, PRE, and Sign.
    pub peer_connection_pool: Arc<PeerConnectionPool>,
    /// Independent MPC fault-reporting subsystem: state, registry, and sink.
    pub reporting_state: Arc<ReportingState>,
}

impl<D> AppState<D>
where
    D: Dkg + Clone + 'static,
{
    pub fn new(
        node_key: String,
        network: Arc<dyn Network>,
        local_storage: LocalStorageImpl,
        authz: Arc<dyn Authz + Send + Sync>,
        bulletin: Arc<dyn Bulletin + Send + Sync>,
    ) -> Self {
        Self {
            node_key,
            network,
            local_storage,
            dkg_session_state: Arc::new(SessionStateManager::new()),
            pre_response_state: Arc::new(PreResponseManager::new()),
            sign_response_state: Arc::new(SignResponseManager::new()),
            authz,
            bulletin,
            ring_index_lock: Arc::new(Mutex::new(())),
            peer_connection_pool: Arc::new(PeerConnectionPool::new()),
            reporting_state: Arc::new(ReportingState::new()),
        }
    }
}

impl<D> std::fmt::Debug for AppState<D>
where
    D: Dkg + Clone + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("node_key", &self.node_key)
            .field("network", &"<Network>")
            .field("dkg_session_state", &"<SessionStateManager>")
            .field("pre_response_state", &"<PreResponseManager>")
            .field("sign_response_state", &"<SignResponseManager>")
            .field("reporting_state", &"<ReportingState>")
            .finish()
    }
}
