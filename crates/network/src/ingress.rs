//! Shared ingress admission for direct streams and authenticated PubSub frames.
//!
//! Independent limits, deliberately kept separate:
//!
//! * [`IngressController::try_admit_connection`] — one slot per accepted inbound
//!   QUIC connection, held for the connection's whole lifetime by the router's
//!   per-connection handler (direct ALPNs and the wrapped Gossip ALPN alike),
//!   plus one *connection-open*-rate tick. Bounds how many connections one
//!   identity — and the node — can keep alive without ever opening a stream.
//! * [`IngressController::try_admit_stream`] — one slot per accepted inbound
//!   QUIC stream, held for the stream's whole lifetime, plus one
//!   *stream-open*-rate tick. Bounds how many streams can be parked in `recv()`
//!   at once (node-wide and per immediate peer) and the rate at which a peer
//!   opens them.
//! * [`IngressController::try_reserve_request_body`] /
//!   [`IngressController::try_reserve_reply_body`] — weighted receive-byte
//!   budgets, reserved after the length prefix is parsed but before the body
//!   buffer is allocated, so a flood of large frames cannot commit gigabytes
//!   ahead of the work-item caps. Requests and replies draw on **separate**
//!   pools so a stalled-request backlog cannot deny an MPC reply its buffer.
//! * [`IngressController::allow_frame`] — one *decoded-frame*-rate tick, charged
//!   only once the whole body has been read. A distinct limiter from the
//!   stream-open rate (so a one-frame request is not double-charged), and
//!   charging after arrival prevents a peer from pre-paying `recv()` calls in
//!   idle windows and then bursting frames using banked tokens.
//! * [`IngressController::try_acquire_request_work`] /
//!   [`IngressController::try_acquire_reply_work`] — one work slot per decoded
//!   frame, held only while the application processes it. Inbound requests and
//!   the replies read on client-opened streams draw on **separate** budgets, so
//!   a request handler that fans out and awaits replies cannot starve those
//!   replies of the capacity it is itself holding.
//!
//! `authorized_reserve_percent` of every shared inbound budget — connections,
//! streams, request work permits, and request body bytes — is held back for
//! peers an [`crate::AuthorizedPeers`] oracle vouches for: an unauthorized peer
//! must take a slot from the matching `shared_*` pool *as well as* the full
//! pool, so a flood of cheap self-issued identities cannot starve the committee
//! of any one ingress resource.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

use crate::error::NetworkError;
use crate::r#trait::{AuthorizedPeers, IngressDropReason, NetworkIngressLimits, PeerId};

const MAX_TRACKED_RATE_LIMIT_PEERS: usize = 8192;
const RATE_LIMIT_PEER_IDLE_TTL: Duration = Duration::from_secs(60);

/// RAII ownership of one request work permit, released when the application
/// finishes with the frame it was admitted for. `_shared` additionally holds a
/// slot in the non-reserved work pool for an unauthorized peer's frame.
#[derive(Debug)]
pub(crate) struct IngressLease {
    _permit: OwnedSemaphorePermit,
    _shared: Option<OwnedSemaphorePermit>,
}

/// RAII ownership of the receive-byte budget for one inbound request-frame body.
/// Held for the lifetime of the resulting [`crate::Message`] so the budget
/// bounds bytes *received and not yet processed*, not merely bytes in transit.
/// `_shared` additionally holds bytes in the non-reserved body pool for an
/// unauthorized peer's frame.
#[derive(Debug)]
pub(crate) struct BodyReservation {
    _permit: OwnedSemaphorePermit,
    _shared: Option<OwnedSemaphorePermit>,
}

/// Why a newly accepted inbound stream was refused before any frame was read.
///
/// Distinct from [`IngressDropReason`], which is a per-frame signal surfaced to
/// PubSub subscribers; a stream refusal never reaches the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamAdmitReason {
    /// The node-wide concurrent inbound-stream budget is exhausted.
    Global,
    /// The shared (non-reserved) portion of the stream budget is exhausted and
    /// this peer is not vouched for by the authorized-peers oracle.
    Unauthorized,
    /// This immediate peer already holds the maximum concurrent inbound streams.
    PerPeer,
    /// This immediate peer is opening streams faster than its per-second budget.
    Rate,
}

impl StreamAdmitReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Global => "stream_limit",
            Self::Unauthorized => "unauthorized_stream_limit",
            Self::PerPeer => "per_peer_stream_limit",
            Self::Rate => "stream_rate_limit",
        }
    }
}

/// Why a newly accepted inbound QUIC connection was refused. Every variant
/// closes the connection immediately — there is nothing to keep open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectionAdmitReason {
    /// The node-wide inbound-connection budget is exhausted.
    Global,
    /// The shared (non-reserved) portion of the budget is exhausted and this
    /// peer is not vouched for by the authorized-peers oracle.
    Unauthorized,
    /// This immediate peer already holds the maximum inbound connections.
    PerPeer,
    /// This immediate peer is opening connections faster than its budget.
    Rate,
}

impl ConnectionAdmitReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Global => "connection_limit",
            Self::Unauthorized => "unauthorized_connection_limit",
            Self::PerPeer => "per_peer_connection_limit",
            Self::Rate => "connection_rate_limit",
        }
    }
}

/// RAII ownership of one node-wide semaphore permit plus one unit of a per-peer
/// count. Both are returned when the lease is dropped — for a stream, when its
/// handler task ends; for a connection, when the connection closes.
///
/// `_shared` additionally holds a slot in the non-reserved connection pool for
/// an unauthorized inbound connection.
#[derive(Debug)]
pub(crate) struct PeerScopedLease {
    _global: OwnedSemaphorePermit,
    _shared: Option<OwnedSemaphorePermit>,
    peer: PeerId,
    counts: Arc<StdMutex<HashMap<PeerId, usize>>>,
}

impl Drop for PeerScopedLease {
    fn drop(&mut self) {
        let mut counts = self
            .counts
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(open) = counts.get_mut(&self.peer) {
            *open = open.saturating_sub(1);
            if *open == 0 {
                counts.remove(&self.peer);
            }
        }
    }
}

/// Which peer-scoped cap a [`admit_peer_scoped`] call hit.
enum PeerScopedRefusal {
    Global,
    PerPeer,
}

/// Outcome of trying to take an unauthorized peer's slot in a shared pool.
enum SharedSlot {
    /// The peer is authorized — no shared slot is taken (it uses the reserve).
    Reserved,
    /// The peer is unauthorized and a shared slot was taken; hold it alongside
    /// the full-pool permit.
    Acquired(OwnedSemaphorePermit),
    /// The peer is unauthorized and the shared pool is exhausted.
    Exhausted,
}

/// Take one node-wide permit, then one per-peer slot. The global permit is
/// taken first, so an early return from the per-peer check drops it (and, with
/// it, the caller's already-acquired `shared` permit).
fn admit_peer_scoped(
    global: &Arc<Semaphore>,
    counts: &Arc<StdMutex<HashMap<PeerId, usize>>>,
    peer: &PeerId,
    per_peer_max: usize,
    shared: Option<OwnedSemaphorePermit>,
) -> Result<PeerScopedLease, PeerScopedRefusal> {
    let permit = Arc::clone(global)
        .try_acquire_owned()
        .map_err(|_| PeerScopedRefusal::Global)?;
    {
        let mut counts = counts.lock().unwrap_or_else(|poison| poison.into_inner());
        let open = counts.entry(peer.clone()).or_insert(0);
        if *open >= per_peer_max {
            return Err(PeerScopedRefusal::PerPeer);
        }
        *open += 1;
    }
    Ok(PeerScopedLease {
        _global: permit,
        _shared: shared,
        peer: peer.clone(),
        counts: Arc::clone(counts),
    })
}

/// One admission controller shared by every direct ALPN handler and PubSub topic.
pub(crate) struct IngressController {
    limits: NetworkIngressLimits,
    /// Bounds inbound-request frames whose application work is executing.
    request_work_permits: Arc<Semaphore>,
    /// Bounds reply frames (read on client-opened streams) whose application
    /// work is executing. Separate from `request_work_permits` so a request
    /// handler awaiting replies cannot starve them.
    reply_work_permits: Arc<Semaphore>,
    /// Bounds accepted-but-not-yet-closed inbound QUIC connections node-wide.
    connection_permits: Arc<Semaphore>,
    /// Optional oracle: is this endpoint identity an authorized peer? `None`
    /// treats every peer as authorized (no reservation enforced).
    authorized_peers: Option<Arc<dyn AuthorizedPeers>>,
    /// The non-reserved portion of each budget below
    /// (`budget * (100 - authorized_reserve_percent) / 100`). An unauthorized
    /// peer must take a slot from the matching `shared_*` pool *as well as* the
    /// full pool, so `authorized_reserve_percent` of every budget stays
    /// available to authorized peers under a Sybil flood.
    shared_connection_permits: Arc<Semaphore>,
    shared_stream_permits: Arc<Semaphore>,
    shared_request_work_permits: Arc<Semaphore>,
    shared_request_body_bytes: Arc<Semaphore>,
    /// Bounds accepted-but-not-yet-closed inbound streams node-wide.
    stream_permits: Arc<Semaphore>,
    /// Weighted byte budget for inbound-request frame bodies received and not
    /// yet dropped by the application.
    request_body_bytes: Arc<Semaphore>,
    /// Weighted byte budget for reply frame bodies (client-opened streams).
    /// Separate pool from `request_body_bytes` — sized so its `min(len,..)`
    /// combined ceiling is still the operator-configured total — so a backlog of
    /// stalled inbound requests cannot deny an incoming MPC reply its buffer.
    reply_body_bytes: Arc<Semaphore>,
    /// Per-peer connection-open / stream-open / decoded-frame rate limiters.
    peer_rate_limiters: Mutex<HashMap<PeerId, PeerLimiters>>,
    /// Concurrent inbound stream count per immediate peer.
    peer_stream_counts: Arc<StdMutex<HashMap<PeerId, usize>>>,
    /// Concurrent inbound connection count per immediate peer.
    peer_connection_counts: Arc<StdMutex<HashMap<PeerId, usize>>>,
}

impl IngressController {
    pub(crate) fn new(
        limits: NetworkIngressLimits,
        authorized_peers: Option<Arc<dyn AuthorizedPeers>>,
    ) -> Result<Self, NetworkError> {
        // A zero limit does not "limit" its path — it wedges it shut forever
        // (`Semaphore::new(0)` never admits; a zero rate rejects every peer).
        // Reject each at construction instead of silently building a controller
        // that can never admit anything.
        if limits.max_concurrent_work == 0 {
            return Err(NetworkError::InvalidConfig(
                "max_concurrent_work must be at least 1".to_string(),
            ));
        }
        if limits.max_concurrent_reply_work == 0 {
            return Err(NetworkError::InvalidConfig(
                "max_concurrent_reply_work must be at least 1".to_string(),
            ));
        }
        if limits.max_events_per_peer_per_second == 0 {
            return Err(NetworkError::InvalidConfig(
                "max_events_per_peer_per_second must be at least 1".to_string(),
            ));
        }
        if limits.max_concurrent_connections == 0 {
            return Err(NetworkError::InvalidConfig(
                "max_concurrent_connections must be at least 1".to_string(),
            ));
        }
        if limits.max_connections_per_peer == 0 {
            return Err(NetworkError::InvalidConfig(
                "max_connections_per_peer must be at least 1".to_string(),
            ));
        }
        if limits.authorized_reserve_percent > 100 {
            return Err(NetworkError::InvalidConfig(format!(
                "authorized_reserve_percent ({}) must be 0..=100",
                limits.authorized_reserve_percent
            )));
        }
        if limits.max_concurrent_streams == 0 {
            return Err(NetworkError::InvalidConfig(
                "max_concurrent_streams must be at least 1".to_string(),
            ));
        }
        if limits.max_streams_per_peer == 0 {
            return Err(NetworkError::InvalidConfig(
                "max_streams_per_peer must be at least 1".to_string(),
            ));
        }
        if limits.max_inbound_request_body_bytes == 0 {
            return Err(NetworkError::InvalidConfig(
                "max_inbound_request_body_bytes must be at least 1".to_string(),
            ));
        }
        if limits.max_inbound_reply_body_bytes == 0 {
            return Err(NetworkError::InvalidConfig(
                "max_inbound_reply_body_bytes must be at least 1".to_string(),
            ));
        }
        let request_body_bytes = limits
            .max_inbound_request_body_bytes
            .min(Semaphore::MAX_PERMITS);
        let reply_body_bytes = limits
            .max_inbound_reply_body_bytes
            .min(Semaphore::MAX_PERMITS);
        // Non-reserved portion of a budget: `budget - budget * percent / 100`.
        // `percent == 0` yields exactly `budget` (the reservation is inert). The
        // `u128` widen keeps the large byte budgets from overflowing.
        let shared = |budget: usize| {
            let reserve =
                (budget as u128 * limits.authorized_reserve_percent as u128 / 100) as usize;
            budget - reserve
        };
        Ok(Self {
            limits,
            request_work_permits: Arc::new(Semaphore::new(limits.max_concurrent_work)),
            reply_work_permits: Arc::new(Semaphore::new(limits.max_concurrent_reply_work)),
            connection_permits: Arc::new(Semaphore::new(limits.max_concurrent_connections)),
            authorized_peers,
            shared_connection_permits: Arc::new(Semaphore::new(shared(
                limits.max_concurrent_connections,
            ))),
            shared_stream_permits: Arc::new(Semaphore::new(shared(limits.max_concurrent_streams))),
            shared_request_work_permits: Arc::new(Semaphore::new(shared(
                limits.max_concurrent_work,
            ))),
            shared_request_body_bytes: Arc::new(Semaphore::new(shared(request_body_bytes))),
            stream_permits: Arc::new(Semaphore::new(limits.max_concurrent_streams)),
            request_body_bytes: Arc::new(Semaphore::new(request_body_bytes)),
            reply_body_bytes: Arc::new(Semaphore::new(reply_body_bytes)),
            peer_rate_limiters: Mutex::new(HashMap::new()),
            peer_stream_counts: Arc::new(StdMutex::new(HashMap::new())),
            peer_connection_counts: Arc::new(StdMutex::new(HashMap::new())),
        })
    }

    /// The largest inbound-request frame body this controller's request
    /// receive-byte pool can ever reserve. The router validates route-level
    /// `max_message_size` overrides against this.
    pub(crate) fn max_inbound_request_body_bytes(&self) -> usize {
        self.limits.max_inbound_request_body_bytes
    }

    /// Admit one newly accepted inbound QUIC connection without queueing. Held
    /// for the whole connection lifetime by the router's per-connection handler.
    ///
    /// The peer's per-second connection-open budget is charged first — before
    /// the caps — so a peer that reconnects in a tight loop still pays for each
    /// attempt. A peer the authorized-peers oracle does not vouch for must also
    /// take a slot in the shared (non-reserved) pool, so the reserve stays
    /// available for authorized peers under a Sybil flood. Every refusal closes
    /// the connection.
    pub(crate) async fn try_admit_connection(
        &self,
        peer_id: &PeerId,
    ) -> Result<PeerScopedLease, ConnectionAdmitReason> {
        if !self
            .allow(peer_id, |limiters| limiters.connection_opens.allow())
            .await
        {
            return Err(ConnectionAdmitReason::Rate);
        }

        let shared = if self.is_authorized(peer_id) {
            None
        } else {
            Some(
                Arc::clone(&self.shared_connection_permits)
                    .try_acquire_owned()
                    .map_err(|_| ConnectionAdmitReason::Unauthorized)?,
            )
        };

        admit_peer_scoped(
            &self.connection_permits,
            &self.peer_connection_counts,
            peer_id,
            self.limits.max_connections_per_peer,
            shared,
        )
        .map_err(|refusal| match refusal {
            PeerScopedRefusal::Global => ConnectionAdmitReason::Global,
            PeerScopedRefusal::PerPeer => ConnectionAdmitReason::PerPeer,
        })
    }

    /// Admit one newly accepted inbound QUIC stream without queueing.
    ///
    /// The peer's per-second stream-open budget is charged first — before the
    /// caps — so a peer that is refused for being at its stream cap still pays
    /// for the open attempt, and a peer opening streams too fast is rejected
    /// outright. An unauthorized peer must also take a slot from the shared
    /// stream pool, so the reserved portion stays for authorized peers.
    pub(crate) async fn try_admit_stream(
        &self,
        peer_id: &PeerId,
    ) -> Result<PeerScopedLease, StreamAdmitReason> {
        if !self.allow_stream_open(peer_id).await {
            return Err(StreamAdmitReason::Rate);
        }

        let shared = if self.is_authorized(peer_id) {
            None
        } else {
            Some(
                Arc::clone(&self.shared_stream_permits)
                    .try_acquire_owned()
                    .map_err(|_| StreamAdmitReason::Unauthorized)?,
            )
        };

        admit_peer_scoped(
            &self.stream_permits,
            &self.peer_stream_counts,
            peer_id,
            self.limits.max_streams_per_peer,
            shared,
        )
        .map_err(|refusal| match refusal {
            PeerScopedRefusal::Global => StreamAdmitReason::Global,
            PeerScopedRefusal::PerPeer => StreamAdmitReason::PerPeer,
        })
    }

    /// Admit one decoded inbound frame without queueing: charge the decoded-frame
    /// rate, then take a request work permit. Used by the PubSub topic path,
    /// where a frame is already fully materialized by Gossip and there is nothing
    /// to size a receive-byte reservation against. `peer_id` is the immediate
    /// Gossip relay — in a healthy committee mesh a committee member — so the
    /// reserve heuristically covers relayed committee traffic.
    pub(crate) async fn try_admit_frame(
        &self,
        peer_id: &PeerId,
    ) -> Result<IngressLease, IngressDropReason> {
        if !self.allow_frame(peer_id).await {
            return Err(IngressDropReason::RateLimit);
        }
        self.try_acquire_request_work(peer_id)
            .ok_or(IngressDropReason::ConcurrencyLimit)
    }

    /// `true` when no oracle is configured, or the oracle vouches for `peer_id`.
    pub(crate) fn is_authorized(&self, peer_id: &PeerId) -> bool {
        self.authorized_peers
            .as_ref()
            .is_none_or(|oracle| oracle.is_authorized(peer_id))
    }

    /// Charge one unit of the peer's per-second stream-open budget.
    pub(crate) async fn allow_stream_open(&self, peer_id: &PeerId) -> bool {
        self.allow(peer_id, |limiters| limiters.stream_opens.allow())
            .await
    }

    /// Charge one unit of the peer's per-second decoded-frame budget. Call only
    /// once the whole frame body has been read, so tokens cannot be banked.
    pub(crate) async fn allow_frame(&self, peer_id: &PeerId) -> bool {
        self.allow(peer_id, |limiters| limiters.frames.allow())
            .await
    }

    /// Take one work permit for an inbound-request frame about to be processed.
    /// An unauthorized peer also spends a slot from the shared work pool.
    pub(crate) fn try_acquire_request_work(&self, peer_id: &PeerId) -> Option<IngressLease> {
        let shared = match self.shared_slot(&self.shared_request_work_permits, peer_id, 1) {
            SharedSlot::Reserved => None,
            SharedSlot::Acquired(permit) => Some(permit),
            SharedSlot::Exhausted => return None,
        };
        let permit = Arc::clone(&self.request_work_permits)
            .try_acquire_owned()
            .ok()?;
        Some(IngressLease {
            _permit: permit,
            _shared: shared,
        })
    }

    /// Take one work permit for a reply frame (read on a client-opened stream)
    /// about to be processed. Replies are our own solicited traffic — no reserve.
    pub(crate) fn try_acquire_reply_work(&self) -> Option<IngressLease> {
        Arc::clone(&self.reply_work_permits)
            .try_acquire_owned()
            .ok()
            .map(|permit| IngressLease {
                _permit: permit,
                _shared: None,
            })
    }

    /// Reserve `len` bytes of the inbound-request receive-body pool. `None` when
    /// the pool is exhausted (the caller must then not allocate the body). An
    /// unauthorized peer also spends `len` bytes of the shared body pool.
    pub(crate) fn try_reserve_request_body(
        &self,
        peer_id: &PeerId,
        len: usize,
    ) -> Option<BodyReservation> {
        let permits = u32::try_from(len).ok()?;
        let shared = match self.shared_slot(&self.shared_request_body_bytes, peer_id, permits) {
            SharedSlot::Reserved => None,
            SharedSlot::Acquired(permit) => Some(permit),
            SharedSlot::Exhausted => return None,
        };
        let permit = Arc::clone(&self.request_body_bytes)
            .try_acquire_many_owned(permits)
            .ok()?;
        Some(BodyReservation {
            _permit: permit,
            _shared: shared,
        })
    }

    /// Reserve `len` bytes of the reply receive-body pool. Separate from the
    /// request pool so a stalled-request backlog cannot starve replies of buffer.
    pub(crate) fn try_reserve_reply_body(&self, len: usize) -> Option<BodyReservation> {
        let permits = u32::try_from(len).ok()?;
        Arc::clone(&self.reply_body_bytes)
            .try_acquire_many_owned(permits)
            .ok()
            .map(|permit| BodyReservation {
                _permit: permit,
                _shared: None,
            })
    }

    /// The shared-pool slot an unauthorized peer must also hold. `Reserved` for
    /// an authorized peer (it draws straight from the full pool); `Acquired` /
    /// `Exhausted` for an unauthorized one.
    fn shared_slot(&self, shared: &Arc<Semaphore>, peer_id: &PeerId, permits: u32) -> SharedSlot {
        if self.is_authorized(peer_id) {
            SharedSlot::Reserved
        } else {
            match Arc::clone(shared).try_acquire_many_owned(permits) {
                Ok(permit) => SharedSlot::Acquired(permit),
                Err(_) => SharedSlot::Exhausted,
            }
        }
    }

    async fn allow(
        &self,
        peer_id: &PeerId,
        charge: impl FnOnce(&mut PeerLimiters) -> bool,
    ) -> bool {
        let mut limiters = self.peer_rate_limiters.lock().await;
        if !limiters.contains_key(peer_id) && limiters.len() >= MAX_TRACKED_RATE_LIMIT_PEERS {
            let now = Instant::now();
            limiters.retain(|_, limiter| !limiter.is_idle(now, RATE_LIMIT_PEER_IDLE_TTL));

            if limiters.len() >= MAX_TRACKED_RATE_LIMIT_PEERS {
                let least_recently_seen = limiters
                    .iter()
                    .min_by_key(|(_, limiter)| limiter.last_seen())
                    .map(|(peer, _)| peer.clone());
                if let Some(peer) = least_recently_seen {
                    limiters.remove(&peer);
                }
            }
        }

        let limit = self.limits.max_events_per_peer_per_second;
        charge(
            limiters
                .entry(peer_id.clone())
                .or_insert_with(|| PeerLimiters::new(limit)),
        )
    }
}

/// Per-peer fixed-window limiters: connection opens, stream opens, decoded
/// frames — each an independent per-second budget.
struct PeerLimiters {
    connection_opens: FixedWindowRateLimiter,
    stream_opens: FixedWindowRateLimiter,
    frames: FixedWindowRateLimiter,
}

impl PeerLimiters {
    fn new(limit: usize) -> Self {
        let one_second = Duration::from_secs(1);
        Self {
            connection_opens: FixedWindowRateLimiter::new(limit, one_second),
            stream_opens: FixedWindowRateLimiter::new(limit, one_second),
            frames: FixedWindowRateLimiter::new(limit, one_second),
        }
    }

    fn last_seen(&self) -> Instant {
        self.connection_opens
            .last_seen
            .max(self.stream_opens.last_seen)
            .max(self.frames.last_seen)
    }

    fn is_idle(&self, now: Instant, idle_ttl: Duration) -> bool {
        self.connection_opens.is_idle(now, idle_ttl)
            && self.stream_opens.is_idle(now, idle_ttl)
            && self.frames.is_idle(now, idle_ttl)
    }
}

struct FixedWindowRateLimiter {
    max_events: usize,
    window: Duration,
    window_start: Instant,
    last_seen: Instant,
    events: usize,
}

impl FixedWindowRateLimiter {
    fn new(max_events: usize, window: Duration) -> Self {
        let now = Instant::now();
        Self {
            max_events,
            window,
            window_start: now,
            last_seen: now,
            events: 0,
        }
    }

    fn allow(&mut self) -> bool {
        let now = Instant::now();
        self.last_seen = now;

        if now.duration_since(self.window_start) >= self.window {
            self.window_start = now;
            self.events = 0;
        }

        if self.events >= self.max_events {
            return false;
        }

        self.events += 1;
        true
    }

    fn is_idle(&self, now: Instant, idle_ttl: Duration) -> bool {
        now.duration_since(self.last_seen) >= idle_ttl
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_window_rate_limiter_rejects_after_limit() {
        let mut limiter = FixedWindowRateLimiter::new(2, Duration::from_secs(60));

        assert!(limiter.allow());
        assert!(limiter.allow());
        assert!(!limiter.allow());
    }

    #[test]
    fn fixed_window_rate_limiter_zero_limit_rejects_all() {
        let mut limiter = FixedWindowRateLimiter::new(0, Duration::from_secs(60));

        assert!(!limiter.allow());
    }

    const MIB: usize = 1024 * 1024;

    fn limits(
        work: usize,
        rate: usize,
        streams: usize,
        per_peer: usize,
        body: usize,
    ) -> NetworkIngressLimits {
        NetworkIngressLimits {
            max_concurrent_work: work,
            // Same as `work` unless a test overrides it via struct-update syntax.
            max_concurrent_reply_work: work,
            max_events_per_peer_per_second: rate,
            // Connection caps reuse the stream cap knobs unless a test overrides.
            max_concurrent_connections: streams,
            max_connections_per_peer: per_peer,
            // Reservation off unless a test opts in via struct-update syntax.
            authorized_reserve_percent: 0,
            max_concurrent_streams: streams,
            max_streams_per_peer: per_peer,
            max_inbound_request_body_bytes: body,
            // Same as the request pool unless a test overrides it.
            max_inbound_reply_body_bytes: body,
        }
    }

    #[tokio::test]
    async fn frame_admission_shares_rate_and_concurrency_state() {
        let controller = IngressController::new(limits(1, 2, 8, 4, MIB), None)
            .expect("nonzero limits construct a controller");
        let peer = PeerId::from_bytes(&[7; 32]);

        let lease = controller
            .try_admit_frame(&peer)
            .await
            .expect("first admission");
        assert_eq!(
            controller.try_admit_frame(&peer).await.unwrap_err(),
            IngressDropReason::ConcurrencyLimit
        );
        drop(lease);
        assert_eq!(
            controller.try_admit_frame(&peer).await.unwrap_err(),
            IngressDropReason::RateLimit
        );
    }

    #[tokio::test]
    async fn stream_admission_enforces_per_peer_then_global_caps() {
        // Rate large enough that only the stream caps bite here.
        let controller =
            IngressController::new(limits(4, 1024, 3, 2, MIB), None).expect("valid limits");
        let a = PeerId::from_bytes(&[1; 32]);
        let b = PeerId::from_bytes(&[2; 32]);

        let a1 = controller.try_admit_stream(&a).await.expect("a stream 1");
        let _a2 = controller.try_admit_stream(&a).await.expect("a stream 2");
        // Peer a is at its per-peer cap of 2 even though the global cap of 3
        // still has a free slot.
        assert_eq!(
            controller.try_admit_stream(&a).await.unwrap_err(),
            StreamAdmitReason::PerPeer
        );

        // A different peer can still take the last global slot.
        let _b1 = controller.try_admit_stream(&b).await.expect("b stream 1");
        assert_eq!(
            controller.try_admit_stream(&b).await.unwrap_err(),
            StreamAdmitReason::Global
        );

        // Releasing one of peer a's streams frees both a per-peer and a global
        // slot for a subsequent admission.
        drop(a1);
        let _a3 = controller
            .try_admit_stream(&a)
            .await
            .expect("a stream after release");
    }

    #[tokio::test]
    async fn stream_admission_rate_limits_opens() {
        let controller =
            IngressController::new(limits(4, 2, 64, 64, MIB), None).expect("valid limits");
        let peer = PeerId::from_bytes(&[3; 32]);

        let _s1 = controller.try_admit_stream(&peer).await.expect("open 1");
        let _s2 = controller.try_admit_stream(&peer).await.expect("open 2");
        // Third open in the same window trips the per-peer stream-open rate,
        // even though both stream caps still have room.
        assert_eq!(
            controller.try_admit_stream(&peer).await.unwrap_err(),
            StreamAdmitReason::Rate
        );
    }

    #[tokio::test]
    async fn connection_admission_enforces_per_peer_then_global_caps() {
        // 3 connections node-wide, 2 per peer; rate high enough not to interfere.
        let controller = IngressController::new(
            NetworkIngressLimits {
                max_concurrent_connections: 3,
                max_connections_per_peer: 2,
                ..limits(4, 1024, 64, 64, MIB)
            },
            None,
        )
        .expect("valid limits");
        let a = PeerId::from_bytes(&[1; 32]);
        let b = PeerId::from_bytes(&[2; 32]);

        let a1 = controller.try_admit_connection(&a).await.expect("a conn 1");
        let _a2 = controller.try_admit_connection(&a).await.expect("a conn 2");
        assert_eq!(
            controller.try_admit_connection(&a).await.unwrap_err(),
            ConnectionAdmitReason::PerPeer
        );
        let _b1 = controller.try_admit_connection(&b).await.expect("b conn 1");
        assert_eq!(
            controller.try_admit_connection(&b).await.unwrap_err(),
            ConnectionAdmitReason::Global
        );

        drop(a1);
        let _a3 = controller
            .try_admit_connection(&a)
            .await
            .expect("a conn after release");
    }

    #[tokio::test]
    async fn connection_admission_rate_limits_opens() {
        let controller = IngressController::new(
            NetworkIngressLimits {
                max_concurrent_connections: 64,
                max_connections_per_peer: 64,
                ..limits(4, 2, 64, 64, MIB)
            },
            None,
        )
        .expect("valid limits");
        let peer = PeerId::from_bytes(&[3; 32]);

        let _c1 = controller
            .try_admit_connection(&peer)
            .await
            .expect("open 1");
        let _c2 = controller
            .try_admit_connection(&peer)
            .await
            .expect("open 2");
        assert_eq!(
            controller.try_admit_connection(&peer).await.unwrap_err(),
            ConnectionAdmitReason::Rate
        );
        // The connection-open limiter is independent of the stream-open one.
        assert!(controller.allow_stream_open(&peer).await);
    }

    #[tokio::test]
    async fn authorized_connection_reserve_protects_the_committee() {
        struct Allowlist(std::collections::HashSet<Vec<u8>>);
        impl AuthorizedPeers for Allowlist {
            fn is_authorized(&self, peer: &PeerId) -> bool {
                self.0.contains(peer.as_bytes())
            }
        }

        let authorized = PeerId::from_bytes(&[7; 32]);
        let oracle: Arc<dyn AuthorizedPeers> = Arc::new(Allowlist(
            [authorized.as_bytes().to_vec()].into_iter().collect(),
        ));

        // 4 total connection slots, 50% reserved → 2 reserved, 2 shared.
        let controller = IngressController::new(
            NetworkIngressLimits {
                max_concurrent_connections: 4,
                max_connections_per_peer: 64,
                authorized_reserve_percent: 50,
                ..limits(4, 1024, 64, 64, MIB)
            },
            Some(oracle),
        )
        .expect("valid limits");

        // Two unauthorized identities fill the shared pool.
        let _u1 = controller
            .try_admit_connection(&PeerId::from_bytes(&[1; 32]))
            .await
            .expect("unauthorized 1");
        let _u2 = controller
            .try_admit_connection(&PeerId::from_bytes(&[2; 32]))
            .await
            .expect("unauthorized 2");
        // A third unauthorized identity is refused even though 2 total slots
        // remain — those are the reserve.
        assert_eq!(
            controller
                .try_admit_connection(&PeerId::from_bytes(&[3; 32]))
                .await
                .unwrap_err(),
            ConnectionAdmitReason::Unauthorized
        );

        // The authorized peer still gets in, twice, from the reserve.
        let _a1 = controller
            .try_admit_connection(&authorized)
            .await
            .expect("authorized 1");
        let _a2 = controller
            .try_admit_connection(&authorized)
            .await
            .expect("authorized 2");
        // Now the whole budget is spent — even the authorized peer is refused.
        assert_eq!(
            controller
                .try_admit_connection(&authorized)
                .await
                .unwrap_err(),
            ConnectionAdmitReason::Global
        );
    }

    #[tokio::test]
    async fn authorized_reserve_protects_stream_body_and_work_pools() {
        struct Allowlist(Vec<u8>);
        impl AuthorizedPeers for Allowlist {
            fn is_authorized(&self, peer: &PeerId) -> bool {
                peer.as_bytes() == self.0
            }
        }
        let vip = PeerId::from_bytes(&[7; 32]);
        let sybil = PeerId::from_bytes(&[9; 32]);
        let oracle: Arc<dyn AuthorizedPeers> = Arc::new(Allowlist(vip.as_bytes().to_vec()));

        // 4 of each pool, 50% reserved → 2 shared, 2 reserved. Rate/per-peer
        // high enough not to interfere.
        let controller = IngressController::new(
            NetworkIngressLimits {
                max_concurrent_streams: 4,
                max_concurrent_work: 4,
                max_inbound_request_body_bytes: 4,
                max_streams_per_peer: 64,
                authorized_reserve_percent: 50,
                ..limits(4, 4096, 64, 64, 4)
            },
            Some(oracle),
        )
        .expect("valid limits");

        // Streams: two unauthorized fill the shared portion; a third is refused
        // while the reserve still has room; the VIP takes the reserve.
        let _s1 = controller
            .try_admit_stream(&sybil)
            .await
            .expect("sybil stream 1");
        let _s2 = controller
            .try_admit_stream(&sybil)
            .await
            .expect("sybil stream 2");
        assert_eq!(
            controller.try_admit_stream(&sybil).await.unwrap_err(),
            StreamAdmitReason::Unauthorized
        );
        let _sv = controller.try_admit_stream(&vip).await.expect("vip stream");

        // Request work permits: same shape.
        let _w1 = controller
            .try_acquire_request_work(&sybil)
            .expect("sybil work 1");
        let _w2 = controller
            .try_acquire_request_work(&sybil)
            .expect("sybil work 2");
        assert!(
            controller.try_acquire_request_work(&sybil).is_none(),
            "unauthorized work is capped at the shared portion"
        );
        assert!(
            controller.try_acquire_request_work(&vip).is_some(),
            "the VIP draws work from the reserve"
        );

        // Request body bytes: same shape (1 byte each of a 4-byte pool).
        let _b1 = controller
            .try_reserve_request_body(&sybil, 1)
            .expect("sybil body 1");
        let _b2 = controller
            .try_reserve_request_body(&sybil, 1)
            .expect("sybil body 2");
        assert!(
            controller.try_reserve_request_body(&sybil, 1).is_none(),
            "unauthorized body bytes are capped at the shared portion"
        );
        assert!(
            controller.try_reserve_request_body(&vip, 1).is_some(),
            "the VIP draws body bytes from the reserve"
        );
    }

    #[test]
    fn new_rejects_reserve_percent_over_100() {
        let bad = NetworkIngressLimits {
            authorized_reserve_percent: 101,
            ..limits(4, 1024, 64, 64, MIB)
        };
        let Err(error) = IngressController::new(bad, None) else {
            panic!("a reserve percent over 100 must be rejected");
        };
        assert!(matches!(error, NetworkError::InvalidConfig(_)));
    }

    #[test]
    fn request_and_reply_work_budgets_are_independent() {
        // One request permit, four reply permits.
        let controller = IngressController::new(
            NetworkIngressLimits {
                max_concurrent_reply_work: 4,
                ..limits(1, 1024, 8, 8, MIB)
            },
            None,
        )
        .expect("valid limits");

        // No oracle → every peer is authorized → the shared gate is a no-op.
        let peer = PeerId::from_bytes(&[0; 32]);

        // The single request permit can be fully held...
        let _request = controller
            .try_acquire_request_work(&peer)
            .expect("request work permit");
        assert!(
            controller.try_acquire_request_work(&peer).is_none(),
            "request budget is exhausted"
        );

        // ...without starving replies, which draw on their own budget.
        let _r1 = controller.try_acquire_reply_work().expect("reply permit 1");
        let _r2 = controller.try_acquire_reply_work().expect("reply permit 2");
        let _r3 = controller.try_acquire_reply_work().expect("reply permit 3");
        let _r4 = controller.try_acquire_reply_work().expect("reply permit 4");
        assert!(
            controller.try_acquire_reply_work().is_none(),
            "reply budget is independently bounded"
        );
    }

    #[tokio::test]
    async fn stream_open_and_frame_rates_are_separate_limiters() {
        // Rate 1: one stream open AND one frame are both allowed in a window.
        let controller =
            IngressController::new(limits(4, 1, 8, 8, MIB), None).expect("valid limits");
        let peer = PeerId::from_bytes(&[5; 32]);

        assert!(controller.allow_stream_open(&peer).await, "first open");
        assert!(
            controller.allow_frame(&peer).await,
            "a one-frame request is not double-charged by the open"
        );
        // Second of each in the same window is refused.
        assert!(!controller.allow_stream_open(&peer).await);
        assert!(!controller.allow_frame(&peer).await);
    }

    #[test]
    fn request_and_reply_body_pools_bound_bytes_independently() {
        // Request pool 100 bytes, reply pool 50 bytes.
        let controller = IngressController::new(
            NetworkIngressLimits {
                max_inbound_reply_body_bytes: 50,
                ..limits(4, 1024, 8, 8, 100)
            },
            None,
        )
        .expect("valid limits");
        let peer = PeerId::from_bytes(&[0; 32]);

        // Fill the request pool completely.
        let req = controller
            .try_reserve_request_body(&peer, 100)
            .expect("first 100 request bytes fit");
        assert!(
            controller.try_reserve_request_body(&peer, 1).is_none(),
            "request pool is exhausted"
        );
        // A reply still gets its buffer from the separate reply pool.
        let reply = controller
            .try_reserve_reply_body(50)
            .expect("reply pool is untouched by the request backlog");
        assert!(controller.try_reserve_reply_body(1).is_none());

        drop(req);
        drop(reply);
        let _again = controller
            .try_reserve_request_body(&peer, 100)
            .expect("request pool frees when its reservation drops");
    }

    #[tokio::test]
    async fn stream_lease_drop_forgets_idle_peer() {
        let controller =
            IngressController::new(limits(4, 1024, 8, 2, MIB), None).expect("valid limits");
        let peer = PeerId::from_bytes(&[9; 32]);

        let lease = controller.try_admit_stream(&peer).await.expect("stream");
        assert_eq!(
            controller
                .peer_stream_counts
                .lock()
                .unwrap()
                .get(&peer)
                .copied(),
            Some(1)
        );
        drop(lease);
        assert!(!controller
            .peer_stream_counts
            .lock()
            .unwrap()
            .contains_key(&peer));
    }

    #[test]
    fn new_rejects_zero_limits() {
        for bad in [
            limits(0, 2, 8, 4, MIB),
            limits(1, 0, 8, 4, MIB),
            limits(1, 2, 0, 4, MIB),
            limits(1, 2, 8, 0, MIB),
            limits(1, 2, 8, 4, 0),
            NetworkIngressLimits {
                max_concurrent_reply_work: 0,
                ..limits(1, 2, 8, 4, MIB)
            },
            NetworkIngressLimits {
                max_inbound_reply_body_bytes: 0,
                ..limits(1, 2, 8, 4, MIB)
            },
            NetworkIngressLimits {
                max_concurrent_connections: 0,
                ..limits(1, 2, 8, 4, MIB)
            },
            NetworkIngressLimits {
                max_connections_per_peer: 0,
                ..limits(1, 2, 8, 4, MIB)
            },
        ] {
            let Err(error) = IngressController::new(bad, None) else {
                panic!("zero limit must be rejected: {bad:?}");
            };
            assert!(matches!(error, NetworkError::InvalidConfig(_)));
        }
    }
}
