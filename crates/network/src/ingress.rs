//! Shared ingress admission for direct streams and authenticated PubSub frames.
//!
//! Independent limits, deliberately kept separate:
//!
//! * [`IngressController::try_admit_stream`] — one slot per accepted inbound
//!   QUIC stream, held for the stream's whole lifetime, and one peer-rate tick
//!   for the open itself. Bounds how many streams can be parked in `recv()` at
//!   once, node-wide and per immediate peer, and the rate at which a peer may
//!   open them.
//! * [`IngressController::charge_peer_rate`] — one peer-rate tick per `recv()`
//!   attempt, charged before any bytes are read so malformed, oversized, and
//!   timed-out frames that never decode still cost the peer its budget.
//! * [`IngressController::try_reserve_body`] — a weighted receive-byte budget,
//!   reserved after the length prefix is parsed but before the body buffer is
//!   allocated, so a flood of large frames cannot commit gigabytes ahead of the
//!   work-item cap.
//! * [`IngressController::try_acquire_work`] — one slot per *decoded frame*,
//!   held only while the application processes it. Bounds real work.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

use crate::error::NetworkError;
use crate::r#trait::{IngressDropReason, NetworkIngressLimits, PeerId};

const MAX_TRACKED_RATE_LIMIT_PEERS: usize = 8192;
const RATE_LIMIT_PEER_IDLE_TTL: Duration = Duration::from_secs(60);

/// RAII ownership of one global ingress work permit, released when the
/// application finishes with the frame it was admitted for.
#[derive(Debug)]
pub(crate) struct IngressLease {
    _permit: OwnedSemaphorePermit,
}

/// RAII ownership of the node-wide receive-byte budget for one inbound frame
/// body. Held for the lifetime of the resulting [`crate::Message`] so the budget
/// bounds bytes *received and not yet processed*, not merely bytes in transit.
#[derive(Debug)]
pub(crate) struct BodyReservation {
    _permit: OwnedSemaphorePermit,
}

/// Why a newly accepted inbound stream was refused before any frame was read.
///
/// Distinct from [`IngressDropReason`], which is a per-frame signal surfaced to
/// PubSub subscribers; a stream refusal never reaches the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamAdmitReason {
    /// The node-wide concurrent inbound-stream budget is exhausted.
    Global,
    /// This immediate peer already holds the maximum concurrent inbound streams.
    PerPeer,
    /// This immediate peer is opening streams faster than its per-second budget.
    Rate,
}

impl StreamAdmitReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Global => "stream_limit",
            Self::PerPeer => "per_peer_stream_limit",
            Self::Rate => "stream_rate_limit",
        }
    }
}

/// RAII ownership of one accepted inbound stream slot: one node-wide stream
/// permit plus one unit of this peer's concurrent-stream budget. Both are
/// returned when the stream's handler task ends.
#[derive(Debug)]
pub(crate) struct StreamLease {
    _global: OwnedSemaphorePermit,
    peer: PeerId,
    per_peer: Arc<StdMutex<HashMap<PeerId, usize>>>,
}

impl Drop for StreamLease {
    fn drop(&mut self) {
        let mut counts = self
            .per_peer
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

/// One admission controller shared by every direct ALPN handler and PubSub topic.
pub(crate) struct IngressController {
    limits: NetworkIngressLimits,
    /// Bounds inbound frames whose application work is currently executing.
    work_permits: Arc<Semaphore>,
    /// Bounds accepted-but-not-yet-closed inbound streams node-wide.
    stream_permits: Arc<Semaphore>,
    /// Weighted budget (in bytes) for inbound frame bodies received and not yet
    /// dropped by the application.
    body_bytes: Arc<Semaphore>,
    peer_rate_limiters: Mutex<HashMap<PeerId, FixedWindowRateLimiter>>,
    /// Concurrent inbound stream count per immediate peer.
    peer_stream_counts: Arc<StdMutex<HashMap<PeerId, usize>>>,
}

impl IngressController {
    pub(crate) fn new(limits: NetworkIngressLimits) -> Result<Self, NetworkError> {
        // A zero limit does not "limit" its path — it wedges it shut forever
        // (`Semaphore::new(0)` never admits; a zero rate rejects every peer).
        // Reject each at construction instead of silently building a controller
        // that can never admit anything.
        if limits.max_concurrent_work == 0 {
            return Err(NetworkError::InvalidConfig(
                "max_concurrent_work must be at least 1".to_string(),
            ));
        }
        if limits.max_events_per_peer_per_second == 0 {
            return Err(NetworkError::InvalidConfig(
                "max_events_per_peer_per_second must be at least 1".to_string(),
            ));
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
        if limits.max_inbound_body_bytes == 0 {
            return Err(NetworkError::InvalidConfig(
                "max_inbound_body_bytes must be at least 1".to_string(),
            ));
        }
        let body_bytes = limits.max_inbound_body_bytes.min(Semaphore::MAX_PERMITS);
        Ok(Self {
            limits,
            work_permits: Arc::new(Semaphore::new(limits.max_concurrent_work)),
            stream_permits: Arc::new(Semaphore::new(limits.max_concurrent_streams)),
            body_bytes: Arc::new(Semaphore::new(body_bytes)),
            peer_rate_limiters: Mutex::new(HashMap::new()),
            peer_stream_counts: Arc::new(StdMutex::new(HashMap::new())),
        })
    }

    /// Admit one newly accepted inbound QUIC stream without queueing.
    ///
    /// The peer's per-second budget is charged first — before the caps — so a
    /// peer that is refused for being at its stream cap still pays for the open
    /// attempt, and a peer opening streams too fast is rejected outright. The
    /// node-wide permit is taken next, the per-peer slot last, so an early
    /// return from the per-peer check drops (and thereby releases) the node-wide
    /// permit.
    pub(crate) async fn try_admit_stream(
        &self,
        peer_id: &PeerId,
    ) -> Result<StreamLease, StreamAdmitReason> {
        if !self.charge_peer_rate(peer_id).await {
            return Err(StreamAdmitReason::Rate);
        }

        let global = Arc::clone(&self.stream_permits)
            .try_acquire_owned()
            .map_err(|_| StreamAdmitReason::Global)?;

        {
            let mut counts = self
                .peer_stream_counts
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            let open = counts.entry(peer_id.clone()).or_insert(0);
            if *open >= self.limits.max_streams_per_peer {
                return Err(StreamAdmitReason::PerPeer);
            }
            *open += 1;
        }

        Ok(StreamLease {
            _global: global,
            peer: peer_id.clone(),
            per_peer: Arc::clone(&self.peer_stream_counts),
        })
    }

    /// Admit one decoded inbound frame without queueing: charge the peer rate,
    /// then take a work permit. Used by the PubSub topic path, where a frame is
    /// already fully materialized by Gossip and there is nothing to size a
    /// receive-byte reservation against.
    pub(crate) async fn try_admit_frame(
        &self,
        peer_id: &PeerId,
    ) -> Result<IngressLease, IngressDropReason> {
        if !self.charge_peer_rate(peer_id).await {
            return Err(IngressDropReason::RateLimit);
        }
        self.try_acquire_work()
            .ok_or(IngressDropReason::ConcurrencyLimit)
    }

    /// Charge one unit of the peer's per-second activity budget. Returns `false`
    /// when the peer is over budget for the current window. Every inbound
    /// `recv()` attempt and every inbound stream open charges once.
    pub(crate) async fn charge_peer_rate(&self, peer_id: &PeerId) -> bool {
        self.allow_peer(peer_id).await
    }

    /// Take one node-wide work permit for a frame whose application work is
    /// about to run. `None` when the budget is exhausted.
    pub(crate) fn try_acquire_work(&self) -> Option<IngressLease> {
        Arc::clone(&self.work_permits)
            .try_acquire_owned()
            .ok()
            .map(|permit| IngressLease { _permit: permit })
    }

    /// Reserve `len` bytes of the node-wide receive-body budget. `None` when the
    /// budget is exhausted (the caller must then not allocate the body). A
    /// zero-length body reserves nothing but still yields a reservation.
    pub(crate) fn try_reserve_body(&self, len: usize) -> Option<BodyReservation> {
        let permits = u32::try_from(len).ok()?;
        Arc::clone(&self.body_bytes)
            .try_acquire_many_owned(permits)
            .ok()
            .map(|permit| BodyReservation { _permit: permit })
    }

    async fn allow_peer(&self, peer_id: &PeerId) -> bool {
        let mut limiters = self.peer_rate_limiters.lock().await;
        if !limiters.contains_key(peer_id) && limiters.len() >= MAX_TRACKED_RATE_LIMIT_PEERS {
            let now = Instant::now();
            limiters.retain(|_, limiter| !limiter.is_idle(now, RATE_LIMIT_PEER_IDLE_TTL));

            if limiters.len() >= MAX_TRACKED_RATE_LIMIT_PEERS {
                let least_recently_seen = limiters
                    .iter()
                    .min_by_key(|(_, limiter)| limiter.last_seen)
                    .map(|(peer, _)| peer.clone());
                if let Some(peer) = least_recently_seen {
                    limiters.remove(&peer);
                }
            }
        }

        let limit = self.limits.max_events_per_peer_per_second;
        limiters
            .entry(peer_id.clone())
            .or_insert_with(|| FixedWindowRateLimiter::new(limit, Duration::from_secs(1)))
            .allow()
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
            max_events_per_peer_per_second: rate,
            max_concurrent_streams: streams,
            max_streams_per_peer: per_peer,
            max_inbound_body_bytes: body,
        }
    }

    #[tokio::test]
    async fn frame_admission_shares_rate_and_concurrency_state() {
        let controller = IngressController::new(limits(1, 2, 8, 4, MIB))
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
        let controller = IngressController::new(limits(4, 1024, 3, 2, MIB)).expect("valid limits");
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
        let controller = IngressController::new(limits(4, 2, 64, 64, MIB)).expect("valid limits");
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

    #[test]
    fn body_reservation_bounds_total_inflight_bytes() {
        let controller = IngressController::new(limits(4, 1024, 8, 8, 100)).expect("valid limits");

        let first = controller.try_reserve_body(60).expect("first 60 bytes fit");
        assert!(
            controller.try_reserve_body(60).is_none(),
            "only 40 of 100 bytes remain"
        );
        // A body the budget cannot cover under any circumstance is refused.
        assert!(controller.try_reserve_body(101).is_none());
        drop(first);
        let _second = controller
            .try_reserve_body(60)
            .expect("budget frees when the first reservation drops");
    }

    #[tokio::test]
    async fn stream_lease_drop_forgets_idle_peer() {
        let controller = IngressController::new(limits(4, 1024, 8, 2, MIB)).expect("valid limits");
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
        ] {
            let Err(error) = IngressController::new(bad) else {
                panic!("zero limit must be rejected: {bad:?}");
            };
            assert!(matches!(error, NetworkError::InvalidConfig(_)));
        }
    }
}
