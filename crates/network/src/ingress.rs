//! Shared ingress admission for direct streams and authenticated PubSub frames.
//!
//! Two independent limits, deliberately kept separate:
//!
//! * [`IngressController::try_admit_stream`] — one slot per accepted inbound
//!   QUIC stream, held for the stream's whole lifetime. Bounds how many streams
//!   can be parked in `recv()` at once, node-wide and per immediate peer. A
//!   parked stream does no CPU work, so this budget is cheap and generous.
//! * [`IngressController::try_admit_frame`] — one slot per *decoded frame*, held
//!   only while the application processes that frame. Bounds real work, and
//!   charges the per-peer rate budget once per message rather than once per
//!   stream.

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

/// Why a newly accepted inbound stream was refused before any frame was read.
///
/// Distinct from [`IngressDropReason`], which is a per-frame signal surfaced to
/// PubSub subscribers; a stream refusal never reaches the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamAdmitReason {
    /// The node-wide concurrent inbound-stream budget is exhausted.
    GlobalStreamLimit,
    /// This immediate peer already holds the maximum concurrent inbound streams.
    PerPeerStreamLimit,
}

impl StreamAdmitReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::GlobalStreamLimit => "stream_limit",
            Self::PerPeerStreamLimit => "per_peer_stream_limit",
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
        Ok(Self {
            limits,
            work_permits: Arc::new(Semaphore::new(limits.max_concurrent_work)),
            stream_permits: Arc::new(Semaphore::new(limits.max_concurrent_streams)),
            peer_rate_limiters: Mutex::new(HashMap::new()),
            peer_stream_counts: Arc::new(StdMutex::new(HashMap::new())),
        })
    }

    /// Admit one newly accepted inbound QUIC stream without queueing.
    ///
    /// The node-wide permit is taken first; the per-peer slot second, so an
    /// early return from the per-peer check drops (and thereby releases) the
    /// node-wide permit.
    pub(crate) fn try_admit_stream(
        &self,
        peer_id: &PeerId,
    ) -> Result<StreamLease, StreamAdmitReason> {
        let global = Arc::clone(&self.stream_permits)
            .try_acquire_owned()
            .map_err(|_| StreamAdmitReason::GlobalStreamLimit)?;

        {
            let mut counts = self
                .peer_stream_counts
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            let open = counts.entry(peer_id.clone()).or_insert(0);
            if *open >= self.limits.max_streams_per_peer {
                return Err(StreamAdmitReason::PerPeerStreamLimit);
            }
            *open += 1;
        }

        Ok(StreamLease {
            _global: global,
            peer: peer_id.clone(),
            per_peer: Arc::clone(&self.peer_stream_counts),
        })
    }

    /// Admit one decoded inbound frame without queueing.
    ///
    /// Charged once per frame: a long-lived stream that keeps sending frames
    /// keeps spending its per-peer rate budget, so per-peer admission is per
    /// message, not per stream. Rate admission happens before concurrency
    /// admission; a rejected concurrency attempt still consumes the peer's rate
    /// budget for the current window.
    pub(crate) async fn try_admit_frame(
        &self,
        peer_id: &PeerId,
    ) -> Result<IngressLease, IngressDropReason> {
        if !self.allow_peer(peer_id).await {
            return Err(IngressDropReason::RateLimit);
        }

        let permit = Arc::clone(&self.work_permits)
            .try_acquire_owned()
            .map_err(|_| IngressDropReason::ConcurrencyLimit)?;
        Ok(IngressLease { _permit: permit })
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

    fn limits(work: usize, rate: usize, streams: usize, per_peer: usize) -> NetworkIngressLimits {
        NetworkIngressLimits {
            max_concurrent_work: work,
            max_events_per_peer_per_second: rate,
            max_concurrent_streams: streams,
            max_streams_per_peer: per_peer,
        }
    }

    #[tokio::test]
    async fn frame_admission_shares_rate_and_concurrency_state() {
        let controller = IngressController::new(limits(1, 2, 8, 4))
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

    #[test]
    fn stream_admission_enforces_per_peer_then_global_caps() {
        let controller = IngressController::new(limits(4, 4, 3, 2)).expect("valid limits");
        let a = PeerId::from_bytes(&[1; 32]);
        let b = PeerId::from_bytes(&[2; 32]);

        let a1 = controller.try_admit_stream(&a).expect("a stream 1");
        let _a2 = controller.try_admit_stream(&a).expect("a stream 2");
        // Peer a is at its per-peer cap of 2 even though the global cap of 3
        // still has a free slot.
        assert_eq!(
            controller.try_admit_stream(&a).unwrap_err(),
            StreamAdmitReason::PerPeerStreamLimit
        );

        // A different peer can still take the last global slot.
        let _b1 = controller.try_admit_stream(&b).expect("b stream 1");
        assert_eq!(
            controller.try_admit_stream(&b).unwrap_err(),
            StreamAdmitReason::GlobalStreamLimit
        );

        // Releasing one of peer a's streams frees both a per-peer and a global
        // slot for a subsequent admission.
        drop(a1);
        let _a3 = controller
            .try_admit_stream(&a)
            .expect("a stream after release");
    }

    #[test]
    fn stream_lease_drop_forgets_idle_peer() {
        let controller = IngressController::new(limits(4, 4, 8, 2)).expect("valid limits");
        let peer = PeerId::from_bytes(&[9; 32]);

        let lease = controller.try_admit_stream(&peer).expect("stream");
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
            limits(0, 2, 8, 4),
            limits(1, 0, 8, 4),
            limits(1, 2, 0, 4),
            limits(1, 2, 8, 0),
        ] {
            let Err(error) = IngressController::new(bad) else {
                panic!("zero limit must be rejected: {bad:?}");
            };
            assert!(matches!(error, NetworkError::InvalidConfig(_)));
        }
    }
}
