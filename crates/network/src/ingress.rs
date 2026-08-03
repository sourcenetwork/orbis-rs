//! Shared ingress admission for direct streams and authenticated PubSub frames.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

use crate::error::NetworkError;
use crate::r#trait::{IngressDropReason, NetworkIngressLimits, PeerId};

const MAX_TRACKED_RATE_LIMIT_PEERS: usize = 8192;
const RATE_LIMIT_PEER_IDLE_TTL: Duration = Duration::from_secs(60);

/// RAII ownership of one global ingress work permit.
#[derive(Debug)]
pub(crate) struct IngressLease {
    _permit: OwnedSemaphorePermit,
}

/// One admission controller shared by every direct ALPN handler and PubSub topic.
pub(crate) struct IngressController {
    limits: NetworkIngressLimits,
    permits: Arc<Semaphore>,
    peer_rate_limiters: Mutex<HashMap<PeerId, FixedWindowRateLimiter>>,
}

impl IngressController {
    pub(crate) fn new(limits: NetworkIngressLimits) -> Result<Self, NetworkError> {
        // A zero `max_concurrent_work` builds a `Semaphore::new(0)`: every
        // `try_acquire_owned` would fail forever, permanently wedging all
        // ingress work rather than just limiting it. A zero
        // `max_events_per_peer_per_second` similarly rejects every peer
        // outright. Neither is a sane "limit" — reject them at construction
        // instead of silently building a controller that can never admit
        // anything.
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
        Ok(Self {
            limits,
            permits: Arc::new(Semaphore::new(limits.max_concurrent_work)),
            peer_rate_limiters: Mutex::new(HashMap::new()),
        })
    }

    /// Admit one unit of authenticated-peer ingress without queueing.
    ///
    /// Rate admission intentionally happens before concurrency admission, matching
    /// the previous direct-stream behavior. A rejected concurrency attempt still
    /// consumes the peer's rate budget for the current window.
    pub(crate) async fn try_admit(
        &self,
        peer_id: &PeerId,
    ) -> Result<IngressLease, IngressDropReason> {
        if !self.allow_peer(peer_id).await {
            return Err(IngressDropReason::RateLimit);
        }

        let permit = Arc::clone(&self.permits)
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

    #[tokio::test]
    async fn controller_shares_rate_and_concurrency_state() {
        let controller = IngressController::new(NetworkIngressLimits {
            max_concurrent_work: 1,
            max_events_per_peer_per_second: 2,
        })
        .expect("nonzero limits construct a controller");
        let peer = PeerId::from_bytes(&[7; 32]);

        let lease = controller.try_admit(&peer).await.expect("first admission");
        assert_eq!(
            controller.try_admit(&peer).await.unwrap_err(),
            IngressDropReason::ConcurrencyLimit
        );
        drop(lease);
        assert_eq!(
            controller.try_admit(&peer).await.unwrap_err(),
            IngressDropReason::RateLimit
        );
    }

    #[test]
    fn new_rejects_zero_max_concurrent_work() {
        let Err(error) = IngressController::new(NetworkIngressLimits {
            max_concurrent_work: 0,
            max_events_per_peer_per_second: 2,
        }) else {
            panic!("zero max_concurrent_work must be rejected");
        };
        assert!(matches!(error, NetworkError::InvalidConfig(_)));
    }

    #[test]
    fn new_rejects_zero_max_events_per_peer_per_second() {
        let Err(error) = IngressController::new(NetworkIngressLimits {
            max_concurrent_work: 1,
            max_events_per_peer_per_second: 0,
        }) else {
            panic!("zero max_events_per_peer_per_second must be rejected");
        };
        assert!(matches!(error, NetworkError::InvalidConfig(_)));
    }
}
