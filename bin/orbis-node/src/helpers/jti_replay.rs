//! Single-use enforcement for client JWTs.
//!
//! Every JWT [`authn::jwt_builder::JwtSigner`] issues carries a random `jti`
//! ([`authn::BearerToken::jwt_id`]). [`JtiReplayGuard`] records each `jti` the
//! first time this node accepts it and rejects any later request that reuses it,
//! so an observed token cannot be replayed within its validity window.
//!
//! Placement (see `docs/security-review-findings.md` SEC-03):
//! - client entrypoints: `start_pre`, `start_sign`, `store_secret`;
//! - responder handlers that see the forwarded token exactly once:
//!   `handle_reencrypt_request` (PRE), `handle_nonce_request` (Sign FROST Round 1).
//!
//! **Not** `handle_sign_request` (FROST Round 2): it legitimately re-presents the
//! same token, and is already single-use via the atomic nonce consume bound to
//! the Round 1 coordinator peer.
//!
//! The guard is per-node. It stops a client replaying to the same node and a
//! malicious coordinator / ring insider replaying a captured forwarded request
//! to responders. A replay routed through a fourth ring member that was not
//! involved in the original round is not covered — that needs committee-shared
//! `jti` state.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;

use crate::constants::{
    JTI_EXPIRATION_CHECK_INTERVAL, JWT_CLOCK_SKEW_LEEWAY_SECS, MAX_JTI_ENTRIES,
    MAX_TOKEN_LIFETIME_SECS,
};
use crate::metrics;

/// Why the replay guard rejected a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayError {
    /// The `jti` was already accepted by this node.
    AlreadyUsed,
    /// The token carries no `jti` (minted before the field existed, or forged).
    MissingJti,
}

impl ReplayError {
    fn reason(self) -> &'static str {
        match self {
            ReplayError::AlreadyUsed => "already_used",
            ReplayError::MissingJti => "missing_jti",
        }
    }
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplayError::AlreadyUsed => write!(f, "token has already been used"),
            ReplayError::MissingJti => write!(f, "token is missing a jti (id) claim"),
        }
    }
}

/// How a `jti` was recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// Recorded with room to spare.
    Recorded,
    /// Recorded only after evicting the oldest (still-unexpired) entry because the
    /// map was at [`MAX_JTI_ENTRIES`]. The evicted id is replayable until its own
    /// token expires — the caller warns.
    RecordedAfterEvicting,
}

/// Records accepted JWT ids and rejects reuse. One per node, held in `AppState`.
pub struct JtiReplayGuard {
    /// `jti` -> the instant the entry may be swept (token `exp` + clock skew).
    seen: Arc<RwLock<HashMap<String, Instant>>>,
}

impl Default for JtiReplayGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl JtiReplayGuard {
    pub fn new() -> Self {
        let seen = Arc::new(RwLock::new(HashMap::new()));
        let sweep = seen.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(JTI_EXPIRATION_CHECK_INTERVAL);
            loop {
                interval.tick().await;
                let mut map = sweep.write().await;
                let before = map.len();
                Self::sweep_expired(&mut map, Instant::now());
                let removed = before - map.len();
                if removed > 0 {
                    tracing::debug!(
                        removed,
                        remaining = map.len(),
                        "JtiReplayGuard: swept expired token ids"
                    );
                }
            }
        });
        Self { seen }
    }

    /// Accept `jti` for `site`, or reject it as a replay / missing id.
    ///
    /// `token_exp_unix` is the JWT `exp` (unix seconds); the entry is retained
    /// until then, clamped to [`MAX_TOKEN_LIFETIME_SECS`] and padded by the
    /// clock-skew leeway, then swept.
    pub async fn check_and_record(
        &self,
        jti: &str,
        token_exp_unix: u64,
        site: &str,
    ) -> Result<(), ReplayError> {
        if jti.is_empty() {
            metrics::record_jwt_replay_rejected(ReplayError::MissingJti.reason(), site);
            return Err(ReplayError::MissingJti);
        }
        let now = Instant::now();
        let deadline = now + Self::retention(token_exp_unix);
        let mut map = self.seen.write().await;
        Self::sweep_expired(&mut map, now);
        match Self::try_record(&mut map, jti, deadline, now) {
            Err(error) => {
                metrics::record_jwt_replay_rejected(error.reason(), site);
                Err(error)
            }
            Ok(Outcome::Recorded) => Ok(()),
            Ok(Outcome::RecordedAfterEvicting) => {
                // The map hit MAX_JTI_ENTRIES and an unexpired id was dropped to
                // make room — that id is now replayable until its own token
                // expires. Raise the cap, shard, or investigate the token rate.
                tracing::warn!(
                    site = %site,
                    capacity = MAX_JTI_ENTRIES,
                    "JtiReplayGuard at capacity: evicted a still-valid token id to record a new one"
                );
                Ok(())
            }
        }
    }

    /// How long a `jti` stays on record: `exp - now`, clamped to the max token
    /// lifetime, plus the clock-skew leeway.
    fn retention(token_exp_unix: u64) -> Duration {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let secs = token_exp_unix
            .saturating_sub(now_unix)
            .min(MAX_TOKEN_LIFETIME_SECS)
            .saturating_add(JWT_CLOCK_SKEW_LEEWAY_SECS);
        Duration::from_secs(secs)
    }

    /// Core insert: sweep, reject a duplicate, evict the oldest entry if the map
    /// is full, then record. Split out so it can be unit tested with controlled
    /// `Instant`s.
    fn try_record(
        map: &mut HashMap<String, Instant>,
        jti: &str,
        deadline: Instant,
        now: Instant,
    ) -> Result<Outcome, ReplayError> {
        Self::try_record_with_cap(map, jti, deadline, now, MAX_JTI_ENTRIES)
    }

    /// [`try_record`] with an explicit capacity, so the eviction branch can be
    /// unit-tested without inserting a million entries.
    fn try_record_with_cap(
        map: &mut HashMap<String, Instant>,
        jti: &str,
        deadline: Instant,
        now: Instant,
        max_entries: usize,
    ) -> Result<Outcome, ReplayError> {
        Self::sweep_expired(map, now);
        if map.contains_key(jti) {
            return Err(ReplayError::AlreadyUsed);
        }
        let mut outcome = Outcome::Recorded;
        if map.len() >= max_entries {
            if let Some(oldest) = map
                .iter()
                .min_by_key(|(_, expiry)| **expiry)
                .map(|(key, _)| key.clone())
            {
                map.remove(&oldest);
                outcome = Outcome::RecordedAfterEvicting;
            }
        }
        map.insert(jti.to_string(), deadline);
        Ok(outcome)
    }

    fn sweep_expired(map: &mut HashMap<String, Instant>, now: Instant) {
        map.retain(|_, expiry| *expiry > now);
    }

    #[cfg(test)]
    pub(crate) async fn len(&self) -> usize {
        self.seen.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map() -> HashMap<String, Instant> {
        HashMap::new()
    }

    #[test]
    fn first_use_is_recorded_then_reuse_is_rejected() {
        let mut m = map();
        let now = Instant::now();
        let deadline = now + Duration::from_secs(3600);

        assert_eq!(
            JtiReplayGuard::try_record(&mut m, "abc", deadline, now),
            Ok(Outcome::Recorded)
        );
        assert_eq!(
            JtiReplayGuard::try_record(&mut m, "abc", deadline, now),
            Err(ReplayError::AlreadyUsed)
        );
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn a_distinct_jti_is_accepted() {
        let mut m = map();
        let now = Instant::now();
        let deadline = now + Duration::from_secs(3600);
        assert!(JtiReplayGuard::try_record(&mut m, "a", deadline, now).is_ok());
        assert!(JtiReplayGuard::try_record(&mut m, "b", deadline, now).is_ok());
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn expired_entries_are_swept_and_the_jti_becomes_reusable() {
        let mut m = map();
        let t0 = Instant::now();
        let deadline = t0 + Duration::from_secs(10);
        assert!(JtiReplayGuard::try_record(&mut m, "abc", deadline, t0).is_ok());

        // Same instant: still on record.
        assert_eq!(
            JtiReplayGuard::try_record(&mut m, "abc", deadline, t0),
            Err(ReplayError::AlreadyUsed)
        );

        // Past the deadline: swept, so it can be recorded again.
        let later = t0 + Duration::from_secs(20);
        assert!(
            JtiReplayGuard::try_record(&mut m, "abc", later + Duration::from_secs(10), later)
                .is_ok()
        );
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn at_capacity_the_oldest_entry_is_evicted() {
        // Small explicit cap — the real MAX_JTI_ENTRIES is 1M and `try_record`
        // is O(n) per call (the per-call `sweep_expired`), so filling it for real
        // is O(n^2) and takes hours.
        const CAP: usize = 8;
        let mut m = map();
        let now = Instant::now();
        for i in 0..CAP {
            // Strictly increasing deadlines so entry 0 is unambiguously oldest.
            let deadline = now + Duration::from_secs(3600 + i as u64);
            JtiReplayGuard::try_record_with_cap(&mut m, &format!("jti-{i}"), deadline, now, CAP)
                .unwrap();
        }
        assert_eq!(m.len(), CAP);

        let deadline = now + Duration::from_secs(3600 + CAP as u64);
        assert_eq!(
            JtiReplayGuard::try_record_with_cap(&mut m, "newcomer", deadline, now, CAP),
            Ok(Outcome::RecordedAfterEvicting)
        );

        assert_eq!(m.len(), CAP);
        assert!(
            !m.contains_key("jti-0"),
            "oldest entry should have been evicted"
        );
        assert!(m.contains_key("newcomer"));
    }

    #[tokio::test]
    async fn guard_rejects_empty_jti_and_then_reuse() {
        let guard = JtiReplayGuard::new();
        assert_eq!(
            guard.check_and_record("", 4_000_000_000, "test").await,
            Err(ReplayError::MissingJti)
        );
        assert!(guard
            .check_and_record("deadbeef", 4_000_000_000, "test")
            .await
            .is_ok());
        assert_eq!(
            guard
                .check_and_record("deadbeef", 4_000_000_000, "test")
                .await,
            Err(ReplayError::AlreadyUsed)
        );
        assert_eq!(guard.len().await, 1);
    }
}
