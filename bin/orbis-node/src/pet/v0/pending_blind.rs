//! Responder-side one-use secret state for the PET blind equality test
//! (audit finding #2) — holds a freshly generated blinding scalar `z_i` and
//! its commitment-opening salt between round 1 (commit) and round 2
//! (reveal). Nothing in this codebase held secret state across two separate
//! incoming requests before this: FROST's own `SigningState` is held by the
//! *initiator* within one call stack, not by a responder between messages.
//!
//! Mirrors `sign::v0::response_state`'s FROST nonce-state store almost
//! exactly — same problem (secret state spanning two rounds, bound to a
//! context key, consumed exactly once, TTL-bounded) — including its
//! belt-and-suspenders double check: an entry is bound to both a
//! `context_digest` (recomputed and compared by the caller at reveal time)
//! and the raw authenticated peer that committed it (`coordinator_peer_id`,
//! checked here), so neither a mismatched context nor a different relaying
//! node can consume it.

use crate::constants::{
    MAX_PET_BLIND_PENDING, PET_BLIND_EXPIRATION_CHECK_INTERVAL, PET_BLIND_PENDING_TTL,
};
use crypto::ScalarField as Fr;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use zeroize::Zeroizing;

/// One responder's pending blinding contribution, held between commit and
/// reveal.
pub(crate) struct PendingBlinding {
    pub(crate) z_i: Zeroizing<Fr>,
    pub(crate) commit_salt: [u8; 32],
    pub(crate) node_id: u32,
    /// Bound at commit time from independently verified inputs; the reveal
    /// handler recomputes its own `context_digest` from the reveal request
    /// and compares — any drift in ring state, document, actor, or
    /// coordinator between the two phases fails that comparison.
    pub(crate) context_digest: [u8; 32],
    /// `C_i`, this node's own commitment — kept so the reveal handler
    /// doesn't need to recompute the blinded points a second time just to
    /// re-hash them.
    pub(crate) commitment: [u8; 32],
    coordinator_peer_id: Vec<u8>,
    created_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PendingBlindingStoreOutcome {
    Stored,
    AlreadyExists,
    LimitReached,
}

pub(crate) struct PetPendingBlindingStore {
    entries: Arc<RwLock<HashMap<String, PendingBlinding>>>,
}

impl PetPendingBlindingStore {
    fn key(protocol_version: u64, attempt_id: &str) -> String {
        format!("v{protocol_version}:{attempt_id}")
    }

    pub(crate) fn new() -> Self {
        let entries: Arc<RwLock<HashMap<String, PendingBlinding>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let entries_clone = entries.clone();
        tokio::spawn(async move {
            Self::expiration_worker(entries_clone).await;
        });
        Self { entries }
    }

    async fn expiration_worker(entries: Arc<RwLock<HashMap<String, PendingBlinding>>>) {
        let mut interval = tokio::time::interval(PET_BLIND_EXPIRATION_CHECK_INTERVAL);
        loop {
            interval.tick().await;
            let mut map = entries.write().await;
            let removed = Self::remove_expired(&mut map, Instant::now());
            if removed > 0 {
                tracing::info!(
                    removed,
                    remaining = map.len(),
                    "PetPendingBlindingStore: expired blinding-state cleanup complete"
                );
            }
        }
    }

    fn remove_expired(map: &mut HashMap<String, PendingBlinding>, now: Instant) -> usize {
        let before = map.len();
        map.retain(|attempt_id, entry| {
            let age = now.duration_since(entry.created_at);
            if age >= PET_BLIND_PENDING_TTL {
                tracing::warn!(
                    attempt_id = %attempt_id,
                    age_secs = age.as_secs(),
                    "PetPendingBlindingStore: removing expired blinding state"
                );
                return false;
            }
            true
        });
        before - map.len()
    }

    /// Store this responder's freshly generated commit-phase secret. Fails
    /// with `AlreadyExists` if a pending entry already exists for this
    /// `attempt_id` — a genuine retry gets a fresh `attempt_id`, so a second
    /// commit for the same one is a replay, not a legitimate resend; see the
    /// design doc's "why partial retries are unsafe" section.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn store(
        &self,
        protocol_version: u64,
        attempt_id: &str,
        z_i: Fr,
        commit_salt: [u8; 32],
        node_id: u32,
        context_digest: [u8; 32],
        commitment: [u8; 32],
        coordinator_peer_id: Vec<u8>,
    ) -> PendingBlindingStoreOutcome {
        let key = Self::key(protocol_version, attempt_id);
        let mut map = self.entries.write().await;
        Self::remove_expired(&mut map, Instant::now());
        if map.len() >= MAX_PET_BLIND_PENDING {
            tracing::error!(
                pending = map.len(),
                max = MAX_PET_BLIND_PENDING,
                "PetPendingBlindingStore: pending state limit exceeded"
            );
            return PendingBlindingStoreOutcome::LimitReached;
        }
        if map.contains_key(&key) {
            tracing::warn!(
                attempt_id = %attempt_id,
                "PetPendingBlindingStore: pending state already exists for attempt_id"
            );
            return PendingBlindingStoreOutcome::AlreadyExists;
        }
        map.insert(
            key,
            PendingBlinding {
                z_i: Zeroizing::new(z_i),
                commit_salt,
                node_id,
                context_digest,
                commitment,
                coordinator_peer_id,
                created_at: Instant::now(),
            },
        );
        PendingBlindingStoreOutcome::Stored
    }

    /// Atomically consume the pending state for `attempt_id`, only if the
    /// requesting peer matches the one that committed it. One-use: a second
    /// call for the same `attempt_id` (or a call from a different peer)
    /// finds nothing. The caller must still independently compare
    /// `context_digest` before trusting the returned entry — see this
    /// module's doc comment.
    pub(crate) async fn take(
        &self,
        protocol_version: u64,
        attempt_id: &str,
        requesting_peer_id: &[u8],
    ) -> Option<PendingBlinding> {
        let key = Self::key(protocol_version, attempt_id);
        let mut map = self.entries.write().await;
        let entry = map.get(&key)?;
        if entry.coordinator_peer_id != requesting_peer_id {
            tracing::warn!(
                attempt_id = %attempt_id,
                "PetPendingBlindingStore: reveal requester does not match the commit-phase coordinator"
            );
            return None;
        }
        map.remove(&key)
    }
}

impl Default for PetPendingBlindingStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(byte: u8) -> Fr {
        use crypto::r#trait::CryptoDeserialize;
        // A small, fixed nonzero scalar built via modular reduction of a
        // single repeated byte — this store never inspects the scalar's
        // value, only its presence, so any deterministic nonzero value works.
        Fr::from_bytes(&[byte; 32]).unwrap_or_else(|_| {
            Fr::from_bytes(&{
                let mut bytes = [0u8; 32];
                bytes[0] = byte;
                bytes
            })
            .expect("fallback scalar decode")
        })
    }

    #[tokio::test]
    async fn store_then_take_round_trips() {
        let store = PetPendingBlindingStore::new();
        let outcome = store
            .store(
                0,
                "attempt-1",
                scalar(7),
                [1u8; 32],
                3,
                [2u8; 32],
                [3u8; 32],
                vec![9, 9],
            )
            .await;
        assert_eq!(outcome, PendingBlindingStoreOutcome::Stored);

        let entry = store.take(0, "attempt-1", &[9, 9]).await;
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().node_id, 3);
    }

    #[tokio::test]
    async fn take_is_one_use() {
        let store = PetPendingBlindingStore::new();
        store
            .store(
                0,
                "attempt-1",
                scalar(7),
                [1u8; 32],
                3,
                [2u8; 32],
                [3u8; 32],
                vec![9, 9],
            )
            .await;

        assert!(store.take(0, "attempt-1", &[9, 9]).await.is_some());
        assert!(
            store.take(0, "attempt-1", &[9, 9]).await.is_none(),
            "a second take for the same attempt_id must find nothing"
        );
    }

    #[tokio::test]
    async fn take_rejects_a_different_peer() {
        let store = PetPendingBlindingStore::new();
        store
            .store(
                0,
                "attempt-1",
                scalar(7),
                [1u8; 32],
                3,
                [2u8; 32],
                [3u8; 32],
                vec![9, 9],
            )
            .await;

        assert!(
            store.take(0, "attempt-1", &[1, 1]).await.is_none(),
            "a reveal request from a different peer than the committer must be rejected"
        );
        // The entry is still there for the genuine coordinator.
        assert!(store.take(0, "attempt-1", &[9, 9]).await.is_some());
    }

    #[tokio::test]
    async fn duplicate_commit_for_the_same_attempt_is_rejected() {
        let store = PetPendingBlindingStore::new();
        let first = store
            .store(
                0,
                "attempt-1",
                scalar(7),
                [1u8; 32],
                3,
                [2u8; 32],
                [3u8; 32],
                vec![9, 9],
            )
            .await;
        assert_eq!(first, PendingBlindingStoreOutcome::Stored);

        let second = store
            .store(
                0,
                "attempt-1",
                scalar(8),
                [4u8; 32],
                3,
                [2u8; 32],
                [5u8; 32],
                vec![9, 9],
            )
            .await;
        assert_eq!(
            second,
            PendingBlindingStoreOutcome::AlreadyExists,
            "a genuine retry must use a fresh attempt_id, not resend the same one"
        );
    }

    #[tokio::test]
    async fn protocol_versions_are_isolated() {
        let store = PetPendingBlindingStore::new();
        store
            .store(
                0,
                "same-id",
                scalar(7),
                [1u8; 32],
                3,
                [2u8; 32],
                [3u8; 32],
                vec![9, 9],
            )
            .await;
        store
            .store(
                1,
                "same-id",
                scalar(8),
                [4u8; 32],
                5,
                [6u8; 32],
                [7u8; 32],
                vec![8, 8],
            )
            .await;

        let v0 = store.take(0, "same-id", &[9, 9]).await.unwrap();
        assert_eq!(v0.node_id, 3);
        let v1 = store.take(1, "same-id", &[8, 8]).await.unwrap();
        assert_eq!(v1.node_id, 5);
    }
}
