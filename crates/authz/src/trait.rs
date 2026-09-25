use crate::error::Result;
use async_trait::async_trait;

#[async_trait]
pub trait Authz: Send + Sync {
    /// Evaluate the policy for `subject` at the latest state (the live request path).
    async fn check(&self, permission: Vec<u8>, subject: &str) -> Result<bool>;

    /// Evaluate the policy for `subject` as of an **opaque anchor** — a backend-defined
    /// point-in-history token (e.g. a block height, or a timestamp). Report refutations pass the
    /// anchor recorded at relay time so every co-signer reaches the same verdict.
    async fn check_at(&self, permission: Vec<u8>, subject: &str, anchor: &str) -> Result<bool>;

    /// The backend's current point-in-history token. Captured by the acceptor when it detects an
    /// unauthorized relay, so the ACP re-check is pinned to ≈ the relay moment.
    async fn current_anchor(&self) -> Result<String>;

    /// The wall-clock unix time an `anchor` represents. Used only to bound an anchor's freshness
    /// against the relayer's signed `signed_at`; keeps the anchor itself opaque to callers.
    async fn anchor_time(&self, anchor: &str) -> Result<u64>;
}
