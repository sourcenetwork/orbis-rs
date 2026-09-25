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

    /// Resolve the single actor holding `relation` on `(resource, object_id)` under
    /// `policy_id` — e.g. reading who holds the `"owner"` relation on an audit-target
    /// object, so a PET check verifies against the real registered owner rather than
    /// a value the requester merely asserts. Returns `Err` if zero or more than one
    /// actor holds the relation: an audit target must resolve unambiguously.
    async fn resolve_relation_subject(
        &self,
        policy_id: &str,
        resource: &str,
        object_id: &str,
        relation: &str,
    ) -> Result<String>;
}
