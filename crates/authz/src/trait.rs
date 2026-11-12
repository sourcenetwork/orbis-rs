use crate::error::Result;
use async_trait::async_trait;

/// The outcome of verifying a bundle from `Authz::capture_evidence`.
pub struct VerifiedEvidence {
    /// The bundle's own authenticated capture time (unix seconds). Backends whose evidence
    /// embeds a signed timestamp return it as verified here; callers apply their own
    /// freshness policy against it rather than the trait encoding one.
    pub captured_at: u64,
    /// The access decision for the `(permission, subject)` passed to `verify_evidence`.
    pub allowed: bool,
}

#[async_trait]
pub trait Authz: Send + Sync {
    /// Evaluate the policy for `subject` at the latest state (the live request path).
    async fn check(&self, permission: Vec<u8>, subject: &str) -> Result<bool>;

    /// Capture a self-contained, offline-verifiable evidence bundle of the access decision
    /// for `(permission, subject)` right now. Opaque bytes; format is backend-defined.
    /// Captured by the acceptor when it detects an unauthorized relay, so a later refutation
    /// can be checked purely from the bundle rather than re-querying chain history.
    async fn capture_evidence(&self, permission: Vec<u8>, subject: &str) -> Result<Vec<u8>>;

    /// Verify a bundle from `capture_evidence`, re-deriving the decision for
    /// `(permission, subject)` purely from the bundle. Report refutations pass the bundle
    /// recorded at relay time so every co-signer reaches the same verdict.
    async fn verify_evidence(
        &self,
        evidence: &[u8],
        permission: Vec<u8>,
        subject: &str,
    ) -> Result<VerifiedEvidence>;
}
