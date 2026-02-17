//! ACP authorization tests: verify access control policies are enforced.
//!
//! These tests verify that:
//! - Authorized users CAN request re-encryption
//! - Unauthorized users CANNOT request re-encryption
//! - ACP policies on SourceHub are checked before PRE operations
//!
//! Requires: DKG + PRE + ACP integration with SourceHub

use orbis_e2e::ring::OrbisRing;

/// Authorized user can reencrypt; unauthorized user is rejected.
#[tokio::test]
#[ignore = "requires ACP integration with SourceHub"]
async fn acp_allows_authorized_rejects_unauthorized() {
    let _ring = OrbisRing::builder()
        .nodes(3)
        .threshold(2)
        .build()
        .await
        .expect("ring should start");

    // TODO: Form ring
    // TODO: Store secret with an ACP policy
    // TODO: Create authorized DID (matches policy)
    // TODO: Create unauthorized DID (doesn't match policy)
    // TODO: Authorized DID requests reencrypt → succeeds
    // TODO: Unauthorized DID requests reencrypt → fails with auth error
    todo!("implement when ACP integration is working");
}

/// Verify that PRE requests without valid JWT authentication are rejected.
#[tokio::test]
#[ignore = "requires authentication enforcement"]
async fn unauthenticated_request_rejected() {
    let _ring = OrbisRing::builder()
        .nodes(3)
        .threshold(2)
        .build()
        .await
        .expect("ring should start");

    // TODO: Form ring
    // TODO: Send PRE request without JWT bearer token
    // TODO: Verify request is rejected
    todo!("implement when auth enforcement is working");
}
