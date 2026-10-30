// Shared with native (`tests/native_startup.rs`) — see that file's own
// declaration and the standing decision in the harness-unification plan
// against backend-only test files: one shared test, real on whichever
// backend supports the behavior, `#[ignore]`-gated with a reason on the
// other until its gap closes.
#[cfg(feature = "integration-test-cosmos")]
#[path = "support/cancel_ring_reshare.rs"]
mod cancel_ring_reshare;
// Everything below this point, up to `node`, is still genuinely
// Cosmos/SourceHub-specific (real Vera-in-Docker, or `common::blockchain::
// {ChainConfig, VeraClient}` directly) — gated on `integration-test-cosmos`,
// not the backend-neutral `integration-test` base, so a native-only
// `integration-test-native` build doesn't try to compile them (they'd fail:
// `ChainConfig`/`VeraClient` require the `cosmos` feature). Not yet migrated
// to a shared file — see the harness-unification plan's PR 5 roadmap.
#[cfg(feature = "integration-test-cosmos")]
mod concurrent;
#[cfg(feature = "integration-test-cosmos")]
mod constants;
#[cfg(all(feature = "fault-injection", feature = "integration-test-cosmos"))]
mod fault_injection;
#[cfg(feature = "integration-test-cosmos")]
mod integration;
mod node;
// Declared here (not inside `integration.rs`) so `cancel_ring_reshare.rs`
// can reuse them too — both are siblings under this module.
#[cfg(feature = "integration-test-cosmos")]
#[path = "support/pre_scenario.rs"]
mod pre_scenario;
#[cfg(feature = "integration-test-cosmos")]
#[path = "support/sign_scenario.rs"]
mod sign_scenario;
// Harness-unification migration: the compile-time-selected test environment
// for this backend.
#[cfg(feature = "integration-test-cosmos")]
use test_support::CosmosTestEnvironment as TestEnvironmentImpl;
// Shared with native (`tests/native_startup.rs`) — see that file's own
// declaration and the standing decision in the harness-unification plan
// against backend-only test files.
#[cfg(feature = "integration-test-cosmos")]
#[path = "support/pending_ring_cancellation.rs"]
mod pending_ring_cancellation;
#[cfg(feature = "integration-test-cosmos")]
mod reporting;
#[cfg(feature = "scale-testing")]
mod scale_testing;
// Shared with native (`tests/native_startup.rs`) — see that file's own
// declaration and the standing decision in the harness-unification plan
// against backend-only test files.
#[cfg(feature = "integration-test-cosmos")]
#[path = "support/upgrade.rs"]
mod upgrade;
