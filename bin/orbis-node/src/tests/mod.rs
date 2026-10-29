// All of these are Cosmos/SourceHub-specific (real Vera-in-Docker, or
// `common::blockchain::{ChainConfig, VeraClient}` directly) — gated on
// `integration-test-cosmos`, not the backend-neutral `integration-test` base,
// so a native-only `integration-test-native` build doesn't try to compile
// them (they'd fail: `ChainConfig`/`VeraClient` require the `cosmos` feature).
#[cfg(feature = "integration-test-cosmos")]
mod cancel_ring_reshare;
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
#[cfg(feature = "integration-test-cosmos")]
mod pending_ring_cancellation;
#[cfg(feature = "integration-test-cosmos")]
mod reporting;
#[cfg(feature = "scale-testing")]
mod scale_testing;
#[cfg(feature = "integration-test-cosmos")]
mod upgrade;
