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
#[cfg(feature = "integration-test-cosmos")]
mod pending_ring_cancellation;
#[cfg(feature = "integration-test-cosmos")]
mod reporting;
#[cfg(feature = "scale-testing")]
mod scale_testing;
#[cfg(feature = "integration-test-cosmos")]
mod upgrade;
