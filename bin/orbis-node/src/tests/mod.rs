// Shared with native (`tests/native_startup.rs`) — see that file's own
// declaration and the standing decision in the harness-unification plan
// against backend-only test files: one shared test, real on whichever
// backend supports the behavior, `#[ignore]`-gated with a reason on the
// other until its gap closes.
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
#[path = "support/cancel_ring_reshare.rs"]
mod cancel_ring_reshare;
// Everything below this point, up to `node`, is still genuinely
// Cosmos/SourceHub-specific (real Vera-in-Docker, or `common::blockchain::
// {ChainConfig, VeraClient}` directly) — gated on `all(integration-test,
// cosmos)`, not the backend-neutral `integration-test` base alone, so a
// native-only (`integration-test`+`native`) build doesn't try to compile
// them (they'd fail: `ChainConfig`/`VeraClient` require the `cosmos`
// feature). Not yet migrated to a shared file — see the harness-
// unification plan's PR 5 roadmap.
// Shared with native (`tests/native_startup.rs`) — see that file's own
// declaration and the standing decision in the harness-unification plan
// against backend-only test files.
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
#[path = "support/concurrent_delegated_dkg.rs"]
mod concurrent_delegated_dkg;
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
#[path = "support/concurrent_dkg_non_participant.rs"]
mod concurrent_dkg_non_participant;
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
#[path = "support/concurrent_invalid_dkg_share_report.rs"]
mod concurrent_invalid_dkg_share_report;
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
#[path = "support/concurrent_pre_requests.rs"]
mod concurrent_pre_requests;
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
#[path = "support/concurrent_sign_requests.rs"]
mod concurrent_sign_requests;
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
#[path = "support/concurrent_simultaneous_dkg.rs"]
mod concurrent_simultaneous_dkg;
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
#[path = "support/fault_dkg_unreachable.rs"]
mod fault_dkg_unreachable;
#[cfg(all(
    feature = "fault-injection",
    feature = "integration-test",
    feature = "cosmos"
))]
mod fault_injection;
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
#[path = "support/fault_pre_below_threshold.rs"]
mod fault_pre_below_threshold;
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
#[path = "support/fault_pre_one_node_down.rs"]
mod fault_pre_one_node_down;
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
#[path = "support/fault_sign_below_threshold.rs"]
mod fault_sign_below_threshold;
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
#[path = "support/fault_sign_one_node_down.rs"]
mod fault_sign_one_node_down;
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
mod integration;
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
#[path = "support/live_node.rs"]
mod live_node;
mod node;
// Declared here (not inside `integration.rs`) so sibling modules
// (`cancel_ring_reshare.rs`, the `report_*.rs` family) can reuse them too
// — all are siblings under this module.
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
#[path = "support/pet_dkg_scenario.rs"]
mod pet_dkg_scenario;
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
#[path = "support/pre_scenario.rs"]
mod pre_scenario;
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
#[path = "support/sign_scenario.rs"]
mod sign_scenario;
// Harness-unification migration: the compile-time-selected test environment
// for this backend.
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
use test_support::CosmosTestEnvironment as TestEnvironmentImpl;
// Shared with native (`tests/native_startup.rs`) — see that file's own
// declaration and the standing decision in the harness-unification plan
// against backend-only test files.
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
#[path = "support/pending_ring_cancellation.rs"]
mod pending_ring_cancellation;
// Shared helpers for the former `reporting.rs`/`report_offline_pre_sign.rs` family
// — declared here (not inside either) so both can reach it via `super::`.
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
#[path = "support/report_scenario.rs"]
mod report_scenario;
// Shared with native (`tests/native_startup.rs`) — see that file's own
// declaration and the standing decision in the harness-unification plan
// against backend-only test files.
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
#[path = "support/report_offline_pre_sign.rs"]
mod report_offline_pre_sign;
// Corrupts node3's own BLS share directly — FROST's threshold-sized
// signing set would deterministically exclude node3 from Sign, so this
// test only makes sense for the default non-interactive BLS backend.
#[cfg(all(
    feature = "integration-test",
    feature = "cosmos",
    not(feature = "jubjub")
))]
#[path = "support/report_invalid_crypto_response.rs"]
mod report_invalid_crypto_response;
#[cfg(all(feature = "integration-test", feature = "cosmos", feature = "jubjub"))]
#[path = "support/report_invalid_sign_share_frost.rs"]
mod report_invalid_sign_share_frost;
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
#[path = "support/report_kick_promotes_backup_node.rs"]
mod report_kick_promotes_backup_node;
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
#[path = "support/report_pet_invalid_decrypt_share.rs"]
mod report_pet_invalid_decrypt_share;
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
#[path = "support/report_refresh_invalid_commitment.rs"]
mod report_refresh_invalid_commitment;
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
#[path = "support/report_refresh_leader_offline.rs"]
mod report_refresh_leader_offline;
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
#[path = "support/report_refresh_offline.rs"]
mod report_refresh_offline;
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
#[path = "support/report_refresh_stall_offline.rs"]
mod report_refresh_stall_offline;
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
#[path = "support/report_reshare_bad_dkg_share_relay.rs"]
mod report_reshare_bad_dkg_share_relay;
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
#[path = "support/report_reshare_dkg_equivocation.rs"]
mod report_reshare_dkg_equivocation;
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
#[path = "support/report_reshare_offline.rs"]
mod report_reshare_offline;
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
#[path = "support/report_reshare_stall_offline.rs"]
mod report_reshare_stall_offline;
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
#[path = "support/report_unauthorized_relay.rs"]
mod report_unauthorized_relay;
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
#[path = "support/report_unauthorized_relay_bulletin_inline.rs"]
mod report_unauthorized_relay_bulletin_inline;
#[cfg(feature = "scale-testing")]
mod scale_testing;
// Shared with native (`tests/native_startup.rs`) — see that file's own
// declaration and the standing decision in the harness-unification plan
// against backend-only test files.
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
#[path = "support/upgrade.rs"]
mod upgrade;
