#[cfg(all(
    feature = "integration-test",
    any(
        all(feature = "authz-native", feature = "bulletin-vera"),
        all(feature = "authz-vera", feature = "bulletin-native")
    )
))]
compile_error!(
    "the E2E harness currently provisions one coherent chain pair; mixed authz/bulletin production builds remain supported, but need a two-chain test adapter"
);

// Backend-neutral scenarios are declared once in this library test tree.
// A backend with a real capability gap keeps the same scenario visible but
// ignored with the reason, rather than defining a second test body.
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/cancel_ring_reshare.rs"]
mod cancel_ring_reshare;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/concurrent_delegated_dkg.rs"]
mod concurrent_delegated_dkg;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/concurrent_dkg_non_participant.rs"]
mod concurrent_dkg_non_participant;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/concurrent_invalid_dkg_share_report.rs"]
mod concurrent_invalid_dkg_share_report;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/concurrent_pre_requests.rs"]
mod concurrent_pre_requests;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/concurrent_sign_requests.rs"]
mod concurrent_sign_requests;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/concurrent_simultaneous_dkg.rs"]
mod concurrent_simultaneous_dkg;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/fault_dkg_unreachable.rs"]
mod fault_dkg_unreachable;
#[cfg(all(
    feature = "fault-injection",
    feature = "integration-test",
    feature = "cosmos"
))]
mod fault_injection;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/fault_pre_below_threshold.rs"]
mod fault_pre_below_threshold;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/fault_pre_one_node_down.rs"]
mod fault_pre_one_node_down;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/fault_sign_below_threshold.rs"]
mod fault_sign_below_threshold;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/fault_sign_one_node_down.rs"]
mod fault_sign_one_node_down;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
mod integration;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/live_node.rs"]
mod live_node;
mod node;
// Declared here (not inside `integration.rs`) so sibling modules
// (`cancel_ring_reshare.rs`, the `report_*.rs` family) can reuse them too
// — all are siblings under this module.
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/pet_dkg_scenario.rs"]
mod pet_dkg_scenario;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/pre_scenario.rs"]
mod pre_scenario;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/refresh_scenario.rs"]
mod refresh_scenario;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/reshare_scenario.rs"]
mod reshare_scenario;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/sign_scenario.rs"]
mod sign_scenario;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/standard_dkg_pre.rs"]
mod standard_dkg_pre;
// The same scenario modules bind to exactly one environment at compile time.
#[cfg(all(feature = "integration-test", feature = "native"))]
use native_environment::NativeTestEnvironment as TestEnvironmentImpl;
#[cfg(all(feature = "integration-test", feature = "cosmos"))]
use test_support::CosmosTestEnvironment as TestEnvironmentImpl;

// Native-only chain-client/workflow/PET-scenario/Defra-replication plumbing.
// These are adapter support, not alternative copies of shared scenarios.
#[cfg(all(feature = "integration-test", feature = "native"))]
#[path = "support/native_confirmation.rs"]
mod native_confirmation;
#[cfg(all(
    feature = "integration-test",
    feature = "native",
    any(feature = "bls12-381", feature = "jubjub")
))]
#[path = "support/native_pet.rs"]
mod native_pet;
#[cfg(all(
    feature = "integration-test",
    feature = "native",
    any(feature = "bls12-381", feature = "jubjub")
))]
#[path = "support/native_trust_gateway.rs"]
mod native_trust_gateway;
#[cfg(all(
    feature = "integration-test",
    feature = "native",
    any(feature = "bls12-381", feature = "jubjub")
))]
#[path = "support/native_workflow.rs"]
mod native_workflow;
#[cfg(all(
    feature = "integration-test",
    feature = "native",
    any(feature = "bls12-381", feature = "jubjub")
))]
#[path = "support/policy_generations.rs"]
mod policy_generations;
// A second, independent instance of the same source file `native_pet`'s own
// `stored_bundle` submodule uses — `native_environment` is a sibling of
// `native_pet` under this module, not a descendant of it, so it cannot
// reach `native_pet`'s copy through `super::`.
#[cfg(all(
    feature = "integration-test",
    feature = "native",
    feature = "bls12-381"
))]
#[path = "support/defra_documents.rs"]
mod defra_documents;
#[cfg(all(
    feature = "integration-test",
    feature = "native",
    feature = "bls12-381"
))]
#[path = "support/defra_peers.rs"]
mod defra_peers;
#[cfg(all(
    feature = "integration-test",
    feature = "native",
    feature = "bls12-381"
))]
#[path = "support/defra_signer.rs"]
mod defra_signer;
#[cfg(all(
    feature = "integration-test",
    feature = "native",
    any(feature = "bls12-381", feature = "jubjub")
))]
#[path = "support/native_environment.rs"]
mod native_environment;
#[cfg(all(
    feature = "integration-test",
    feature = "native",
    any(feature = "bls12-381", feature = "jubjub")
))]
#[path = "support/native_pet/scheduled_store.rs"]
#[allow(dead_code)]
mod stored_bundle;
// Native lifecycle qualifications that have no backend-neutral contract yet.
#[cfg(all(feature = "integration-test", feature = "native"))]
#[path = "support/native_lifecycle.rs"]
mod native_lifecycle;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/pending_ring_cancellation.rs"]
mod pending_ring_cancellation;
// Shared helpers for the former `reporting.rs`/`report_offline_pre_sign.rs` family
// — declared here (not inside either) so both can reach it via `super::`.
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/report_offline_pre_sign.rs"]
mod report_offline_pre_sign;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/report_scenario.rs"]
mod report_scenario;
// Corrupts node3's own BLS share directly — FROST's threshold-sized
// signing set would deterministically exclude node3 from Sign, so this
// test only makes sense for the default non-interactive BLS backend.
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native"),
    not(feature = "jubjub")
))]
#[path = "support/report_invalid_crypto_response.rs"]
mod report_invalid_crypto_response;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native"),
    feature = "jubjub"
))]
#[path = "support/report_invalid_sign_share_frost.rs"]
mod report_invalid_sign_share_frost;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/report_kick_promotes_backup_node.rs"]
mod report_kick_promotes_backup_node;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/report_pet_invalid_decrypt_share.rs"]
mod report_pet_invalid_decrypt_share;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/report_refresh_invalid_commitment.rs"]
mod report_refresh_invalid_commitment;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/report_refresh_leader_offline.rs"]
mod report_refresh_leader_offline;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/report_refresh_offline.rs"]
mod report_refresh_offline;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/report_refresh_stall_offline.rs"]
mod report_refresh_stall_offline;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/report_reshare_bad_dkg_share_relay.rs"]
mod report_reshare_bad_dkg_share_relay;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/report_reshare_dkg_equivocation.rs"]
mod report_reshare_dkg_equivocation;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/report_reshare_offline.rs"]
mod report_reshare_offline;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/report_reshare_stall_offline.rs"]
mod report_reshare_stall_offline;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/report_unauthorized_relay.rs"]
mod report_unauthorized_relay;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/report_unauthorized_relay_bulletin_inline.rs"]
mod report_unauthorized_relay_bulletin_inline;
#[cfg(feature = "scale-testing")]
mod scale_testing;
#[cfg(all(
    feature = "integration-test",
    any(feature = "cosmos", feature = "native")
))]
#[path = "support/upgrade.rs"]
mod upgrade;
