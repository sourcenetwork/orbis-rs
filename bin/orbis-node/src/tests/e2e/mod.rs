//! Backend-neutral E2E scenarios.
//!
//! This module is the whole integration-test tree. A build selects exactly
//! one production backend feature, and that choice is bound to
//! `TestEnvironmentImpl` below. Scenario modules describe behavior once;
//! they do not mention `cosmos` or `native`.

#[cfg(not(any(feature = "cosmos", feature = "native")))]
compile_error!("the E2E harness requires exactly one backend feature: `cosmos` or `native`");

#[cfg(all(feature = "cosmos", feature = "native"))]
compile_error!("the E2E harness requires exactly one backend feature: `cosmos` or `native`");

#[cfg(any(
    all(feature = "authz-native", feature = "bulletin-vera"),
    all(feature = "authz-vera", feature = "bulletin-native")
))]
compile_error!(
    "the E2E harness currently provisions one coherent chain pair; mixed authz/bulletin production builds remain supported, but need a two-chain test adapter"
);

// Backend-neutral scenarios. A backend with a real capability gap keeps the
// same scenario visible and ignored, rather than defining a second test body.
// Curve-specific variants follow the production crypto features.
mod cancel_ring_reshare;
mod concurrent_delegated_dkg;
mod concurrent_dkg_non_participant;
mod concurrent_invalid_dkg_share_report;
mod concurrent_pre_requests;
mod concurrent_sign_requests;
mod concurrent_simultaneous_dkg;
mod fault_dkg_unreachable;
mod fault_pre_below_threshold;
mod fault_pre_one_node_down;
mod fault_sign_below_threshold;
mod fault_sign_one_node_down;
mod integration;
mod live_node;
mod member_replacement;
mod pending_ring_cancellation;
mod pet_dkg_scenario;
mod pre_scenario;
mod production_kdf;
mod refresh_scenario;
mod report_kick_promotes_backup_node;
mod report_offline_pre_sign;
mod report_pet_invalid_decrypt_share;
mod report_refresh_invalid_commitment;
mod report_refresh_leader_offline;
mod report_refresh_offline;
mod report_refresh_stall_offline;
mod report_reshare_bad_dkg_share_relay;
mod report_reshare_dkg_equivocation;
mod report_reshare_offline;
mod report_reshare_stall_offline;
mod report_scenario;
mod report_unauthorized_relay;
mod report_unauthorized_relay_bulletin_inline;
mod reshare_scenario;
mod restart_scenario;
mod scheduled_refresh;
mod sign_scenario;
#[cfg(all(feature = "native", feature = "bls12-381"))]
mod defra_documents;
mod standard_dkg_pre;
mod upgrade;

// Corrupts node3's own BLS share directly. FROST's threshold-sized signing
// set would deterministically exclude node3 from Sign, so this test only
// makes sense for the default non-interactive BLS backend.
#[cfg(not(feature = "jubjub"))]
mod report_invalid_crypto_response;
#[cfg(feature = "jubjub")]
mod report_invalid_sign_share_frost;

#[cfg(all(feature = "cosmos", not(feature = "native")))]
use test_support::CosmosTestEnvironment as TestEnvironmentImpl;

// Native Vera adapter. These modules provision state and perform chain
// operations; they are not a second copy of the shared scenarios.
#[cfg(feature = "native")]
mod native_confirmation;
#[cfg(feature = "native")]
mod native_environment;
#[cfg(feature = "native")]
mod native_trust_gateway;
#[cfg(feature = "native")]
mod policy_generations;
// Share-bundle codec. Native reads a stopped node's store from disk; both
// backends backdate a live store through the diagnostic RPC.
#[allow(dead_code)]
mod stored_bundle;
// Node startup for the hosted Trust gateway. The external runner launches
// `native_trust_gateway_ring_dkg` by that exact name.
#[cfg(feature = "native")]
mod native_lifecycle;

#[cfg(all(feature = "native", not(feature = "cosmos")))]
use native_environment::NativeTestEnvironment as TestEnvironmentImpl;

// In-process FaultNetwork qualifications. Isolated from the shared scenario
// contract: only the Cosmos adapter has this harness today.
#[cfg(all(feature = "cosmos", feature = "fault-injection"))]
mod fault_injection;
