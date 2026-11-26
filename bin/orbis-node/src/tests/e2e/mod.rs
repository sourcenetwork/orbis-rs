//! E2E scenarios against Vera.
//!
//! This module is the whole integration-test tree. Scenario modules describe
//! behavior through `TestEnvironmentImpl`, bound below to the Vera adapter.

#[cfg(not(feature = "vera"))]
compile_error!("the E2E harness requires the `vera` feature");

// Curve-specific variants follow the production crypto features.
mod cancel_ring_reshare;
mod concurrent_delegated_dkg;
mod concurrent_dkg_non_participant;
mod concurrent_invalid_dkg_share_report;
mod concurrent_pre_requests;
mod concurrent_sign_requests;
mod concurrent_simultaneous_dkg;
// Support code for `sign_scenario.rs`'s embedded Defra remote-signing
// checks (real capability gap, not a test-authoring difference — see that
// file's own doc comment). Not test files themselves: no `#[test]` fns.
#[cfg(all(feature = "vera", feature = "bls12-381"))]
mod defra_documents;
#[cfg(all(feature = "vera", feature = "bls12-381"))]
mod defra_peers;
mod fault_dkg_unreachable;
mod fault_pre_below_threshold;
mod fault_pre_one_node_down;
mod fault_sign_below_threshold;
mod fault_sign_one_node_down;
mod integration;
mod live_node;
mod member_replacement;
mod passkey_sign_scenario;
mod pending_ring_cancellation;
mod pet_dkg_scenario;
mod pre_passkey_scenario;
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
mod standard_dkg_pre;
mod upgrade;

// Corrupts node3's own BLS share directly. FROST's threshold-sized signing
// set would deterministically exclude node3 from Sign, so this test only
// makes sense for the default non-interactive BLS backend.
#[cfg(not(feature = "jubjub"))]
mod report_invalid_crypto_response;
#[cfg(feature = "jubjub")]
mod report_invalid_sign_share_frost;

// Vera adapter. These modules provision state and perform chain operations;
// they are not scenarios themselves.
#[cfg(feature = "vera")]
mod policy_generations;
#[cfg(feature = "vera")]
mod vera_confirmation;
#[cfg(feature = "vera")]
mod vera_environment;
#[cfg(feature = "vera")]
mod vera_trust_gateway;
// Share-bundle codec. A stopped node's store is read from disk; a live store
// is backdated through the diagnostic RPC.
#[allow(dead_code)]
mod stored_bundle;
// Node startup for the hosted Trust gateway. The external runner launches
// `vera_trust_gateway_ring_dkg` by that exact name.
#[cfg(feature = "vera")]
mod vera_lifecycle;

#[cfg(feature = "vera")]
use vera_environment::VeraTestEnvironment as TestEnvironmentImpl;

// Real Defra container over a real ring's `pre_share_endpoints`.
mod defra_pre_scenario;

// Image and runtime gating of the diagnostic service.
#[cfg(feature = "vera")]
mod unsafe_testing_gate;

// In-process FaultNetwork qualifications against a native Vera cluster of
// `verad` processes. Isolated from the shared scenario contract.
#[cfg(all(feature = "vera", feature = "fault-injection"))]
mod cluster_logs;
#[cfg(all(feature = "vera", feature = "fault-injection"))]
mod fault_injection;
