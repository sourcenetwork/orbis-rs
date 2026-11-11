#!/usr/bin/env bash
# Compile and discover the backend-neutral E2E contract without executing it.

set -Eeuo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd "$script_dir/.." && pwd)
inventory_file=$(mktemp "${TMPDIR:-/tmp}/orbis-e2e-inventory.XXXXXX")
trap 'rm -f "$inventory_file"' EXIT

readonly filter='package(orbis-node) & test(/^tests::e2e::/)'

# Every scenario below was confirmed present in all four CI compile cells
# (cosmos/native x bls12-381/jubjub) via `cargo nextest list --run-ignored
# all` on each cell's own `cargo_flags` (see .github/workflows/rust.yml's
# `compile` matrix). Regenerate by re-running that command for each cell and
# intersecting the four outputs; add any new name that shows up in all four,
# and only there -- a name a future PR can't put in this list without
# someone noticing it's cfg'd out of one backend/crypto build.
readonly -a required_tests=(
  'tests::e2e::cancel_ring_reshare::test_cancel_stuck_reshare_reverts_ring_and_preserves_signing'
  'tests::e2e::concurrent_delegated_dkg::test_delegated_dkg_with_vera_end_to_end'
  'tests::e2e::concurrent_dkg_non_participant::test_dkg_non_participant_initiator_completes'
  'tests::e2e::concurrent_invalid_dkg_share_report::test_vera_accepts_invalid_crypto_dkg_share_report_from_live_nodes'
  'tests::e2e::concurrent_pre_requests::test_concurrent_pre_requests'
  'tests::e2e::concurrent_sign_requests::test_concurrent_sign_requests'
  'tests::e2e::concurrent_simultaneous_dkg::test_two_simultaneous_dkg_sessions'
  'tests::e2e::defra_pre_scenario::test_defra_backed_pre_end_to_end'
  'tests::e2e::fault_dkg_unreachable::test_dkg_fails_when_node_unreachable'
  'tests::e2e::fault_pre_below_threshold::test_pre_below_threshold_nodes_down_fails_fast'
  'tests::e2e::fault_pre_one_node_down::test_pre_one_node_down_succeeds'
  'tests::e2e::fault_sign_below_threshold::test_sign_below_threshold_nodes_down_fails_fast'
  'tests::e2e::fault_sign_one_node_down::test_sign_one_node_down_succeeds'
  'tests::e2e::integration::pet_reshare::convergence_rejects_timestamp_only_and_mixed_generations'
  'tests::e2e::integration::pet_reshare::convergence_requires_the_exact_finalized_committee'
  'tests::e2e::integration::test_cli_calls_dkg_for_pet_ring'
  'tests::e2e::integration::test_pet_ring_refresh_and_reshare'
  'tests::e2e::member_replacement::test_spare_member_replaces_original'
  'tests::e2e::pending_ring_cancellation::test_stale_pending_dkg_is_cancelled'
  'tests::e2e::production_kdf::test_stopped_store_keeps_production_kdf_header'
  'tests::e2e::report_kick_promotes_backup_node::test_report_kick_promotes_backup_node'
  'tests::e2e::report_offline_pre_sign::test_pre_and_sign_offline_triggers_on_chain_report'
  'tests::e2e::report_pet_invalid_decrypt_share::test_pet_invalid_decrypt_share_triggers_on_chain_report'
  'tests::e2e::report_refresh_invalid_commitment::test_refresh_invalid_commitment_triggers_on_chain_report'
  'tests::e2e::report_refresh_leader_offline::test_refresh_leader_offline_before_preparation_triggers_on_chain_report'
  'tests::e2e::report_refresh_offline::test_refresh_offline_triggers_on_chain_report'
  'tests::e2e::report_refresh_stall_offline::test_refresh_stall_offline_triggers_on_chain_report'
  'tests::e2e::report_reshare_bad_dkg_share_relay::test_reshare_bad_dkg_share_relay_triggers_on_chain_report'
  'tests::e2e::report_reshare_dkg_equivocation::test_reshare_dkg_equivocation_triggers_on_chain_report'
  'tests::e2e::report_reshare_offline::test_reshare_offline_triggers_on_chain_report'
  'tests::e2e::report_reshare_stall_offline::test_reshare_stall_offline_triggers_on_chain_report'
  'tests::e2e::report_unauthorized_relay::test_unauthorized_relay_pre_and_sign_triggers_on_chain_report'
  'tests::e2e::report_unauthorized_relay_bulletin_inline::test_pre_unauthorized_relay_bulletin_and_inline_document_triggers_on_chain_report'
  'tests::e2e::restart_scenario::test_restarted_member_keeps_identity_and_polynomial'
  'tests::e2e::scheduled_refresh::test_due_refresh_completes_after_restart'
  'tests::e2e::standard_dkg_pre::test_cli_calls_dkg_and_pre_endpoint'
  'tests::e2e::upgrade::test_v0_services_rejected_after_ring_upgrade'
)

# Not a cfg drift risk the same way: `report_invalid_crypto_response`
# corrupts a BLS share directly, so it only makes sense for the default
# non-interactive BLS backend; `report_invalid_sign_share_frost` is its
# jubjub/FROST counterpart (see bin/orbis-node/src/tests/e2e/mod.rs's own
# `#[cfg(not(feature = "jubjub"))]`/`#[cfg(feature = "jubjub")]` split).
# Exactly one must be in every cell's inventory, never both and never
# neither.
readonly -a one_of_crypto_variant_tests=(
  'tests::e2e::report_invalid_crypto_response::test_invalid_crypto_response_triggers_on_chain_report'
  'tests::e2e::report_invalid_sign_share_frost::test_frost_invalid_sign_share_triggers_on_chain_report'
)

# Specialized qualifications: real coverage, deliberately not part of the
# backend-neutral contract above, so their absence from a given cell's
# inventory is expected and not checked here.
#   - `tests::e2e::fault_injection::*` — Cosmos-only fault-injection harness
#     (gated on the `fault-injection` feature, only wired for Cosmos cells).
#   - `tests::e2e::native_lifecycle::*`/`tests::e2e::native_trust_gateway::*`
#     — native-only; `native_trust_gateway_ring_dkg` itself is `#[ignore]`d
#     (needs a real native Docker image + compiled Trust gateway contract
#     artifacts not built in CI).

cd "$repository_root"

# `nextest list` builds the selected test binary and asks the Rust test harness
# for its inventory. It does not execute test bodies. Include ignored tests so
# a backend capability gap remains visible as part of the shared contract.
# Color stays off: the workflow sets CARGO_TERM_COLOR=always, and nextest then
# splits `module::test_name` with ANSI codes, which hides the required names.
CARGO_TERM_COLOR=never cargo nextest list -p orbis-node --lib "$@" \
  --run-ignored all \
  --message-format oneline \
  -E "$filter" | tee "$inventory_file"

missing=0
for test_name in "${required_tests[@]}"; do
  if ! grep -Fq -- "$test_name" "$inventory_file"; then
    echo "missing required shared E2E test: $test_name" >&2
    missing=1
  fi
done

crypto_variants_present=0
for test_name in "${one_of_crypto_variant_tests[@]}"; do
  if grep -Fq -- "$test_name" "$inventory_file"; then
    crypto_variants_present=$((crypto_variants_present + 1))
  fi
done
if ((crypto_variants_present != 1)); then
  echo "expected exactly one of the crypto-variant invalid-share tests, found $crypto_variants_present:" >&2
  printf '  %s\n' "${one_of_crypto_variant_tests[@]}" >&2
  missing=1
fi

if ((missing != 0)); then
  echo "backend-neutral E2E inventory is incomplete" >&2
  exit 1
fi

echo "verified ${#required_tests[@]} required shared E2E scenarios (+1 crypto-variant pair)"
