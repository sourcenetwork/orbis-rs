#!/usr/bin/env bash
# Compile and discover the backend-neutral E2E contract without executing it.

set -Eeuo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd "$script_dir/.." && pwd)
inventory_file=$(mktemp "${TMPDIR:-/tmp}/orbis-e2e-inventory.XXXXXX")
trap 'rm -f "$inventory_file"' EXIT

readonly filter='package(orbis-node) & test(/^tests::e2e::/)'
readonly -a required_tests=(
  'tests::e2e::standard_dkg_pre::test_cli_calls_dkg_and_pre_endpoint'
  'tests::e2e::integration::test_cli_calls_dkg_for_pet_ring'
  'tests::e2e::integration::test_pet_ring_refresh_and_reshare'
  'tests::e2e::restart_scenario::test_restarted_member_keeps_identity_and_polynomial'
  'tests::e2e::member_replacement::test_spare_member_replaces_original'
  'tests::e2e::scheduled_refresh::test_due_refresh_completes_after_restart'
  'tests::e2e::production_kdf::test_stopped_store_keeps_production_kdf_header'
)

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

if ((missing != 0)); then
  echo "backend-neutral E2E inventory is incomplete" >&2
  exit 1
fi

echo "verified ${#required_tests[@]} required shared E2E scenarios"
