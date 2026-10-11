#!/bin/sh
set -eu
cleanup_source=bin/orbis-node/src/dkg/v0/coordinator/reshare/cleanup.rs
baseline_revision=7bb41c9
baseline_log="$RUNNER_TEMP/paired-promotion-baseline.txt"
trap 'git restore -- "$cleanup_source"' EXIT
git show "$baseline_revision:$cleanup_source" > "$cleanup_source"
set +e
cargo test --locked -p orbis-node --no-default-features --features "native,redb,iroh,$NATIVE_RESTART_CURVE" --lib confirmation_waits_for_this_members_pet_bundle -- --test-threads=1 > "$baseline_log" 2>&1
baseline_status=$?
set -e
if [ "$baseline_status" != 101 ] || ! grep -Fq 'running 1 test' "$baseline_log" || ! grep -Fq 'confirmation must wait for local PET staging' "$baseline_log" || ! grep -Fq '0 passed; 1 failed;' "$baseline_log"; then
  cat "$baseline_log"
  echo 'Delayed local PET staging did not reproduce the expected baseline failure' >&2
  exit 1
fi
echo 'Baseline reproduced: confirmation completed before local PET staging'
