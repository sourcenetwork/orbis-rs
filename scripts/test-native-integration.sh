#!/usr/bin/env bash
set -euo pipefail
curve=${1:?expected native curve}
case "$curve" in bls12-381|jubjub) ;; *) exit 2 ;; esac
# The shared Rust workflow's reduced KDF/profile settings are for other fixtures.
while IFS='=' read -r name _; do
  case "$name" in
    CARGO_PROFILE_*|ORBIS_LOCAL_STORAGE_KDF_*|RUSTFLAGS|CARGO_ENCODED_RUSTFLAGS|CARGO_BUILD_RUSTFLAGS|VERA_E2E_DEADLINE_SCALE|RUSTC|RUSTDOC|RUSTUP_TOOLCHAIN|RUSTC_WRAPPER|RUSTC_WORKSPACE_WRAPPER|CARGO_BUILD_RUSTC*|CARGO_BUILD_RUSTDOC*|CARGO_BUILD_TARGET|CARGO_TARGET_*_RUSTFLAGS) unset "$name" ;;
  esac
done < <(env)
umask 077
work=$(mktemp -d "${RUNNER_TEMP:-/tmp}/orbis-native-integration.XXXXXX")
export CARGO_TARGET_DIR="$work/target" CARGO_BUILD_JOBS=2 CARGO_TERM_COLOR=never
export VERA_E2E_KEEP=1 VERA_E2E_DIR="$work/vera" ORBIS_NATIVE_E2E_DIR="$work/orbis"
mkdir -p "$VERA_E2E_DIR" "$ORBIS_NATIVE_E2E_DIR"
features="native,redb,iroh,$curve"
expression='binary(native_startup) & (test(=native_pet_threshold_workflows) | test(=native_distributed_threshold_workflows) | test(=native_pet_member_replacement))'
common=(--release --locked --build-jobs 2 -p orbis-node --no-default-features --features "$features" --test native_startup --run-ignored only -E "$expression")
if ! cargo +1.98.0 nextest list "${common[@]}" --message-format json > "$work/selection.json" 2> "$work/compile.log"; then
  echo 'Native container test compilation failed; diagnostics remain private.' >&2
  exit 1
fi
python3 scripts/native_lifecycle_summary.py --list "$work/selection.json"
status=0
cargo +1.98.0 nextest run --profile ci "${common[@]}" --retries 0 --test-threads 1 --no-capture > "$work/runtime.log" 2>&1 || status=$?
python3 scripts/native_lifecycle_summary.py --log "$work/runtime.log" --curve "$curve" --exit-code "$status"

# The normal image and three-scenario qualification above remain separate from
# the opt-in testing service used by this one attributable-fault regression.
fault="$work/fault-report"
mkdir -p "$fault"
common=(--release --locked --build-jobs 2 -p orbis-node --no-default-features --features "$features,unsafe-testing" --test native_startup --run-ignored only -E 'binary(native_startup) & test(=native_pet_fault_reports)')
if ! cargo +1.98.0 nextest list "${common[@]}" --message-format json > "$fault/selection.json" 2> "$fault/compile.log"; then
  echo 'Native fault-report compilation failed; diagnostics remain private.' >&2
  exit 1
fi
python3 scripts/native_lifecycle_summary.py --suite fault-report --list "$fault/selection.json"
status=0
cargo +1.98.0 nextest run --profile ci "${common[@]}" --retries 0 --test-threads 1 --no-tests fail --no-capture > "$fault/runtime.log" 2>&1 || status=$?
python3 scripts/native_lifecycle_summary.py --suite fault-report --log "$fault/runtime.log" --curve "$curve" --exit-code "$status"
