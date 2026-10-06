#!/usr/bin/env bash
set -euo pipefail
umask 077
work=$(mktemp -d "${RUNNER_TEMP:-/tmp}/orbis-common-backend.XXXXXX")
for backend in cosmos shared; do
  flags=()
  expected=34
  if [[ "$backend" == shared ]]; then
    flags=(--no-default-features)
    expected=16
  fi
  if ! cargo +1.98.0 test --locked --jobs 2 -p common --lib "${flags[@]}" > "$work/$backend-tests.log" 2>&1; then
    echo "common backend=$backend tests=failed; diagnostics remain private" >&2
    exit 1
  fi
  python3 scripts/common-backend-summary.py "$work/$backend-tests.log" "$backend" "$expected"
  if ! cargo +1.98.0 clippy --locked --jobs 2 -p common --all-targets "${flags[@]}" -- -D warnings > "$work/$backend-clippy.log" 2>&1; then
    echo "common backend=$backend clippy=failed; diagnostics remain private" >&2
    exit 1
  fi
  echo "common backend=$backend clippy=passed"
done
