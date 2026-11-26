#!/usr/bin/env bash
set -euo pipefail
umask 077
work=$(mktemp -d "${RUNNER_TEMP:-/tmp}/orbis-common-backend.XXXXXX")
for backend in vera shared; do
  flags=(--features vera)
  expected=9
  if [[ "$backend" == shared ]]; then
    flags=(--no-default-features)
    expected=7
  fi
  if ! cargo +1.99.1 test --locked --jobs 2 -p common --lib "${flags[@]}" > "$work/$backend-tests.log" 2>&1; then
    echo "common backend=$backend tests=failed; diagnostics remain private" >&2
    exit 1
  fi
  python3 scripts/common-backend-summary.py "$work/$backend-tests.log" "$backend" "$expected"
  if ! cargo +1.99.1 clippy --message-format=json --locked --jobs 2 -p common --all-targets "${flags[@]}" -- -D warnings > "$work/$backend-clippy.log" 2>&1; then
    python3 scripts/common-backend-summary.py --diagnostics "$work/$backend-clippy.log" "$backend"
    echo "common backend=$backend clippy=failed; diagnostics remain private" >&2
    exit 1
  fi
  echo "common backend=$backend clippy=passed"
done
