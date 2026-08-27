#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPOSITORY_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/orbis-upgrade-unit.XXXXXX")
trap 'rm -rf "$TEST_ROOT"' EXIT

expect_failure() {
  local label=$1
  shift
  if "$SCRIPT_DIR/test-upgrade.sh" "$@" >"$TEST_ROOT/$label.log" 2>&1; then
    echo "expected failure: $label" >&2
    exit 1
  fi
}

bash -n "$SCRIPT_DIR/test-upgrade.sh"

"$SCRIPT_DIR/test-upgrade.sh" \
  --from HEAD \
  --to WORKTREE \
  --crypto both \
  --output "$TEST_ROOT/worktree" \
  --dry-run >"$TEST_ROOT/worktree.log"
grep -F "baseline: HEAD -> $(git -C "$REPOSITORY_ROOT" rev-parse HEAD)" \
  "$TEST_ROOT/worktree.log" >/dev/null
grep -F "target:   WORKTREE -> WORKTREE@" "$TEST_ROOT/worktree.log" >/dev/null

"$SCRIPT_DIR/test-upgrade.sh" \
  --from HEAD \
  --to HEAD \
  --crypto bls12-381 \
  --output "$TEST_ROOT/committed" \
  --dry-run >"$TEST_ROOT/committed.log"
grep -F "target:   HEAD -> $(git -C "$REPOSITORY_ROOT" rev-parse HEAD)" \
  "$TEST_ROOT/committed.log" >/dev/null

expect_failure invalid-ref \
  --from refs/heads/orbis-upgrade-ref-that-does-not-exist \
  --to HEAD \
  --dry-run
expect_failure baseline-worktree --from WORKTREE --to HEAD --dry-run
expect_failure invalid-crypto --from HEAD --to HEAD --crypto invalid --dry-run

echo "upgrade shell validation passed"
