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
  --crypto bls12-381 \
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
grep -F "fresh target chain: auto" "$TEST_ROOT/committed.log" >/dev/null

"$SCRIPT_DIR/test-upgrade.sh" \
  --from HEAD \
  --to WORKTREE \
  --crypto bls12-381 \
  --fresh-target-chain \
  --output "$TEST_ROOT/fresh" \
  --dry-run >"$TEST_ROOT/fresh.log"
grep -F "fresh target chain: 1" "$TEST_ROOT/fresh.log" >/dev/null

expect_failure to-vera-ref-missing-value \
  --from HEAD --to HEAD --dry-run --to-vera-ref
expect_failure invalid-ref \
  --from refs/heads/orbis-upgrade-ref-that-does-not-exist \
  --to HEAD \
  --dry-run
expect_failure baseline-worktree --from WORKTREE --to HEAD --dry-run
expect_failure invalid-crypto --from HEAD --to HEAD --crypto invalid --dry-run

# Exercise curve preflight independently of the feature set in this checkout's
FIXTURE_ROOT="$TEST_ROOT/curve-fixture"
mkdir -p "$FIXTURE_ROOT/scripts" "$FIXTURE_ROOT/crates/crypto"
cp "$SCRIPT_DIR/test-upgrade.sh" "$FIXTURE_ROOT/scripts/test-upgrade.sh"
git init --quiet "$FIXTURE_ROOT"
cat >"$FIXTURE_ROOT/crates/crypto/Cargo.toml" <<'EOF'
[features]
bls12-381 = []
EOF
git -C "$FIXTURE_ROOT" add .
git -C "$FIXTURE_ROOT" -c user.name=Test -c user.email=test@example.invalid \
  commit --quiet -m baseline
BASELINE=$(git -C "$FIXTURE_ROOT" rev-parse HEAD)
printf 'jubjub = []\n' >>"$FIXTURE_ROOT/crates/crypto/Cargo.toml"
git -C "$FIXTURE_ROOT" add .
git -C "$FIXTURE_ROOT" -c user.name=Test -c user.email=test@example.invalid \
  commit --quiet -m jubjub

"$FIXTURE_ROOT/scripts/test-upgrade.sh" --from HEAD --to WORKTREE \
  --crypto both --dry-run --output "$TEST_ROOT/supported" >"$TEST_ROOT/supported.log"

if "$FIXTURE_ROOT/scripts/test-upgrade.sh" --from "$BASELINE" --to HEAD \
  --crypto jubjub --dry-run >"$TEST_ROOT/missing-baseline.log" 2>&1; then
  echo "expected unsupported baseline to fail before dry-run success" >&2
  exit 1
fi
grep -F "baseline $BASELINE does not support jubjub" "$TEST_ROOT/missing-baseline.log" >/dev/null

if "$FIXTURE_ROOT/scripts/test-upgrade.sh" --from HEAD --to "$BASELINE" \
  --crypto jubjub --dry-run >"$TEST_ROOT/missing-target.log" 2>&1; then
  echo "expected unsupported target to fail before dry-run success" >&2
  exit 1
fi
grep -F "target $BASELINE does not support jubjub" "$TEST_ROOT/missing-target.log" >/dev/null

echo "upgrade shell validation passed"
