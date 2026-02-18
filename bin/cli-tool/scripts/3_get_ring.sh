#!/usr/bin/env bash
# Get latest ring from bulletin (run after DKG completes). Prints RING_ID= and RING_PK= for eval.
# Usage: eval $(./bin/cli-tool/scripts/3_get_ring.sh)
# Optional: sleep 15 before running if DKG was just started.
set -e
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"
CLI_BIN="${CLI_BIN:-cargo run -p cli-tool --}"

"$CLI_BIN" get-latest-ring 2>/dev/null | grep -E '^RING_'
