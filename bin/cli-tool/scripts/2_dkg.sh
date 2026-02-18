#!/usr/bin/env bash
# Run DKG. Requires ENDPOINT, NODE_PEER_ID (or PEER_IDS), and optionally THRESHOLD (default 1).
set -e
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"
CLI_BIN="${CLI_BIN:-cargo run -p cli-tool --}"

ENDPOINT="${ENDPOINT:-http://localhost:50051}"
THRESHOLD="${THRESHOLD:-1}"
PEER_IDS="${PEER_IDS:-$NODE_PEER_ID}"

: "${PEER_IDS:?Set PEER_IDS or NODE_PEER_ID (eval \$(./bin/cli-tool/scripts/0_info.sh))}"

"$CLI_BIN" dkg --endpoint "$ENDPOINT" --threshold "$THRESHOLD" --peer-ids $PEER_IDS
echo "DKG started. Wait ~15s then run: eval \$(./bin/cli-tool/scripts/3_get_ring.sh)"
