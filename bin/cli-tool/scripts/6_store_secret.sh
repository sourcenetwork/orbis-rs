#!/usr/bin/env bash
# Store a secret. Requires ENDPOINT, RING_PK, RING_ID, POLICY_ID, READER_PK, READER_SK, READER_DID_PK.
# Optional: SECRET (default "Hello from CLI flow"), RESOURCE (document), PERMISSION (read).
# Exports OBJECT_ID from output (for use in 7 and 8).
set -e
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"
CLI_BIN="${CLI_BIN:-cargo run -p cli-tool --}"

ENDPOINT="${ENDPOINT:-http://localhost:50051}"
SECRET="${SECRET:-Hello from CLI flow}"
RESOURCE="${RESOURCE:-document}"
PERMISSION="${PERMISSION:-read}"

: "${RING_PK:?Set RING_PK (eval \$(./bin/cli-tool/scripts/3_get_ring.sh))}"
: "${RING_ID:?Set RING_ID}"
: "${POLICY_ID:?Set POLICY_ID}"
: "${READER_DID_PK:?Set READER_DID_PK (eval \$(./bin/cli-tool/scripts/5_reader_key.sh))}"

OUT="$("$CLI_BIN" store-secret \
  --endpoint "$ENDPOINT" \
  --secret "$SECRET" \
  --ring-pk-hex "$RING_PK" \
  --ring-id "$RING_ID" \
  --policy-id "$POLICY_ID" \
  --resource "$RESOURCE" \
  --permission "$PERMISSION" \
  --reader-did-pk "$READER_DID_PK" 2>/dev/null)"
echo "$OUT"
OBJECT_ID="$(echo "$OUT" | grep 'Object ID:' | awk '{print $NF}')"
echo "export OBJECT_ID=$OBJECT_ID"
