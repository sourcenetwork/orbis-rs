#!/usr/bin/env bash
# Run PRE: re-encrypt secret for reader and decrypt. Prints decrypted secret.
# Requires ENDPOINT, RING_PK, READER_PK, READER_SK, OBJECT_ID, NAMESPACE, READER_DID_PK.
set -e
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"
CLI_BIN="${CLI_BIN:-cargo run -p cli-tool --}"

ENDPOINT="${ENDPOINT:-http://localhost:50051}"

: "${RING_PK:?Set RING_PK}"
: "${READER_PK:?Set READER_PK}"
: "${READER_SK:?Set READER_SK}"
: "${OBJECT_ID:?Set OBJECT_ID}"
: "${NAMESPACE:?Set NAMESPACE}"
: "${READER_DID_PK:?Set READER_DID_PK}"

"$CLI_BIN" pre \
  --endpoint "$ENDPOINT" \
  --ring-pk "$RING_PK" \
  --reader-pk "$READER_PK" \
  --reader-sk "$READER_SK" \
  --object-id "$OBJECT_ID" \
  --namespace "$NAMESPACE" \
  --reader-did-pk "$READER_DID_PK"
