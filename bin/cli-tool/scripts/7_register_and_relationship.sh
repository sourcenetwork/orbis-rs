#!/usr/bin/env bash
# Register object on chain and set reader relationship for the DID.
# Requires POLICY_ID, OBJECT_ID, RESOURCE (default: document), READER_DID_PK.
set -e
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"
CLI_BIN="${CLI_BIN:-cargo run -p cli-tool --}"

RESOURCE="${RESOURCE:-document}"

: "${POLICY_ID:?Set POLICY_ID}"
: "${OBJECT_ID:?Set OBJECT_ID (from 6_store_secret.sh output)}"
: "${READER_DID_PK:?Set READER_DID_PK}"

"$CLI_BIN" register-object-to-chain --policy-id "$POLICY_ID" --object-id "$OBJECT_ID" --resource "$RESOURCE"
"$CLI_BIN" set-relationship-on-chain \
  --policy-id "$POLICY_ID" --object-id "$OBJECT_ID" --resource "$RESOURCE" \
  --relation reader --reader-did-pk "$READER_DID_PK"
echo "Object registered and reader relationship set."
