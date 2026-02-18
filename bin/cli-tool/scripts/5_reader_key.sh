#!/usr/bin/env bash
# Generate reader keypair and print exports READER_SK, READER_PK, READER_DID_PK.
# Usage: eval $(./bin/cli-tool/scripts/5_reader_key.sh)
set -e
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"
CLI_BIN="${CLI_BIN:-cargo run -p cli-tool --}"

KEYOUT="$("$CLI_BIN" generate-reader-key 2>/dev/null)"
READER_SK="$(echo "$KEYOUT" | grep -A1 'Reader Secret Key' | tail -1 | tr -d ' \t\r\n')"
READER_PK="$(echo "$KEYOUT" | grep -A1 'Reader Public Key' | tail -1 | tr -d ' \t\r\n')"
READER_DID_PK="${READER_DID_PK:-test_reader_did}"
echo "export READER_SK=$READER_SK"
echo "export READER_PK=$READER_PK"
echo "export READER_DID_PK=$READER_DID_PK"
