#!/usr/bin/env bash
# Register bulletin namespace "orbis" and add node as collaborator.
# Requires NODE_PUBLIC_ADDRESS (from 0_info.sh).
set -e
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"
CLI_BIN="${CLI_BIN:-cargo run -p cli-tool --}"

: "${NODE_PUBLIC_ADDRESS:?Set NODE_PUBLIC_ADDRESS (eval \$(./bin/cli-tool/scripts/0_info.sh))}"

"$CLI_BIN" register-bulletin-namespace --namespace orbis
"$CLI_BIN" add-bulletin-collaborator --namespace orbis --collaborator "$NODE_PUBLIC_ADDRESS"
echo "Orbis namespace registered and collaborator added."
