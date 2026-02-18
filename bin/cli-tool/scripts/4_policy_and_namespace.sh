#!/usr/bin/env bash
# Add test policy to chain, register user namespace, add node as collaborator.
# Exports POLICY_ID and NAMESPACE. Set NAMESPACE (default: demo) and NODE_PUBLIC_ADDRESS.
set -e
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"
CLI_BIN="${CLI_BIN:-cargo run -p cli-tool --}"

NAMESPACE="${NAMESPACE:-demo}"
: "${NODE_PUBLIC_ADDRESS:?Set NODE_PUBLIC_ADDRESS}"

POLICY_ID="$("$CLI_BIN" add-policy-to-chain 2>/dev/null | grep '^POLICY_ID=' | cut -d= -f2-)"
export POLICY_ID
echo "export POLICY_ID=$POLICY_ID"
echo "export NAMESPACE=$NAMESPACE"

"$CLI_BIN" register-bulletin-namespace --namespace "$NAMESPACE"
"$CLI_BIN" add-bulletin-collaborator --namespace "$NAMESPACE" --collaborator "$NODE_PUBLIC_ADDRESS"
echo "Policy and namespace ready."
