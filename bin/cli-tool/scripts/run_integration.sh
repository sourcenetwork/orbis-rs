#!/usr/bin/env bash
# Run the full Orbis flow against the Docker integration stack (3 nodes, threshold 2).
# Mirrors test_cli_calls_dkg_and_pre_endpoint in bin/orbis-node/src/tests.rs.
#
# Prerequisites:
#   - From workspace root: docker compose -f docker/docker-compose-integration-test.yml up -d
#   - Wait until sourcehub and all 3 nodes are healthy (ports 26657, 50051, 50052, 50053)
set -e
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"
CLI_BIN="${CLI_BIN:-cargo run -p cli-tool --}"

# Match IntegrationTestNetwork in crates/common
NODE1_GRPC="http://localhost:50051"
NODE2_GRPC="http://localhost:50052"
NODE3_GRPC="http://localhost:50053"
NODE1_CONTAINER="orbis-integration-node-1"
NODE2_CONTAINER="orbis-integration-node-2"
NODE3_CONTAINER="orbis-integration-node-3"
THRESHOLD=2
NAMESPACE="${NAMESPACE:-docker_test_namespace}"

# Transform P2P address for Docker: peer_id@0.0.0.0:port -> peer_id@container:port
transform_p2p() {
  local p2p="$1"
  local container="$2"
  if [[ "$p2p" =~ ^([^@]+)@[^:]*:(.+)$ ]]; then
    echo "${BASH_REMATCH[1]}@${container}:${BASH_REMATCH[2]}"
  else
    echo "$p2p"
  fi
}

echo "=== Waiting for nodes (integration stack) ==="
for port in 26657 50051 50052 50053; do
  for i in {1..60}; do
    if nc -z localhost "$port" 2>/dev/null; then break; fi
    if [[ $i -eq 60 ]]; then echo "Port $port not ready"; exit 1; fi
    sleep 1
  done
done
echo "Nodes ready."

echo "=== 0: Node info (all 3) ==="
INFO1="$($CLI_BIN info --endpoint "$NODE1_GRPC" 2>/dev/null)"
INFO2="$($CLI_BIN info --endpoint "$NODE2_GRPC" 2>/dev/null)"
INFO3="$($CLI_BIN info --endpoint "$NODE3_GRPC" 2>/dev/null)"

NODE1_PUBLIC="$(echo "$INFO1" | awk '/Public Address:/ { sub(/^[ \t]*Public Address: /, ""); print; exit }')"
NODE2_PUBLIC="$(echo "$INFO2" | awk '/Public Address:/ { sub(/^[ \t]*Public Address: /, ""); print; exit }')"
NODE3_PUBLIC="$(echo "$INFO3" | awk '/Public Address:/ { sub(/^[ \t]*Public Address: /, ""); print; exit }')"
NODE1_P2P="$(echo "$INFO1" | awk '/P2P Address:/ { sub(/^[ \t]*P2P Address: /, ""); print; exit }')"
NODE2_P2P="$(echo "$INFO2" | awk '/P2P Address:/ { sub(/^[ \t]*P2P Address: /, ""); print; exit }')"
NODE3_P2P="$(echo "$INFO3" | awk '/P2P Address:/ { sub(/^[ \t]*P2P Address: /, ""); print; exit }')"

PEER1="$(transform_p2p "$NODE1_P2P" "$NODE1_CONTAINER")"
PEER2="$(transform_p2p "$NODE2_P2P" "$NODE2_CONTAINER")"
PEER3="$(transform_p2p "$NODE3_P2P" "$NODE3_CONTAINER")"
echo "Transformed peer 1: $PEER1"
echo "Transformed peer 2: $PEER2"
echo "Transformed peer 3: $PEER3"

echo "=== 1: Register orbis namespace and add all 3 as collaborators ==="
$CLI_BIN register-bulletin-namespace --namespace orbis
$CLI_BIN add-bulletin-collaborator --namespace orbis --collaborator "$NODE1_PUBLIC"
$CLI_BIN add-bulletin-collaborator --namespace orbis --collaborator "$NODE2_PUBLIC"
$CLI_BIN add-bulletin-collaborator --namespace orbis --collaborator "$NODE3_PUBLIC"

echo "=== 2: DKG (3 nodes, threshold 2) ==="
$CLI_BIN dkg --endpoint "$NODE1_GRPC" --threshold "$THRESHOLD" --peer-ids "$PEER1" "$PEER2" "$PEER3"

echo "=== 3: Wait for DKG completion then get RING_ID / RING_PK ==="
echo "Waiting 30s for DKG to complete..."
sleep 30
eval "$($CLI_BIN get-latest-ring 2>/dev/null | grep -E '^RING_')"
if [[ -z "${RING_ID:-}" || -z "${RING_PK:-}" ]]; then
  echo "Error: Could not get RING_ID/RING_PK (get-latest-ring failed or no ring in orbis namespace). DKG may need more time or check node logs." >&2
  exit 1
fi

echo "=== 4: Policy and user namespace ==="
export NAMESPACE
POLICY_ID="$($CLI_BIN add-policy-to-chain 2>/dev/null | grep '^POLICY_ID=' | cut -d= -f2-)"
export POLICY_ID
$CLI_BIN register-bulletin-namespace --namespace "$NAMESPACE"
$CLI_BIN add-bulletin-collaborator --namespace "$NAMESPACE" --collaborator "$NODE1_PUBLIC"

echo "=== 5: Generate reader keypair ==="
KEYOUT="$($CLI_BIN generate-reader-key 2>/dev/null)"
READER_SK="$(echo "$KEYOUT" | grep -A1 'Reader Secret Key' | tail -1 | tr -d ' \t\r\n')"
READER_PK="$(echo "$KEYOUT" | grep -A1 'Reader Public Key' | tail -1 | tr -d ' \t\r\n')"
export READER_SK READER_PK
READER_DID_PK="${READER_DID_PK:-test_did_secret}"
export READER_DID_PK

echo "=== 6: Store secret ==="
SECRET="${SECRET:-Hello from StoreSecret!}"
RESOURCE="${RESOURCE:-document}"
PERMISSION="${PERMISSION:-read}"
OUT="$($CLI_BIN store-secret \
  --endpoint "$NODE1_GRPC" \
  --secret "$SECRET" \
  --ring-pk-hex "$RING_PK" \
  --ring-id "$RING_ID" \
  --namespace "$NAMESPACE" \
  --policy-id "$POLICY_ID" \
  --resource "$RESOURCE" \
  --permission "$PERMISSION" \
  --reader-did-pk "$READER_DID_PK" \
  --with-proof)"
echo "$OUT"
OBJECT_ID="$(echo "$OUT" | grep 'Object ID:' | awk '{print $NF}')"
if [[ -z "${OBJECT_ID:-}" ]]; then
  echo "Error: Store secret did not return Object ID. Check output above." >&2
  exit 1
fi
export OBJECT_ID

echo "=== 7: Register object and set reader relationship ==="
$CLI_BIN register-object-to-chain --policy-id "$POLICY_ID" --object-id "$OBJECT_ID" --resource "$RESOURCE"
$CLI_BIN set-relationship-on-chain \
  --policy-id "$POLICY_ID" --object-id "$OBJECT_ID" --resource "$RESOURCE" \
  --relation reader --reader-did-pk "$READER_DID_PK"

echo "=== 8: PRE (re-encrypt and decrypt) ==="
$CLI_BIN pre \
  --endpoint "$NODE1_GRPC" \
  --ring-pk "$RING_PK" \
  --reader-pk "$READER_PK" \
  --reader-sk "$READER_SK" \
  --object-id "$OBJECT_ID" \
  --namespace "$NAMESPACE" \
  --reader-did-pk "$READER_DID_PK"

echo "=== Done ==="
