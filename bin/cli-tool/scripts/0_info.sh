#!/usr/bin/env bash
# Query node info and print exports for NODE_PEER_ID, NODE_PUBLIC_ADDRESS, NODE_P2P_ADDRESS.
# Usage: eval $(./bin/cli-tool/scripts/0_info.sh)
set -e
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"
CLI_BIN="${CLI_BIN:-cargo run -p cli-tool --}"
ENDPOINT="${ENDPOINT:-http://localhost:50051}"

"$CLI_BIN" info --endpoint "$ENDPOINT" 2>/dev/null | awk '
  /Public Address:/ { sub(/^[ \t]*Public Address: /, ""); print "export NODE_PUBLIC_ADDRESS=" $0 }
  /Peer ID:/         { sub(/^[ \t]*Peer ID: /, ""); print "export NODE_PEER_ID=" $0 }
  /P2P Address:/    { sub(/^[ \t]*P2P Address: /, ""); print "export NODE_P2P_ADDRESS=" $0 }
'
echo "export ENDPOINT=$ENDPOINT"
