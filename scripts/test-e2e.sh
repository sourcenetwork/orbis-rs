#!/usr/bin/env bash
# Run the E2E test tree against Vera.

set -Eeuo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd "$script_dir/.." && pwd)

crypto=bls12-381

usage() {
  cat <<'ENDUSAGE'
Usage: scripts/test-e2e.sh [--crypto <bls12-381|jubjub>]

Executes the `tests::e2e` module. Tests are never retried, so a qualification
failure cannot be hidden by nextest's CI profile.
ENDUSAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --crypto)
      crypto=${2:?missing crypto implementation}
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$crypto" in
  bls12-381 | jubjub) ;;
  *)
    echo "--crypto must be bls12-381 or jubjub" >&2
    exit 2
    ;;
esac

cd "$repository_root"
echo "==> E2E crypto=$crypto"
cargo nextest run --locked --profile ci --retries 0 --no-tests fail -p orbis-node --lib \
  --no-default-features --features "integration-test,vera,test-support/vera,redb,iroh,$crypto" \
  -E 'test(/^tests::e2e::/)'
