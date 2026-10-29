#!/usr/bin/env bash
#
# Run the canonical DKG/PRE E2E scenario against one backend, or both.
#
# The scenario implementation is shared (bin/orbis-node/tests/support/{pre,
# sign,refresh,reshare}_scenario.rs); only which adapter/Cargo feature set and
# which test binary gets invoked differs per backend. `--backend all` runs
# cosmos then native sequentially and fails on the first failure — no retries.

set -Eeuo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPOSITORY_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

BACKEND=
SCENARIO=
CRYPTO=bls12-381
TOOLCHAIN=+1.98.0

usage() {
  cat <<'EOF'
Usage: scripts/test-e2e.sh --backend <cosmos|native|all> --scenario <dkg-pre> [options]

Options:
  --crypto <bls12-381|jubjub>   Crypto implementation, default: bls12-381
  -h, --help                    Show this help

Examples:
  scripts/test-e2e.sh --backend cosmos --scenario dkg-pre
  scripts/test-e2e.sh --backend native --scenario dkg-pre --crypto jubjub
  scripts/test-e2e.sh --backend all    --scenario dkg-pre
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --backend)
      BACKEND="$2"
      shift 2
      ;;
    --scenario)
      SCENARIO="$2"
      shift 2
      ;;
    --crypto)
      CRYPTO="$2"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

case "$BACKEND" in
  cosmos | native | all) ;;
  *)
    echo "--backend must be one of: cosmos, native, all (got: ${BACKEND:-<none>})" >&2
    exit 1
    ;;
esac

case "$SCENARIO" in
  dkg-pre) ;;
  *)
    echo "--scenario must be one of: dkg-pre (got: ${SCENARIO:-<none>})" >&2
    exit 1
    ;;
esac

case "$CRYPTO" in
  bls12-381 | jubjub) ;;
  *)
    echo "--crypto must be one of: bls12-381, jubjub (got: $CRYPTO)" >&2
    exit 1
    ;;
esac

run_cosmos_dkg_pre() {
  echo "==> cosmos dkg-pre (crypto=$CRYPTO)"
  cargo "$TOOLCHAIN" test --locked -p orbis-node \
    --features "integration-test-cosmos,$CRYPTO" \
    --lib -- tests::integration::cosmos_dkg_and_pre --exact --nocapture
}

run_native_dkg_pre() {
  echo "==> native dkg-pre (crypto=$CRYPTO)"
  cargo "$TOOLCHAIN" nextest run --locked -p orbis-node \
    --no-default-features \
    --features "integration-test-native,redb,iroh,$CRYPTO" \
    --test native_startup \
    -E 'test(=native_dkg_and_pre)'
}

cd "$REPOSITORY_ROOT"

case "$BACKEND" in
  cosmos)
    run_cosmos_dkg_pre
    ;;
  native)
    run_native_dkg_pre
    ;;
  all)
    run_cosmos_dkg_pre
    run_native_dkg_pre
    ;;
esac
