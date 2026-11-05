#!/usr/bin/env bash
# Run the same backend-neutral E2E test tree against Cosmos or native Vera.

set -Eeuo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd "$script_dir/.." && pwd)

backend=
crypto=bls12-381

usage() {
  cat <<'EOF'
Usage: scripts/test-e2e.sh --backend <cosmos|native|all> [--crypto <bls12-381|jubjub>]

The backend changes only the compile-time adapter. Both variants execute the
same `tests::e2e` module and backend-neutral scenario contracts. Tests are never
retried, so a qualification failure cannot be hidden by nextest's CI profile.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --backend)
      backend=${2:?missing backend}
      shift 2
      ;;
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

case "$backend" in
  cosmos | native | all) ;;
  *)
    echo "--backend must be cosmos, native, or all" >&2
    exit 2
    ;;
esac

case "$crypto" in
  bls12-381 | jubjub) ;;
  *)
    echo "--crypto must be bls12-381 or jubjub" >&2
    exit 2
    ;;
esac

run_backend() {
  local selected=$1
  local features
  local default_flags=()

  case "$selected" in
    cosmos)
      features="integration-test,authz-vera,bulletin-vera,fault-injection,$crypto"
      if [[ "$crypto" == jubjub ]]; then
        default_flags=(--no-default-features)
      fi
      ;;
    native)
      features="integration-test,native,redb,iroh,$crypto"
      default_flags=(--no-default-features)
      ;;
  esac

  echo "==> E2E backend=$selected crypto=$crypto"
  cargo nextest run --locked --profile ci --retries 0 --no-tests fail -p orbis-node --lib \
    "${default_flags[@]}" --features "$features" \
    -E 'test(/^tests::e2e::/)'
}

cd "$repository_root"
if [[ "$backend" == all ]]; then
  run_backend cosmos
  run_backend native
else
  run_backend "$backend"
fi
