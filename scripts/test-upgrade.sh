#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPOSITORY_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
COMPOSE_FILE="$REPOSITORY_ROOT/docker/docker-compose-upgrade-test.yml"

FROM_REF=
TO_REF=
CRYPTO=both
OUTPUT=
KEEP_ON_FAILURE=0
DRY_RUN=0
TEMP_ROOT=
FROM_CONTEXT=
TO_CONTEXT=
CURRENT_PROJECT=
CURRENT_OUTPUT=
CURRENT_IMAGE=
WORKTREES=()

NODE_SERVICES=(node-001 node-002 node-003 node-004)

usage() {
  cat <<'EOF'
Usage: scripts/test-upgrade.sh --from <git-ref> --to <git-ref|WORKTREE> [options]

Options:
  --crypto <bls12-381|decaf377|both>  Crypto implementation(s), default: both
  --output <directory>                Evidence directory
  --keep-on-failure                   Leave the failed Compose project running
  --dry-run                           Resolve inputs without building or starting Docker
  -h, --help                          Show this help

Both committed revisions must contain the upgrade-driver v1 contract. WORKTREE
is accepted only for --to and includes committed, modified, and untracked files.
EOF
}

die() {
  echo "upgrade harness: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --from)
      [[ $# -ge 2 ]] || die "--from requires a value"
      FROM_REF=$2
      shift 2
      ;;
    --to)
      [[ $# -ge 2 ]] || die "--to requires a value"
      TO_REF=$2
      shift 2
      ;;
    --crypto)
      [[ $# -ge 2 ]] || die "--crypto requires a value"
      CRYPTO=$2
      shift 2
      ;;
    --output)
      [[ $# -ge 2 ]] || die "--output requires a value"
      OUTPUT=$2
      shift 2
      ;;
    --keep-on-failure)
      KEEP_ON_FAILURE=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

[[ -n "$FROM_REF" ]] || die "--from is required"
[[ -n "$TO_REF" ]] || die "--to is required"
[[ "$FROM_REF" != WORKTREE ]] || die "WORKTREE is supported only for --to"
case "$CRYPTO" in
  bls12-381|decaf377|both) ;;
  *) die "--crypto must be bls12-381, decaf377, or both" ;;
esac

require_command git
require_command shasum
if [[ "$DRY_RUN" -eq 0 ]]; then
  require_command docker
fi

FROM_SHA=$(git -C "$REPOSITORY_ROOT" rev-parse --verify "${FROM_REF}^{commit}") \
  || die "cannot resolve baseline ref: $FROM_REF"

worktree_fingerprint() {
  local root=$1
  {
    git -C "$root" rev-parse HEAD
    git -C "$root" diff --binary HEAD -- .
    while IFS= read -r -d '' file; do
      printf '%s\0' "$file"
      shasum -a 256 "$root/$file"
    done < <(git -C "$root" ls-files --others --exclude-standard -z)
  } | shasum -a 256 | awk '{print $1}'
}

if [[ "$TO_REF" == WORKTREE ]]; then
  TO_SHA=$(git -C "$REPOSITORY_ROOT" rev-parse HEAD)
  TO_FINGERPRINT=$(worktree_fingerprint "$REPOSITORY_ROOT")
  TO_DESCRIPTION="WORKTREE@$TO_SHA+$TO_FINGERPRINT"
else
  TO_SHA=$(git -C "$REPOSITORY_ROOT" rev-parse --verify "${TO_REF}^{commit}") \
    || die "cannot resolve target ref: $TO_REF"
  TO_FINGERPRINT=$TO_SHA
  TO_DESCRIPTION=$TO_SHA
fi

if [[ -z "$OUTPUT" ]]; then
  RUN_STAMP=$(date -u +%Y%m%dT%H%M%SZ)
  OUTPUT="$REPOSITORY_ROOT/target/upgrade-tests/${RUN_STAMP}-${FROM_SHA:0:8}-${TO_FINGERPRINT:0:8}"
fi
mkdir -p "$OUTPUT"
OUTPUT=$(cd "$OUTPUT" && pwd)

echo "baseline: $FROM_REF -> $FROM_SHA"
echo "target:   $TO_REF -> $TO_DESCRIPTION"
echo "crypto:   $CRYPTO"
echo "evidence: $OUTPUT"

if [[ "$DRY_RUN" -eq 1 ]]; then
  exit 0
fi

TEMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/orbis-upgrade.XXXXXX")

remove_worktrees() {
  local worktree
  for worktree in "${WORKTREES[@]:-}"; do
    git -C "$REPOSITORY_ROOT" worktree remove --force "$worktree" >/dev/null 2>&1 || true
  done
  if [[ -n "$TEMP_ROOT" && -d "$TEMP_ROOT" ]]; then
    rmdir "$TEMP_ROOT" >/dev/null 2>&1 || true
  fi
}

compose() {
  docker compose --project-name "$CURRENT_PROJECT" --file "$COMPOSE_FILE" "$@"
}

collect_diagnostics() {
  [[ -n "$CURRENT_PROJECT" && -n "$CURRENT_OUTPUT" ]] || return 0
  mkdir -p "$CURRENT_OUTPUT/logs"
  compose ps --all >"$CURRENT_OUTPUT/logs/compose-ps.txt" 2>&1 || true
  compose logs --no-color >"$CURRENT_OUTPUT/logs/compose.log" 2>&1 || true
}

archive_databases() {
  local stage=$1
  local destination="$CURRENT_OUTPUT/databases/$stage"
  local service
  mkdir -p "$destination"
  for service in "${NODE_SERVICES[@]}"; do
    compose cp "$service:/data/dbs/orbis.redb" "$destination/$service.redb"
    shasum -a 256 "$destination/$service.redb" >"$destination/$service.redb.sha256"
  done
}

cleanup_current_project() {
  compose --profile driver down --volumes --remove-orphans >/dev/null 2>&1 || true
  CURRENT_PROJECT=
  CURRENT_OUTPUT=
  CURRENT_IMAGE=
}

on_exit() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n "$CURRENT_PROJECT" ]]; then
    collect_diagnostics
    if [[ "$status" -ne 0 && "$KEEP_ON_FAILURE" -eq 1 ]]; then
      echo "failed Compose project retained: $CURRENT_PROJECT" >&2
      echo "evidence directory: $CURRENT_OUTPUT" >&2
    else
      if [[ "$status" -ne 0 ]]; then
        compose stop --timeout 30 "${NODE_SERVICES[@]}" >/dev/null 2>&1 || true
        archive_databases failure >/dev/null 2>&1 || true
      fi
      cleanup_current_project
    fi
  fi
  remove_worktrees
  exit "$status"
}
trap on_exit EXIT INT TERM

FROM_CONTEXT="$TEMP_ROOT/from"
git -C "$REPOSITORY_ROOT" worktree add --detach "$FROM_CONTEXT" "$FROM_SHA" >/dev/null
WORKTREES+=("$FROM_CONTEXT")

if [[ "$TO_REF" == WORKTREE ]]; then
  TO_CONTEXT=$REPOSITORY_ROOT
else
  TO_CONTEXT="$TEMP_ROOT/to"
  git -C "$REPOSITORY_ROOT" worktree add --detach "$TO_CONTEXT" "$TO_SHA" >/dev/null
  WORKTREES+=("$TO_CONTEXT")
fi

require_contract() {
  local context=$1
  local label=$2
  [[ -f "$context/bin/orbis-bench/src/bin/orbis-upgrade-driver.rs" ]] \
    || die "$label revision predates the upgrade-driver v1 compatibility floor"
  [[ -f "$context/docker/Dockerfile.upgrade-test" ]] \
    || die "$label revision does not contain docker/Dockerfile.upgrade-test"
}
require_contract "$FROM_CONTEXT" baseline
require_contract "$TO_CONTEXT" target

SOURCEHUB_REF=$(tr -d '[:space:]' <"$FROM_CONTEXT/docker/SOURCEHUB_REF")
[[ -n "$SOURCEHUB_REF" ]] || die "baseline docker/SOURCEHUB_REF is empty"
SOURCEHUB_TAG_HASH=$(printf '%s' "$SOURCEHUB_REF" | shasum -a 256 | awk '{print $1}')
SOURCEHUB_IMAGE="orbis-upgrade-sourcehub:${SOURCEHUB_TAG_HASH:0:12}"

run_phase() {
  local label=$1
  shift
  local started ended status
  started=$(date +%s)
  printf '%s start %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$label" \
    | tee -a "$CURRENT_OUTPUT/phase-timings.log"
  set +e
  "$@"
  status=$?
  set -e
  ended=$(date +%s)
  printf '%s finish %s status=%s duration_secs=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$label" "$status" "$((ended - started))" \
    | tee -a "$CURRENT_OUTPUT/phase-timings.log"
  return "$status"
}

SOURCEHUB_BUILD_OUTPUT="$OUTPUT/sourcehub-build"
mkdir -p "$SOURCEHUB_BUILD_OUTPUT"
CURRENT_OUTPUT=$SOURCEHUB_BUILD_OUTPUT
run_phase build-sourcehub docker build \
  --file "$FROM_CONTEXT/docker/Dockerfile.sourcehub-integration" \
  --tag "$SOURCEHUB_IMAGE" \
  --build-arg "SOURCEHUB_REF=$SOURCEHUB_REF" \
  "$FROM_CONTEXT/docker"
docker image inspect --format '{{.Id}}' "$SOURCEHUB_IMAGE" \
  >"$SOURCEHUB_BUILD_OUTPUT/image-id.txt"
CURRENT_OUTPUT=

if [[ "$CRYPTO" == both ]]; then
  CRYPTO_RUNS=(bls12-381 decaf377)
else
  CRYPTO_RUNS=("$CRYPTO")
fi

run_crypto_upgrade() {
  local crypto=$1
  local from_image="orbis-upgrade-driver:${FROM_SHA:0:12}-${crypto}"
  local to_image="orbis-upgrade-driver:${TO_FINGERPRINT:0:12}-${crypto}"
  local project_crypto=${crypto//[^a-zA-Z0-9]/-}

  CURRENT_OUTPUT="$OUTPUT/$crypto"
  CURRENT_PROJECT="orbis-upgrade-$$-$project_crypto"
  CURRENT_IMAGE=$from_image
  mkdir -p "$CURRENT_OUTPUT"
  cp "$COMPOSE_FILE" "$CURRENT_OUTPUT/compose.yaml"
  {
    printf 'FROM_REF=%q\n' "$FROM_REF"
    printf 'FROM_SHA=%q\n' "$FROM_SHA"
    printf 'TO_REF=%q\n' "$TO_REF"
    printf 'TO_SHA=%q\n' "$TO_SHA"
    printf 'TO_FINGERPRINT=%q\n' "$TO_FINGERPRINT"
    printf 'CRYPTO=%q\n' "$crypto"
    printf 'SOURCEHUB_REF=%q\n' "$SOURCEHUB_REF"
    printf 'SOURCEHUB_IMAGE=%q\n' "$SOURCEHUB_IMAGE"
    printf 'BASELINE_IMAGE=%q\n' "$from_image"
    printf 'TARGET_IMAGE=%q\n' "$to_image"
    printf 'COMPOSE_PROJECT=%q\n' "$CURRENT_PROJECT"
  } >"$CURRENT_OUTPUT/resolved-refs.env"

  run_phase build-baseline-driver docker build \
    --file "$FROM_CONTEXT/docker/Dockerfile.upgrade-test" \
    --tag "$from_image" \
    --build-arg "CRYPTO_FEATURE=$crypto" \
    "$FROM_CONTEXT"
  run_phase build-target-driver docker build \
    --file "$TO_CONTEXT/docker/Dockerfile.upgrade-test" \
    --tag "$to_image" \
    --build-arg "CRYPTO_FEATURE=$crypto" \
    "$TO_CONTEXT"
  {
    printf 'SOURCEHUB_IMAGE_ID=%q\n' "$(docker image inspect --format '{{.Id}}' "$SOURCEHUB_IMAGE")"
    printf 'BASELINE_IMAGE_ID=%q\n' "$(docker image inspect --format '{{.Id}}' "$from_image")"
    printf 'TARGET_IMAGE_ID=%q\n' "$(docker image inspect --format '{{.Id}}' "$to_image")"
  } >>"$CURRENT_OUTPUT/resolved-refs.env"

  export ORBIS_UPGRADE_SOURCEHUB_IMAGE=$SOURCEHUB_IMAGE
  export ORBIS_UPGRADE_IMAGE=$from_image
  export ORBIS_UPGRADE_OUTPUT=$CURRENT_OUTPUT

  run_phase start-baseline compose up --detach --wait --wait-timeout 600 \
    sourcehub "${NODE_SERVICES[@]}"
  local sourcehub_container
  sourcehub_container=$(compose ps --quiet sourcehub)
  [[ -n "$sourcehub_container" ]] || die "SourceHub container was not created"
  printf 'SOURCEHUB_CONTAINER=%q\n' "$sourcehub_container" \
    >>"$CURRENT_OUTPUT/container-ids.env"
  local service
  for service in "${NODE_SERVICES[@]}"; do
    printf 'BASELINE_%s=%q\n' "${service//-/_}" "$(compose ps --quiet "$service")" \
      >>"$CURRENT_OUTPUT/container-ids.env"
  done
  run_phase prepare-baseline compose run --rm --no-deps driver prepare \
    --manifest /artifacts/fixture-v1.json \
    --baseline-sha "$FROM_SHA" \
    --crypto "$crypto" \
    --sourcehub-ref "$SOURCEHUB_REF"

  run_phase stop-baseline compose stop --timeout 30 "${NODE_SERVICES[@]}"
  run_phase archive-baseline archive_databases pre-cutover

  export ORBIS_UPGRADE_IMAGE=$to_image
  CURRENT_IMAGE=$to_image
  run_phase start-target compose up --detach --no-deps --force-recreate \
    --wait --wait-timeout 600 "${NODE_SERVICES[@]}"
  [[ "$(compose ps --quiet sourcehub)" == "$sourcehub_container" ]] \
    || die "SourceHub was recreated during the Orbis-only cutover"
  for service in "${NODE_SERVICES[@]}"; do
    local baseline_container target_container baseline_key
    baseline_key="BASELINE_${service//-/_}"
    baseline_container=$(sed -n "s/^${baseline_key}=//p" "$CURRENT_OUTPUT/container-ids.env")
    target_container=$(compose ps --quiet "$service")
    [[ -n "$target_container" && "$target_container" != "$baseline_container" ]] \
      || die "$service was not recreated with the target image"
    printf 'TARGET_%s=%q\n' "${service//-/_}" "$target_container" \
      >>"$CURRENT_OUTPUT/container-ids.env"
  done
  run_phase verify-target compose run --rm --no-deps driver verify \
    --manifest /artifacts/fixture-v1.json \
    --result /artifacts/verification-v1.json \
    --target-sha "$TO_DESCRIPTION"

  run_phase stop-target compose stop --timeout 30 "${NODE_SERVICES[@]}"
  run_phase archive-target archive_databases post-reshare
  collect_diagnostics
  cleanup_current_project
}

for crypto in "${CRYPTO_RUNS[@]}"; do
  run_crypto_upgrade "$crypto"
done

echo "upgrade compatibility verified; evidence: $OUTPUT"
