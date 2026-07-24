#!/usr/bin/env bash
#
# Sync dashboard JSON in docker/grafana/dashboards/ with a running Grafana
# instance over its HTTP API, instead of relying on the filesystem-based
# provisioning that docker-compose uses (bind mount + file provider). This is
# what lets you get these dashboards into a Kubernetes Grafana without
# wiring up a ConfigMap/PVC/sidecar just to place a file on disk.
#
# Usage:
#   sync-dashboards.sh push [--dir DIR] [--folder NAME]
#     Upload every *.json in DIR into Grafana via POST /api/dashboards/db.
#     Idempotent: matches by each dashboard's own "uid" field and overwrites
#     in place, so re-running never creates duplicates.
#
#   sync-dashboards.sh dump [--dir DIR] [--folder NAME] [uid...] [--all]
#     Pull dashboard JSON back out of Grafana via GET /api/dashboards/uid/:uid
#     and write it into DIR, so edits made in the Grafana UI can be captured
#     back into the repo. With no uid given, re-dumps whatever is already
#     tracked in DIR. With --all, also discovers and writes dashboards that
#     exist in the target Grafana folder but aren't tracked locally yet.
#
# Config (env vars):
#   GRAFANA_URL       Base URL of the target Grafana. Default: http://localhost:3000
#   GRAFANA_USER      Basic auth username. Default: admin
#   GRAFANA_PASSWORD  Basic auth password. Default: admin
#   GRAFANA_API_KEY   If set, used as a bearer token instead of basic auth.
#                     Use this for a locked-down Grafana (e.g. a Kubernetes
#                     service account token) instead of GRAFANA_USER/PASSWORD.
#   GRAFANA_FOLDER    Folder title dashboards live in. Default: Orbis
#                     (must match docker/grafana/provisioning/dashboards/dashboards.yml)
#
# Examples:
#   # Push local dashboards into the docker-compose Grafana (admin/admin)
#   ./sync-dashboards.sh push
#
#   # Push into a Kubernetes Grafana reachable via port-forward, using an API token
#   GRAFANA_URL=http://localhost:3000 GRAFANA_API_KEY=glsa_xxx ./sync-dashboards.sh push
#
#   # Capture UI edits back into the repo
#   ./sync-dashboards.sh dump
#
# Requires: curl, jq
#
# Note: this uses Grafana's legacy /api/dashboards, /api/folders, and
# /api/search endpoints. They remain supported as of this writing but Grafana
# has been migrating toward a newer /apis/... resource-model API in recent
# major versions -- if a future Grafana upgrade drops the legacy endpoints,
# this script will need updating.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DASHBOARD_DIR="${SCRIPT_DIR}/dashboards"
GRAFANA_URL="${GRAFANA_URL:-http://localhost:3000}"
GRAFANA_USER="${GRAFANA_USER:-admin}"
GRAFANA_PASSWORD="${GRAFANA_PASSWORD:-admin}"
GRAFANA_FOLDER="${GRAFANA_FOLDER:-Orbis}"

usage() {
  sed -n '2,48p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

check_deps() {
  local bin
  for bin in curl jq; do
    if ! command -v "$bin" >/dev/null 2>&1; then
      echo "error: '$bin' is required but not found on PATH" >&2
      exit 1
    fi
  done
}

# Populates the global AUTH_ARGS array used by every api_call. Deliberately
# not "local" -- plain assignment inside a bash function is global scope,
# which keeps this portable to bash 3.2 (macOS's default; no "declare -g" there).
set_auth_args() {
  if [[ -n "${GRAFANA_API_KEY:-}" ]]; then
    AUTH_ARGS=(-H "Authorization: Bearer ${GRAFANA_API_KEY}")
  else
    AUTH_ARGS=(-u "${GRAFANA_USER}:${GRAFANA_PASSWORD}")
  fi
}

# api_call METHOD PATH [JSON_BODY] -> prints response body on stdout.
# Fails (prints an error to stderr, returns 1) on a non-2xx response.
api_call() {
  local method="$1" path="$2" data="${3:-}"
  local url="${GRAFANA_URL%/}${path}"
  local -a curl_args=(-sS -w '\n%{http_code}' -X "$method" "${AUTH_ARGS[@]}" -H 'Content-Type: application/json')
  if [[ -n "$data" ]]; then
    curl_args+=(-d "$data")
  fi

  local response status body
  response=$(curl "${curl_args[@]}" "$url")
  status="${response##*$'\n'}"
  body="${response%$'\n'*}"

  if [[ "$status" -lt 200 || "$status" -ge 300 ]]; then
    echo "error: $method $path failed (HTTP $status): $body" >&2
    return 1
  fi
  printf '%s' "$body"
}

# Resolves GRAFANA_FOLDER to a folder uid, creating the folder if it doesn't exist yet.
resolve_folder_uid() {
  local folders uid
  folders=$(api_call GET "/api/folders")
  uid=$(jq -r --arg title "$GRAFANA_FOLDER" '.[] | select(.title == $title) | .uid' <<<"$folders" | head -n1)
  if [[ -n "$uid" ]]; then
    printf '%s' "$uid"
    return
  fi

  local created
  created=$(api_call POST "/api/folders" "$(jq -n --arg title "$GRAFANA_FOLDER" '{title: $title}')")
  jq -r '.uid' <<<"$created"
}

cmd_push() {
  local folder_uid
  folder_uid=$(resolve_folder_uid)

  shopt -s nullglob
  local files=("$DASHBOARD_DIR"/*.json)
  shopt -u nullglob
  if [[ ${#files[@]} -eq 0 ]]; then
    echo "no dashboard JSON files found in $DASHBOARD_DIR" >&2
    exit 1
  fi

  local failed=0
  for file in "${files[@]}"; do
    local dashboard uid title payload
    dashboard=$(jq '.id = null' "$file")
    uid=$(jq -r '.uid' <<<"$dashboard")
    title=$(jq -r '.title' <<<"$dashboard")
    payload=$(jq -n --argjson dashboard "$dashboard" --arg folderUid "$folder_uid" \
      '{dashboard: $dashboard, folderUid: $folderUid, overwrite: true, message: "sync-dashboards.sh push"}')

    if api_call POST "/api/dashboards/db" "$payload" >/dev/null; then
      echo "pushed: $title (uid=$uid) <- $file"
    else
      echo "FAILED: $title <- $file"
      failed=1
    fi
  done

  exit "$failed"
}

cmd_dump() {
  local dump_all=0
  local -a uids=()
  local arg
  for arg in "$@"; do
    case "$arg" in
      --all) dump_all=1 ;;
      *) uids+=("$arg") ;;
    esac
  done

  local folder_uid
  folder_uid=$(resolve_folder_uid)

  # Map local files to their tracked uid via parallel arrays (not an
  # associative array -- those need bash 4+, and macOS ships bash 3.2).
  local -a known_uids=()
  local -a known_paths=()
  shopt -s nullglob
  local f u
  for f in "$DASHBOARD_DIR"/*.json; do
    u=$(jq -r '.uid' "$f")
    known_uids+=("$u")
    known_paths+=("$f")
  done
  shopt -u nullglob

  if [[ ${#uids[@]} -eq 0 && $dump_all -eq 0 ]]; then
    uids=("${known_uids[@]+"${known_uids[@]}"}")
  fi

  if [[ $dump_all -eq 1 ]]; then
    local search remote_uid already existing
    search=$(api_call GET "/api/search?folderUIDs=${folder_uid}&type=dash-db")
    while IFS= read -r remote_uid; do
      [[ -n "$remote_uid" ]] || continue
      already=0
      for existing in "${uids[@]+"${uids[@]}"}"; do
        [[ "$existing" == "$remote_uid" ]] && already=1 && break
      done
      [[ $already -eq 0 ]] && uids+=("$remote_uid")
    done < <(jq -r '.[].uid' <<<"$search")
  fi

  if [[ ${#uids[@]} -eq 0 ]]; then
    echo "no dashboards to dump (nothing tracked locally in $DASHBOARD_DIR; pass a uid or --all)" >&2
    exit 1
  fi

  local uid resp dashboard title target slug idx
  for uid in "${uids[@]}"; do
    resp=$(api_call GET "/api/dashboards/uid/${uid}")
    dashboard=$(jq '.dashboard | .id = null' <<<"$resp")
    title=$(jq -r '.title' <<<"$dashboard")

    target=""
    for ((idx = 0; idx < ${#known_uids[@]}; idx++)); do
      if [[ "${known_uids[$idx]}" == "$uid" ]]; then
        target="${known_paths[$idx]}"
        break
      fi
    done
    if [[ -z "$target" ]]; then
      slug=$(echo "$title" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-' | sed 's/^-//;s/-$//')
      target="$DASHBOARD_DIR/${slug}.json"
      echo "new dashboard, writing $target -- remember to 'git add' it"
    fi

    jq '.' <<<"$dashboard" >"$target"
    echo "dumped: $title (uid=$uid) -> $target"
  done
}

main() {
  if [[ $# -lt 1 ]]; then
    usage
    exit 1
  fi

  local cmd="$1"
  shift

  local -a rest=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dir)
        DASHBOARD_DIR="$2"
        shift 2
        ;;
      --folder)
        GRAFANA_FOLDER="$2"
        shift 2
        ;;
      -h | --help)
        usage
        exit 0
        ;;
      *)
        rest+=("$1")
        shift
        ;;
    esac
  done

  case "$cmd" in
    push | dump)
      check_deps
      set_auth_args
      ;;
  esac

  case "$cmd" in
    push)
      cmd_push
      ;;
    dump)
      cmd_dump "${rest[@]+"${rest[@]}"}"
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "unknown command: $cmd" >&2
      usage
      exit 1
      ;;
  esac
}

main "$@"
