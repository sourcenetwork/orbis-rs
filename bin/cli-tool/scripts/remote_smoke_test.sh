#!/usr/bin/env bash
# Smoke test: create-ring -> dkg -> store-secret -> pre -> post-key-derivation -> sign,
# run against an already-deployed orbis network via the compiled cli-tool binary.
#
# This does NOT create the target network -- it assumes one already exists and is
# reachable. Network/signing config comes entirely from cli-tool's own environment
# variables (ORBIS_ENDPOINT, ORBIS_RPC_URL, etc) -- export those before running.
#
# See scripts/README.md for prerequisites, especially the whitelist-policy-id
# assumption this script relies on.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# ---------------------------------------------------------------------------
# Config (flag > env var > default)
# ---------------------------------------------------------------------------
CLI_BIN="${CLI_BIN:-}"
WHITELIST_POLICY_ID="${ORBIS_WHITELIST_POLICY_ID:-}"
PEER_NODE_KEYS="${ORBIS_SMOKE_PEER_NODE_KEYS:-}"
THRESHOLD="${ORBIS_SMOKE_THRESHOLD:-}"
DKG_TIMEOUT_SECS="${ORBIS_SMOKE_DKG_TIMEOUT_SECS:-180}"
DKG_POLL_INTERVAL_SECS="${ORBIS_SMOKE_DKG_POLL_INTERVAL_SECS:-5}"
SECRET="${ORBIS_SMOKE_SECRET:-}"
DERIVATION="${ORBIS_SMOKE_DERIVATION:-orbis-remote-smoke-test-derivation}"
SIGN_MESSAGE="${ORBIS_SMOKE_SIGN_MESSAGE:-orbis-remote-smoke-test-sign-message}"
RESOURCE="${ORBIS_SMOKE_RESOURCE:-document}"
PERMISSION="${ORBIS_SMOKE_PERMISSION:-read}"
RELATION="${ORBIS_SMOKE_RELATION:-reader}"
RING_NONCE="${ORBIS_SMOKE_RING_NONCE:-}"

# State populated by step functions, reported in the exit summary.
OBJECT_POLICY_ID=""
RING_ID=""
RING_PK=""
READER_SK=""
READER_PK=""
OBJECT_ID=""
DERIVATION_ID=""
DERIVED_PK=""
SIGNATURE=""
SIGN_MESSAGE_HEX=""
STEP_LOG=""

usage() {
  cat <<'EOF'
Usage: remote_smoke_test.sh [OPTIONS]

Runs create-ring -> dkg -> store-secret -> pre -> post-key-derivation -> sign
against an already-deployed orbis network, using the cli-tool binary.

Network/signing config is taken entirely from cli-tool's own environment
variables (export these before running):
  ORBIS_ENDPOINT, ORBIS_CHAIN_ID, ORBIS_RPC_URL, ORBIS_REST_URL,
  ORBIS_CHAIN_GRPC_URL, ORBIS_ACCOUNT_PREFIX, ORBIS_SIGNING_KEY (required)

Options (flag > env var > default):
  --cli-bin <path>             CLI_BIN                             (autodetect target/release/cli-tool)
  --whitelist-policy-id <id>   ORBIS_WHITELIST_POLICY_ID            (required, no default)
  --peer-node-keys <csv>       ORBIS_SMOKE_PEER_NODE_KEYS           (required)
  --threshold <n>              ORBIS_SMOKE_THRESHOLD                (required)
  --dkg-timeout <secs>         ORBIS_SMOKE_DKG_TIMEOUT_SECS         (default 180)
  --dkg-poll-interval <secs>   ORBIS_SMOKE_DKG_POLL_INTERVAL_SECS   (default 5)
  --secret <string>            ORBIS_SMOKE_SECRET                   (default: generated)
  --derivation <string>        ORBIS_SMOKE_DERIVATION               (default: orbis-remote-smoke-test-derivation)
  --sign-message <string>      ORBIS_SMOKE_SIGN_MESSAGE             (default: orbis-remote-smoke-test-sign-message)
  --resource <string>          ORBIS_SMOKE_RESOURCE                 (default: document)
  --permission <string>        ORBIS_SMOKE_PERMISSION               (default: read)
  --relation <string>          ORBIS_SMOKE_RELATION                 (default: reader)
  --ring-nonce <string>        ORBIS_SMOKE_RING_NONCE               (default: generated)
  -h, --help                   show this help and exit

--resource/--permission/--relation must match the fixed policy schema that
add-policy-to-chain creates (resource "document", relations creator/reader,
permission read = creator + reader) -- see scripts/README.md.

See scripts/README.md for prerequisites, especially the whitelist-policy-id
assumption.
EOF
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --cli-bin) CLI_BIN="$2"; shift 2 ;;
      --whitelist-policy-id) WHITELIST_POLICY_ID="$2"; shift 2 ;;
      --peer-node-keys) PEER_NODE_KEYS="$2"; shift 2 ;;
      --threshold) THRESHOLD="$2"; shift 2 ;;
      --dkg-timeout) DKG_TIMEOUT_SECS="$2"; shift 2 ;;
      --dkg-poll-interval) DKG_POLL_INTERVAL_SECS="$2"; shift 2 ;;
      --secret) SECRET="$2"; shift 2 ;;
      --derivation) DERIVATION="$2"; shift 2 ;;
      --sign-message) SIGN_MESSAGE="$2"; shift 2 ;;
      --resource) RESOURCE="$2"; shift 2 ;;
      --permission) PERMISSION="$2"; shift 2 ;;
      --relation) RELATION="$2"; shift 2 ;;
      --ring-nonce) RING_NONCE="$2"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
  done
}

hex_encode() {
  printf '%s' "$1" | od -An -tx1 | tr -d ' \n'
}

resolve_defaults() {
  if [ -z "$CLI_BIN" ]; then
    CLI_BIN="$REPO_ROOT/target/release/cli-tool"
  fi
  if [ -z "$SECRET" ]; then
    SECRET="orbis-remote-smoke-test-secret-$(date +%s)"
  fi
  if [ -z "$RING_NONCE" ]; then
    RING_NONCE="smoke-$(date +%s)-$$"
  fi
  SIGN_MESSAGE_HEX="$(hex_encode "$SIGN_MESSAGE")"
}

# ---------------------------------------------------------------------------
# Step runner
# ---------------------------------------------------------------------------

# Runs a step function directly (not via command substitution) so any global
# variables it sets persist in this shell. Redirects its stdout/stderr to
# STEP_LOG; on failure, prints the anyhow "Error: ..." line if present
# (falling back to the log's last line), dumps the full log indented, then
# exits non-zero immediately (fail-fast).
run_step() {
  local name="$1"
  shift
  printf '==> %s...' "$name"
  if "$@" >"$STEP_LOG" 2>&1; then
    printf ' ok\n'
    : > "$STEP_LOG"
  else
    local rc=$?
    local reason
    reason="$(grep -m1 '^Error:' "$STEP_LOG" | sed 's/^Error: //')" || true
    if [ -z "$reason" ]; then
      reason="$(tail -n1 "$STEP_LOG")"
    fi
    printf ' FAILED: %s\n' "${reason:-see output below}"
    echo '    --- step output ---'
    sed 's/^/    /' "$STEP_LOG"
    exit "$rc"
  fi
}

# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------

step_preflight() {
  if [ -z "$CLI_BIN" ] || [ ! -x "$CLI_BIN" ]; then
    echo "cli-tool binary not found or not executable at '$CLI_BIN' (set --cli-bin or CLI_BIN)"
    return 1
  fi
  if [ -z "${ORBIS_SIGNING_KEY:-}" ]; then
    echo "ORBIS_SIGNING_KEY is not set (a funded signing key is required for every write this script performs)"
    return 1
  fi
  if [ -z "$WHITELIST_POLICY_ID" ]; then
    echo "--whitelist-policy-id/ORBIS_WHITELIST_POLICY_ID is not set. Target nodes must already be whitelisted (once, out-of-band) for a known policy_id -- see scripts/README.md 'Prerequisites'."
    return 1
  fi
  if [ -z "$PEER_NODE_KEYS" ]; then
    echo "--peer-node-keys/ORBIS_SMOKE_PEER_NODE_KEYS is not set"
    return 1
  fi
  if [ -z "$THRESHOLD" ]; then
    echo "--threshold/ORBIS_SMOKE_THRESHOLD is not set"
    return 1
  fi
  local peer_count
  peer_count="$(printf '%s' "$PEER_NODE_KEYS" | tr ',' '\n' | grep -c .)" || true
  if [ "${peer_count:-0}" -lt "$THRESHOLD" ]; then
    echo "peer_node_keys count (${peer_count:-0}) is less than threshold ($THRESHOLD)"
    return 1
  fi
  return 0
}

step_create_object_policy() {
  local out
  if ! out="$("$CLI_BIN" add-policy-to-chain 2>&1)"; then
    printf '%s\n' "$out"
    return 1
  fi
  printf '%s\n' "$out"
  OBJECT_POLICY_ID="$(printf '%s\n' "$out" | grep '^POLICY_ID=' | cut -d= -f2-)" || true
  if [ -z "$OBJECT_POLICY_ID" ]; then
    echo "POLICY_ID not found in add-policy-to-chain output"
    return 1
  fi
  return 0
}

step_create_ring() {
  local out
  if ! out="$("$CLI_BIN" create-ring \
    --peer-node-keys "$PEER_NODE_KEYS" \
    --threshold "$THRESHOLD" \
    --policy-id "$WHITELIST_POLICY_ID" \
    --nonce "$RING_NONCE" 2>&1)"; then
    printf '%s\n' "$out"
    return 1
  fi
  printf '%s\n' "$out"
  RING_ID="$(printf '%s\n' "$out" | grep '^RING_ID=' | cut -d= -f2-)" || true
  if [ -z "$RING_ID" ]; then
    echo "RING_ID not found in create-ring output"
    return 1
  fi
  return 0
}

step_start_dkg() {
  "$CLI_BIN" dkg --ring-id "$RING_ID"
}

# Not run through run_step: it needs to emit periodic heartbeat lines during a
# potentially multi-minute wait (avoids CI "no output" hang detection), while
# still using the same "==> name... ok"/"FAILED" framing itself.
wait_for_dkg_finalization() {
  local start deadline now out
  start=$(date +%s)
  deadline=$(( start + DKG_TIMEOUT_SECS ))
  printf '==> wait_for_dkg_finalization...\n'
  while true; do
    if out="$("$CLI_BIN" get-latest-ring --ring-id "$RING_ID" 2>&1)"; then
      RING_PK="$(printf '%s\n' "$out" | grep '^RING_PK=' | cut -d= -f2-)" || true
      if [ -n "$RING_PK" ]; then
        echo '==> wait_for_dkg_finalization... ok'
        return 0
      fi
    else
      echo '==> wait_for_dkg_finalization... FAILED: ring row not found'
      printf '%s\n' "$out" | sed 's/^/    /'
      return 1
    fi
    now=$(date +%s)
    if [ "$now" -ge "$deadline" ]; then
      echo "==> wait_for_dkg_finalization... FAILED: timed out after ${DKG_TIMEOUT_SECS}s, RING_PK still empty"
      return 1
    fi
    printf '    ...ring not finalized yet (%ss/%ss elapsed), retrying in %ss\n' \
      "$(( now - start ))" "$DKG_TIMEOUT_SECS" "$DKG_POLL_INTERVAL_SECS"
    sleep "$DKG_POLL_INTERVAL_SECS"
  done
}

step_generate_reader_key() {
  local out
  if ! out="$("$CLI_BIN" generate-reader-key 2>&1)"; then
    printf '%s\n' "$out"
    return 1
  fi
  printf '%s\n' "$out"
  READER_SK="$(printf '%s\n' "$out" | grep -A1 'Reader Secret Key' | tail -1 | tr -d '[:space:]')" || true
  READER_PK="$(printf '%s\n' "$out" | grep -A1 'Reader Public Key' | tail -1 | tr -d '[:space:]')" || true
  if [ -z "$READER_SK" ] || [ -z "$READER_PK" ]; then
    echo "failed to parse reader keypair from generate-reader-key output"
    return 1
  fi
  export ORBIS_READER_SK="$READER_SK"
  export ORBIS_READER_DID_PK="${ORBIS_READER_DID_PK:-orbis-remote-smoke-test-reader}"
  return 0
}

step_store_secret() {
  local out
  if ! out="$("$CLI_BIN" store-secret \
    --secret "$SECRET" \
    --ring-pk-hex "$RING_PK" \
    --ring-id "$RING_ID" \
    --policy-id "$OBJECT_POLICY_ID" \
    --resource "$RESOURCE" \
    --permission "$PERMISSION" \
    --with-proof 2>&1)"; then
    printf '%s\n' "$out"
    return 1
  fi
  printf '%s\n' "$out"
  OBJECT_ID="$(printf '%s\n' "$out" | grep '  Object ID:' | sed 's/.*Object ID: //')" || true
  if [ -z "$OBJECT_ID" ]; then
    echo "Object ID not found in store-secret output"
    return 1
  fi
  return 0
}

step_register_secret_object() {
  "$CLI_BIN" register-object-to-chain \
    --policy-id "$OBJECT_POLICY_ID" \
    --object-id "$OBJECT_ID" \
    --resource "$RESOURCE"
}

step_grant_secret_reader_access() {
  "$CLI_BIN" set-relationship-on-chain \
    --policy-id "$OBJECT_POLICY_ID" \
    --object-id "$OBJECT_ID" \
    --resource "$RESOURCE" \
    --relation "$RELATION"
}

step_run_pre_and_verify_plaintext() {
  local out decrypted
  if ! out="$("$CLI_BIN" pre \
    --ring-pk "$RING_PK" \
    --reader-pk "$READER_PK" \
    --object-id "$OBJECT_ID" 2>&1)"; then
    printf '%s\n' "$out"
    return 1
  fi
  printf '%s\n' "$out"
  decrypted="$(printf '%s\n' "$out" | grep '  Decrypted Secret:' | sed 's/.*Decrypted Secret: //')" || true
  if [ "$decrypted" != "$SECRET" ]; then
    echo "decrypted secret did not match stored secret (got '$decrypted', want '$SECRET')"
    return 1
  fi
  return 0
}

step_post_key_derivation() {
  local out
  if ! out="$("$CLI_BIN" post-key-derivation \
    --ring-id "$RING_ID" \
    --derivation "$DERIVATION" \
    --policy-id "$OBJECT_POLICY_ID" \
    --resource "$RESOURCE" \
    --permission "$PERMISSION" 2>&1)"; then
    printf '%s\n' "$out"
    return 1
  fi
  printf '%s\n' "$out"
  DERIVATION_ID="$(printf '%s\n' "$out" | grep '^DERIVATION_ID=' | cut -d= -f2-)" || true
  DERIVED_PK="$(printf '%s\n' "$out" | grep '^DERIVED_PK=' | cut -d= -f2-)" || true
  if [ -z "$DERIVATION_ID" ]; then
    echo "DERIVATION_ID not found in post-key-derivation output"
    return 1
  fi
  return 0
}

step_register_derivation_object() {
  "$CLI_BIN" register-object-to-chain \
    --policy-id "$OBJECT_POLICY_ID" \
    --object-id "$DERIVATION_ID" \
    --resource "$RESOURCE"
}

step_grant_derivation_reader_access() {
  "$CLI_BIN" set-relationship-on-chain \
    --policy-id "$OBJECT_POLICY_ID" \
    --object-id "$DERIVATION_ID" \
    --resource "$RESOURCE" \
    --relation "$RELATION"
}

# Confirms the Sign RPC succeeded and returned a plausible signature. Does NOT
# cryptographically verify it against DERIVED_PK the way the Rust integration
# test does with SignImpl::verify -- reimplementing curve math in bash isn't
# worthwhile for a smoke test; this is a deliberately shallow check.
step_threshold_sign() {
  local out
  if ! out="$("$CLI_BIN" sign \
    --message "$SIGN_MESSAGE_HEX" \
    --derivation-id "$DERIVATION_ID" 2>&1)"; then
    printf '%s\n' "$out"
    return 1
  fi
  printf '%s\n' "$out"
  SIGNATURE="$(printf '%s\n' "$out" | grep '  Signature:' | sed 's/.*Signature: //')" || true
  case "$SIGNATURE" in
    '' | *[!0-9a-fA-F]*)
      echo "sign did not return a plausible hex signature (got '$SIGNATURE')"
      return 1
      ;;
  esac
  return 0
}

# ---------------------------------------------------------------------------
# Exit handling
# ---------------------------------------------------------------------------

on_exit() {
  local rc=$?
  [ -n "$STEP_LOG" ] && rm -f "$STEP_LOG" 2>/dev/null
  echo
  echo 'Resources from this run:'
  echo "  whitelist_policy_id : ${WHITELIST_POLICY_ID:-<not set>}"
  echo "  object_policy_id    : ${OBJECT_POLICY_ID:-<not created>}"
  echo "  ring_id             : ${RING_ID:-<not created>}"
  echo "  ring_pk             : ${RING_PK:-<not finalized>}"
  echo "  object_id           : ${OBJECT_ID:-<not stored>}"
  echo "  derivation_id       : ${DERIVATION_ID:-<not posted>}"
  echo
  if [ "$rc" -eq 0 ]; then
    echo 'SMOKE TEST PASSED'
  else
    echo 'SMOKE TEST FAILED'
  fi
  exit "$rc"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  parse_args "$@"
  resolve_defaults

  STEP_LOG="$(mktemp "${TMPDIR:-/tmp}/orbis_smoke.XXXXXX")"
  trap on_exit EXIT
  trap 'exit 130' INT TERM

  run_step "preflight" step_preflight
  run_step "create_object_policy" step_create_object_policy
  run_step "create_ring" step_create_ring
  run_step "start_dkg" step_start_dkg
  wait_for_dkg_finalization || exit 1
  run_step "generate_reader_key" step_generate_reader_key
  run_step "store_secret" step_store_secret
  run_step "register_secret_object" step_register_secret_object
  run_step "grant_secret_reader_access" step_grant_secret_reader_access
  run_step "run_pre_and_verify_plaintext" step_run_pre_and_verify_plaintext
  run_step "post_key_derivation" step_post_key_derivation
  run_step "register_derivation_object" step_register_derivation_object
  run_step "grant_derivation_reader_access" step_grant_derivation_reader_access
  run_step "threshold_sign" step_threshold_sign
}

main "$@"
