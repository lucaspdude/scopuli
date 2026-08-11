#!/usr/bin/env bash
# Smoke test for scopuli.
#
# Modes:
#   ./scripts/smoke-test.sh          — runs the local ./bin/scopuli binary
#   ./scripts/smoke-test.sh docker   — uses the running container named "scopuli-smoke"
#
# The smoke test boots the server, logs in, creates a secret, an agent key,
# reads the secret via the key, runs FTS5 search, verifies the audit chain,
# and exits with status 0 on success.

set -euo pipefail

MODE="${1:-local}"
PORT="${PORT:-8080}"
URL="http://127.0.0.1:${PORT}"
DATA_DIR="${DATA_DIR:-/tmp/scopuli-smoke}"
CONTAINER_NAME="${CONTAINER_NAME:-scopuli-smoke}"
MASTER="${MASTER_PASSWORD:-smoketest-passphrase-9f3a2b}"

if [[ "$MODE" == "docker" ]]; then
  BIN=""
else
  BIN="./bin/scopuli"
fi

# --- helpers -----------------------------------------------------------

red()   { printf "\033[31m%s\033[0m\n" "$*"; }
green() { printf "\033[32m%s\033[0m\n" "$*"; }
info()  { printf "\033[36m[smoke]\033[0m %s\n" "$*"; }

fail() {
  red "FAIL: $*"
  if [[ -n "${OP_TOKEN:-}" ]]; then
    red "operator token captured: $OP_TOKEN"
  fi
  exit 1
}

cleanup() {
  if [[ "$MODE" != "docker" ]]; then
    if [[ -n "${PID:-}" ]]; then
      kill "$PID" 2>/dev/null || true
    fi
  fi
  rm -rf /tmp/scopuli-creds
}
trap cleanup EXIT

# --- start server ------------------------------------------------------

if [[ "$MODE" == "docker" ]]; then
  info "using running container on $URL"
  for i in $(seq 1 30); do
    if curl -fsS "$URL/healthz" >/dev/null 2>&1; then
      break
    fi
    sleep 0.5
  done
  if ! curl -fsS "$URL/healthz" >/dev/null; then
    fail "container not reachable at $URL/healthz — run 'make docker-run' first"
  fi
  green "✓ server up"
  # Extract operator token from container logs.
  if [[ -z "${OP_TOKEN:-}" ]]; then
    OP_TOKEN=$(docker logs "$CONTAINER_NAME" 2>&1 | grep -oE 'scot_live_[A-Za-z0-9_-]+' | head -1 || true)
  fi
  if [[ -z "$OP_TOKEN" ]]; then
    fail "operator token not in container logs (only printed on first boot)"
  fi
  info "captured operator token (length=${#OP_TOKEN})"
else
  rm -rf "$DATA_DIR"
  mkdir -p "$DATA_DIR"
  info "starting local binary on $URL (data: $DATA_DIR)"
  MASTER_PASSWORD="$MASTER" SCOPULI_BIND="127.0.0.1:${PORT}" \
    SCOPULI_DB_PATH="$DATA_DIR/vault.db" SCOPULI_LOG_LEVEL=warn \
    "$BIN" serve > /tmp/scopuli.log 2>&1 &
  PID=$!
  # Wait for healthz (max 30s).
  for i in $(seq 1 30); do
    if curl -fsS "$URL/healthz" >/dev/null 2>&1; then
      break
    fi
    sleep 0.5
    if ! kill -0 "$PID" 2>/dev/null; then
      red "server died; last 30 lines of log:"
      tail -30 /tmp/scopuli.log
      fail "server exited unexpectedly"
    fi
  done
  if ! curl -fsS "$URL/healthz" >/dev/null; then
    red "server failed to become healthy"
    tail -30 /tmp/scopuli.log
    fail "healthz timeout"
  fi
  green "✓ server up"

  # Extract operator token from log.
  OP_TOKEN=$(grep -oE 'scot_live_[A-Za-z0-9_-]+' /tmp/scopuli.log | head -1)
  if [[ -z "$OP_TOKEN" ]]; then
    tail -30 /tmp/scopuli.log
    fail "operator token not in log"
  fi
  info "captured operator token (length=${#OP_TOKEN})"
fi

# --- helpers using direct curl (avoid CLI binary in this test) --------

H_OP=(-H "X-Scopuli-Operator: $OP_TOKEN" -H "Content-Type: application/json")
H_AUTH_BASE=(-H "Content-Type: application/json")

api() {
  local method="$1" path="$2" body="${3:-}"
  if [[ -n "$body" ]]; then
    curl -fsS -X "$method" "${H_OP[@]}" --data "$body" "$URL$path"
  else
    curl -fsS -X "$method" "${H_OP[@]}" "$URL$path"
  fi
}

# --- run scenarios -----------------------------------------------------

info "PUT secret"
api POST /api/secrets '{"path":"aws/prod/stripe","value":"sk_live_xxx","label":"Stripe","tags":["aws","prod"],"description":"Production Stripe key","metadata":{"owner":"alice"}}' >/dev/null
api POST /api/secrets '{"path":"github/lucas/pat","value":"ghp_yyy","description":"Personal access token"}' >/dev/null
api POST /api/secrets '{"path":"aws/dev/stripe","value":"sk_test_zzz","description":"Dev Stripe"}' >/dev/null
green "✓ 3 secrets created"

info "LIST secrets"
COUNT=$(api GET /api/secrets | python3 -c 'import sys,json; print(len(json.load(sys.stdin)))')
if [[ "$COUNT" != "3" ]]; then fail "expected 3 secrets, got $COUNT"; fi
green "✓ list returns 3"

info "GET secret"
VAL=$(api GET /api/secrets/aws/prod/stripe | python3 -c 'import sys,json; print(json.load(sys.stdin)["value"])')
if [[ "$VAL" != "sk_live_xxx" ]]; then fail "value = $VAL, want sk_live_xxx"; fi
green "✓ get returns plaintext"

info "ANNOTATE secret (description change → re-encrypts)"
api POST '/api/secrets/annotate?path=aws/prod/stripe' '{"description":"Production Stripe key (rotated 2025-08-15)"}' >/dev/null
NEW=$(api GET /api/secrets/aws/prod/stripe | python3 -c 'import sys,json; v=json.load(sys.stdin); print(v["description"], "|", v["value"])')
if [[ "$NEW" != "Production Stripe key (rotated 2025-08-15) | sk_live_xxx" ]]; then
  fail "after annotate: $NEW"
fi
green "✓ annotation preserved value, updated description"

info "CREATE agent key"
KEY_JSON=$(api POST /api/keys '{"name":"devkey","scope":"aws/dev/*","permissions":"read","description":"Dev read-only key","tags":["dev"]}')
KEY=$(echo "$KEY_JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin)["key"])')
if [[ ! "$KEY" =~ ^sk_live_ ]]; then fail "key missing sk_live_ prefix: $KEY"; fi
green "✓ agent key issued"

info "READ with agent key (allowed)"
H_KEY=(-H "X-Scopuli-Key: $KEY" -H "Content-Type: application/json")
ALLOWED=$(curl -fsS "${H_KEY[@]}" "$URL/api/secrets/aws/dev/stripe" | python3 -c 'import sys,json; print(json.load(sys.stdin)["value"])')
if [[ "$ALLOWED" != "sk_test_zzz" ]]; then fail "key read returned $ALLOWED"; fi
green "✓ agent key read in-scope"

info "READ with agent key (denied)"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' "${H_KEY[@]}" "$URL/api/secrets/aws/prod/stripe")
if [[ "$STATUS" != "403" ]]; then fail "expected 403 out-of-scope, got $STATUS"; fi
green "✓ out-of-scope correctly denied (403)"

info "SEARCH secrets (FTS5)"
HITS=$(api GET '/api/secrets/search?q=stripe' | python3 -c 'import sys,json; print(len(json.load(sys.stdin)))')
if [[ "$HITS" != "2" ]]; then fail "expected 2 stripe hits, got $HITS"; fi
green "✓ FTS5 search returned 2 hits"

info "SEARCH secrets (FTS5 with metadata match)"
HITS=$(api GET '/api/secrets/search?q=alice' | python3 -c 'import sys,json; print(len(json.load(sys.stdin)))')
if [[ "$HITS" != "1" ]]; then fail "expected 1 metadata hit, got $HITS"; fi
green "✓ FTS5 indexed metadata"

info "REVOKE agent key"
api POST /api/keys/devkey/revoke '' >/dev/null
STATUS=$(curl -s -o /dev/null -w '%{http_code}' "${H_KEY[@]}" "$URL/api/secrets/aws/dev/stripe")
if [[ "$STATUS" != "401" ]]; then fail "expected 401 after revoke, got $STATUS"; fi
green "✓ revoked key rejected (401)"

info "AUDIT verify chain"
RES=$(api GET /api/audit/verify)
if ! echo "$RES" | grep -q '"ok":true'; then
  fail "audit verify failed: $RES"
fi
green "✓ audit chain verifies"

info "AUDIT list (last 5)"
api GET '/api/audit?limit=5' | python3 -m json.tool > /dev/null
green "✓ audit list renders"

# --- web UI ------------------------------------------------------------
# The htmx operator console. Auth uses the same master key (operator token).

UI_COOKIE_JAR="/tmp/scopuli-ui-cookie"
rm -f "$UI_COOKIE_JAR"

info "UI: login page renders"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' "$URL/ui/login")
if [[ "$STATUS" != "200" ]]; then fail "ui/login = $STATUS, want 200"; fi
if ! curl -fsS "$URL/ui/login" | grep -q "Master key"; then
  fail "login page missing master key field"
fi
green "✓ login page renders"
# NOTE: UI checks below capture curl output to a file before grepping —
# `curl | grep -q` races: grep exits on first match and curl dies with
# SIGPIPE, which `set -o pipefail` turns into a spurious failure.

info "UI: wrong master key rejected (no session cookie)"
STATUS=$(curl -s -c "$UI_COOKIE_JAR" -o /dev/null -w '%{http_code}' \
  -d "token=scot_live_wrong" "$URL/ui/login")
if [[ "$STATUS" != "200" ]]; then fail "bad login = $STATUS, want 200"; fi
if grep -q scopuli_session "$UI_COOKIE_JAR"; then
  fail "bad login must not issue a session cookie"
fi
green "✓ wrong master key rejected"

info "UI: login with master key issues session"
STATUS=$(curl -s -c "$UI_COOKIE_JAR" -o /dev/null -w '%{http_code}' \
  -d "token=$OP_TOKEN" "$URL/ui/login")
if [[ "$STATUS" != "302" ]]; then fail "login = $STATUS, want 302"; fi
if ! grep -q scopuli_session "$UI_COOKIE_JAR"; then
  fail "no session cookie in jar"
fi
green "✓ login issues session cookie"

info "UI: dashboard renders"
if ! curl -fsS -b "$UI_COOKIE_JAR" "$URL/ui/" | grep -q "Dashboard"; then
  fail "dashboard did not render"
fi
green "✓ dashboard renders"
UI_PAGE=""
fetch_ui() { UI_PAGE=$(curl -fsS -b "$UI_COOKIE_JAR" "$1" 2>/dev/null) || true; }

info "UI: secrets page lists vault secrets"
fetch_ui "$URL/ui/secrets"
if ! echo "$UI_PAGE" | grep -q "aws/prod/stripe"; then
  fail "secrets page missing aws/prod/stripe"
fi
green "✓ secrets page renders"

info "UI: create secret via htmx form"
STATUS=$(curl -s -b "$UI_COOKIE_JAR" -H "HX-Request: true" -o /dev/null -w '%{http_code}' \
  -d 'path=ui/smoke/test&value=ui_via_form&tags=ui,smoke' "$URL/ui/secrets")
if [[ "$STATUS" != "200" ]]; then fail "ui secret create = $STATUS, want 200"; fi
COUNT=$(api GET /api/secrets | python3 -c 'import sys,json; print(len(json.load(sys.stdin)))')
if [[ "$COUNT" != "4" ]]; then fail "expected 4 secrets after UI create, got $COUNT"; fi
green "✓ UI secret creation writes through to the vault"

info "UI: keys page lists agent keys"
fetch_ui "$URL/ui/keys"
if ! echo "$UI_PAGE" | grep -q "devkey"; then
  fail "keys page missing devkey"
fi
green "✓ keys page renders"

info "UI: audit page shows intact chain"
fetch_ui "$URL/ui/audit"
if ! echo "$UI_PAGE" | grep -q "Chain intact"; then
  fail "audit page missing chain-intact banner"
fi
green "✓ audit page verifies chain"

info "UI: mutation without htmx header rejected (CSRF)"
STATUS=$(curl -s -b "$UI_COOKIE_JAR" -o /dev/null -w '%{http_code}' \
  -d 'path=ui/csrf&value=x' "$URL/ui/secrets")
if [[ "$STATUS" != "403" ]]; then fail "non-htmx mutation = $STATUS, want 403"; fi
green "✓ CSRF guard rejects non-htmx mutations"

info "UI: unauthenticated page access redirects to login"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' "$URL/ui/")
if [[ "$STATUS" != "302" ]]; then fail "ui/ unauthenticated = $STATUS, want 302"; fi
green "✓ session guard redirects"

rm -f "$UI_COOKIE_JAR"

green ""
green "==================================="
green "  ALL SMOKE TESTS PASSED ✓"
green "==================================="
exit 0
