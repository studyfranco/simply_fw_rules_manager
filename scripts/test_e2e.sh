#!/usr/bin/env bash
#
# End-to-end test suite for simply_fw_rules_manager.
#
# Runs dependency updates, security audits via cargo audit, builds the daemon, runs workspace
# unit & integration tests, then boots a live instance against an isolated temporary SQLite database
# to verify liveness, readiness, and authenticated API operations over real HTTP.
#
# Usage: ./scripts/test_e2e.sh
# Requires: curl, jq, cargo, cargo-audit.

set -uo pipefail

if [[ "$(basename "$PWD")" != "simply_fw_rules_manager" ]]; then
  echo "ERROR: Script must be executed from the simply_fw_rules_manager repository root." >&2
  echo "       Current directory: $PWD" >&2
  exit 1
fi

for marker in Cargo.toml src/main.rs scripts/test_e2e.sh; do
  if [[ ! -e "$marker" ]]; then
    echo "ERROR: '$PWD' is named simply_fw_rules_manager but is not this repository." >&2
    echo "       Expected to find '$marker' and did not." >&2
    exit 1
  fi
done

PROJECT_ROOT="$PWD"
export PATH="$HOME/.cargo/bin:$PATH"

PASS_COUNT=0
FAIL_COUNT=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
RESET='\033[0m'
BOLD='\033[1m'

ts() { date +"%H:%M:%S.%3N"; }
log() { echo -e "$(ts) ${CYAN}[INFO]${RESET} $*" >&2; }
warn() { echo -e "$(ts) ${YELLOW}[WARN]${RESET} $*" >&2; }
err() { echo -e "$(ts) ${RED}[ERROR]${RESET} $*" >&2; }
log_section() {
    echo "" >&2
    echo -e "$(ts) ${BOLD}${MAGENTA}=== $* ===${RESET}" >&2
}

# ── Preflight ────────────────────────────────────────────────────────────────
log_section "Preflight"
for tool in cargo curl jq; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        err "Required tool '$tool' not found on PATH."
        exit 1
    fi
    log "Found $tool: $(command -v "$tool")"
done

if ! command -v cargo-audit >/dev/null 2>&1 && ! cargo audit --version >/dev/null 2>&1; then
    log "cargo-audit not found on PATH; attempting to install via 'cargo install cargo-audit'..."
    if ! cargo install cargo-audit; then
        err "cargo-audit is required for dependency security audits but is missing and could not be installed."
        exit 1
    fi
fi
log "Found cargo-audit: $(command -v cargo-audit 2>/dev/null || echo "cargo audit subcommand")"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/simply_fw_rules_manager_e2e.XXXXXX")"
DB_PATH="$WORK_DIR/e2e.db"
SERVER_LOG="$WORK_DIR/server.log"
SERVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        log "Stopping server (pid $SERVER_PID)..."
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT INT TERM

# ── Dependencies & Security Audit ────────────────────────────────────────────
log_section "Dependencies & Security Audit"

log "Running cargo update in $PROJECT_ROOT ..."
if ! (cd "$PROJECT_ROOT" && cargo update >"$WORK_DIR/cargo_update.log" 2>&1); then
    err "cargo update failed:"
    cat "$WORK_DIR/cargo_update.log" >&2
    exit 1
fi
log "cargo update succeeded."

log "Running cargo audit in $PROJECT_ROOT ..."
# RUSTSEC-2026-0459: upstream unpatched SQLite CVE in libsqlite3-sys 0.37.0 transitively pinned by
# sqlx-sqlite 0.9.0 (which restricts libsqlite3-sys <0.38.0). Ignored until sqlx publishes a patch release.
AUDIT_ARGS=(${CARGO_AUDIT_ARGS:---ignore RUSTSEC-2026-0459})
if ! (cd "$PROJECT_ROOT" && cargo audit "${AUDIT_ARGS[@]}" >"$WORK_DIR/cargo_audit.log" 2>&1); then
    err "cargo audit detected vulnerabilities or failed:"
    cat "$WORK_DIR/cargo_audit.log" >&2
    exit 1
fi
log "cargo audit passed cleanly."

# ── Build ────────────────────────────────────────────────────────────────────
log_section "Build"
log "Running cargo build in $PROJECT_ROOT ..."
if ! (cd "$PROJECT_ROOT" && cargo build --quiet 2>"$WORK_DIR/build.log"); then
    err "Build failed:"
    cat "$WORK_DIR/build.log" >&2
    exit 1
fi
log "Build succeeded."

# ── Cargo Tests ──────────────────────────────────────────────────────────────
log_section "Cargo Tests"
log "Running cargo test in $PROJECT_ROOT ..."
if ! (cd "$PROJECT_ROOT" && cargo test --workspace --quiet 2>"$WORK_DIR/cargo_test.log"); then
    err "cargo test failed:"
    cat "$WORK_DIR/cargo_test.log" >&2
    exit 1
fi
log "cargo test passed cleanly."

# ── Live Instance Boot & Smoke Test ─────────────────────────────────────────
log_section "Live Server Smoke Test"

BIND_HOST="127.0.0.1"
SERVER_PORT=3399
MASTER_KEY="e2e0000000000000000000000000000000000000000000000000000000000e2e"
MASTER_SECRET="secret0000000000000000000000000000000000000000000000000000000000"

log "Booting simply_fw_rules_manager on $BIND_HOST:$SERVER_PORT ..."
DATABASE_URL="sqlite://$DB_PATH?mode=rwc" RUST_LOG=info \
    INITIAL_MASTER_KEY="$MASTER_KEY" \
    INITIAL_MASTER_SIGNING_SECRET="$MASTER_SECRET" \
    PORT="$SERVER_PORT" BIND_HOST="$BIND_HOST" \
    "$PROJECT_ROOT/target/debug/simply_fw_rules_manager" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

READY=0
for _ in $(seq 1 40); do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        err "Server process exited prematurely during boot. Log:"
        cat "$SERVER_LOG" >&2
        exit 1
    fi
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://$BIND_HOST:$SERVER_PORT/ready" 2>/dev/null || true)
    if [ "$STATUS" == "200" ]; then
        READY=1
        break
    fi
    sleep 0.25
done

if [ "$READY" -ne 1 ]; then
    err "Server did not answer /ready in time. Log:"
    cat "$SERVER_LOG" >&2
    exit 1
fi
log "Server is ready."

# Health probe check
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://$BIND_HOST:$SERVER_PORT/health")
if [ "$STATUS" == "200" ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} /health returns 200" >&2
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} /health returned $STATUS (expected 200)" >&2
fi

# Unauthenticated /api/auth/me check -> 401
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://$BIND_HOST:$SERVER_PORT/api/auth/me")
if [ "$STATUS" == "401" ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} /api/auth/me without credentials returns 401" >&2
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} /api/auth/me unauthenticated returned $STATUS (expected 401)" >&2
fi

# Authenticated /api/auth/me check with HMAC signature -> 200
TS=$(date +%s)
SIG=$(printf 'GET\n/api/auth/me\n%s\n' "$TS" | openssl dgst -sha256 -hmac "$MASTER_SECRET" -r | cut -d' ' -f1)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "X-API-Key: $MASTER_KEY" \
    -H "X-Timestamp: $TS" \
    -H "X-Signature-256: sha256=$SIG" \
    "http://$BIND_HOST:$SERVER_PORT/api/auth/me")
if [ "$STATUS" == "200" ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} /api/auth/me with MASTER_KEY and HMAC signature returns 200" >&2
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} /api/auth/me authenticated returned $STATUS (expected 200)" >&2
fi

log_section "Summary"
log "Passed checks: $PASS_COUNT"
log "Failed checks: $FAIL_COUNT"

if [ "$FAIL_COUNT" -gt 0 ]; then
    err "E2E suite failed with $FAIL_COUNT errors."
    exit 1
fi

log "${GREEN}E2E test suite passed cleanly.${RESET}"
exit 0
