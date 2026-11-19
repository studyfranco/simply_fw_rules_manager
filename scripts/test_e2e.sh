#!/usr/bin/env bash
#
# End-to-end test suite for simply_fw_rules_manager.
#
# Runs dependency updates, security audits via cargo audit, builds the daemon, runs workspace
# unit & integration tests, then boots a live instance against an isolated temporary SQLite database
# on an ephemeral port to verify:
#   1. Health, readiness opacity, and CANONICAL_V1 HMAC-SHA256 Master authentication.
#   2. Global firewall settings CRUD and encrypted hook credential redaction (has_hook_api_key boolean).
#   3. Zone rules CRUD across all zones/kinds and 1-click enabled toggle reflected in live preview.
#   4. Docker inter-container rules CRUD and enabled toggle.
#   5. Blocklists CRUD, duplicate conflict detection, and script preview generation.
#   6. Special rules editor, firewall.tools helper extraction, and 3-stage validation pipeline.
#   7. Live preview and atomic disk generation (0700 permissions + bash -n syntax/content verification).
#   8. Shell-injection boundary rejections (", $(id), `id`, ; id, | cat, \n) across all endpoints
#      and verification that rejected payloads never appear in generated previews.
#   9. Blocklist SSRF protection (loopback, link-local metadata 169.254.169.254, RFC1918, CGNAT, IPv6)
#      and import-example path traversal confinement (../../../etc/passwd, /etc, /tmp).
#  10. RBAC boundary checks, secret opacity for authorized readers, and R4 delegation hierarchy
#      (non-Master Parent with can_manage_keys blocked from granting can_manage_keys or global scopes).
#  11. Anti-replay digest enforcement (hex case swap a-f <-> A-F on X-Signature-256 -> 401),
#      timestamp skew window rejection (+/- 305s -> 401), and body tampering rejection.
#  12. Master key immutability (/rotate, /rotate-secret, rename, scope change, delete -> 403),
#      sub-key credential rotation, and /api/audit-logs substring filtering (client_ip, api_key).
#
# Usage: ./scripts/test_e2e.sh
# Requires: curl, jq, cargo, openssl, cargo-audit.

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
DIM='\033[2m'
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

status_color() {
    case "$1" in
        2??) echo -n "$GREEN" ;;
        400|401|403|404|409|413|422|429) echo -n "$YELLOW" ;;
        4??) echo -n "$YELLOW" ;;
        5??) echo -n "$RED" ;;
        *) echo -n "$RESET" ;;
    esac
}

# ── Preflight ────────────────────────────────────────────────────────────────
log_section "Preflight"
for tool in cargo curl jq openssl bash; do
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
GEN_OUT_DIR="$WORK_DIR/generated_firewall"
SERVER_LOG="$WORK_DIR/server.log"
RESP_BODY_FILE="$WORK_DIR/resp_body"
REQ_BODY_FILE="$WORK_DIR/req_body"
SERVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        log "Stopping simply_fw_rules_manager (pid $SERVER_PID)..."
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT INT TERM

# ── Helpers ──────────────────────────────────────────────────────────────────

BIND_HOST="127.0.0.1"
SERVER_PORT="${SERVER_PORT:-$((14300 + (RANDOM % 500)))}"
BASE_URL="http://$BIND_HOST:$SERVER_PORT"

MASTER_KEY="e2e0000000000000000000000000000000000000000000000000000000000e2e"
MASTER_SECRET="feed00000000000000000000000000000000000000000000000000000000feed"
E2E_ENCRYPTION_KEY="1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809"

declare -A SIGNING_SECRETS=()
SIGNING_SECRETS["$MASTER_KEY"]="$MASTER_SECRET"

register_key_secret() {
    local key="$1" secret="$2"
    if [ -z "$key" ] || [ "$key" == "null" ] || [ -z "$secret" ] || [ "$secret" == "null" ]; then
        err "register_key_secret called with empty key/secret"
        return 1
    fi
    SIGNING_SECRETS["$key"]="$secret"
}

# Computes CANONICAL_V1 HMAC-SHA256 signature: `sha256=<hex>` over METHOD\nTARGET\nTIMESTAMP\nRAW_BODY
hmac_sign() {
    local secret="$1" method="$2" target="$3" timestamp="$4" body="${5:-}"
    local hex
    hex=$(printf '%s\n%s\n%s\n%s' "$method" "$target" "$timestamp" "$body" \
        | openssl dgst -sha256 -hmac "$secret" \
        | sed 's/^.*= //')
    printf 'sha256=%s' "$hex"
}

declare -A LAST_SIGNED_AT=()
next_timestamp() {
    local identity="$1"
    local now; now=$(date -u +%s)
    local previous="${LAST_SIGNED_AT[$identity]:-0}"
    if [ "$now" -le "$previous" ]; then
        now=$((previous + 1))
    fi
    LAST_SIGNED_AT["$identity"]=$now
    SIGNED_TS=$now
}

RESP_STATUS=""
RESP_BODY=""

api_call() {
    local method="$1" path="$2" api_key="${3:-}" data="${4:-}"
    local args=(-s -o "$RESP_BODY_FILE" -w "%{http_code}" -X "$method")

    if [ -n "$api_key" ]; then
        next_timestamp "$method|$path|$api_key|$data"
        local timestamp="$SIGNED_TS"
        local secret="${SIGNING_SECRETS[$api_key]:-unregistered-signing-secret}"
        local sig; sig=$(hmac_sign "$secret" "$method" "$path" "$timestamp" "$data")
        args+=(-H "X-API-Key: $api_key" -H "X-Timestamp: $timestamp" -H "X-Signature-256: $sig")
    fi

    if [ -n "$data" ]; then
        printf '%s' "$data" > "$REQ_BODY_FILE"
        args+=(-H "Content-Type: application/json" --data-binary "@$REQ_BODY_FILE")
    fi

    RESP_STATUS=$(curl "${args[@]}" "$BASE_URL$path")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    local color; color=$(status_color "$RESP_STATUS")
    printf "%s ${color}[%s]${RESET} %-6s %s\n" "$(ts)" "$RESP_STATUS" "$method" "$path" >&2
}

raw_call() {
    local method="$1" path="$2"; shift 2
    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X "$method" "$@" "$BASE_URL$path")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    local color; color=$(status_color "$RESP_STATUS")
    printf "%s ${color}[%s]${RESET} %-6s %s\n" "$(ts)" "$RESP_STATUS" "$method" "$path" >&2
}

check() {
    local expected="$1" description="$2"
    if [ "$RESP_STATUS" == "$expected" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $description (expected $expected, got $RESP_STATUS)" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} $description (expected $expected, got $RESP_STATUS) — body: $RESP_BODY" >&2
    fi
}

check_jq() {
    local filter="$1" expected="$2" description="$3"
    local actual
    actual=$(echo "$RESP_BODY" | jq -r "$filter" 2>/dev/null || echo "__JQ_ERR__")
    if [ "$actual" == "$expected" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $description (got '$actual')" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} $description (expected '$expected', got '$actual')" >&2
    fi
}

check_local() {
    local actual="$1" expected="$2" description="$3"
    if [ "$actual" == "$expected" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $description" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} $description (expected '$expected', got '$actual')" >&2
    fi
}

check_contains() {
    local haystack="$1" needle="$2" description="$3"
    if [[ "$haystack" == *"$needle"* ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $description" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} $description (did not find '$needle')" >&2
    fi
}

check_not_contains() {
    local haystack="$1" needle="$2" description="$3"
    if [[ "$haystack" != *"$needle"* ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $description" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} $description (unexpectedly found '$needle')" >&2
    fi
}

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

# ── 1. Live Instance Boot, Health, Readiness Opacity & Master Auth ───────────
log_section "1. Live Server Boot, Readiness Opacity & Master Auth"

log "Booting simply_fw_rules_manager on $BIND_HOST:$SERVER_PORT ..."
DATABASE_URL="sqlite://$DB_PATH?mode=rwc" RUST_LOG=info \
    INITIAL_MASTER_KEY="$MASTER_KEY" \
    INITIAL_MASTER_SIGNING_SECRET="$MASTER_SECRET" \
    FW_ENCRYPTION_KEY="$E2E_ENCRYPTION_KEY" \
    PORT="$SERVER_PORT" BIND_HOST="$BIND_HOST" \
    "$PROJECT_ROOT/target/debug/simply_fw_rules_manager" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

READY=0
for _ in $(seq 1 60); do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        err "Server process exited prematurely during boot. Log:"
        cat "$SERVER_LOG" >&2
        exit 1
    fi
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/ready" 2>/dev/null || true)
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
log "Server is ready (pid $SERVER_PID)."

raw_call GET "/health"
check "200" "GET /health returns 200 OK"
check_jq ".status" "ok" "GET /health reports status=ok"

raw_call GET "/healthz"
check "200" "GET /healthz returns 200 OK"
check_jq ".status" "ok" "GET /healthz reports status=ok"

raw_call GET "/ready"
check "200" "GET /ready returns 200 OK"
check_jq ".status" "ready" "GET /ready reports status=ready"
check_jq "keys | length" "1" "GET /ready is opaque and exposes only the status key"
check_jq 'has("master_pinned")' "false" "GET /ready does not leak internal master_pinned flag"
check_jq 'has("database")' "false" "GET /ready does not leak internal database flag"

raw_call GET "/readyz"
check "200" "GET /readyz returns 200 OK"
check_jq ".status" "ready" "GET /readyz reports status=ready"

raw_call GET "/api/auth/me"
check "401" "GET /api/auth/me without credentials returns 401 Unauthorized"

api_call GET "/api/auth/me" "$MASTER_KEY"
check "200" "GET /api/auth/me with MASTER_KEY and CANONICAL_V1 HMAC signature returns 200"
check_jq ".is_master" "true" "Master key profile reports is_master=true"
check_jq ".can_manage_keys" "true" "Master key profile reports can_manage_keys=true"
check_jq ".can_manage_settings" "true" "Master key profile reports can_manage_settings=true"
check_jq ".can_manage_special_rules" "true" "Master key profile reports can_manage_special_rules=true"
check_jq ".can_manage_blocklists" "true" "Master key profile reports can_manage_blocklists=true"
check_jq ".can_deploy_and_reload" "true" "Master key profile reports can_deploy_and_reload=true"
MASTER_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call GET "/api/system/settings" "$MASTER_KEY"
check "200" "GET /api/system/settings returns 200 OK"
check_jq ".encryption_enabled" "true" "System settings confirm XChaCha20-Poly1305 encryption is enabled"
check_jq ".api_key_count" "1" "System settings report api_key_count=1"

api_call GET "/api/settings" "$MASTER_KEY"
check "200" "GET /api/settings alias returns 200 OK"

api_call GET "/api/docker/discovery" "$MASTER_KEY"
check "200" "GET /api/docker/discovery returns 200 OK"

# ── 2. Global Firewall Settings CRUD & Secret Redaction ──────────────────────
log_section "2. Global Firewall Settings CRUD & Hook Credential Redaction"

api_call GET "/api/firewall/settings" "$MASTER_KEY"
check "200" "GET /api/firewall/settings returns initial seeded settings"
check_jq ".has_hook_api_key" "false" "Initially has_hook_api_key is false"
check_jq ".has_hook_signing_secret" "false" "Initially has_hook_signing_secret is false"

HOOK_PLAIN_KEY="hook_api_key_super_secret_do_not_leak_987654321"
HOOK_PLAIN_SEC="hook_signing_secret_super_secret_do_not_leak_123456789"

SETTINGS_PAYLOAD=$(jq -nc \
    --arg out_dir "$GEN_OUT_DIR" \
    --arg hkey "$HOOK_PLAIN_KEY" \
    --arg hsec "$HOOK_PLAIN_SEC" \
    '{
        main_inter: "eth0",
        inter_out: ["eth0;198.51.100.0/24"],
        interface_to_go_outside: ["eth0"],
        intern_interface_have_access_as_local: ["vlan10"],
        interface_local: ["lan0"],
        interface_with_dhcp: {"lan0": true, "vlan10": false},
        interface_with_no_rules: ["lo0"],
        docker_network_with_internet_access: ["net_front"],
        docker_network_with_access: ["net_back"],
        ip_autor: ["203.0.113.10/32", "2001:db8::10/128"],
        ip_autor_dnat_port_tcp: ["8443,eth0,192.168.1.50,,443"],
        ip_autor_dnat_port_udp: ["51820,eth0,192.168.1.51,,51820"],
        country_open_port: "FR,CH",
        blocked_country: "CN,RU",
        blocked_country_2: "KP",
        output_dir: $out_dir,
        hook_executor_url: "https://hooks.example.org",
        hook_executor_api_key: $hkey,
        hook_executor_signing_secret: $hsec,
        hook_reload_name: "firewall_reload",
        hook_update_containers_name: "firewall_docker_sync"
    }')

api_call PUT "/api/firewall/settings" "$MASTER_KEY" "$SETTINGS_PAYLOAD"
check "200" "PUT /api/firewall/settings updates global settings"
check_jq ".main_inter" "eth0" "Updated main_inter is eth0"
check_jq ".country_open_port" "FR,CH" "Updated country_open_port is FR,CH"
check_jq ".blocked_country" "CN,RU" "Updated blocked_country is CN,RU"
check_jq ".blocked_country_2" "KP" "Updated blocked_country_2 is KP"
check_jq ".output_dir" "$GEN_OUT_DIR" "Updated output_dir matches temporary output directory"
check_jq ".has_hook_api_key" "true" "PUT response reports has_hook_api_key=true"
check_jq ".has_hook_signing_secret" "true" "PUT response reports has_hook_signing_secret=true"
check_jq 'has("hook_executor_api_key")' "false" "PUT response omits plaintext hook_executor_api_key field"
check_jq 'has("hook_executor_signing_secret")' "false" "PUT response omits plaintext hook_executor_signing_secret field"
check_not_contains "$RESP_BODY" "$HOOK_PLAIN_KEY" "PUT response body never leaks plaintext hook_executor_api_key"
check_not_contains "$RESP_BODY" "$HOOK_PLAIN_SEC" "PUT response body never leaks plaintext hook_executor_signing_secret"

api_call GET "/api/firewall/settings" "$MASTER_KEY"
check "200" "GET /api/firewall/settings reads back updated settings"
check_jq ".main_inter" "eth0" "Persisted main_inter is eth0"
check_jq ".ip_autor | length" "2" "Persisted ip_autor has 2 entries"
check_jq ".has_hook_api_key" "true" "GET response reports has_hook_api_key=true"
check_jq ".has_hook_signing_secret" "true" "GET response reports has_hook_signing_secret=true"
check_jq 'has("hook_executor_api_key")' "false" "GET response omits hook_executor_api_key field"
check_jq 'has("hook_executor_signing_secret")' "false" "GET response omits hook_executor_signing_secret field"
check_not_contains "$RESP_BODY" "$HOOK_PLAIN_KEY" "GET response body never leaks plaintext hook_executor_api_key"
check_not_contains "$RESP_BODY" "$HOOK_PLAIN_SEC" "GET response body never leaks plaintext hook_executor_signing_secret"

# ── 3. Zone Rules CRUD & 1-Click Toggle ──────────────────────────────────────
log_section "3. Zone Rules CRUD & 1-Click Toggle"

api_call GET "/api/firewall/zones" "$MASTER_KEY"
check "200" "GET /api/firewall/zones lists existing zone rules"

api_call POST "/api/firewall/zones" "$MASTER_KEY" \
    '{"zone":"open","rule_kind":"OpenPortsTCP","value":"18443","enabled":true,"comment":"E2E Open HTTPS","sort_order":10}'
check "201" "POST /api/firewall/zones creates open OpenPortsTCP rule"
OPEN_RULE_ID=$(echo "$RESP_BODY" | jq -r '.id')
check_jq ".value" "18443" "Created open rule value is 18443"
check_jq ".enabled" "true" "Created open rule is enabled"

api_call POST "/api/firewall/zones" "$MASTER_KEY" \
    '{"zone":"ww","rule_kind":"OpenPortsUDP","value":"51829","enabled":true,"comment":"E2E WireGuard WW","sort_order":20}'
check "201" "POST /api/firewall/zones creates ww OpenPortsUDP rule"
WW_RULE_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/firewall/zones" "$MASTER_KEY" \
    '{"zone":"internal","rule_kind":"RedirectPortTCP","value":"18080,80","enabled":true,"comment":"E2E Internal Redirect","sort_order":30}'
check "201" "POST /api/firewall/zones creates internal RedirectPortTCP rule"
INT_RULE_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/firewall/zones" "$MASTER_KEY" \
    '{"zone":"local","rule_kind":"DnatPortTCP","value":"19443,lan0,192.168.10.20,,443","enabled":true,"comment":"E2E Local DNAT","sort_order":40}'
check "201" "POST /api/firewall/zones creates local DnatPortTCP rule"
LOCAL_RULE_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/firewall/zones" "$MASTER_KEY" \
    '{"zone":"ip_autor","rule_kind":"DockerTCP","value":"19000,net_back,e2e_admin_ct,9000","enabled":true,"comment":"E2E IPAutor Docker","sort_order":50}'
check "201" "POST /api/firewall/zones creates ip_autor DockerTCP rule"
AUTOR_RULE_ID=$(echo "$RESP_BODY" | jq -r '.id')
check_jq ".container_name" "e2e_admin_ct" "DockerTCP rule extracts container_name=e2e_admin_ct"

# ip_autor only allows DockerTCP / DockerUDP
api_call POST "/api/firewall/zones" "$MASTER_KEY" \
    '{"zone":"ip_autor","rule_kind":"OpenPortsTCP","value":"22","enabled":true}'
check "400" "POST /api/firewall/zones rejects non-Docker rule_kind on ip_autor zone"

# 1-click toggle: disable WW_RULE_ID and verify it disappears from live preview
api_call PUT "/api/firewall/zones/$WW_RULE_ID" "$MASTER_KEY" \
    '{"zone":"ww","rule_kind":"OpenPortsUDP","value":"51829","enabled":false,"comment":"Toggled off","sort_order":20}'
check "200" "PUT /api/firewall/zones/{id} toggles enabled=false"
check_jq ".enabled" "false" "Zone rule reports enabled=false after toggle"

api_call GET "/api/firewall/preview" "$MASTER_KEY"
check "200" "GET /api/firewall/preview succeeds after zone rule toggle off"
PREVIEW_SETTINGS=$(echo "$RESP_BODY" | jq -r '.firewall_settings')
check_contains "$PREVIEW_SETTINGS" "\"18443\"" "Enabled open rule 18443 is present in preview"
check_not_contains "$PREVIEW_SETTINGS" "\"51829\"" "Disabled ww rule 51829 is omitted from preview"

# Toggle WW_RULE_ID back on
api_call PUT "/api/firewall/zones/$WW_RULE_ID" "$MASTER_KEY" \
    '{"zone":"ww","rule_kind":"OpenPortsUDP","value":"51829","enabled":true,"comment":"Toggled back on","sort_order":20}'
check "200" "PUT /api/firewall/zones/{id} toggles enabled=true"
check_jq ".enabled" "true" "Zone rule reports enabled=true"

api_call GET "/api/firewall/preview" "$MASTER_KEY"
check "200" "GET /api/firewall/preview succeeds after zone rule toggle on"
PREVIEW_SETTINGS=$(echo "$RESP_BODY" | jq -r '.firewall_settings')
check_contains "$PREVIEW_SETTINGS" "\"51829\"" "Re-enabled ww rule 51829 is present in preview again"

# Delete INT_RULE_ID and verify 204 then 404
api_call DELETE "/api/firewall/zones/$INT_RULE_ID" "$MASTER_KEY"
check "204" "DELETE /api/firewall/zones/{id} returns 204 No Content"

api_call DELETE "/api/firewall/zones/$INT_RULE_ID" "$MASTER_KEY"
check "404" "Repeating DELETE /api/firewall/zones/{id} returns 404 Not Found"

# ── 4. Docker Inter-Container Rules CRUD ─────────────────────────────────────
log_section "4. Docker Inter-Container Rules CRUD"

api_call GET "/api/firewall/docker-rules" "$MASTER_KEY"
check "200" "GET /api/firewall/docker-rules lists inter-container rules"

api_call POST "/api/firewall/docker-rules" "$MASTER_KEY" \
    '{"source_container":"e2e_proxy","destination_container":"e2e_app","network_name":"net_back","proto":"tcp","ports":"8080;8443","enabled":true,"comment":"Proxy to app","sort_order":10}'
check "201" "POST /api/firewall/docker-rules creates inter-container rule"
DOCKER_RULE_ID=$(echo "$RESP_BODY" | jq -r '.id')
check_jq ".source_container" "e2e_proxy" "Inter-rule source_container is e2e_proxy"
check_jq ".ports" "8080;8443" "Inter-rule ports is 8080;8443"

api_call PUT "/api/firewall/docker-rules/$DOCKER_RULE_ID" "$MASTER_KEY" \
    '{"source_container":"e2e_proxy","destination_container":"e2e_app","network_name":"net_back","proto":"tcp","ports":"8080;8443;9090","enabled":false,"comment":"Paused rule","sort_order":10}'
check "200" "PUT /api/firewall/docker-rules/{id} updates ports and disables rule"
check_jq ".enabled" "false" "Inter-rule reports enabled=false"
check_jq ".ports" "8080;8443;9090" "Inter-rule ports updated to 8080;8443;9090"

api_call PUT "/api/firewall/docker-rules/$DOCKER_RULE_ID" "$MASTER_KEY" \
    '{"source_container":"e2e_proxy","destination_container":"e2e_app","network_name":"net_back","proto":"tcp","ports":"8080;8443;9090","enabled":true,"comment":"Active rule","sort_order":10}'
check "200" "PUT /api/firewall/docker-rules/{id} re-enables rule"
check_jq ".enabled" "true" "Inter-rule reports enabled=true"

api_call POST "/api/firewall/docker-rules" "$MASTER_KEY" \
    '{"source_container":"e2e_temp_src","destination_container":"e2e_temp_dst","network_name":"net_back","proto":"udp","ports":"53","enabled":true}'
check "201" "POST /api/firewall/docker-rules creates temporary inter-rule"
TMP_DOCKER_RULE_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call DELETE "/api/firewall/docker-rules/$TMP_DOCKER_RULE_ID" "$MASTER_KEY"
check "204" "DELETE /api/firewall/docker-rules/{id} returns 204 No Content"

api_call DELETE "/api/firewall/docker-rules/$TMP_DOCKER_RULE_ID" "$MASTER_KEY"
check "404" "Repeating DELETE /api/firewall/docker-rules/{id} returns 404 Not Found"

# ── 5. Blocklists CRUD & Script Preview ──────────────────────────────────────
log_section "5. Blocklists CRUD & Script Preview"

api_call GET "/api/firewall/blocklists" "$MASTER_KEY"
check "200" "GET /api/firewall/blocklists lists blocklists and script_preview"

api_call POST "/api/firewall/blocklists" "$MASTER_KEY" \
    '{"name":"e2e_threat_feed","url":"https://feeds.example.org/threats.txt","enabled":true,"description":"E2E Threat Feed","sort_order":10}'
check "201" "POST /api/firewall/blocklists creates new blocklist entry"
BL_ID=$(echo "$RESP_BODY" | jq -r '.id')
check_jq ".name" "e2e_threat_feed" "Blocklist name is e2e_threat_feed"

api_call POST "/api/firewall/blocklists" "$MASTER_KEY" \
    '{"name":"e2e_threat_feed","url":"https://feeds.example.org/other.txt","enabled":true}'
check "409" "POST /api/firewall/blocklists with duplicate name returns 409 Conflict"

api_call PUT "/api/firewall/blocklists/$BL_ID" "$MASTER_KEY" \
    '{"name":"e2e_threat_feed","url":"https://feeds.example.org/threats_v2.txt","enabled":false,"description":"Disabled feed","sort_order":10}'
check "200" "PUT /api/firewall/blocklists/{id} updates URL and disables feed"
check_jq ".enabled" "false" "Blocklist reports enabled=false"

api_call GET "/api/firewall/blocklists" "$MASTER_KEY"
check "200" "GET /api/firewall/blocklists after disabling feed"
BL_PREVIEW=$(echo "$RESP_BODY" | jq -r '.script_preview')
check_not_contains "$BL_PREVIEW" "threats_v2.txt" "Disabled blocklist is excluded from script_preview"

api_call PUT "/api/firewall/blocklists/$BL_ID" "$MASTER_KEY" \
    '{"name":"e2e_threat_feed","url":"https://feeds.example.org/threats_v2.txt","enabled":true,"description":"Enabled feed","sort_order":10}'
check "200" "PUT /api/firewall/blocklists/{id} re-enables feed"

api_call GET "/api/firewall/blocklists" "$MASTER_KEY"
check "200" "GET /api/firewall/blocklists after re-enabling feed"
BL_PREVIEW=$(echo "$RESP_BODY" | jq -r '.script_preview')
check_contains "$BL_PREVIEW" 'generate_list "https://feeds.example.org/threats_v2.txt" "e2e_threat_feed" &' \
    "Re-enabled blocklist appears in script_preview"

api_call POST "/api/firewall/blocklists" "$MASTER_KEY" \
    '{"name":"e2e_temp_feed","url":"https://feeds.example.org/temp.txt","enabled":true}'
check "201" "POST /api/firewall/blocklists creates temporary blocklist"
TMP_BL_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call DELETE "/api/firewall/blocklists/$TMP_BL_ID" "$MASTER_KEY"
check "204" "DELETE /api/firewall/blocklists/{id} returns 204 No Content"

api_call DELETE "/api/firewall/blocklists/$TMP_BL_ID" "$MASTER_KEY"
check "404" "Repeating DELETE /api/firewall/blocklists/{id} returns 404 Not Found"

# ── 6. Special Rules Editor & 3-Stage Validator ──────────────────────────────
log_section "6. Special Rules Editor & 3-Stage Validator"

api_call GET "/api/firewall/tools-functions" "$MASTER_KEY"
check "200" "GET /api/firewall/tools-functions returns parsed helper functions"

api_call GET "/api/firewall/special-rules" "$MASTER_KEY"
check "200" "GET /api/firewall/special-rules returns current special rules script"
ORIG_SPECIAL_SCRIPT=$(echo "$RESP_BODY" | jq -r '.script_content')

# Stage 1 failure: broken bash syntax
api_call POST "/api/firewall/special-rules/validate" "$MASTER_KEY" \
    '{"script_content":"#!/bin/bash\nif [ \"$1\" == \"broken\"\n"}'
check "200" "POST /api/firewall/special-rules/validate runs 3-stage check on invalid syntax"
check_jq ".valid" "false" "Validator reports valid=false on broken bash syntax"
check_jq ".bash_n_ok" "false" "Validator reports bash_n_ok=false on broken bash syntax"

api_call PUT "/api/firewall/special-rules" "$MASTER_KEY" \
    '{"script_content":"#!/bin/bash\nif [ \"$1\" == \"broken\"\n"}'
check "422" "PUT /api/firewall/special-rules rejects broken bash syntax with 422 Unprocessable Entity"

# Stage 2 failure: undefined $CHAIN* / $IPS* variable
api_call PUT "/api/firewall/special-rules" "$MASTER_KEY" \
    '{"script_content":"#!/bin/bash\nsource /etc/firewall/firewall.tools\nsource /etc/firewall/firewall.settings\necho \"$CHAIN_TOTALLY_UNDEFINED_E2E_VAR\"\n"}'
check "422" "PUT /api/firewall/special-rules rejects undefined \$CHAIN_* variable with 422"
check_jq ".validation.variables_ok" "false" "422 diagnostic report identifies variables_ok=false"

# Valid special rules update
VALID_SPECIAL_PAYLOAD=$(jq -nc --arg sc "$ORIG_SPECIAL_SCRIPT" '{script_content: $sc, allow_warnings: true}')
api_call PUT "/api/firewall/special-rules" "$MASTER_KEY" "$VALID_SPECIAL_PAYLOAD"
check "200" "PUT /api/firewall/special-rules saves valid firewall.rules.special script"
check_jq ".validation.bash_n_ok" "true" "Saved script passed bash -n check"
check_jq ".validation.variables_ok" "true" "Saved script passed variable resolution check"

# ── 7. Preview & Atomic Disk Generation (bash -n & Content Verification) ─────
log_section "7. Preview & Atomic Disk Generation (bash -n & Content Verification)"

api_call GET "/api/firewall/preview" "$MASTER_KEY"
check "200" "GET /api/firewall/preview renders all 3 firewall files"
check_jq ".output_dir" "$GEN_OUT_DIR" "Preview bundle reports configured output_dir"

echo "$RESP_BODY" | jq -r '.firewall_settings' > "$WORK_DIR/preview_firewall.settings"
echo "$RESP_BODY" | jq -r '.firewall_rules_special' > "$WORK_DIR/preview_firewall.rules.special"
echo "$RESP_BODY" | jq -r '.firewall_get_list' > "$WORK_DIR/preview_firewall.get.list"

for f in preview_firewall.settings preview_firewall.rules.special preview_firewall.get.list; do
    if bash -n "$WORK_DIR/$f" 2>"$WORK_DIR/${f}_bash_n.err"; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} Preview $f passes 'bash -n' syntax check" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} Preview $f failed 'bash -n': $(cat "$WORK_DIR/${f}_bash_n.err")" >&2
    fi
done

PREVIEW_SETTINGS_CONTENT=$(cat "$WORK_DIR/preview_firewall.settings")
PREVIEW_GETLIST_CONTENT=$(cat "$WORK_DIR/preview_firewall.get.list")

check_contains "$PREVIEW_SETTINGS_CONTENT" 'mainInter="eth0"' "Preview firewall.settings contains mainInter=\"eth0\""
check_contains "$PREVIEW_SETTINGS_CONTENT" 'declare -a INTEROut=("eth0;198.51.100.0/24")' "Preview firewall.settings contains INTEROut"
check_contains "$PREVIEW_SETTINGS_CONTENT" 'declare -a IPAutor=("203.0.113.10/32" "2001:db8::10/128")' "Preview firewall.settings contains IPAutor"
check_contains "$PREVIEW_SETTINGS_CONTENT" 'declare -a countryOpenPort="FR,CH"' "Preview firewall.settings contains countryOpenPort"
check_contains "$PREVIEW_SETTINGS_CONTENT" 'declare -a blockedCountry="CN,RU"' "Preview firewall.settings contains blockedCountry"
check_contains "$PREVIEW_SETTINGS_CONTENT" '"18443"' "Preview firewall.settings contains open port 18443"
check_contains "$PREVIEW_SETTINGS_CONTENT" '"51829"' "Preview firewall.settings contains ww port 51829"
check_contains "$PREVIEW_SETTINGS_CONTENT" '"19443,lan0,192.168.10.20,,443"' "Preview firewall.settings contains local DNAT rule"
check_contains "$PREVIEW_GETLIST_CONTENT" 'generate_list "https://feeds.example.org/threats_v2.txt" "e2e_threat_feed" &' "Preview firewall.get.list contains e2e_threat_feed"
check_contains "$PREVIEW_GETLIST_CONTENT" 'finalize_blocklists' "Preview firewall.get.list ends with finalize_blocklists"

# Atomic generation to disk
api_call POST "/api/firewall/generate" "$MASTER_KEY"
check "200" "POST /api/firewall/generate writes all 3 files to disk"
check_jq ".files_written | length" "3" "generate wrote 3 files"

for fname in firewall.settings firewall.rules.special firewall.get.list; do
    fpath="$GEN_OUT_DIR/$fname"
    if [ -f "$fpath" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} Generated file exists on disk: $fname" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} Generated file missing on disk: $fname" >&2
    fi
    perms=$(stat -c "%a" "$fpath" 2>/dev/null || echo "")
    check_local "$perms" "700" "Generated $fname has mode 0700"
    if bash -n "$fpath" 2>/dev/null; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} On-disk $fname passes 'bash -n'" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} On-disk $fname failed 'bash -n'" >&2
    fi
done

# ── 8. Boundary & Security: Shell-Injection Payloads ─────────────────────────
log_section "8. Shell-Injection Payloads (\", \$(id), \`id\`, ; id, | cat, \\n) -> 400 & Absent From Preview"

# 8a. Settings shell-injection payloads
INJECT_SETTINGS_CASES=(
    '{"main_inter":"eth0\"pwn"}'
    '{"main_inter":"eth0$(id)"}'
    '{"main_inter":"eth0`id`"}'
    '{"main_inter":"eth0; id"}'
    '{"main_inter":"eth0| cat"}'
    '{"main_inter":"eth0\nid"}'
    '{"inter_out":["eth0;1.2.3.0/24$(id)"]}'
    '{"inter_out":["eth0; id"]}'
    '{"inter_out":["eth0|cat"]}'
    '{"inter_out":["eth0\"pwn"]}'
    '{"ip_autor":["1.2.3.4; id"]}'
    '{"ip_autor":["1.2.3.4$(id)"]}'
    '{"ip_autor":["1.2.3.4`id`"]}'
    '{"ip_autor":["1.2.3.4\"pwn"]}'
    '{"country_open_port":"FR;id"}'
    '{"country_open_port":"FR$(id)"}'
    '{"blocked_country":"CN|cat"}'
    '{"blocked_country":"CN`id`"}'
    '{"docker_network_with_access":["net\"pwn"]}'
    '{"docker_network_with_access":["net$(id)"]}'
    '{"docker_network_with_access":["net`id`"]}'
    '{"docker_network_with_access":["net; id"]}'
    '{"docker_network_with_access":["net| cat"]}'
    '{"docker_network_with_access":["net\nid"]}'
    '{"output_dir":"/tmp/fw$(id)"}'
    '{"output_dir":"/tmp/fw;id"}'
    '{"output_dir":"/tmp/fw\"pwn"}'
    '{"docker_endpoint":"unix:///var/run/docker.sock$(id)"}'
    '{"hook_reload_name":"reload$(id)"}'
    '{"hook_reload_name":"reload;id"}'
    '{"hook_executor_url":"https://hooks.example.org/$(id)"}'
)

for payload in "${INJECT_SETTINGS_CASES[@]}"; do
    api_call PUT "/api/firewall/settings" "$MASTER_KEY" "$payload"
    check "400" "Settings rejects shell-injection payload: $payload"
done

# 8b. Zone rules shell-injection payloads
INJECT_ZONE_CASES=(
    '{"zone":"open","rule_kind":"OpenPortsTCP","value":"80\"pwn"}'
    '{"zone":"open","rule_kind":"OpenPortsTCP","value":"80$(id)"}'
    '{"zone":"open","rule_kind":"OpenPortsTCP","value":"80`id`"}'
    '{"zone":"open","rule_kind":"OpenPortsTCP","value":"80; id"}'
    '{"zone":"open","rule_kind":"OpenPortsTCP","value":"80| cat"}'
    '{"zone":"open","rule_kind":"OpenPortsTCP","value":"80\nid"}'
    '{"zone":"open","rule_kind":"DockerTCP","value":"443,net_back,ct\"pwn,443"}'
    '{"zone":"open","rule_kind":"DockerTCP","value":"443,net_back,ct$(id),443"}'
    '{"zone":"open","rule_kind":"DockerTCP","value":"443,net_back,ct`id`,443"}'
    '{"zone":"open","rule_kind":"DockerTCP","value":"443,net_back,ct;id,443"}'
    '{"zone":"open","rule_kind":"DockerTCP","value":"443,net_back,ct|cat,443"}'
    '{"zone":"open","rule_kind":"DockerTCP","value":"443,net_back,ct\nid,443"}'
    '{"zone":"open","rule_kind":"DnatPortTCP","value":"443,eth0$(id),192.168.1.2,,443"}'
)

for payload in "${INJECT_ZONE_CASES[@]}"; do
    api_call POST "/api/firewall/zones" "$MASTER_KEY" "$payload"
    check "400" "Zone rule creation rejects shell-injection payload: $payload"
done

# 8c. Docker inter-container rules shell-injection payloads
INJECT_DOCKER_CASES=(
    '{"source_container":"src\"pwn","destination_container":"dst","network_name":"net","proto":"tcp","ports":"80"}'
    '{"source_container":"src$(id)","destination_container":"dst","network_name":"net","proto":"tcp","ports":"80"}'
    '{"source_container":"src`id`","destination_container":"dst","network_name":"net","proto":"tcp","ports":"80"}'
    '{"source_container":"src; id","destination_container":"dst","network_name":"net","proto":"tcp","ports":"80"}'
    '{"source_container":"src| cat","destination_container":"dst","network_name":"net","proto":"tcp","ports":"80"}'
    '{"source_container":"src\nid","destination_container":"dst","network_name":"net","proto":"tcp","ports":"80"}'
    '{"source_container":"src","destination_container":"dst","network_name":"net","proto":"tcp","ports":"80;id"}'
    '{"source_container":"src","destination_container":"dst","network_name":"net","proto":"tcp","ports":"80;$(id)"}'
    '{"source_container":"src","destination_container":"dst","network_name":"net","proto":"tcp","ports":"80|cat"}'
)

for payload in "${INJECT_DOCKER_CASES[@]}"; do
    api_call POST "/api/firewall/docker-rules" "$MASTER_KEY" "$payload"
    check "400" "Docker inter-rule rejects shell-injection payload: $payload"
done

# 8d. Blocklist URLs & names shell-injection payloads
INJECT_BLOCKLIST_CASES=(
    '{"name":"bl_inj1","url":"https://feeds.example.org/list\"pwn.txt"}'
    '{"name":"bl_inj2","url":"https://feeds.example.org/$(id).txt"}'
    '{"name":"bl_inj3","url":"https://feeds.example.org/`id`.txt"}'
    '{"name":"bl_inj4","url":"https://feeds.example.org/list;id.txt"}'
    '{"name":"bl_inj5","url":"https://feeds.example.org/list|cat.txt"}'
    '{"name":"bl_inj6","url":"https://feeds.example.org/list\nid.txt"}'
    '{"name":"bl\"pwn","url":"https://feeds.example.org/clean.txt"}'
    '{"name":"bl$(id)","url":"https://feeds.example.org/clean.txt"}'
    '{"name":"bl`id`","url":"https://feeds.example.org/clean.txt"}'
    '{"name":"bl;id","url":"https://feeds.example.org/clean.txt"}'
    '{"name":"bl|cat","url":"https://feeds.example.org/clean.txt"}'
    '{"name":"bl\nid","url":"https://feeds.example.org/clean.txt"}'
    '{"name":"bl_creds","url":"https://user:pass@feeds.example.org/clean.txt"}'
    '{"name":"bl_file","url":"file:///etc/passwd"}'
)

for payload in "${INJECT_BLOCKLIST_CASES[@]}"; do
    api_call POST "/api/firewall/blocklists" "$MASTER_KEY" "$payload"
    check "400" "Blocklist creation rejects shell-injection/unsafe payload: $payload"
done

# 8e. Verify none of the injection tokens ever made it into generated preview
api_call GET "/api/firewall/preview" "$MASTER_KEY"
check "200" "GET /api/firewall/preview succeeds after all injection attempts"
AFTER_INJ_SETTINGS=$(echo "$RESP_BODY" | jq -r '.firewall_settings')
AFTER_INJ_GETLIST=$(echo "$RESP_BODY" | jq -r '.firewall_get_list')

for forbidden in '$(id)' '`id`' '; id' '| cat' '|cat' 'pwn'; do
    check_not_contains "$AFTER_INJ_SETTINGS" "$forbidden" "Preview firewall.settings is free of injection token '$forbidden'"
    check_not_contains "$AFTER_INJ_GETLIST" "$forbidden" "Preview firewall.get.list is free of injection token '$forbidden'"
done

echo "$AFTER_INJ_SETTINGS" > "$WORK_DIR/post_inj_firewall.settings"
echo "$AFTER_INJ_GETLIST" > "$WORK_DIR/post_inj_firewall.get.list"
bash -n "$WORK_DIR/post_inj_firewall.settings"
check_local "$?" "0" "Preview firewall.settings still passes bash -n after injection attempts"
bash -n "$WORK_DIR/post_inj_firewall.get.list"
check_local "$?" "0" "Preview firewall.get.list still passes bash -n after injection attempts"

# ── 9. Blocklist SSRF Protection & Import Path Traversal Confinement ─────────
log_section "9. Blocklist SSRF Protection & Import Path Traversal Confinement"

SSRF_URLS=(
    "http://127.0.0.1:$SERVER_PORT/feed"
    "http://127.0.0.1/feed.txt"
    "http://169.254.169.254/latest/meta-data/"
    "http://localhost/feed.txt"
    "http://internal.localhost/feed.txt"
    "http://service.local/feed.txt"
    "http://metadata.internal/feed.txt"
    "http://10.0.0.1/feed.txt"
    "http://172.16.0.1/feed.txt"
    "http://192.168.1.1/feed.txt"
    "http://100.64.0.1/feed.txt"
    "http://[::1]/feed.txt"
    "http://[fe80::1]/feed.txt"
    "http://[fd00::1]/feed.txt"
)

idx=0
for ssrf_url in "${SSRF_URLS[@]}"; do
    idx=$((idx + 1))
    api_call POST "/api/firewall/blocklists" "$MASTER_KEY" \
        "{\"name\":\"ssrf_probe_${idx}\",\"url\":\"$ssrf_url\"}"
    check "400" "Blocklist creation rejects SSRF target '$ssrf_url' with 400 Bad Request"
done

api_call PUT "/api/firewall/blocklists/$BL_ID" "$MASTER_KEY" \
    "{\"name\":\"e2e_threat_feed\",\"url\":\"http://127.0.0.1:$SERVER_PORT/feed\"}"
check "400" "Blocklist update (PUT) rejects loopback SSRF URL http://127.0.0.1:$SERVER_PORT/feed"

api_call PUT "/api/firewall/blocklists/$BL_ID" "$MASTER_KEY" \
    '{"name":"e2e_threat_feed","url":"http://169.254.169.254/latest/meta-data/"}'
check "400" "Blocklist update (PUT) rejects cloud metadata SSRF URL http://169.254.169.254/..."

# Direct test of POST /api/firewall/blocklists/{id}/test SSRF guard when DB row points to loopback or link-local metadata
if command -v python3 >/dev/null 2>&1; then
    python3 - "$DB_PATH" "e2e_threat_feed" "http://127.0.0.1:$SERVER_PORT/feed" <<'PY'
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
conn.execute("UPDATE fw_blocklists SET url = ? WHERE name = ?", (sys.argv[3], sys.argv[2]))
conn.commit()
conn.close()
PY
    api_call POST "/api/firewall/blocklists/$BL_ID/test" "$MASTER_KEY"
    check "400" "POST /api/firewall/blocklists/{id}/test rejects loopback SSRF URL (http://127.0.0.1:$SERVER_PORT/feed)"

    python3 - "$DB_PATH" "e2e_threat_feed" "http://169.254.169.254/latest/meta-data/" <<'PY'
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
conn.execute("UPDATE fw_blocklists SET url = ? WHERE name = ?", (sys.argv[3], sys.argv[2]))
conn.commit()
conn.close()
PY
    api_call POST "/api/firewall/blocklists/$BL_ID/test" "$MASTER_KEY"
    check "400" "POST /api/firewall/blocklists/{id}/test rejects link-local metadata SSRF URL (http://169.254.169.254/...)"

    python3 - "$DB_PATH" "e2e_threat_feed" "https://feeds.example.org/threats_v2.txt" <<'PY'
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
conn.execute("UPDATE fw_blocklists SET url = ? WHERE name = ?", (sys.argv[3], sys.argv[2]))
conn.commit()
conn.close()
PY
fi

# Import path traversal attempts
api_call POST "/api/firewall/import" "$MASTER_KEY" '{"source_dir":"../../../etc/passwd"}'
check "400" "POST /api/firewall/import rejects '../../../etc/passwd' traversal with 400"

api_call POST "/api/firewall/import" "$MASTER_KEY" '{"source_dir":"example/../../etc"}'
check "400" "POST /api/firewall/import rejects 'example/../../etc' traversal with 400"

api_call POST "/api/firewall/import" "$MASTER_KEY" '{"source_dir":"/etc"}'
check "403" "POST /api/firewall/import rejects '/etc' outside permitted roots with 403"

api_call POST "/api/firewall/import" "$MASTER_KEY" '{"source_dir":"/tmp"}'
check "403" "POST /api/firewall/import rejects '/tmp' outside permitted roots with 403"

# ── 10. RBAC Boundary Checks, Secret Opacity & R4 Delegation Hierarchy ───────
log_section "10. RBAC Boundary Checks, Secret Opacity & R4 Delegation Hierarchy"

# 10a. Daughter key without can_manage_settings (only can_manage_blocklists)
api_call POST "/api/keys" "$MASTER_KEY" \
    '{"name":"Blocklist-Only Daughter","can_manage_keys":false,"can_manage_settings":false,"can_manage_special_rules":false,"can_manage_blocklists":true,"can_deploy_and_reload":false}'
check "201" "Created Blocklist-Only Daughter key"
BL_DAUGHTER_ID=$(echo "$RESP_BODY" | jq -r '.id')
BL_DAUGHTER_KEY=$(echo "$RESP_BODY" | jq -r '.raw_key')
BL_DAUGHTER_SECRET=$(echo "$RESP_BODY" | jq -r '.signing_secret')
register_key_secret "$BL_DAUGHTER_KEY" "$BL_DAUGHTER_SECRET"

api_call GET "/api/firewall/settings" "$BL_DAUGHTER_KEY"
check "403" "Daughter without can_manage_settings is rejected (403) on GET /api/firewall/settings"

api_call PUT "/api/firewall/settings" "$BL_DAUGHTER_KEY" '{"main_inter":"eth1"}'
check "403" "Daughter without can_manage_settings is rejected (403) on PUT /api/firewall/settings"

api_call GET "/api/firewall/zones" "$BL_DAUGHTER_KEY"
check "403" "Daughter without can_manage_settings is rejected (403) on GET /api/firewall/zones"

api_call POST "/api/firewall/zones" "$BL_DAUGHTER_KEY" '{"zone":"open","rule_kind":"OpenPortsTCP","value":"8080"}'
check "403" "Daughter without can_manage_settings is rejected (403) on POST /api/firewall/zones"

api_call GET "/api/firewall/docker-rules" "$BL_DAUGHTER_KEY"
check "403" "Daughter without can_manage_settings is rejected (403) on GET /api/firewall/docker-rules"

api_call GET "/api/firewall/special-rules" "$BL_DAUGHTER_KEY"
check "403" "Daughter without can_manage_special_rules is rejected (403) on GET /api/firewall/special-rules"

api_call GET "/api/firewall/preview" "$BL_DAUGHTER_KEY"
check "403" "Daughter without settings/deploy scopes is rejected (403) on GET /api/firewall/preview"

api_call POST "/api/firewall/generate" "$BL_DAUGHTER_KEY"
check "403" "Daughter without can_deploy_and_reload is rejected (403) on POST /api/firewall/generate"

api_call POST "/api/firewall/import" "$BL_DAUGHTER_KEY" '{}'
check "403" "Daughter without can_deploy_and_reload is rejected (403) on POST /api/firewall/import"

api_call POST "/api/keys" "$BL_DAUGHTER_KEY" '{"name":"Unauthorized Subkey"}'
check "403" "Daughter without can_manage_keys is rejected (403) on POST /api/keys"

api_call GET "/api/audit-logs" "$BL_DAUGHTER_KEY"
check "403" "Non-Master Daughter key is rejected (403) on GET /api/audit-logs"

api_call GET "/api/firewall/blocklists" "$BL_DAUGHTER_KEY"
check "200" "Blocklist-Only Daughter can access GET /api/firewall/blocklists (200 OK)"

# 10b. Authorized settings reader never receives plaintext hook_executor_api_key
api_call POST "/api/keys" "$MASTER_KEY" \
    '{"name":"Settings-Reader Daughter","can_manage_settings":true}'
check "201" "Created Settings-Reader Daughter key"
SR_DAUGHTER_ID=$(echo "$RESP_BODY" | jq -r '.id')
SR_DAUGHTER_KEY=$(echo "$RESP_BODY" | jq -r '.raw_key')
SR_DAUGHTER_SECRET=$(echo "$RESP_BODY" | jq -r '.signing_secret')
register_key_secret "$SR_DAUGHTER_KEY" "$SR_DAUGHTER_SECRET"

api_call GET "/api/firewall/settings" "$SR_DAUGHTER_KEY"
check "200" "Authorized Settings-Reader Daughter can call GET /api/firewall/settings"
check_jq ".has_hook_api_key" "true" "Authorized reader sees has_hook_api_key=true boolean"
check_jq ".has_hook_signing_secret" "true" "Authorized reader sees has_hook_signing_secret=true boolean"
check_jq 'has("hook_executor_api_key")' "false" "Authorized reader JSON never contains hook_executor_api_key"
check_jq 'has("hook_executor_signing_secret")' "false" "Authorized reader JSON never contains hook_executor_signing_secret"
check_not_contains "$RESP_BODY" "$HOOK_PLAIN_KEY" "Authorized reader response never leaks plaintext hook API key"
check_not_contains "$RESP_BODY" "$HOOK_PLAIN_SEC" "Authorized reader response never leaks plaintext hook signing secret"

# 10c. R4 delegation hierarchy: non-Master Parent key with can_manage_keys
api_call POST "/api/keys" "$MASTER_KEY" \
    '{"name":"Delegating-Parent-Key","can_manage_keys":true,"can_manage_blocklists":true,"can_manage_settings":false,"can_manage_special_rules":false,"can_deploy_and_reload":false}'
check "201" "Master created Delegating-Parent-Key with can_manage_keys=true and can_manage_blocklists=true"
PARENT_ID=$(echo "$RESP_BODY" | jq -r '.id')
PARENT_PREFIX=$(echo "$RESP_BODY" | jq -r '.prefix')
PARENT_KEY=$(echo "$RESP_BODY" | jq -r '.raw_key')
PARENT_SECRET=$(echo "$RESP_BODY" | jq -r '.signing_secret')
register_key_secret "$PARENT_KEY" "$PARENT_SECRET"

api_call POST "/api/keys" "$PARENT_KEY" \
    '{"name":"Illegal-Sub-Manager","can_manage_keys":true}'
check "403" "R4: Non-Master Parent key is forbidden from granting can_manage_keys"

api_call POST "/api/keys" "$PARENT_KEY" \
    '{"name":"Illegal-Settings-Child","can_manage_settings":true}'
check "403" "R4: Non-Master Parent key is forbidden from granting global scope can_manage_settings"

api_call POST "/api/keys" "$PARENT_KEY" \
    '{"name":"Illegal-SpecialRules-Child","can_manage_special_rules":true}'
check "403" "R4: Non-Master Parent key is forbidden from granting global scope can_manage_special_rules"

api_call POST "/api/keys" "$PARENT_KEY" \
    '{"name":"Illegal-Deploy-Child","can_deploy_and_reload":true}'
check "403" "Non-Master Parent key is forbidden from granting unpossessed scope can_deploy_and_reload"

api_call POST "/api/keys" "$PARENT_KEY" \
    '{"name":"Valid-Blocklist-Grandchild","can_manage_blocklists":true}'
check "201" "Non-Master Parent key can grant subset scope can_manage_blocklists to Grandchild"
GRANDCHILD_ID=$(echo "$RESP_BODY" | jq -r '.id')
GRANDCHILD_KEY=$(echo "$RESP_BODY" | jq -r '.raw_key')
GRANDCHILD_SECRET=$(echo "$RESP_BODY" | jq -r '.signing_secret')
register_key_secret "$GRANDCHILD_KEY" "$GRANDCHILD_SECRET"

api_call PUT "/api/keys/$GRANDCHILD_ID" "$PARENT_KEY" '{"can_manage_keys":true}'
check "403" "R4: Non-Master Parent key cannot escalate Grandchild to can_manage_keys via PUT"

api_call PUT "/api/keys/$GRANDCHILD_ID" "$PARENT_KEY" '{"can_manage_settings":true}'
check "403" "R4: Non-Master Parent key cannot escalate Grandchild to can_manage_settings via PUT"

api_call DELETE "/api/keys/$SR_DAUGHTER_ID" "$PARENT_KEY"
check "404" "Non-Master Parent key cannot delete a sibling key created by Master (404 Not Found)"

# 10d. bound_ips restriction
api_call POST "/api/keys" "$MASTER_KEY" \
    '{"name":"IP-Bound Daughter","bound_ips":"10.254.254.99/32"}'
check "201" "Created IP-Bound Daughter key scoped to 10.254.254.99/32"
BOUND_DAUGHTER_KEY=$(echo "$RESP_BODY" | jq -r '.raw_key')
BOUND_DAUGHTER_SECRET=$(echo "$RESP_BODY" | jq -r '.signing_secret')
register_key_secret "$BOUND_DAUGHTER_KEY" "$BOUND_DAUGHTER_SECRET"

api_call GET "/api/auth/me" "$BOUND_DAUGHTER_KEY"
check "403" "IP-Bound Daughter calling from 127.0.0.1 is rejected with 403 Forbidden"

# ── 11. Anti-Replay Hex Case Swap & Timestamp Skew Rejection ─────────────────
log_section "11. Anti-Replay Hex Case Swap (a-f <-> A-F) & Timestamp Skew Rejection"

REPLAY_TS=$(date -u +%s)
# Ensure REPLAY_TS does not collide with any earlier next_timestamp for GET /api/auth/me
REPLAY_TS=$((REPLAY_TS + 2))
ORIG_SIG=$(hmac_sign "$MASTER_SECRET" "GET" "/api/auth/me" "$REPLAY_TS" "")
ORIG_HEX="${ORIG_SIG#sha256=}"
SWAPPED_HEX=$(printf '%s' "$ORIG_HEX" | tr 'a-fA-F' 'A-Fa-f')
SWAPPED_SIG="sha256=$SWAPPED_HEX"

raw_call GET "/api/auth/me" \
    -H "X-API-Key: $MASTER_KEY" \
    -H "X-Timestamp: $REPLAY_TS" \
    -H "X-Signature-256: $ORIG_SIG"
check "200" "Initial request with fresh signature is accepted (200 OK)"

raw_call GET "/api/auth/me" \
    -H "X-API-Key: $MASTER_KEY" \
    -H "X-Timestamp: $REPLAY_TS" \
    -H "X-Signature-256: $ORIG_SIG"
check "401" "Exact replay of the same signature is rejected with 401 Unauthorized"

raw_call GET "/api/auth/me" \
    -H "X-API-Key: $MASTER_KEY" \
    -H "X-Timestamp: $REPLAY_TS" \
    -H "X-Signature-256: $SWAPPED_SIG"
check "401" "Hex case-swapped replay (a-f <-> A-F) of the same signature is rejected with 401 Unauthorized"
check_contains "$RESP_BODY" "already been used" "Hex case-swapped replay hits digest-based ReplayGuard"

# Out-of-window timestamps
PAST_TS=$(( $(date -u +%s) - 305 ))
PAST_SIG=$(hmac_sign "$MASTER_SECRET" "GET" "/api/auth/me" "$PAST_TS" "")
raw_call GET "/api/auth/me" \
    -H "X-API-Key: $MASTER_KEY" \
    -H "X-Timestamp: $PAST_TS" \
    -H "X-Signature-256: $PAST_SIG"
check "401" "Out-of-window past timestamp (-305s) is rejected with 401 Unauthorized"

FUTURE_TS=$(( $(date -u +%s) + 305 ))
FUTURE_SIG=$(hmac_sign "$MASTER_SECRET" "GET" "/api/auth/me" "$FUTURE_TS" "")
raw_call GET "/api/auth/me" \
    -H "X-API-Key: $MASTER_KEY" \
    -H "X-Timestamp: $FUTURE_TS" \
    -H "X-Signature-256: $FUTURE_SIG"
check "401" "Out-of-window future timestamp (+305s) is rejected with 401 Unauthorized"

raw_call GET "/api/auth/me" \
    -H "X-API-Key: $MASTER_KEY" \
    -H "X-Timestamp: not-a-timestamp" \
    -H "X-Signature-256: $ORIG_SIG"
check "401" "Malformed non-numeric X-Timestamp is rejected with 401 Unauthorized"

# Body tampering after signing
TAMPER_TS=$(( $(date -u +%s) + 3 ))
TAMPER_SIG=$(hmac_sign "$MASTER_SECRET" "PUT" "/api/firewall/settings" "$TAMPER_TS" '{"main_inter":"eth0"}')
raw_call PUT "/api/firewall/settings" \
    -H "X-API-Key: $MASTER_KEY" \
    -H "X-Timestamp: $TAMPER_TS" \
    -H "X-Signature-256: $TAMPER_SIG" \
    -H "Content-Type: application/json" \
    --data-binary '{"main_inter":"eth1"}'
check "401" "Request whose JSON body was modified after signing is rejected with 401 Unauthorized"

# ── 12. Master Key Immutability, Key Rotation & Audit Log Substring Matching ─
log_section "12. Master Key Immutability, Key Rotation & /api/audit-logs Substring Matching"

api_call POST "/api/keys/$MASTER_ID/rotate" "$MASTER_KEY"
check "403" "Master key cannot be rotated via POST /api/keys/{master_id}/rotate (403)"

api_call POST "/api/keys/$MASTER_ID/rotate-secret" "$MASTER_KEY"
check "403" "Master key signing secret cannot be rotated via POST /api/keys/{master_id}/rotate-secret (403)"

api_call PUT "/api/keys/$MASTER_ID" "$MASTER_KEY" '{"name":"Renamed-Master"}'
check "403" "Master key cannot be renamed via PUT /api/keys/{master_id} (403)"

api_call PATCH "/api/keys/$MASTER_ID" "$MASTER_KEY" '{"name":"Renamed-Master"}'
check "403" "Master key cannot be renamed via PATCH /api/keys/{master_id} (403)"

api_call PUT "/api/keys/$MASTER_ID" "$MASTER_KEY" '{"can_manage_keys":false}'
check "403" "Master key permissions cannot be modified via PUT /api/keys/{master_id} (403)"

api_call DELETE "/api/keys/$MASTER_ID" "$MASTER_KEY"
check "403" "Master key cannot be deleted via DELETE /api/keys/{master_id} (403)"

# Only bound_ips may be modified on Master
api_call PUT "/api/keys/$MASTER_ID" "$MASTER_KEY" '{"bound_ips":"127.0.0.1/32"}'
check "200" "Master key allows updating bound_ips to 127.0.0.1/32"
check_jq ".bound_ips" "127.0.0.1/32" "Master key bound_ips updated"

api_call PUT "/api/keys/$MASTER_ID" "$MASTER_KEY" '{"bound_ips":""}'
check "200" "Master key allows clearing bound_ips"

# Sub-key rotation (/rotate and /rotate-secret)
OLD_GC_KEY="$GRANDCHILD_KEY"
api_call POST "/api/keys/$GRANDCHILD_ID/rotate" "$PARENT_KEY"
check "200" "Parent rotates Grandchild API key via POST /api/keys/{id}/rotate"
NEW_GC_KEY=$(echo "$RESP_BODY" | jq -r '.raw_key')
register_key_secret "$NEW_GC_KEY" "$GRANDCHILD_SECRET"

api_call GET "/api/auth/me" "$OLD_GC_KEY"
check "401" "Old Grandchild API key is immediately rejected (401) after rotation"

api_call GET "/api/auth/me" "$NEW_GC_KEY"
check "200" "New Grandchild API key authenticates immediately after rotation"

api_call POST "/api/keys/$GRANDCHILD_ID/rotate-secret" "$PARENT_KEY"
check "200" "Parent rotates Grandchild signing secret via POST /api/keys/{id}/rotate-secret"
NEW_GC_SECRET=$(echo "$RESP_BODY" | jq -r '.signing_secret')

# Old secret must now fail
api_call GET "/api/auth/me" "$NEW_GC_KEY"
check "401" "Old Grandchild signing secret is immediately rejected (401) after rotate-secret"

# Register new secret and confirm it works
register_key_secret "$NEW_GC_KEY" "$NEW_GC_SECRET"
api_call GET "/api/auth/me" "$NEW_GC_KEY"
check "200" "New Grandchild signing secret authenticates immediately"

# /api/audit-logs (and /api/audit) substring matching & filters
api_call GET "/api/audit-logs?limit=200" "$MASTER_KEY"
check "200" "GET /api/audit-logs returns audit trail for Master"
TOTAL_AUDIT=$(echo "$RESP_BODY" | jq 'length')
if [ "$TOTAL_AUDIT" -ge 15 ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} Audit log recorded lifecycle actions (count=$TOTAL_AUDIT)" >&2
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} Expected >= 15 audit entries, got $TOTAL_AUDIT" >&2
fi

# Substring match on client_ip (e.g. "127.0." matches "127.0.0.1")
api_call GET "/api/audit-logs?client_ip=127.0." "$MASTER_KEY"
check "200" "GET /api/audit-logs?client_ip=127.0. succeeds"
IP_SUB_COUNT=$(echo "$RESP_BODY" | jq 'length')
if [ "$IP_SUB_COUNT" -ge 1 ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} client_ip substring filter '127.0.' matched $IP_SUB_COUNT entries" >&2
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} client_ip substring filter '127.0.' returned 0 entries" >&2
fi

# Substring match on api_key by name substring ("Delegating-Parent")
api_call GET "/api/audit-logs?api_key=Delegating-Parent" "$MASTER_KEY"
check "200" "GET /api/audit-logs?api_key=Delegating-Parent succeeds"
NAME_SUB_COUNT=$(echo "$RESP_BODY" | jq 'length')
if [ "$NAME_SUB_COUNT" -ge 1 ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} api_key name substring filter 'Delegating-Parent' matched $NAME_SUB_COUNT entries" >&2
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} api_key name substring filter 'Delegating-Parent' returned 0 entries" >&2
fi

# Substring match on api_key by prefix substring
PREFIX_SUB="${PARENT_PREFIX:0:6}"
api_call GET "/api/audit-logs?api_key=$PREFIX_SUB" "$MASTER_KEY"
check "200" "GET /api/audit-logs?api_key=$PREFIX_SUB (prefix substring) succeeds"
PREF_SUB_COUNT=$(echo "$RESP_BODY" | jq 'length')
if [ "$PREF_SUB_COUNT" -ge 1 ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} api_key prefix substring filter '$PREFIX_SUB' matched $PREF_SUB_COUNT entries" >&2
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} api_key prefix substring filter '$PREFIX_SUB' returned 0 entries" >&2
fi

# Exact UUID match on api_key
api_call GET "/api/audit-logs?api_key=$PARENT_ID" "$MASTER_KEY"
check "200" "GET /api/audit-logs?api_key=$PARENT_ID (UUID) succeeds"
UUID_MATCH_COUNT=$(echo "$RESP_BODY" | jq 'length')
if [ "$UUID_MATCH_COUNT" -ge 1 ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} api_key UUID filter '$PARENT_ID' matched $UUID_MATCH_COUNT entries" >&2
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} api_key UUID filter '$PARENT_ID' returned 0 entries" >&2
fi

# Inclusive until timestamp check
LATEST_AUDIT_TS=$(echo "$RESP_BODY" | jq -r '.[0].timestamp')
api_call GET "/api/audit-logs?since=$LATEST_AUDIT_TS&until=$LATEST_AUDIT_TS" "$MASTER_KEY"
check "200" "GET /api/audit-logs with inclusive since==until succeeds"
INCLUSIVE_COUNT=$(echo "$RESP_BODY" | jq 'length')
if [ "$INCLUSIVE_COUNT" -ge 1 ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} /api/audit-logs until parameter is inclusive (found $INCLUSIVE_COUNT entry at exact timestamp)" >&2
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} /api/audit-logs until parameter excluded entry at exact timestamp $LATEST_AUDIT_TS" >&2
fi

# Malformed audit query params & deny_unknown_fields
api_call GET "/api/audit-logs?since=not-rfc3339" "$MASTER_KEY"
check "400" "GET /api/audit-logs rejects malformed 'since' timestamp with 400"

api_call GET "/api/audit-logs?until=not-rfc3339" "$MASTER_KEY"
check "400" "GET /api/audit-logs rejects malformed 'until' timestamp with 400"

api_call GET "/api/audit-logs?unknown_param=1" "$MASTER_KEY"
check "400" "GET /api/audit-logs rejects unknown query parameter (deny_unknown_fields) with 400"

api_call POST "/api/keys" "$MASTER_KEY" '{"name":"BadFieldKey","unknown_field":true}'
check "400" "POST /api/keys rejects unknown JSON field (deny_unknown_fields) with 400"

# Bootstrap import smoke check at end so all earlier custom rules were tested undisturbed
api_call POST "/api/firewall/import" "$MASTER_KEY" '{}'
check "200" "POST /api/firewall/import imports default configuration cleanly"

log_section "Summary"
TOTAL=$((PASS_COUNT + FAIL_COUNT))
log "Passed checks: $PASS_COUNT / $TOTAL"
log "Failed checks: $FAIL_COUNT / $TOTAL"

if [ "$FAIL_COUNT" -gt 0 ]; then
    err "E2E suite failed with $FAIL_COUNT errors."
    exit 1
fi

log "${GREEN}E2E test suite passed cleanly ($PASS_COUNT checks).${RESET}"
exit 0
