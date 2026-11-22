---
name: use-fw-rules-manager
description: Operate and configure simply_fw_rules_manager via its CANONICAL_V1 HMAC-SHA256 API, manage firewall settings, zone and Docker rules, special rules, blocklist feeds, and deploy via simply_hook_executor or Ansible.
---

# Using `simply_fw_rules_manager`

`simply_fw_rules_manager` is the firewall configuration, validation, and artifact-generation service in the `simply_*` ecosystem. It manages `firewall.settings`, `firewall.rules.special`, and `firewall.get.list`, discovers live Docker containers via `socket_proxy` (or Unix socket), and delegates host reloads to `simply_hook_executor`.

## Network & Isolation Boundaries

- **Strictly `isolate`-only:** `simply_fw_rules_manager` attaches only to the internal `isolate` Docker bridge (`10.123.0.0/16` by default in `ansible/inventory/group_vars/all.yml`) and must not attach to `ext`.
- **Reverse-proxy access:** Expose the dashboard/API to operators through a host-loopback listener (`localDockerTCP`, e.g., host-loopback port `3004` forwarding to `simply_fw_rules_manager:3000`) rather than adding `ext`.
- **Ecosystem separation:** Threat-feed ingestion belongs to `simply_ip_sync` (`isolate` + `ext`), IP reputation storage to `simply_ip_vault`, plaintext feed serving to `simply_ip_exporter` (`isolate`-only), and privileged host execution to `simply_hook_executor`.

## `CANONICAL_V1` Authentication & `OriginalUri`

Every `/api/*` route requires three headers (see `src/middleware.rs` and `src/crypto.rs`):

- `X-API-Key`: Key identifier.
- `X-Timestamp`: UTC Unix epoch seconds within `±300` seconds.
- `X-Signature-256`: `sha256=<hex_hmac_sha256>` computed with the key's signing secret over:

```text
<METHOD>\n<ORIGINAL_URI_PATH_AND_QUERY>\n<TIMESTAMP>\n<RAW_BODY_UTF8>
```

- **`OriginalUri` rule:** `auth_middleware` extracts `OriginalUri` (falling back to the request URI) before Axum's `/api` nesting strips prefixes. If a reverse proxy forwards `/fw/api/firewall/settings?foo=1` without rewriting, sign `/fw/api/firewall/settings?foo=1`; if accessed directly at `https://fw.example.test/api/firewall/settings`, sign `/api/firewall/settings`.
- **Replay protection:** `(key_id, timestamp, signature)` tuples are single-use within the replay window.
- **Request limits & strict JSON:** Bodies are capped at 3 MiB (`MAX_BODY_SIZE_MIB` / `DefaultBodyLimit`) and payloads reject unknown fields (`#[serde(deny_unknown_fields)]`).

### Example `curl` + `openssl` Call (RFC 2606 / RFC 5737)

```bash
FW_URL="https://fw.example.test"
API_KEY="0000000000000000000000000000000000000000000000000000000000000000"
SECRET="1111111111111111111111111111111111111111111111111111111111111111"
METHOD="GET"
TARGET="/api/firewall/settings"
TS="$(date -u +%s)"
BODY=""
SIG="$(printf '%s\n%s\n%s\n%s' "$METHOD" "$TARGET" "$TS" "$BODY" | openssl dgst -sha256 -hmac "$SECRET" | sed 's/^.*= //')"

curl -fsS -X "$METHOD" \
  -H "X-API-Key: ${API_KEY}" \
  -H "X-Timestamp: ${TS}" \
  -H "X-Signature-256: sha256=${SIG}" \
  "${FW_URL}${TARGET}"
```

## API Route Reference (`src/lib.rs`)

### Unauthenticated Probes

- `GET /health`, `GET /healthz` — Liveness probe.
- `GET /ready`, `GET /readyz` — Readiness probe (`SELECT 1` DB check).

### Authenticated `/api/*` Routes

| Area | Method & Path | Purpose |
| :--- | :--- | :--- |
| **Auth & Keys** | `GET /api/auth/me` | Inspect caller key metadata and permissions. |
| | `GET, POST /api/keys` | List or mint scoped daughter API keys (bindable to CIDRs like `192.0.2.0/24` or `2001:db8::/32`). |
| | `PUT, PATCH, DELETE /api/keys/{id}` | Update or revoke an API key. |
| | `POST /api/keys/{id}/rotate` | Rotate API key ID. |
| | `POST /api/keys/{id}/rotate-secret` | Rotate signing secret. |
| **Audit & System** | `GET /api/audit`, `GET /api/audit-logs` | Query audit logs (`api_key`, `client_ip`, `action`, `since`, `until`). |
| | `GET /api/system/settings`, `GET /api/settings` | Master-only daemon introspection and entity counts. |
| **Settings** | `GET, PUT /api/firewall/settings` | Read or update `firewall.settings` interfaces, networks, trusted IPs (`IPAutor`), GeoIP, and hook config. |
| **Zone Rules** | `GET, POST /api/firewall/zones` | List or create zone rules (`internal`, `local`, `open`, `WW`, `IPAutor`). |
| | `PUT, DELETE /api/firewall/zones/{id}` | Update or delete a zone rule. |
| **Docker Inter-Rules** | `GET, POST /api/firewall/docker-rules` | List or create `dockerAccessBetweenThem` tuples. |
| | `PUT, DELETE /api/firewall/docker-rules/{id}` | Update or delete an inter-container rule. |
| **Docker Discovery** | `GET /api/docker/discovery` | Live container and network inventory from Docker Engine API. |
| **Special Rules** | `GET, PUT /api/firewall/special-rules` | Read or save `firewall.rules.special` (enforces 3-stage validation on save). |
| | `POST /api/firewall/special-rules/validate` | Dry-run 3-stage validation (`bash -n`, `shellcheck`, `$CHAIN*`/`$IPS*` variable resolution). |
| | `GET /api/firewall/tools-functions` | List helper functions parsed from `scripts_etc/firewall.tools`. |
| **Blocklists** | `GET, POST /api/firewall/blocklists` | List or create `firewall.get.list` feed entries. |
| | `PUT, DELETE /api/firewall/blocklists/{id}` | Update or delete a blocklist feed entry. |
| | `POST /api/firewall/blocklists/{id}/test` | Fetch and validate IPv4/IPv6/CIDR lines from a feed URL. |
| **Deploy & Import** | `GET /api/firewall/preview` | Preview generated `firewall.settings`, `firewall.rules.special`, and `firewall.get.list`. |
| | `POST /api/firewall/import` | Import baseline scripts from disk or fixtures. |
| | `POST /api/firewall/generate` | Write generated files in-place to `FW_OUTPUT_DIR` (active `running` containers only). |
| | `POST /api/firewall/reload` | Trigger reload hook on `simply_hook_executor` (`https://hook.example.test`). |
| | `POST /api/firewall/generate-and-reload` | Generate files and immediately trigger firewall reload. |
| | `POST /api/firewall/update-containers` | Trigger container update hook on `simply_hook_executor`. |

## Firewall & Feed Cookbook

1. **Add a trusted IPv4/IPv6 rule or zone rule:**
   - Use `POST /api/firewall/zones` with RFC 5737/3849 targets (e.g., `198.51.100.10` or `2001:db8::10`), then `GET /api/firewall/preview` to verify the rendered `firewall.settings` array before calling `POST /api/firewall/generate-and-reload`.
2. **Validate custom Netfilter hooks (`firewall.rules.special`):**
   - Always test edits with `POST /api/firewall/special-rules/validate` first so `bash -n`, `shellcheck`, and `$CHAIN*`/`$IPS*` checks pass before `PUT /api/firewall/special-rules`.
3. **Consume `simply_ip_exporter` feeds:**
   - Register the exporter plaintext feed URL (e.g., `https://exporter.example.test/feed/v1/<token>/list.txt`) via `POST /api/firewall/blocklists`, test with `POST /api/firewall/blocklists/{id}/test`, and regenerate `firewall.get.list`.
4. **Ansible ecosystem deployment (`ansible/`):**
   - Configure `ansible/inventory/group_vars/all.yml` (including `sync_default_destination_groups` feeds with `REGEX_LINE` or `JSON_PATH` + `parser_config`), then deploy with `ansible-playbook playbooks/site.yml`.
   - `ansible/roles/vault_integration/tasks/main.yml` reconciles `simply_ip_sync` destination groups and feeds idempotently (including `parser_config_json` for `JSON_PATH` feeds).
