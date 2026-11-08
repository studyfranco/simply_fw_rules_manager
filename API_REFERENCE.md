# API Reference (`simply_fw_rules_manager`)

All `/api/*` endpoints require `CANONICAL_V1` HMAC-SHA256 authentication. All request DTOs enforce `#[serde(deny_unknown_fields)]`.

---

## 1. Health Probes (Unauthenticated)
- `GET /health` -> `200 OK` (`{"status": "ok"}`)
- `GET /healthz` -> `200 OK` (`{"status": "ok"}`)
- `GET /readyz` -> `200 OK` (`{"status": "ready"}`) after running `SELECT 1` against the database

---

## 2. API Keys (`/api/keys`)
- `GET /api/keys` — List API keys visible to caller (`is_master` sees all; `can_manage_keys` sees own + direct children).
- `POST /api/keys` — Create a new API key (returns plaintext `api_key` and `signing_secret` once).
- `PUT /api/keys/{id}` (and `PATCH /api/keys/{id}`) — Update key permissions or `bound_ips` (Master key only allows `bound_ips` updates).
- `DELETE /api/keys/{id}` — Delete a sub-key (cascades to children; Master key returns `403 Forbidden`).

---

## 3. Audit Logs (`/api/audit`)
- `GET /api/audit` — Query audit logs with optional filters: `action`, `client_ip`, `api_key` (matches name, prefix, or UUID), `since` (RFC 3339), `until` (RFC 3339), `limit` (1..=500, default 100), `offset`.

---

## 4. Firewall Settings & Zones (`/api/firewall/settings`, `/api/firewall/zones`, `/api/firewall/docker-rules`)
- `GET /api/firewall/settings` — Retrieve global network interfaces, Docker network lists, trusted IPs (`IPAutor`), GeoIP country lists, Docker daemon endpoint, target output directory, and `simply_hook_executor` configuration.
- `PUT /api/firewall/settings` — Update global settings.
- `GET /api/firewall/zones` — List all zone rules (`ip_autor`, `internal`, `local`, `open`, `ww`), enriched with live Docker container status (`running` / `stopped` / `missing`).
- `POST /api/firewall/zones` — Create a zone rule (`OpenPortsTCP/UDP`, `RedirectPortTCP/UDP`, `DnatPortTCP/UDP`, `DockerTCP/UDP`).
- `PUT /api/firewall/zones/{id}` — Update a zone rule (including `enabled` toggle).
- `DELETE /api/firewall/zones/{id}` — Delete a zone rule.
- `GET /api/firewall/docker-rules` — List inter-container rules (`dockerAccessBetweenThem`), enriched with live status of both `source_container` and `destination_container`.
- `POST /api/firewall/docker-rules` — Create an inter-container flow rule.
- `PUT /api/firewall/docker-rules/{id}` — Update an inter-container flow rule.
- `DELETE /api/firewall/docker-rules/{id}` — Delete an inter-container flow rule.

---

## 5. Docker Discovery (`/api/docker`)
- `GET /api/docker/discovery` — Inspect the configured Docker daemon (`unix:///var/run/docker.sock` or `http://...:2375`) and return all containers (name, state `running`/`exited`, attached networks, IPv4/IPv6 addresses, exposed ports) and Docker networks (name, driver, bridge interface, subnets).

---

## 6. Special Rules Editor & 3-Stage Validator (`/api/firewall/special-rules`)
- `GET /api/firewall/special-rules` — Return the current `firewall.rules.special` script, the last validation report, and the parsed reference list of utility functions from `firewall.tools`.
- `POST /api/firewall/special-rules/validate` — Execute the 3-stage validation pipeline (`bash -n`, `shellcheck`, and `$CHAIN*`/`$IPS*` variable resolution against `firewall.tools`, `firewall.settings`, and script-local variables) without saving.
- `PUT /api/firewall/special-rules` — Run the 3-stage validation pipeline and save `firewall.rules.special` in database (rejects with `422 Unprocessable Entity` and full diagnostics if syntax or undefined-variable checks fail, unless `allow_warnings` is set for non-fatal shellcheck style hints).

---

## 7. Blocklists (`firewall.get.list`) (`/api/firewall/blocklists`)
- `GET /api/firewall/blocklists` — List all configured blocklist feeds and preview the generated `firewall.get.list` script.
- `POST /api/firewall/blocklists` — Add a new `(name, url)` blocklist entry.
- `PUT /api/firewall/blocklists/{id}` — Update a blocklist entry.
- `DELETE /api/firewall/blocklists/{id}` — Delete a blocklist entry.
- `POST /api/firewall/blocklists/{id}/test` — Perform a live HTTP GET against the feed URL and verify that the response is a valid plaintext list of IPv4/IPv6/CIDR addresses.

---

## 8. Bootstrap Import, File Generation & Hook Execution (`/api/firewall/deploy`)
- `POST /api/firewall/import` — Import/re-import configuration from `/example/MainServ/etc_firewall/` (or custom directory), automatically refactoring `.rules.special` and `.get.list`.
- `GET /api/firewall/preview` — Render a live preview of all 3 generated files (`firewall.settings`, `firewall.rules.special`, `firewall.get.list`) along with active/skipped container rule counts.
- `POST /api/firewall/generate` — Atomically write `firewall.settings`, `firewall.rules.special`, and `firewall.get.list` (`0700`) to the configured `output_dir` (filtering out stopped containers in `firewall.settings`).
- `POST /api/firewall/reload` — Trigger the configured `simply_hook_executor` reload hook via signed `CANONICAL_V1` request.
- `POST /api/firewall/generate-and-reload` — Atomically generate the 3 files and immediately trigger `simply_hook_executor` reload.
- `POST /api/firewall/update-containers` — Trigger the configured `simply_hook_executor` container update hook.
