# Agent Engineering Notes (`simply_fw_rules_manager`)

## Session 1 — Ecosystem Unification & `simply_fw_rules_manager` Implementation

### 1. Ecosystem Unification (Phase 1)
- Audited `simply_ip_vault`, `simply_hook_executor`, `simply_ip_sync`, and `simply_ip_exporter`.
- Standardized login form titles, labels (`API Key`, `Signing Secret`, `API Base Path Override`), and button text (`Unlock Dashboard`) across all 5 repositories.
- Standardized `/api/audit` query filtering (`action`, `client_ip`, `api_key`, `since`, `until`, `limit`, `offset` with `#[serde(deny_unknown_fields)]`) and 6-column WebUI Audit Log rendering (`Timestamp`, `API Key`, `Client IP`, `Action`, `Target`, `Details`).
- Verified AbuseIPDB v2 JSON ingestion in `simply_ip_sync` (`JSON_PATH` with `array_path: "data"`, `target_address: "$.ipAddress"`, `last_seen_at: "$.lastReportedAt"`, custom `Key` and `Accept: application/json` headers) and added a one-click AbuseIPDB v2 preset in `simply_ip_sync`'s Feed UI.

### 2. Firewall Script Audit & Refactoring (`scripts_etc/`)
- Documented 9 root-cause issues and performance bottlenecks in `scripts_etc/AUDIT_FIREWALL_SCRIPTS.md`.
- Moved all immutable binary paths, `IPSLIST*` set names, and `CHAIN*` netfilter chain constants into `scripts_etc/firewall.tools`.
- Added associative caching (`_FW_CACHE_*`) and generic container rule helpers (`get_container_ipv4_on_network`, `get_container_ipv6_on_network`, `allow_container_to_host_ports`, `insert_container_special_rule_ipv4`, `insert_container_special_rule_ipv6`) with `@fn`/`@usage`/`@desc` doc-comments parsed dynamically by `simply_fw_rules_manager`.

### 3. `simply_fw_rules_manager` Architecture (Phase 2)
- Automatic first-boot import from `example/MainServ/etc_firewall/{firewall.settings,firewall.rules.special,firewall.get.list}` when the database has no seeded rules.
- Automatic refactoring of `add_cloud`, `add_plex`, and `add_pihole` in `firewall.rules.special` to use the generic helpers in `firewall.tools`, and removal of the legacy AbuseIPDB `curl`/`jq` block from `firewall.get.list` in favor of `simply_ip_exporter` feed URLs.
- 3-stage validation pipeline (`bash -n`, `shellcheck`, and `$CHAIN*`/`$IPS*` variable resolution) enforced before saving or generating `firewall.rules.special`.
- Live Docker container state filtering when generating `firewall.settings` so rules referencing stopped containers remain persisted in the database without breaking `docker inspect` during firewall reloads.
