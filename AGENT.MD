# AGENT.MD — Architectural & Operational Specification (`simply_fw_rules_manager`)

## 📑 Document Hierarchy & Source of Truth
This repository uses a modular documentation structure to optimize context windows for AI Coding Agents. Before making architectural, database, or routing changes, consult the relevant specification file:
- **[`AGENT.MD`](file:///home/fallrik/Documents/workspaces/simply_fw_rules_manager/AGENT.MD) (This File)**: High-level architecture, core domain logic, security constraints, firewall script generation, Docker discovery, Bash/ShellCheck integrity verification, and strict coding rules.
- **[`RBAC_MODEL.md`](file:///home/fallrik/Documents/workspaces/simply_fw_rules_manager/RBAC_MODEL.md)**: Cross-service RBAC specification (Master / Parent / Daughter tiers, R1–R7 rules, ownership, oracle discipline).
- **[`SCHEMA.MD`](file:///home/fallrik/Documents/workspaces/simply_fw_rules_manager/SCHEMA.MD)**: Authoritative SeaORM 2.0 database schema, table definitions, foreign keys, and indexing strategies.
- **[`API_REFERENCE.md`](file:///home/fallrik/Documents/workspaces/simply_fw_rules_manager/API_REFERENCE.md)**: Complete REST API specification, route payloads, query parameters, and expected HTTP status codes.
- **[`FILE_MAP.MD`](file:///home/fallrik/Documents/workspaces/simply_fw_rules_manager/FILE_MAP.MD)**: Exhaustive directory and file-by-file codebase map to navigate without running expensive global searches.
- **[`AGENT_NOTES.MD`](file:///home/fallrik/Documents/workspaces/simply_fw_rules_manager/AGENT_NOTES.MD)**: Living architectural memory, resolved edge cases, and lessons learned.

---

## 🔗 Peer Repository Synchronization (`simply_*` Ecosystem)

`simply_fw_rules_manager` is the **5th standalone service** in the `simply_*` network security ecosystem alongside:
1. [`simply_ip_vault`](file:///home/fallrik/Documents/workspaces/simply_ip_vault) — Centralized IP banlist/whitelist vault and RBAC authority.
2. [`simply_hook_executor`](file:///home/fallrik/Documents/workspaces/simply_hook_executor) — Secure webhook & privileged script/SSH execution engine.
3. [`simply_ip_sync`](file:///home/fallrik/Documents/workspaces/simply_ip_sync) — Threat intelligence feed aggregator (including authenticated JSON feeds like AbuseIPDB) pushing to `simply_ip_vault`.
4. [`simply_ip_exporter`](file:///home/fallrik/Documents/workspaces/simply_ip_exporter) — High-throughput, unauthenticated plaintext CIDR feed exporter (`/feed/v1/{token_secret}/list.txt`) consumed by `firewall.get.list`.

**100% Repository Independence:** No internal Rust crate is shared between the 5 repositories. Unification is achieved by strict code, schema, cryptographic, and UI alignment across all 5 repositories:
- **`CANONICAL_V1` HMAC-SHA256 Authentication**: `simply_fw_rules_manager`, `simply_ip_vault`, `simply_ip_sync`, and `simply_ip_exporter` enforce `CANONICAL_V1` signed requests on all `/api/*` routes. (By design, **only `simply_hook_executor`** supports multiple authentication modes on its hook execution routes).
- **XChaCha20-Poly1305 Envelope Encryption (`src/crypto.rs`)**: All secrets at rest (`api_keys.signing_secret`, `hook_executor_configs.api_key`, `hook_executor_configs.signing_secret`) are encrypted using `SecretCipher` (`v1.xchacha20poly1305.<nonce_b64>.<ct_b64>`) keyed via `FW_ENCRYPTION_KEY` (or `SIGNING_SECRET_KEY`).
- **Unified Login Page, CSS & Audit Logs**: Identical login experience, dark enterprise stylesheet (`static/style.css`), and `NOT NULL` denormalized audit attribution (`api_key_id` `ON DELETE SET NULL`, `api_key_name`, `api_key_prefix`, `client_ip`).

---

## 🎯 Project Overview

`simply_fw_rules_manager` is a mission-critical Rust web service and Single-Page Application (SPA) designed to manage, validate, generate, and deploy Linux firewall configurations (`iptables`, `ip6tables`, `ipset`) and their dynamic interactions with Docker containers and `simply_hook_executor`.

On first startup (or via an explicit import API/UI action), the service parses existing firewall scripts (`firewall.settings`, `firewall.rules.special`, `firewall.get.list` from `/example/MainServ/etc_firewall` or a configurable import path) to seed the database.

---

## 🛠️ Tech Stack & Strict Architectural Constraints

- **Language:** Rust (Edition 2024, `rust-version = "1.85"`)
- **Web Framework:** `axum` (v0.8) + `tokio` + `tower-http`
- **ORM & Database:** `sea-orm` (v2.0.0-rc) + `sea-orm-migration` — **100% SQL-Agnostic** (`sqlx-sqlite`, `sqlx-postgres`, `sqlx-mysql`).
  - **Two-Phase Isolated Migration Architecture:** Phase 1 runs `Migrator::up(&db, None)` on a single-connection SQLite pool (`max_connections(1)`) to prevent `SQLITE_BUSY` DDL lock contention; Phase 2 opens the application pool (`SqliteTransactionMode::Immediate` for write serialization, `WAL` journal mode, `foreign_keys=ON`, `synchronous=NORMAL`, `busy_timeout=5000`).
  - **Zero Raw SQL for DML:** All `SELECT`, `INSERT`, `UPDATE`, and `DELETE` operations MUST use SeaORM's typed query builders (`Entity::find()`, `QuerySelect`, `Condition`, `Expr`). The only allowlisted raw SQL statements in `src/` are connection `PRAGMA`s and index inspection in `src/db.rs` and generated-column DDL in `src/migration/`.
- **Frontend:** Strictly Vanilla HTML5, CSS3, and ES6+ JavaScript (`fetch()` API only) served from `./static`.
  - **NO external frontend frameworks** (No React, Vue, Angular, Svelte, Tailwind, Bootstrap) and **NO external CDN dependencies** (zero `<script>` or `<link>` pointing outside the service).
  - Includes a self-contained embedded Bash code editor with line numbers, live syntax highlighting, autocomplete/reference sidebar for `firewall.tools` helper functions, and real-time validation output.
- **Strict Deserialization & Request Ceiling:**
  - All API request payloads MUST use `#[serde(deny_unknown_fields)]` and custom extractors in `src/extract.rs` (`StrictJson`, `OptionalStrictJson`, `StrictPath`, `StrictQuery`) returning structured JSON `{"error": "..."}`.
  - Router-wide `DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES)` capped at **3 MiB**, shared with `auth_middleware`.
- **Documentation & Panic-Free Policy:**
  - `src/lib.rs` enforces `#![warn(missing_docs)]` and `[lints.clippy] all = "warn", pedantic = "warn"`.
  - Production code and HTTP handlers MUST NOT use `.unwrap()` or `.expect()`. Propagate all errors cleanly via `Result<T, AppError>`.

---

## 🔒 Security & Network Architecture

1. **HMAC-SHA256 `CANONICAL_V1` Protocol (`src/middleware.rs` & `src/replay.rs`):**
   - Every `/api/*` request requires `X-API-Key`, `X-Timestamp` (UTC Unix seconds within ±300s), and `X-Signature-256: sha256=<hex>`.
   - Canonical payload: `"{METHOD}\n{PATH_AND_QUERY}\n{TIMESTAMP}\n{RAW_BODY_UTF8}"`.
   - `ReplayGuard` enforces single-use `(key_id, timestamp, signature)` tuples within the validity window.
2. **Master Identity Pinning (`src/master.rs`):**
   - `api_keys` enforces single-master uniqueness at the database level via the generated `master_marker` column and unique index `idx_api_keys_single_master`.
   - `MasterPin::pin_at_boot` verifies the index and pins the sole Master UUID in memory at boot; `auth_middleware` demotes any non-matching row claiming `is_master`.
3. **Trusted Proxy & Client IP Extraction:**
   - Configured via `TRUSTED_PROXIES` (IPs, CIDRs, or Docker container hostnames resolved at startup). `X-Forwarded-For` / `X-Real-IP` are honored only when the immediate TCP peer is trusted.

---

## 🔥 Core Domain Specifications (Phase 2)

### 2.1 Constants Separation & `firewall.settings` Generation
By analyzing `example/MainServ/etc_firewall/firewall.settings` and `scripts_etc/firewall.tools`:
- **Immutable System Constants:** Variables that never change across rule edits — binary paths (`IPT`, `IPT6`, `IPS`, `ROUTE`, `SED`, `DUMPCO`, `DOCKER`, `IFCONFIG`, `JQ`, `FAILBAN`), `ipset` names (`IPSLIST*`, `crowdsecSetIP*`), chain names (`CHAIN*`), and `saveFileGeoIPDB` — are separated from editable user settings. They are maintained in `scripts_etc/firewall.tools` (and emitted as a read-only system header block when generating `firewall.settings` so legacy scripts sourcing `firewall.settings` first continue to work seamlessly). Bash variable names themselves are strictly immutable.
- **Editable Firewall Settings in Database & WebUI:**
  1. **Network Interfaces (`fw_interfaces` / settings):** `mainInter`, `INTEROut`, `interfaceToGoOutSide`, `internInterfaceHaveAccessAsLocal`, `interfaceLocal`, `interfaceWithDHCP`, `interfaceWithNoRules`.
  2. **Docker Networks (`fw_docker_networks`):** `dockerNetworkWithInternetAccess`, `dockerNetworkWithAccess`.
  3. **Inter-Container Flows (`fw_docker_inter_rules`):** `dockerAccessBetweenThem` tuples (`source_container`, `destination_container`, `network_name`, `proto` [`tcp`/`udp`], `ports` `;`-separated list, `enabled`, `comment`).
  4. **Trusted IPs & Access (`fw_trusted_ips` & `fw_trusted_ip_rules`):** `IPAutor` (IPv4/IPv6/CIDR list) and port forwarding rules `IPAutorDnatPortTCP`, `IPAutorDnatPortUDP`, `IPAutorDockerTCP`, `IPAutorDockerUDP`.
  5. **Zone Port & NAT Rules (`fw_zone_rules`):** Organized by zone (`internal`, `local`, `open` [GeoIP-filtered], `WW` [WorldWide]) and rule kind (`OpenPortsTCP`, `OpenPortsUDP`, `RedirectPortTCP`, `RedirectPortUDP`, `DnatPortTCP`, `DnatPortUDP`, `DockerTCP`, `DockerUDP`).
  6. **GeoIP Filtering (`fw_geoip_countries`):** `countryOpenPort`, `blockedCountry`, `blockedCountry2` (ISO-3166 alpha-2 country codes).

### 2.2 Docker Discovery & Dynamic Active/Inactive Filtering (`src/docker.rs`)
- **Configurable Docker Daemon Connection:** Supports connecting to the Docker Engine API either via a local Unix domain socket (`unix:///var/run/docker.sock` or `/var/run/docker.sock`) or via TCP/HTTP (`http://...:2375` / `tcp://...:2375`, e.g., `dockersocprox`). Configurable via environment variables (`DOCKER_ENDPOINT`) and editable in the WebUI System Settings.
- **Container & Network Inventory:** Lists all containers on the host (name, ID, state `running`/`exited`/`paused`, attached networks, IPv4/IPv6 addresses, exposed ports) and Docker networks to power smart selectors and live status badges (`RUNNING` / `STOPPED` / `MISSING`) in the WebUI.
- **Dynamic Active/Inactive Filtering on Generation:**
  - Users can create, edit, and save rules in the database referencing **any** container, even if it is currently stopped/inactive or not yet deployed.
  - When generating `firewall.settings` (`POST /api/firewall/generate` or **"Générer"** in the WebUI), the backend queries live container states from the configured Docker daemon (with a graceful fallback/override option when Docker is unreachable in offline test environments):
    - For single-container rules (`IPAutorDockerTCP/UDP`, `internalDockerTCP/UDP`, `localDockerTCP/UDP`, `openDockerTCP/UDP`, `WWDockerTCP/UDP`), the rule is written to `firewall.settings` **if and only if** the target container is currently `running` (and `enabled == true`).
    - For `dockerAccessBetweenThem`, the rule is written to `firewall.settings` **if and only if both** `source_container` and `destination_container` are currently `running` (and `enabled == true`).
    - Rules for inactive containers remain safely persisted in the database and are visually badged as inactive in the WebUI.

### 2.3 Advanced Editor & 3-Stage Integrity Checker for `firewall.rules.special` (`src/validator.rs`)
- **Refactored Docker Helpers in `scripts_etc/firewall.tools`:**
  - Replaces repetitive manual `${DOCKER} container inspect` blocks in `firewall.rules.special` (`add_cloud`, `add_plex`, `add_pihole`) with generic, reusable container helper functions in `firewall.tools`:
    - `get_container_ipv4_on_network "<container>" "<network>"`
    - `get_container_ipv6_on_network "<container>" "<network>"`
    - `insert_container_special_rule_ipv4 "<container>" "<network>" "<rule_template_with_{IP}>"`
    - `insert_container_special_rule_ipv6 "<container>" "<network>" "<rule_template_with_{IP6}>"`
    - `allow_container_to_host_ports "<container>" "<network>" "<proto>" "<ports_csv>" ["<extra_args>"]`
- **Structured WebUI Code Editor:**
  - Embedded Vanilla JS code editor with line numbers, Bash syntax highlighting, and a side panel listing all helper functions parsed from `firewall.tools` (signature, description, parameters, and one-click snippet insertion).
- **Strict 3-Stage Integrity Check (`POST /api/firewall/special-rules/validate`):**
  Before saving or generating `firewall.rules.special`, the backend executes a 3-stage validation pipeline and returns a structured report to the UI:
  1. **Stage 1 — Bash Syntax (`bash -n`):** Verifies the script has zero Bash syntax errors.
  2. **Stage 2 — Static Analysis (`shellcheck`):** Runs `shellcheck -f json -s bash` (when the binary is installed on the host/container) to catch quoting pitfalls, undefined locals, and common Bash bugs.
  3. **Stage 3 — Variable Resolution Check:** Parses all `$VAR` and `${VAR}` references in `firewall.rules.special` and verifies that every referenced `$CHAIN...`, `$IPS...`, or other variable is defined either in the system constants / `firewall.settings` / `firewall.tools`, in standard Bash built-ins, or locally within `firewall.rules.special`. Undefined variables fail validation with exact line numbers.

### 2.4 Management & Simplification of `firewall.get.list`
- **Template Preservation:** Preserves the `generate_list` bash function and the final aggregation commands (`cat /etc/firewall/*.6 > /etc/firewall/to_block.ipv6` and `cat /etc/firewall/*.4 > /etc/firewall/to_block.ipv4`).
- **Removal of Hardcoded AbuseIPDB Logic:** Strips the legacy `curl`/`jq` AbuseIPDB block from `firewall.get.list`. Complex authenticated feeds (like AbuseIPDB JSON) are ingested by `simply_ip_sync` → `simply_ip_vault` and exposed as a clean plaintext feed by `simply_ip_exporter`, which is added as a standard `generate_list "<URL>" "<list_name>" &` entry.
- **CRUD & Live Feed Validator (`POST /api/firewall/blocklists/test-url`):**
  - Full WebUI & API CRUD to add, edit, enable/disable, reorder, or delete `(url, name)` blocklist entries.
  - Live "Tester l'URL" endpoint that fetches the remote feed (with timeout and size cap) and validates that its non-comment lines are valid IPv4, IPv6, or CIDR blocks (`ipnet`).

### 2.5 Atomic File Deployment, `simply_hook_executor` Integration & Audit Logs
- **Atomic Disk Deployment (`src/generator.rs`):**
  - Writes `firewall.settings`, `firewall.rules.special`, and `firewall.get.list` atomically (write to `.tmp` in target directory + `chmod 0750` + `fs::rename`) to the configured output directory (`FIREWALL_CONFIG_DIR`, defaulting to `./output/etc_firewall` in dev or `/etc/firewall` in prod).
- **`simply_hook_executor` Client Integration (`src/hook_client.rs`):**
  - Stores the `simply_hook_executor` connection profile (Base URL, Reload Hook ID/Name, optional Container Update Hook ID/Name, `X-API-Key`, and `signing_secret` encrypted at rest with `SecretCipher`).
  - Signs outbound requests using `CANONICAL_V1` HMAC-SHA256 (`POST /api/hooks/{id}/execute`).
  - Exposes 3 distinct operator actions in the WebUI:
    1. **"Générer les fichiers"** (`POST /api/firewall/deploy` with `{"trigger_reload": false}`): Generates and writes the configuration files to disk without reloading the firewall.
    2. **"Recharger le Firewall"** (`POST /api/firewall/reload`): Triggers the reload hook on `simply_hook_executor` directly.
    3. **"Générer et appliquer immédiatement"** (`POST /api/firewall/deploy` with `{"trigger_reload": true}`): Validates, generates, writes files to disk, and immediately triggers the `simply_hook_executor` reload hook, returning the captured `stdout`/`stderr`/exit code.
- **Exhaustive Audit Logging:**
  - Every mutating action (settings update, rule CRUD, special rules save/validation failure, blocklist CRUD, file generation, and hook execution trigger) records a `NOT NULL`-attributed row in `audit_logs`.
  - No file versioning or rollback history is stored in the database.

---

*End of directives. Write safe, panic-free (`no .unwrap()`), and elegant Rust code.*
