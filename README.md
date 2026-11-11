# simply_fw_rules_manager

Simply efficient. Linux firewall & container flow orchestrator.

`simply_fw_rules_manager` is a high-assurance, self-hosted API and dashboard for centrally managing
Linux `iptables` / `ip6tables` / `ipset` firewalls, Docker inter-container network flows, custom
Netfilter script extensions (`firewall.rules.special`), and external IP blocklist feeds
(`firewall.get.list`).

It acts as the core rules engine in the `simply_*` security ecosystem, bridging live Docker container
discovery, threat intelligence feeds from `simply_ip_exporter`, and atomic rule reloading via
`simply_hook_executor`.

- **Backend:** Rust, Axum, SeaORM (SQLite by default, zero config, PostgreSQL/MySQL ready).
- **Frontend:** a single-page dashboard in `static/` — vanilla HTML/CSS/JS, no build step, no
  external dependencies.
- **Access control:** every API key can be a full master key, or scoped with fine-grained per-domain
  rights (`can_manage_settings`, `can_manage_special_rules`, `can_manage_blocklists`,
  `can_deploy_and_reload`, `can_manage_keys`) bound to client CIDRs.

---

## Contents

- [Architecture overview](#architecture-overview)
- [Key Features](#key-features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Run it](#run-it)
  - [Configuration & Docker Secrets](#configuration--docker-secrets)
  - [Docker & Socket Proxy Deployment](#docker--socket-proxy-deployment)
- [API Reference](#api-reference)
  - [Health & readiness](#health--readiness)
  - [Authentication](#authentication)
  - [Route Catalogue](#route-catalogue)
- [Testing](#testing)

---

## Architecture overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Socket / Proxy                    │
│            (ghcr.io/wollomatic/socket-proxy:1)              │
└──────────────────────────────┬──────────────────────────────┘
                               │ GET /containers/json, /networks
                               ▼
                     ┌─────────────────────────┐
                     │ simply_fw_rules_manager │
                     │  - Docker Discovery     │
                     │  - 3-Stage Validator    │
                     │  - In-Place Generator   │
                     └──────┬────────────┬─────┘
                            │            │
      In-place file updates │            │ Signed CANONICAL_V1 HMAC
  (/etc/firewall/firewall.*)│            │ (firewall-reload, docker-update)
                            ▼            ▼
               ┌────────────────┐   ┌──────────────────────┐
               │ Linux Firewall │   │ simply_hook_executor │
               │  - iptables    │   │  (executes reload)   │
               │  - ipset       │   └──────────────────────┘
               └────────────────┘
```

---

## Key Features

1. **Separated System Constants & Editable Configuration (`firewall.settings`)**
   - Immutable binary paths, `IPSLIST*` set names, and `CHAIN*` Netfilter chain names live safely in `firewall.tools`.
   - Editable network interfaces (`mainInter`, `INTEROut`, `interfaceToGoOutSide`, `internInterfaceHaveAccessAsLocal`, `interfaceLocal`, `interfaceWithDHCP`, `interfaceWithNoRules`), Docker networks, inter-container rules (`dockerAccessBetweenThem`), trusted IPs (`IPAutor*`), zone rules (`internal`, `local`, `open`, `WW`), and GeoIP country filters are stored in the database and managed via the WebUI.
2. **Real-Time Docker Discovery & Dynamic Active/Inactive Filtering**
   - Connects to the local Docker Unix socket (`unix:///var/run/docker.sock`) or a TCP/HTTP proxy (`ghcr.io/wollomatic/socket-proxy:1` on `http://...:2375`).
   - Displays live `RUNNING` / `STOPPED` status badges on every container rule.
   - Rules for stopped containers are safely preserved in the database, while file generation dynamically writes only rules for `running` containers into `firewall.settings`.
3. **Embedded Bash Editor & 3-Stage Integrity Verification (`firewall.rules.special`)**
   - Syntax-highlighted Bash editor with a live reference sidebar of helper functions parsed from `firewall.tools`.
   - Enforces a 3-stage validation pipeline before saving or generating:
     1. `bash -n` syntax verification.
     2. `shellcheck` static analysis.
     3. Strict `$CHAIN*` / `$IPS*` variable resolution against `firewall.tools`, `firewall.settings`, and script-local declarations.
4. **Simplified Blocklist Feed Pipeline (`firewall.get.list`)**
   - Manages `(URL, list_name)` pairs emitted as `generate_list "<URL>" "<name>" &` (natively consuming raw feeds from `simply_ip_exporter`) with built-in live URL reachability testing.
5. **Safe In-Place File Generation**
   - Generates bundle files directly using `OpenOptions::new().write(true).create(true).truncate(true)` without temporary file renaming, avoiding `EBUSY` errors on Docker bind mounts.
6. **Direct `simply_hook_executor` Integration**
   - One-click actions signed with `CANONICAL_V1` HMAC-SHA256: **"Générer les fichiers"**, **"Recharger le Firewall"**, **"Générer et appliquer immédiatement"**, and **"Mettre à jour les conteneurs"**.
7. **Comprehensive Audit Log**
   - Every mutating action, file generation, and deployment trigger is recorded in an immutable audit log.

---

## Getting Started

### Prerequisites

- A recent stable Rust toolchain (edition 2024 / 1.85+).
- No database server to install — SQLite is used out of the box.

### Run it

```bash
cargo run
```

On first boot, `simply_fw_rules_manager`:

1. Connects to the database (creating the SQLite file if needed) and runs all pending SeaORM migrations automatically.
2. Imports initial firewall configurations from disk or falls back to synthetic embedded fixtures (`fixtures/default_firewall/`) if no existing files are found.
3. Checks whether any API key with master rights exists. If none exists, it generates one and prints it **once**, to stdout, in a boxed banner:

   ```
   ╔══════════════════════════════════════════════════════════════════════════════════╗
   ║ BOOTSTRAP: Master API Key Generated                                              ║
   ╠══════════════════════════════════════════════════════════════════════════════════╣
   ║ X-API-Key      : <64 hex characters>                                             ║
   ║ Signing secret : <64 hex characters>                                             ║
   ║ Bound IPs      : 0.0.0.0/0,::/0                                                  ║
   ║                                                                                  ║
   ║ Both values are needed to sign requests (X-Timestamp + X-Signature-256).         ║
   ║ They will NOT be shown again — store them securely!                              ║
   ╚══════════════════════════════════════════════════════════════════════════════════╝
   ```

   Copy **both** values immediately. Only the key's SHA-256 hash is stored, and the signing secret is stored encrypted (via `FW_ENCRYPTION_KEY` or `SYNC_ENCRYPTION_KEY`) and never echoed back.
4. Starts listening on `0.0.0.0:3000` and serves the dashboard from `static/` at `/`.

Open `http://localhost:3000` and paste **both** the key and the signing secret into the login screen.

> **Note:** The dashboard prefers the browser's native Web Crypto API (HTTPS or `http://localhost`). Over plain HTTP to a LAN address, it transparently falls back to a built-in pure-JS HMAC-SHA256 implementation.
>
> **Behind a reverse proxy:** If your reverse proxy forwards an unstripped prefix (e.g. `/firewall/api`), set the login screen's **API Base Path Override** accordingly to ensure signature paths match.

---

### Configuration & Docker Secrets

All configuration supports **Docker Secrets** with the following precedence order:
1. `<VAR>_FILE` (e.g. `FW_ENCRYPTION_KEY_FILE=/run/secrets/fw_encryption_key`)
2. `/run/secrets/<lowercase_var>` (e.g. `/run/secrets/fw_encryption_key`)
3. `<VAR>` (direct environment variable for zero-config setups and retrocompatibility)

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `DATABASE_URL` | `sqlite://data/simply_fw_rules_manager.db?mode=rwc` | SeaORM connection string (supports SQLite, Postgres, MySQL). |
| `BIND_HOST` / `HOST` | `0.0.0.0` | Address to bind. |
| `PORT` | `3000` | Port to bind. |
| `FW_ENCRYPTION_KEY` | *(unset)* | **Exactly 64 hex characters** (32 bytes) — generate with `openssl rand -hex 32`. Encrypts signing secrets at rest with **XChaCha20-Poly1305**. Unset stores secrets in plaintext (warned at boot). |
| `SYNC_ENCRYPTION_KEY` | *(unset)* | Accepted alias for `FW_ENCRYPTION_KEY` for suite-wide provisioning compatibility. |
| `FW_OUTPUT_DIR` | `/etc/firewall` | Target directory where `firewall.settings`, `firewall.rules.special`, and `firewall.get.list` are written. |
| `FW_IMPORT_DIR` | `example/MainServ/etc_firewall` | Directory from which initial settings and scripts are imported on first boot (falls back to embedded reference fixtures). |
| `FW_TOOLS_PATH` | `scripts_etc/firewall.tools` | Path to `firewall.tools` for parsing utility functions and known Netfilter variables. |
| `DOCKER_ENDPOINT` | `unix:///var/run/docker.sock` | Docker API endpoint. Can point to a Unix socket or a TCP endpoint (e.g. `http://socket_proxy:2375`). |
| `HOOK_EXECUTOR_URL` | *(unset)* | Base URL of `simply_hook_executor` (e.g. `http://simply_hook_executor:3000`). |
| `HOOK_EXECUTOR_API_KEY` | *(unset)* | API key used to authenticate against `simply_hook_executor`. |
| `HOOK_EXECUTOR_SIGNING_SECRET` | *(unset)* | HMAC signing secret used for calls to `simply_hook_executor`. |
| `TRUSTED_PROXIES` | *(empty)* | Comma-separated CIDRs and/or hostnames permitted to supply `X-Forwarded-For` / `X-Real-IP`. |
| `INITIAL_MASTER_KEY` | *(unset)* | Deterministic bootstrap master key (64 hex characters), for test/CI only. |
| `INITIAL_MASTER_SIGNING_SECRET` | *(unset)* | The bootstrap key's HMAC signing secret (64 hex characters), for test/CI only. |
| `RUST_LOG` | `info` | Standard `tracing-subscriber` env filter (e.g. `info`, `simply_fw_rules_manager=debug`). |

---

### Docker & Socket Proxy Deployment

To protect the host Docker daemon, `simply_fw_rules_manager` should communicate with Docker via a read-only socket proxy rather than mounting the raw Unix socket directly.

Example `docker-compose.yml`:

```yaml
services:
  socket_proxy:
    image: ghcr.io/wollomatic/socket-proxy:1
    container_name: simply_socket_proxy
    restart: unless-stopped
    read_only: true
    user: "65534:65534"
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - LOG_LEVEL=warn
      - CONTAINERS=1
      - NETWORKS=1
      - POST=0
      - DELETE=0
      - EXEC=0
      - BUILD=0
    networks:
      - isolate

  simply_fw_rules_manager:
    image: ghcr.io/studyfranco/simply_fw_rules_manager:latest
    container_name: simply_fw_rules_manager
    restart: unless-stopped
    user: "1128:root"
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=64m
    depends_on:
      - socket_proxy
    secrets:
      - fw_encryption_key
    volumes:
      - ./data:/app/data
      - /etc/firewall/firewall.settings:/etc/firewall/firewall.settings:rw
      - /etc/firewall/firewall.rules.special:/etc/firewall/firewall.rules.special:rw
      - /etc/firewall/firewall.get.list:/etc/firewall/firewall.get.list:rw
      - /etc/firewall/firewall.tools:/etc/firewall/firewall.tools:ro
    environment:
      - DATABASE_URL=sqlite://data/simply_fw_rules_manager.db?mode=rwc
      - DOCKER_ENDPOINT=http://socket_proxy:2375
      - FW_OUTPUT_DIR=/etc/firewall
      - FW_TOOLS_PATH=/etc/firewall/firewall.tools
      - HOOK_EXECUTOR_URL=http://simply_hook_executor:3000
    networks:
      - isolate
    ports:
      - "127.0.0.1:3000:3000"

secrets:
  fw_encryption_key:
    file: /etc/firewall/secrets/fw_encryption_key

networks:
  isolate:
    name: isolate
    driver: bridge
```

---

## API Reference

### Health & readiness

Two unauthenticated endpoints are provided for orchestrators, load balancers, and container health probes:

| Route | Meaning |
| :--- | :--- |
| `GET /health` (`/healthz`) | **Liveness.** Answers `200 OK` (`{"status":"ok"}`) as long as the HTTP listener is operational. |
| `GET /ready` (`/readyz`) | **Readiness.** Answers `200 OK` (`{"status":"ready"}`) only when the database responds and migrations are active. |

---

### Authentication

All endpoints under `/api/*` require canonical request signing:

- `X-API-Key`: 64-character hex API key identifier.
- `X-Timestamp`: Current UTC Unix epoch timestamp in seconds (request window is $\pm 300\text{ s}$).
- `X-Signature-256`: Hexadecimal HMAC-SHA256 signature computed over:
  ```text
  <METHOD>\n<URI_PATH_AND_QUERY>\n<TIMESTAMP>\n<RAW_BODY_BYTES>
  ```

---

### Route Catalogue

For full payload contracts and error models, see [`API_REFERENCE.md`](API_REFERENCE.md) and [`RBAC_MODEL.md`](RBAC_MODEL.md).

| Category | Method & Path | Scope Required | Description |
| :--- | :--- | :--- | :--- |
| **Settings** | `GET /api/firewall/settings` | `can_manage_settings` | Get current parsed firewall settings. |
| | `PUT /api/firewall/settings` | `can_manage_settings` | Update firewall interfaces, networks, and general parameters. |
| **Zone Rules** | `GET /api/firewall/zones` | `can_manage_settings` | List all zone rules (`internal`, `local`, `open`, `ww`, `ip_autor`). |
| | `POST /api/firewall/zones` | `can_manage_settings` | Add a new zone rule. |
| | `DELETE /api/firewall/zones/{id}` | `can_manage_settings` | Remove a zone rule. |
| **Inter-Docker Rules** | `GET /api/firewall/docker-rules` | `can_manage_settings` | List inter-container flow rules (`dockerAccessBetweenThem`). |
| | `POST /api/firewall/docker-rules` | `can_manage_settings` | Create an inter-container rule. |
| | `DELETE /api/firewall/docker-rules/{id}` | `can_manage_settings` | Remove an inter-container rule. |
| **Special Rules** | `GET /api/firewall/special-rules` | `can_manage_special_rules` | Get script content, parsed tools functions, and validation status. |
| | `PUT /api/firewall/special-rules` | `can_manage_special_rules` | Save script content after 3-stage validation. |
| | `POST /api/firewall/special-rules/validate`| `can_manage_special_rules` | Dry-run script validation without saving. |
| **Blocklists** | `GET /api/firewall/blocklists` | `can_manage_blocklists` | List external blocklist feed subscriptions. |
| | `POST /api/firewall/blocklists` | `can_manage_blocklists` | Add a new blocklist feed. |
| | `POST /api/firewall/blocklists/{id}/test` | `can_manage_blocklists` | Test feed reachability and count valid IPs/CIDRs. |
| | `DELETE /api/firewall/blocklists/{id}` | `can_manage_blocklists` | Delete a blocklist feed. |
| **Docker Discovery** | `GET /api/firewall/docker/containers` | `can_manage_settings` | Snapshot of discovered containers with live status badges. |
| **Deployment** | `POST /api/firewall/generate` | `can_deploy_and_reload` | Generate files bundle to disk in-place. |
| | `POST /api/firewall/reload` | `can_deploy_and_reload` | Trigger firewall reload hook on `simply_hook_executor`. |
| | `POST /api/firewall/generate-and-reload` | `can_deploy_and_reload` | Atomically generate files bundle and trigger reload hook. |
| | `POST /api/firewall/docker-update` | `can_deploy_and_reload` | Trigger Docker container update hook. |
| **API Keys** | `GET /api/keys` | `can_manage_keys` | List accessible API keys. |
| | `POST /api/keys` | `can_manage_keys` | Mint a new scoped daughter key. |
| | `PUT /api/keys/{id}` | `can_manage_keys` | Update key permissions or IP CIDR bounds. |
| | `DELETE /api/keys/{id}` | `can_manage_keys` | Revoke an API key. |
| **Audit Logs** | `GET /api/audit-logs` | `is_master` | Query paginated audit events with filters. |

---

## Testing

Run the full automated test suite (including unit tests, API integration tests, benchmarks, and hygiene verification):

```bash
cargo test --all-targets
```
