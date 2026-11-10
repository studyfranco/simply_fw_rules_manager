# Database Schema (`simply_fw_rules_manager`)

Every table in `simply_fw_rules_manager` is managed via SeaORM 2.0 SQL-agnostic migrations (`src/migration/`) and supports **SQLite**, **PostgreSQL**, and **MySQL / MariaDB** without raw SQL in runtime DML.

---

## 1. Core Security & Audit Tables

### `api_keys`
| Column | Type | Nullable | Description |
|---|---|---|---|
| `id` | `UUID` (PK) | No | Unique identifier |
| `name` | `String` | No | Human-readable account/key name |
| `key_hash` | `String` (Unique) | No | Unsalted SHA-256 hex digest of the bearer API key |
| `signing_secret` | `String` | Yes | Sealed (`enc:v1:...`) or plaintext HMAC-SHA256 signing secret |
| `prefix` | `String` | No | First 8 chars of the API key for audit identification |
| `is_master` | `Boolean` | No | Full administrative bypass flag |
| `can_manage_keys` | `Boolean` | No | Sub-key delegation flag |
| `can_manage_settings` | `Boolean` | No | Global permission to edit `firewall.settings` & zone/Docker rules |
| `can_manage_special_rules` | `Boolean` | No | Global permission to edit & validate `firewall.rules.special` |
| `can_manage_blocklists` | `Boolean` | No | Global permission to edit & test `firewall.get.list` feeds |
| `can_deploy_and_reload` | `Boolean` | No | Global permission to generate files on disk and trigger `simply_hook_executor` |
| `parent_key_id` | `UUID` (FK `api_keys.id`, `ON DELETE CASCADE`) | Yes | Delegating parent key |
| `bound_ips` | `String` | Yes | Comma-separated IP/CIDR allowlist |
| `created_at` | `DateTimeUtc` | No | Creation timestamp |
| `updated_at` | `DateTimeUtc` | No | Last update timestamp |

### `audit_logs`
| Column | Type | Nullable | Description |
|---|---|---|---|
| `id` | `UUID` (PK) | No | Unique identifier |
| `api_key_id` | `UUID` (FK `api_keys.id`, `ON DELETE SET NULL`) | Yes | Originating key ID (nullable if key deleted) |
| `api_key_name` | `String` | No | Denormalized key name at action time |
| `api_key_prefix` | `String` | No | Denormalized key prefix at action time |
| `action` | `String` | No | Action code (`CREATE_KEY`, `UPDATE_SETTINGS`, `VALIDATE_SPECIAL_RULES`, `GENERATE_FILES`, `TRIGGER_RELOAD`, etc.) |
| `target_resource` | `String` | Yes | Target identifier |
| `details` | `Text` | Yes | Structured description of changes/outcome |
| `client_ip` | `String` | No | Normalized client IP address |
| `timestamp` | `DateTimeUtc` | No | Event timestamp |

---

## 2. Firewall Configuration & Rules Tables

### `fw_settings` (Singleton row `id = 1`)
Stores the global network, GeoIP, Docker daemon, deployment path, and `simply_hook_executor` integration settings:
- `main_inter` (`String`, e.g. `"out"`)
- `inter_out_json` (`Text` JSON array of `"iface;ipv4_cidr;ipv6_cidr"`)
- `interface_to_go_outside_json` (`Text` JSON array)
- `intern_interface_have_access_as_local_json` (`Text` JSON array)
- `interface_local_json` (`Text` JSON array)
- `interface_with_dhcp_json` (`Text` JSON object mapping `"iface;v4;v6"` -> `bool`)
- `interface_with_no_rules_json` (`Text` JSON array)
- `docker_network_with_internet_access_json` (`Text` JSON array of Docker network names)
- `docker_network_with_access_json` (`Text` JSON array of Docker network names)
- `ip_autor_json` (`Text` JSON array of trusted IPv4/IPv6 addresses)
- `ip_autor_dnat_port_tcp_json` (`Text` JSON array of `"port,iface,ipv4,ipv6,dest_port"`)
- `ip_autor_dnat_port_udp_json` (`Text` JSON array)
- `country_open_port` (`String`, comma-separated ISO country codes, e.g. `"FR,CH"`)
- `blocked_country` (`String`, comma-separated ISO country codes)
- `blocked_country_2` (`String`, comma-separated ISO country codes)
- `docker_endpoint` (`String`, e.g. `"unix:///var/run/docker.sock"` or `"http://127.0.0.1:2375"`)
- `output_dir` (`String`, e.g. `"/etc/firewall"`)
- `tools_script_path` (`String`, e.g. `"/etc/firewall/firewall.tools"`)
- `hook_executor_url` (`String`, optional base URL for `simply_hook_executor`)
- `hook_executor_api_key` (`String`, optional bearer key)
- `hook_executor_signing_secret` (`String`, optional `SecretCipher`-sealed secret)
- `hook_reload_name` (`String`, default `"firewall-reload"`)
- `hook_update_containers_name` (`String`, default `"docker-update-containers"`)
- `updated_at` (`DateTimeUtc`)

### `fw_docker_inter_rules` (`dockerAccessBetweenThem`)
| Column | Type | Nullable | Description |
|---|---|---|---|
| `id` | `UUID` (PK) | No | Unique identifier |
| `source_container` | `String` | No | Source container name |
| `destination_container` | `String` | No | Target container name |
| `network_name` | `String` | No | Shared Docker network (`isolate`, `ext`, etc.) |
| `proto` | `String` | No | Protocol (`tcp` or `udp`) |
| `ports` | `String` | No | Semicolon-separated port list (`8096` or `80;443`) |
| `enabled` | `Boolean` | No | Administrative enable toggle (independent of live container state) |
| `comment` | `String` | Yes | Optional operator note |
| `sort_order` | `Integer` | No | Deterministic ordering in generated `firewall.settings` |
| `created_at` | `DateTimeUtc` | No | Creation timestamp |
| `updated_at` | `DateTimeUtc` | No | Update timestamp |

### `fw_zone_rules`
Stores host/NAT/Docker exposure rules across all zones (`ip_autor`, `internal`, `local`, `open`, `ww`):
| Column | Type | Nullable | Description |
|---|---|---|---|
| `id` | `UUID` (PK) | No | Unique identifier |
| `zone` | `String` | No | `"ip_autor"`, `"internal"`, `"local"`, `"open"`, or `"ww"` |
| `rule_kind` | `String` | No | `"OpenPortsTCP"`, `"OpenPortsUDP"`, `"RedirectPortTCP"`, `"RedirectPortUDP"`, `"DnatPortTCP"`, `"DnatPortUDP"`, `"DockerTCP"`, `"DockerUDP"` |
| `value` | `String` | No | Rule tuple (e.g. `"443"` or `"443,ext,traefik,443"`) |
| `container_name` | `String` | Yes | Extracted target container name when `rule_kind` is `DockerTCP` or `DockerUDP` |
| `enabled` | `Boolean` | No | Administrative enable toggle |
| `comment` | `String` | Yes | Optional operator note |
| `sort_order` | `Integer` | No | Deterministic ordering |
| `created_at` | `DateTimeUtc` | No | Creation timestamp |
| `updated_at` | `DateTimeUtc` | No | Update timestamp |

### `fw_special_rules` (Singleton row `id = 1`)
Stores the managed `firewall.rules.special` Bash script and its latest 3-stage validation report:
| Column | Type | Nullable | Description |
|---|---|---|---|
| `id` | `Integer` (PK) | No | Singleton ID (`1`) |
| `script_content` | `Text` | No | Full Bash content of `firewall.rules.special` |
| `last_validation_ok` | `Boolean` | No | Whether the 3-stage check passed |
| `last_validation_json` | `Text` | Yes | Detailed JSON report (`bash_n`, `shellcheck`, `undefined_variables`) |
| `updated_at` | `DateTimeUtc` | No | Last update timestamp |

### `fw_blocklists` (`firewall.get.list`)
| Column | Type | Nullable | Description |
|---|---|---|---|
| `id` | `UUID` (PK) | No | Unique identifier |
| `name` | `String` (Unique) | No | Output list identifier passed as 2nd arg to `generate_list` (e.g. `spamhaus_v4`) |
| `url` | `String` | No | HTTP/HTTPS feed URL (including `simply_ip_exporter` `/feed/v1/<token>/list.txt` URLs) |
| `enabled` | `Boolean` | No | Whether emitted in `firewall.get.list` |
| `description` | `String` | Yes | Optional note |
| `last_test_ok` | `Boolean` | Yes | Result of last live HTTP feed test |
| `last_test_entries` | `Integer` | Yes | Count of valid IPv4/IPv6/CIDR lines parsed during last test |
| `last_test_at` | `DateTimeUtc` | Yes | Timestamp of last test |
| `sort_order` | `Integer` | No | Deterministic ordering |
| `created_at` | `DateTimeUtc` | No | Creation timestamp |
| `updated_at` | `DateTimeUtc` | No | Update timestamp |

---

## 3. Database Indexing & Query Optimization Strategy

All indexes are managed across SQL-agnostic SeaORM migrations (`m20261109_000002_add_performance_indexes.rs` and `m20261110_000003_add_query_optimization_indexes.rs`) to eliminate sequential scans, avoid temporary table sorts, and maximize query execution performance:

### `api_keys`
- `idx_api_keys_single_master` / `key_hash` (Unique Index): Instant O(1) hash lookup during HMAC authentication.
- `idx_api_keys_parent_key_id` (`parent_key_id`): Foreign key traversal and cascade delete optimization.
- `idx_api_keys_prefix` (`prefix`): Prefix-based operator and audit lookups.
- `idx_api_keys_is_master` (`is_master`): Boot-time master key discovery and pinning.
- `idx_api_keys_name` (`name`): Name-based key resolution.
- `idx_api_keys_created_at` (`created_at ASC`): Fast deterministic ordering in `list_api_keys`.
- `idx_api_keys_parent_created` (`parent_key_id, created_at ASC`): Composite index optimizing daughter key RBAC filtering and sorting.

### `audit_logs`
- `idx_audit_logs_timestamp` (`timestamp DESC`): Reverse-chronological global log feeds.
- `idx_audit_logs_action_timestamp` (`action, timestamp DESC`): Filtered action queries with index order scanning.
- `idx_audit_logs_api_key_id` (`api_key_id`): Foreign key traversal on `ON DELETE SET NULL`.
- `idx_audit_logs_key_timestamp` (`api_key_id, timestamp DESC`): Non-master scoped audit feeds without filesort.
- `idx_audit_logs_client_ip_timestamp` (`client_ip, timestamp DESC`): IP-filtered log queries with index-backed descending sort.
- `idx_audit_logs_key_name` (`api_key_name`): Key name search queries.
- `idx_audit_logs_key_prefix` (`api_key_prefix`): Key prefix search queries.

### `fw_zone_rules`
- `idx_fw_zone_rules_zone` (`zone`): Security zone filtering.
- `idx_fw_zone_rules_container_name` (`container_name`): Container status correlation on Docker discovery.
- `idx_fw_zone_rules_enabled_sort` (`enabled, sort_order ASC`): Generator pipeline queries for active zone rules without sort penalty.
- `idx_fw_zone_rules_sort_order` (`sort_order ASC`): WebUI rule ordering.
- `idx_fw_zone_rules_zone_sort` (`zone, sort_order ASC`): Composite zone filtering + ordering.
- `idx_fw_zone_rules_rule_kind` (`rule_kind`): Rule kind filtering (`DockerTCP`, `DockerUDP`, `OpenPortsTCP`, etc.).

### `fw_docker_inter_rules`
- `idx_fw_docker_inter_rules_source` (`source_container`): Source container updates and lookups.
- `idx_fw_docker_inter_rules_dest` (`destination_container`): Destination container updates and lookups.
- `idx_fw_docker_inter_rules_enabled_sort` (`enabled, sort_order ASC`): Generator pipeline queries for active container rules.
- `idx_fw_docker_inter_rules_sort_order` (`sort_order ASC`): WebUI rule ordering.
- `idx_fw_docker_inter_rules_network` (`network_name`): Network isolation queries.

### `fw_blocklists`
- `name` (Unique Index): Unique feed name enforcement.
- `idx_fw_blocklists_enabled` (`enabled`): Active feed filter.
- `idx_fw_blocklists_enabled_sort` (`enabled, sort_order ASC`): Generator pipeline queries for active feeds with sorted output.
- `idx_fw_blocklists_sort_order` (`sort_order ASC`): WebUI list ordering.
