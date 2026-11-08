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
