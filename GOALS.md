# Goals and deployment boundaries

`simply_fw_rules_manager` is the configuration and generation service for Linux firewalls and Docker network flows. It provides an authenticated API and dashboard for managing zone rules, inter-container rules, custom rule extensions, and blocklist inputs. It discovers Docker topology, generates firewall artifacts, records audited changes, and delegates reloads to the hook executor.

Its scope excludes host-level command execution, IP reputation storage, threat-feed ingestion, IP feed publication, and whitelist discovery. Those responsibilities belong to the companion services. The manager and exporter stay off the external Docker network.

## Service architecture

| Service | Responsibility | Docker networks |
| --- | --- | --- |
| `simply_fw_rules_manager` | Manages firewall policy and generates artifacts. Consumes exporter feeds and requests reloads from the hook executor. | `isolate` only |
| `simply_ip_vault` | Stores bans and allowlists and authorizes access to them. | `isolate` by default. Optional `ext` via `vault_allow_ext_network`. |
| `simply_hook_executor` | Receives authenticated hooks and runs configured host-side operations, including firewall reloads. | `isolate` by default. Optional `ext` via `hook_executor_allow_ext_network`. |
| `simply_ip_sync` | Fetches external reputation feeds and pushes records to the vault. | `isolate` and `ext` |
| `simply_ip_exporter` | Reads vault data and serves plaintext CIDR feeds for firewall consumers. | `isolate` only |
| `simply_white_list` | Discovers and synchronizes allowed addresses with the vault. | `isolate` by default. Optional `ext` via `white_list_allow_ext_network`. |

`socket_proxy` mediates Docker API access for container discovery. `fail2ban` detects abuse in service logs and can feed ban events into the vault integration. `simply_postgres` provides PostgreSQL persistence when enabled.

## Network isolation

The [Ansible inventory](ansible/inventory/group_vars/all.yml) defines `isolate` as the internal bridge (`10.123.0.0/16`) for service-to-service traffic and `ext` as the egress-capable bridge (`10.124.0.0/16`). The sync service uses `ext` for outbound feeds and `isolate` to reach the vault. Preserve the network memberships in the table when extending the deployment.

A reverse proxy can reach an opted-in backend over `ext` or forward through a host-loopback listener managed by `localDockerTCP`. Use the host-loopback route for proxy access to strictly isolated backends and keep their container memberships unchanged.

## Documentation data

Use synthetic data throughout examples, fixtures, and onboarding. Keep production hostnames, IP addresses, credentials, tokens, and customer data out of the repository. Use RFC 2606 domains such as `fw.example.test`, RFC 5737 IPv4 addresses such as `192.0.2.10`, `198.51.100.10`, and `203.0.113.10`, and IPv6 addresses from RFC 3849 (`2001:db8::/32`). The two Ansible IPv4 bridge CIDRs above may be documented as internal deployment defaults.

## Agent skill

- [Use `simply_fw_rules_manager`](.agents/skills/use-fw-rules-manager/SKILL.md): Operational cookbook for `CANONICAL_V1` API calls, `OriginalUri` signing, `isolate` network boundaries, firewall rule/feed management, and Ansible deployment.
