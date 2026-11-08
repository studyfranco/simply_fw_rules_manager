# RBAC & Authorization Model (`simply_fw_rules_manager`)

`simply_fw_rules_manager` shares the exact same unified `CANONICAL_V1` authentication and hierarchical API key delegation model as `simply_ip_vault`, `simply_ip_sync`, `simply_ip_exporter`, and `simply_hook_executor`.

---

## 1. Authentication (`CANONICAL_V1` Only)

All `/api/*` endpoints require the 4 mandatory headers:
- `Authorization: Bearer <api_key>`
- `X-Timestamp: <unix_epoch_seconds>` (within $\pm 300\text{ s}$)
- `X-Nonce: <unique_nonce>` (8–128 ASCII chars, tracked in `ReplayGuard`)
- `X-Signature: <hex_hmac_sha256>`

Canonical message:
```text
<METHOD>\n<URI_PATH_AND_QUERY>\n<TIMESTAMP>\n<NONCE>\n<RAW_BODY_BYTES>
```

---

## 2. Permission Flags on `api_keys`

| Flag | Scope |
|---|---|
| `is_master` | Full administrative bypass; seeded at startup from `MASTER_API_KEY` and `MASTER_SIGNING_SECRET`. Cannot be deleted (`403 Forbidden`), and only `bound_ips` may be edited. |
| `can_manage_keys` | Allows creating, viewing, updating, and revoking sub-keys (`parent_key_id = caller.id`). Strict subset delegation prevents granting any capability the caller does not itself possess. |
| `can_manage_settings` | Allows reading/updating `fw_settings`, `fw_zone_rules`, `fw_docker_inter_rules`, and querying live Docker containers/networks. |
| `can_manage_special_rules` | Allows editing and running the 3-stage validator on `firewall.rules.special`. |
| `can_manage_blocklists` | Allows creating, editing, deleting, and testing blocklist feeds (`firewall.get.list`). |
| `can_deploy_and_reload` | Allows generating `/etc/firewall/{firewall.settings,firewall.rules.special,firewall.get.list}` on disk and triggering `simply_hook_executor` hooks (`firewall-reload`, `docker-update-containers`). |

---

## 3. IP Binding (`bound_ips`)

Every API key may optionally specify a comma-separated list of IPv4, IPv6, or CIDR ranges in `bound_ips`. Requests originating from any client IP outside `bound_ips` are rejected in the authentication middleware with `403 Forbidden` before reaching any handler.
