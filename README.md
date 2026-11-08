# Simply FW Rules Manager (`simply_fw_rules_manager`)

A high-assurance, 100% autonomous Rust/Web microservice for managing Linux `iptables` / `ip6tables` / `ipset` firewall configurations, Docker container network flows, custom Netfilter scripts (`firewall.rules.special`), and external IP blocklists (`firewall.get.list`), integrated with `simply_hook_executor`, `simply_ip_exporter`, `simply_ip_sync`, and `simply_ip_vault`.

---

## Key Capabilities

1. **Separated System Constants & Editable Configuration (`firewall.settings`)**
   - Immutable binary paths, `IPSLIST*` set names, and `CHAIN*` netfilter chain names live in `firewall.tools`.
   - Editable network interfaces (`mainInter`, `INTEROut`, `interfaceToGoOutSide`, `internInterfaceHaveAccessAsLocal`, `interfaceLocal`, `interfaceWithDHCP`, `interfaceWithNoRules`), Docker networks, inter-container rules (`dockerAccessBetweenThem`), trusted IPs (`IPAutor*`), zone rules (`internal`, `local`, `open`, `WW`), and GeoIP country filters are stored in the database and managed via the WebUI.
2. **Docker Discovery & Dynamic Active/Inactive Filtering**
   - Connects to the local Docker Unix socket (`unix:///var/run/docker.sock`) or a TCP/HTTP proxy (`dockersocprox` on `http://...:2375`).
   - Displays live `RUNNING` / `STOPPED` status badges on every container rule.
   - Rules for stopped containers are preserved in the database, while file generation dynamically writes only rules for `running` containers into `firewall.settings`.
3. **Embedded Bash Editor & 3-Stage Integrity Checker (`firewall.rules.special`)**
   - Syntax-highlighted Bash editor with a live reference sidebar of helper functions parsed from `firewall.tools`.
   - Enforces a 3-stage validation pipeline before saving/generating:
     1. `bash -n` syntax verification.
     2. `shellcheck` static analysis.
     3. Strict `$CHAIN*` / `$IPS*` variable resolution against `firewall.tools`, `firewall.settings`, and script-local declarations.
4. **Simplified Blocklist Pipeline (`firewall.get.list`)**
   - Manages `(URL, list_name)` pairs emitted as `generate_list "<URL>" "<name>" &` (natively consuming `simply_ip_exporter` raw feeds) with built-in live URL validation.
5. **Atomic Deployment & `simply_hook_executor` Integration**
   - One-click **"Générer les fichiers"**, **"Recharger le Firewall"**, **"Générer et appliquer immédiatement"**, and **"Mettre à jour les conteneurs"** actions signed with `CANONICAL_V1` HMAC-SHA256.
