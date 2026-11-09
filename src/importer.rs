//! Importer for existing `/etc/firewall/` configuration files (`firewall.settings`,
//! `firewall.rules.special`, `firewall.get.list`).
//!
//! Automatically seeds the database on first startup if `fw_settings` does not exist yet,
//! and can also be invoked via `POST /api/firewall/import`.

use std::collections::BTreeMap;
use std::path::Path;

use chrono::Utc;
use regex::Regex;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, Set};
use uuid::Uuid;

use crate::entities::{
    fw_blocklist, fw_docker_inter_rule, fw_settings, fw_special_rules, fw_zone_rule,
};

/// Summary of an import operation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ImportSummary {
    /// Directory imported from.
    pub source_dir: String,
    /// Number of Docker inter-container rules imported.
    pub docker_inter_rules_imported: usize,
    /// Number of zone rules imported.
    pub zone_rules_imported: usize,
    /// Number of blocklist feeds imported.
    pub blocklists_imported: usize,
    /// Whether `firewall.rules.special` was imported and refactored.
    pub special_rules_imported: bool,
}

/// Seeds the database from `default_example_dir` if `fw_settings` (id=1) is not yet present.
///
/// # Errors
/// Returns [`sea_orm::DbErr`] if database operations fail.
pub async fn seed_if_empty(
    db: &DatabaseConnection,
) -> Result<Option<ImportSummary>, sea_orm::DbErr> {
    if fw_settings::Entity::find_by_id(1).one(db).await?.is_some() {
        return Ok(None);
    }

    let example_dir = std::env::var("FW_IMPORT_DIR")
        .unwrap_or_else(|_| "example/MainServ/etc_firewall".to_owned());
    let summary = import_from_directory(db, Path::new(&example_dir), true).await?;
    Ok(Some(summary))
}

/// Parses `firewall.settings`, `firewall.rules.special`, and `firewall.get.list` from `dir`
/// and populates the database tables.
///
/// # Errors
/// Returns [`sea_orm::DbErr`] if database persistence fails.
pub async fn import_from_directory(
    db: &DatabaseConnection,
    dir: &Path,
    replace_existing: bool,
) -> Result<ImportSummary, sea_orm::DbErr> {
    let settings_path = dir.join("firewall.settings");
    let special_path = dir.join("firewall.rules.special");
    let get_list_path = dir.join("firewall.get.list");

    let settings_raw = std::fs::read_to_string(&settings_path).unwrap_or_default();
    let special_raw = std::fs::read_to_string(&special_path).unwrap_or_default();
    let get_list_raw = std::fs::read_to_string(&get_list_path).unwrap_or_default();

    let parsed = parse_firewall_settings(&settings_raw);

    if replace_existing {
        fw_docker_inter_rule::Entity::delete_many().exec(db).await?;
        fw_zone_rule::Entity::delete_many().exec(db).await?;
        fw_blocklist::Entity::delete_many().exec(db).await?;
    }

    let now = Utc::now();
    let output_dir = std::env::var("FW_OUTPUT_DIR").unwrap_or_else(|_| "/etc/firewall".to_owned());
    let tools_path =
        std::env::var("FW_TOOLS_PATH").unwrap_or_else(|_| "scripts_etc/firewall.tools".to_owned());
    let docker_endpoint = std::env::var("DOCKER_ENDPOINT")
        .unwrap_or_else(|_| "unix:///var/run/docker.sock".to_owned());

    let settings_model = fw_settings::ActiveModel {
        id: Set(1),
        main_inter: Set(parsed.main_inter),
        inter_out_json: Set(serde_json::to_string(&parsed.inter_out).unwrap_or_default()),
        interface_to_go_outside_json: Set(
            serde_json::to_string(&parsed.interface_to_go_outside).unwrap_or_default()
        ),
        intern_interface_have_access_as_local_json: Set(serde_json::to_string(
            &parsed.intern_interface_have_access_as_local,
        )
        .unwrap_or_default()),
        interface_local_json: Set(
            serde_json::to_string(&parsed.interface_local).unwrap_or_default()
        ),
        interface_with_dhcp_json: Set(
            serde_json::to_string(&parsed.interface_with_dhcp).unwrap_or_default()
        ),
        interface_with_no_rules_json: Set(
            serde_json::to_string(&parsed.interface_with_no_rules).unwrap_or_default()
        ),
        docker_network_with_internet_access_json: Set(serde_json::to_string(
            &parsed.docker_network_with_internet_access,
        )
        .unwrap_or_default()),
        docker_network_with_access_json: Set(serde_json::to_string(
            &parsed.docker_network_with_access,
        )
        .unwrap_or_default()),
        ip_autor_json: Set(serde_json::to_string(&parsed.ip_autor).unwrap_or_default()),
        ip_autor_dnat_port_tcp_json: Set(
            serde_json::to_string(&parsed.ip_autor_dnat_port_tcp).unwrap_or_default()
        ),
        ip_autor_dnat_port_udp_json: Set(
            serde_json::to_string(&parsed.ip_autor_dnat_port_udp).unwrap_or_default()
        ),
        country_open_port: Set(parsed.country_open_port),
        blocked_country: Set(parsed.blocked_country),
        blocked_country_2: Set(parsed.blocked_country_2),
        docker_endpoint: Set(docker_endpoint),
        output_dir: Set(output_dir),
        tools_script_path: Set(tools_path),
        hook_executor_url: Set(std::env::var("HOOK_EXECUTOR_URL").ok()),
        hook_executor_api_key: Set(std::env::var("HOOK_EXECUTOR_API_KEY").ok()),
        hook_executor_signing_secret: Set(None),
        hook_reload_name: Set("firewall-reload".to_owned()),
        hook_update_containers_name: Set("docker-update-containers".to_owned()),
        updated_at: Set(now),
    };

    if fw_settings::Entity::find_by_id(1).one(db).await?.is_some() {
        settings_model.update(db).await?;
    } else {
        settings_model.insert(db).await?;
    }

    let mut docker_inter_count = 0usize;
    for (idx, entry) in parsed.docker_access_between_them.iter().enumerate() {
        let parts: Vec<&str> = entry.split(';').collect();
        if parts.len() >= 5 {
            let ports = parts[4..].join(";");
            let row = fw_docker_inter_rule::ActiveModel {
                id: Set(Uuid::new_v4()),
                source_container: Set(parts[0].trim().to_owned()),
                destination_container: Set(parts[1].trim().to_owned()),
                network_name: Set(parts[2].trim().to_owned()),
                proto: Set(parts[3].trim().to_owned()),
                ports: Set(ports),
                enabled: Set(true),
                comment: Set(None),
                sort_order: Set(i32::try_from(idx).unwrap_or(0)),
                created_at: Set(now),
                updated_at: Set(now),
            };
            row.insert(db).await?;
            docker_inter_count += 1;
        }
    }

    let mut zone_count = 0usize;
    for (idx, (zone, rule_kind, val)) in parsed.zone_rules.into_iter().enumerate() {
        let container_name = if rule_kind == "DockerTCP" || rule_kind == "DockerUDP" {
            val.split(',').nth(2).map(|s| s.trim().to_owned())
        } else {
            None
        };
        let row = fw_zone_rule::ActiveModel {
            id: Set(Uuid::new_v4()),
            zone: Set(zone),
            rule_kind: Set(rule_kind),
            value: Set(val),
            container_name: Set(container_name),
            enabled: Set(true),
            comment: Set(None),
            sort_order: Set(i32::try_from(idx).unwrap_or(0)),
            created_at: Set(now),
            updated_at: Set(now),
        };
        row.insert(db).await?;
        zone_count += 1;
    }

    let refactored_special = refactor_special_rules_script(&special_raw);
    let special_model = fw_special_rules::ActiveModel {
        id: Set(1),
        script_content: Set(refactored_special),
        last_validation_ok: Set(true),
        last_validation_json: Set(None),
        updated_at: Set(now),
    };
    if fw_special_rules::Entity::find_by_id(1)
        .one(db)
        .await?
        .is_some()
    {
        special_model.update(db).await?;
    } else {
        special_model.insert(db).await?;
    }

    let blocklists = parse_get_list_feeds(&get_list_raw);
    let mut bl_count = 0usize;
    for (idx, (name, url, enabled)) in blocklists.into_iter().enumerate() {
        let row = fw_blocklist::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set(name),
            url: Set(url),
            enabled: Set(enabled),
            description: Set(None),
            last_test_ok: Set(None),
            last_test_entries: Set(None),
            last_test_at: Set(None),
            sort_order: Set(i32::try_from(idx).unwrap_or(0)),
            created_at: Set(now),
            updated_at: Set(now),
        };
        row.insert(db).await?;
        bl_count += 1;
    }

    Ok(ImportSummary {
        source_dir: dir.display().to_string(),
        docker_inter_rules_imported: docker_inter_count,
        zone_rules_imported: zone_count,
        blocklists_imported: bl_count,
        special_rules_imported: !special_raw.is_empty(),
    })
}

/// Parsed representation of `firewall.settings`.
#[derive(Debug, Default)]
pub struct ParsedFirewallSettings {
    pub main_inter: String,
    pub inter_out: Vec<String>,
    pub interface_to_go_outside: Vec<String>,
    pub intern_interface_have_access_as_local: Vec<String>,
    pub interface_local: Vec<String>,
    pub interface_with_dhcp: BTreeMap<String, bool>,
    pub interface_with_no_rules: Vec<String>,
    pub docker_network_with_internet_access: Vec<String>,
    pub docker_network_with_access: Vec<String>,
    pub docker_access_between_them: Vec<String>,
    pub ip_autor: Vec<String>,
    pub ip_autor_dnat_port_tcp: Vec<String>,
    pub ip_autor_dnat_port_udp: Vec<String>,
    pub country_open_port: String,
    pub blocked_country: String,
    pub blocked_country_2: String,
    /// `(zone, rule_kind, value)` tuples.
    pub zone_rules: Vec<(String, String, String)>,
}

fn extract_quoted_items(raw: &str) -> Vec<String> {
    let Ok(re) = Regex::new(r#""([^"]*)""#) else {
        return Vec::new();
    };
    re.captures_iter(raw)
        .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_owned()))
        .collect()
}

/// Parses a `firewall.settings` file into structured domain settings.
#[must_use]
pub fn parse_firewall_settings(content: &str) -> ParsedFirewallSettings {
    let mut out = ParsedFirewallSettings {
        main_inter: "out".to_owned(),
        country_open_port: "FR,CH".to_owned(),
        ..Default::default()
    };

    let assoc_re = Regex::new(r#"\["([^"]+)"\]=(\d+)"#).ok();

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Strip inline comment after closing parenthesis or quote
        let code_part = line.split(" #").next().unwrap_or(line).trim();

        if let Some(rest) = code_part.strip_prefix("mainInter=") {
            out.main_inter = rest.trim_matches('"').to_owned();
        } else if code_part.contains("INTEROut=(") {
            out.inter_out = extract_quoted_items(code_part);
        } else if code_part.contains("interfaceToGoOutSide=(") {
            out.interface_to_go_outside = extract_quoted_items(code_part);
        } else if code_part.contains("internInterfaceHaveAccessAsLocal=(") {
            out.intern_interface_have_access_as_local = extract_quoted_items(code_part);
        } else if code_part.contains("interfaceLocal=(") {
            out.interface_local = extract_quoted_items(code_part);
        } else if code_part.contains("interfaceWithDHCP=(") {
            if let Some(re) = &assoc_re {
                for cap in re.captures_iter(code_part) {
                    if let (Some(k), Some(v)) = (cap.get(1), cap.get(2)) {
                        out.interface_with_dhcp
                            .insert(k.as_str().to_owned(), v.as_str() == "1");
                    }
                }
            }
        } else if code_part.contains("interfaceWithNoRules=(") {
            out.interface_with_no_rules = extract_quoted_items(code_part);
        } else if code_part.contains("dockerNetworkWithInternetAccess=(") {
            out.docker_network_with_internet_access = extract_quoted_items(code_part);
        } else if code_part.contains("dockerNetworkWithAccess=(") {
            out.docker_network_with_access = extract_quoted_items(code_part);
        } else if code_part.contains("dockerAccessBetweenThem=(") {
            out.docker_access_between_them = extract_quoted_items(code_part);
        } else if code_part.contains("IPAutor=(") {
            out.ip_autor = extract_quoted_items(code_part);
        } else if code_part.contains("IPAutorDnatPortTCP=(") {
            out.ip_autor_dnat_port_tcp = extract_quoted_items(code_part);
        } else if code_part.contains("IPAutorDnatPortUDP=(") {
            out.ip_autor_dnat_port_udp = extract_quoted_items(code_part);
        } else if code_part.contains("countryOpenPort=") {
            if let Some(first) = extract_quoted_items(code_part).into_iter().next() {
                out.country_open_port = first;
            }
        } else if code_part.contains("blockedCountry=") {
            if let Some(first) = extract_quoted_items(code_part).into_iter().next() {
                out.blocked_country = first;
            }
        } else if code_part.contains("blockedCountry2=") {
            if let Some(first) = extract_quoted_items(code_part).into_iter().next() {
                out.blocked_country_2 = first;
            }
        } else {
            let zone_mappings = [
                ("IPAutorDockerTCP=(", "ip_autor", "DockerTCP"),
                ("IPAutorDockerUDP=(", "ip_autor", "DockerUDP"),
                ("internalOpenPortsTCP=(", "internal", "OpenPortsTCP"),
                ("internalOpenPortsUDP=(", "internal", "OpenPortsUDP"),
                ("internalRedirectPortTCP=(", "internal", "RedirectPortTCP"),
                ("internalRedirectPortUDP=(", "internal", "RedirectPortUDP"),
                ("internalDnatPortTCP=(", "internal", "DnatPortTCP"),
                ("internalDnatPortUDP=(", "internal", "DnatPortUDP"),
                ("internalDockerTCP=(", "internal", "DockerTCP"),
                ("internalDockerUDP=(", "internal", "DockerUDP"),
                ("localOpenPortsTCP=(", "local", "OpenPortsTCP"),
                ("localOpenPortsUDP=(", "local", "OpenPortsUDP"),
                ("localRedirectPortTCP=(", "local", "RedirectPortTCP"),
                ("localRedirectPortUDP=(", "local", "RedirectPortUDP"),
                ("localDnatPortTCP=(", "local", "DnatPortTCP"),
                ("localDnatPortUDP=(", "local", "DnatPortUDP"),
                ("localDockerTCP=(", "local", "DockerTCP"),
                ("localDockerUDP=(", "local", "DockerUDP"),
                ("WWopenPortTCP=(", "ww", "OpenPortsTCP"),
                ("WWopenPortUDP=(", "ww", "OpenPortsUDP"),
                ("WWredirectPortTCP=(", "ww", "RedirectPortTCP"),
                ("WWredirectPortUDP=(", "ww", "RedirectPortUDP"),
                ("WWdnatPortTCP=(", "ww", "DnatPortTCP"),
                ("WWdnatPortUDP=(", "ww", "DnatPortUDP"),
                ("WWDockerTCP=(", "ww", "DockerTCP"),
                ("WWDockerUDP=(", "ww", "DockerUDP"),
                ("openPortTCP=(", "open", "OpenPortsTCP"),
                ("openPortUDP=(", "open", "OpenPortsUDP"),
                ("redirectPortTCP=(", "open", "RedirectPortTCP"),
                ("redirectPortUDP=(", "open", "RedirectPortUDP"),
                ("dnatPortTCP=(", "open", "DnatPortTCP"),
                ("dnatPortUDP=(", "open", "DnatPortUDP"),
                ("openDockerTCP=(", "open", "DockerTCP"),
                ("openDockerUDP=(", "open", "DockerUDP"),
            ];
            for (prefix, zone, kind) in zone_mappings {
                if code_part.contains(prefix) {
                    for val in extract_quoted_items(code_part) {
                        out.zone_rules.push((zone.to_owned(), kind.to_owned(), val));
                    }
                    break;
                }
            }
        }
    }

    out
}

/// Refactors `firewall.rules.special` to replace manual `docker container inspect` calls
/// in `add_cloud`, `add_plex`, and `add_pihole` with the generic helper functions from
/// `firewall.tools` (`get_container_ipv4_on_network` and `get_container_ipv6_on_network`).
#[must_use]
pub fn refactor_special_rules_script(raw: &str) -> String {
    if raw.trim().is_empty() {
        return "#! /bin/bash\n\nsource /etc/firewall/firewall.tools\nsource /etc/firewall/firewall.settings\n\nwait\nexit 0\n".to_owned();
    }
    let mut out = raw.to_owned();
    out = out.replace(
        r#"$(${DOCKER} container inspect -f "{{ .NetworkSettings.Networks.ext.IPAddress }}" traefik)"#,
        r#"$(get_container_ipv4_on_network "traefik" "ext")"#,
    );
    out = out.replace(
        r#"$(${DOCKER} container inspect -f "{{ .NetworkSettings.Networks.ext.IPAddress }}" plexmediaserver)"#,
        r#"$(get_container_ipv4_on_network "plexmediaserver" "ext")"#,
    );
    out = out.replace(
        r#"$(${DOCKER} container inspect -f "{{ .NetworkSettings.Networks.ext.GlobalIPv6Address }}" plexmediaserver)"#,
        r#"$(get_container_ipv6_on_network "plexmediaserver" "ext")"#,
    );
    out = out.replace(
        r#"$(${DOCKER} container inspect -f "{{ .NetworkSettings.Networks.pihole.IPAddress }}" pihole)"#,
        r#"$(get_container_ipv4_on_network "pihole" "pihole")"#,
    );
    out
}

/// Extracts `(name, url, enabled)` tuples from `firewall.get.list`, ignoring the legacy
/// `AbuseIPDB` `curl`/`jq` block.
#[must_use]
pub fn parse_get_list_feeds(raw: &str) -> Vec<(String, String, bool)> {
    let mut feeds = Vec::new();
    let Ok(re) = Regex::new(r#"^(#?)\s*generate_list\s+"([^"]+)"\s+"([^"]+)""#) else {
        return feeds;
    };
    for line in raw.lines() {
        let trimmed = line.trim();
        if let Some(cap) = re.captures(trimmed) {
            let commented = cap.get(1).is_some_and(|m| m.as_str() == "#");
            let url = cap.get(2).map_or("", |m| m.as_str()).trim().to_owned();
            let name = cap.get(3).map_or("", |m| m.as_str()).trim().to_owned();
            if !url.is_empty() && !name.is_empty() {
                feeds.push((name, url, !commented));
            }
        }
    }
    feeds
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_quoted_items_extracts_all_double_quoted_strings() {
        let input = r#"INTEROut=("eth0" "eth1" "wg0")"#;
        assert_eq!(extract_quoted_items(input), vec!["eth0", "eth1", "wg0"]);

        let empty = r#"INTEROut=()"#;
        assert!(extract_quoted_items(empty).is_empty());
    }

    #[test]
    fn parse_get_list_feeds_parses_active_and_commented_feeds() {
        let sample = r#"
# Header comments
generate_list "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt" "emerging_threats"
# generate_list "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" "feodo_tracker"
# other text that is not a generate_list line
"#;
        let feeds = parse_get_list_feeds(sample);
        assert_eq!(feeds.len(), 2);
        assert_eq!(feeds[0], ("emerging_threats".to_owned(), "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt".to_owned(), true));
        assert_eq!(feeds[1], ("feodo_tracker".to_owned(), "https://feodotracker.abuse.ch/downloads/ipblocklist.txt".to_owned(), false));
    }

    #[test]
    fn refactor_special_rules_script_replaces_docker_inspect_with_tools_helpers() {
        let raw = r#"
TRAEFIK_IP=$(${DOCKER} container inspect -f "{{ .NetworkSettings.Networks.ext.IPAddress }}" traefik)
PLEX_IP=$(${DOCKER} container inspect -f "{{ .NetworkSettings.Networks.ext.IPAddress }}" plexmediaserver)
PLEX_V6=$(${DOCKER} container inspect -f "{{ .NetworkSettings.Networks.ext.GlobalIPv6Address }}" plexmediaserver)
PIHOLE_IP=$(${DOCKER} container inspect -f "{{ .NetworkSettings.Networks.pihole.IPAddress }}" pihole)
"#;
        let refactored = refactor_special_rules_script(raw);
        assert!(refactored.contains(r#"$(get_container_ipv4_on_network "traefik" "ext")"#));
        assert!(refactored.contains(r#"$(get_container_ipv4_on_network "plexmediaserver" "ext")"#));
        assert!(refactored.contains(r#"$(get_container_ipv6_on_network "plexmediaserver" "ext")"#));
        assert!(refactored.contains(r#"$(get_container_ipv4_on_network "pihole" "pihole")"#));
        assert!(!refactored.contains("container inspect"));
    }

    #[test]
    fn parse_firewall_settings_extracts_interfaces_arrays_and_dhcp_map() {
        let content = r#"
mainInter="wan0"
INTEROut=("wan0" "wan1")
interfaceWithDHCP=( ["wan0"]=1 ["lan0"]=0 )
blockedCountry="CN,RU"
"#;
        let parsed = parse_firewall_settings(content);
        assert_eq!(parsed.main_inter, "wan0");
        assert_eq!(parsed.inter_out, vec!["wan0", "wan1"]);
        assert_eq!(parsed.interface_with_dhcp.get("wan0"), Some(&true));
        assert_eq!(parsed.interface_with_dhcp.get("lan0"), Some(&false));
        assert_eq!(parsed.blocked_country, "CN,RU");
    }

    #[test]
    fn parse_firewall_settings_extracts_zone_rules_correctly() {
        let content = r#"
openPortTCP=("80" "443" "8080")
WWopenPortUDP=("53" "123")
"#;
        let parsed = parse_firewall_settings(content);
        assert_eq!(parsed.zone_rules.len(), 5);
        assert!(parsed.zone_rules.contains(&("open".to_owned(), "OpenPortsTCP".to_owned(), "80".to_owned())));
        assert!(parsed.zone_rules.contains(&("open".to_owned(), "OpenPortsTCP".to_owned(), "443".to_owned())));
        assert!(parsed.zone_rules.contains(&("open".to_owned(), "OpenPortsTCP".to_owned(), "8080".to_owned())));
        assert!(parsed.zone_rules.contains(&("ww".to_owned(), "OpenPortsUDP".to_owned(), "53".to_owned())));
        assert!(parsed.zone_rules.contains(&("ww".to_owned(), "OpenPortsUDP".to_owned(), "123".to_owned())));
    }
}
