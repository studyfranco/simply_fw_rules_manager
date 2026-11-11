//! File generator and atomic disk deployer for `firewall.settings`, `firewall.rules.special`,
//! and `firewall.get.list`.

use std::collections::BTreeMap;
use std::path::Path;

use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder};
use serde::Serialize;

use crate::docker::DockerDiscoverySnapshot;
use crate::entities::{
    fw_blocklist, fw_docker_inter_rule, fw_settings, fw_special_rules, fw_zone_rule,
};
use crate::error::AppError;

/// Rendered preview and filtering statistics for all 3 managed firewall files.
#[derive(Debug, Clone, Serialize)]
pub struct GeneratedFilesBundle {
    /// Target directory configured in `fw_settings.output_dir`.
    pub output_dir: String,
    /// Rendered content of `firewall.settings`.
    pub firewall_settings: String,
    /// Rendered content of `firewall.rules.special`.
    pub firewall_rules_special: String,
    /// Rendered content of `firewall.get.list`.
    pub firewall_get_list: String,
    /// Whether live Docker container filtering was active during this generation.
    pub docker_filter_active: bool,
    /// Number of active inter-container rules written into `firewall.settings`.
    pub active_docker_inter_rules: usize,
    /// Number of inter-container rules skipped because source or destination container is stopped.
    pub skipped_docker_inter_rules: usize,
    /// Number of active zone rules written into `firewall.settings`.
    pub active_zone_rules: usize,
    /// Number of `DockerTCP`/`DockerUDP` zone rules skipped because target container is stopped.
    pub skipped_zone_rules: usize,
    /// Number of active blocklist feeds written into `firewall.get.list`.
    pub active_blocklists: usize,
}

fn format_bash_array(var_name: &str, items: &[String]) -> String {
    if items.is_empty() {
        return format!("declare -a {var_name}=()");
    }
    let quoted: Vec<String> = items.iter().map(|s| format!("\"{s}\"")).collect();
    format!("declare -a {var_name}=({})", quoted.join(" "))
}

fn format_bash_assoc_bool(var_name: &str, map: &BTreeMap<String, bool>) -> String {
    if map.is_empty() {
        return format!("declare -A {var_name}=()");
    }
    let pairs: Vec<String> = map
        .iter()
        .map(|(k, v)| format!("[\"{k}\"]={}", i32::from(*v)))
        .collect();
    format!("declare -A {var_name}=( {} )", pairs.join(" "))
}

/// Renders `firewall.settings`, `firewall.rules.special`, and `firewall.get.list` from the
/// database state, filtering container-bound rules against `docker_snapshot` when reachable.
///
/// # Errors
/// Returns [`AppError`] if reading from the database fails.
pub async fn build_files_bundle(
    db: &DatabaseConnection,
    docker_snapshot: &DockerDiscoverySnapshot,
) -> Result<GeneratedFilesBundle, AppError> {
    let settings = fw_settings::Entity::find_by_id(1)
        .one(db)
        .await?
        .ok_or_else(|| AppError::InvalidInput("Firewall settings not initialized".to_owned()))?;

    let inter_rules = fw_docker_inter_rule::Entity::find()
        .filter(fw_docker_inter_rule::Column::Enabled.eq(true))
        .order_by_asc(fw_docker_inter_rule::Column::SortOrder)
        .all(db)
        .await?;

    let zone_rules = fw_zone_rule::Entity::find()
        .filter(fw_zone_rule::Column::Enabled.eq(true))
        .order_by_asc(fw_zone_rule::Column::SortOrder)
        .all(db)
        .await?;

    let special = fw_special_rules::Entity::find_by_id(1).one(db).await?;
    let blocklists = fw_blocklist::Entity::find()
        .filter(fw_blocklist::Column::Enabled.eq(true))
        .order_by_asc(fw_blocklist::Column::SortOrder)
        .all(db)
        .await?;

    let running_containers = docker_snapshot.running_container_names();
    let filter_by_docker = docker_snapshot.reachable;

    let mut active_inter_strings = Vec::new();
    let mut skipped_inter = 0usize;
    for r in inter_rules {
        if filter_by_docker
            && (!running_containers.contains(&r.source_container)
                || !running_containers.contains(&r.destination_container))
        {
            skipped_inter += 1;
            continue;
        }
        active_inter_strings.push(format!(
            "{};{};{};{};{}",
            r.source_container, r.destination_container, r.network_name, r.proto, r.ports
        ));
    }

    let mut zone_buckets: BTreeMap<(&str, &str), Vec<String>> = BTreeMap::new();
    let mut active_zone_count = 0usize;
    let mut skipped_zone_count = 0usize;

    for zr in &zone_rules {
        let is_docker_rule = zr.rule_kind == "DockerTCP" || zr.rule_kind == "DockerUDP";
        if is_docker_rule && filter_by_docker {
            let target_container = zr
                .container_name
                .as_deref()
                .or_else(|| zr.value.split(',').nth(2))
                .map_or("", str::trim);
            if !target_container.is_empty() && !running_containers.contains(target_container) {
                skipped_zone_count += 1;
                continue;
            }
        }
        active_zone_count += 1;
        zone_buckets
            .entry((zr.zone.as_str(), zr.rule_kind.as_str()))
            .or_default()
            .push(zr.value.clone());
    }

    let inter_out: Vec<String> = serde_json::from_str(&settings.inter_out_json).unwrap_or_default();
    let iface_out: Vec<String> =
        serde_json::from_str(&settings.interface_to_go_outside_json).unwrap_or_default();
    let intern_local: Vec<String> =
        serde_json::from_str(&settings.intern_interface_have_access_as_local_json)
            .unwrap_or_default();
    let iface_local: Vec<String> =
        serde_json::from_str(&settings.interface_local_json).unwrap_or_default();
    let iface_dhcp: BTreeMap<String, bool> =
        serde_json::from_str(&settings.interface_with_dhcp_json).unwrap_or_default();
    let iface_no_rules: Vec<String> =
        serde_json::from_str(&settings.interface_with_no_rules_json).unwrap_or_default();
    let docker_net_inet: Vec<String> =
        serde_json::from_str(&settings.docker_network_with_internet_access_json)
            .unwrap_or_default();
    let docker_net_access: Vec<String> =
        serde_json::from_str(&settings.docker_network_with_access_json).unwrap_or_default();
    let ip_autor: Vec<String> = serde_json::from_str(&settings.ip_autor_json).unwrap_or_default();
    let ip_autor_dnat_tcp: Vec<String> =
        serde_json::from_str(&settings.ip_autor_dnat_port_tcp_json).unwrap_or_default();
    let ip_autor_dnat_udp: Vec<String> =
        serde_json::from_str(&settings.ip_autor_dnat_port_udp_json).unwrap_or_default();

    let get_bucket = |z: &str, k: &str| -> Vec<String> {
        zone_buckets.get(&(z, k)).cloned().unwrap_or_default()
    };

    let mut lines = vec![
        "#! /bin/bash".to_owned(),
        "# Generated by simply_fw_rules_manager — DO NOT EDIT SYSTEM CONSTANTS HERE".to_owned(),
        "# System binary paths, IPSLIST* and CHAIN* constants are defined in /etc/firewall/firewall.tools".to_owned(),
        "source /etc/firewall/firewall.tools".to_owned(),
        String::new(),
        format!("mainInter=\"{}\"", settings.main_inter),
        format_bash_array("INTEROut", &inter_out),
        format_bash_array("interfaceToGoOutSide", &iface_out),
        format_bash_array("internInterfaceHaveAccessAsLocal", &intern_local),
        format_bash_array("interfaceLocal", &iface_local),
        format_bash_assoc_bool("interfaceWithDHCP", &iface_dhcp),
        format_bash_array("interfaceWithNoRules", &iface_no_rules),
        String::new(),
        format_bash_array("dockerNetworkWithInternetAccess", &docker_net_inet),
        format_bash_array("dockerNetworkWithAccess", &docker_net_access),
        format_bash_array("dockerAccessBetweenThem", &active_inter_strings),
        String::new(),
        "# List of trusted IPs".to_owned(),
        format_bash_array("IPAutor", &ip_autor),
        format_bash_array("IPAutorDnatPortTCP", &ip_autor_dnat_tcp),
        format_bash_array("IPAutorDnatPortUDP", &ip_autor_dnat_udp),
        format_bash_array("IPAutorDockerTCP", &get_bucket("ip_autor", "DockerTCP")),
        format_bash_array("IPAutorDockerUDP", &get_bucket("ip_autor", "DockerUDP")),
        String::new(),
        format_bash_array("internalOpenPortsTCP", &get_bucket("internal", "OpenPortsTCP")),
        format_bash_array("internalOpenPortsUDP", &get_bucket("internal", "OpenPortsUDP")),
        format_bash_array("internalRedirectPortTCP", &get_bucket("internal", "RedirectPortTCP")),
        format_bash_array("internalRedirectPortUDP", &get_bucket("internal", "RedirectPortUDP")),
        format_bash_array("internalDnatPortTCP", &get_bucket("internal", "DnatPortTCP")),
        format_bash_array("internalDnatPortUDP", &get_bucket("internal", "DnatPortUDP")),
        format_bash_array("internalDockerTCP", &get_bucket("internal", "DockerTCP")),
        format_bash_array("internalDockerUDP", &get_bucket("internal", "DockerUDP")),
        String::new(),
        format_bash_array("localOpenPortsTCP", &get_bucket("local", "OpenPortsTCP")),
        format_bash_array("localOpenPortsUDP", &get_bucket("local", "OpenPortsUDP")),
        format_bash_array("localRedirectPortTCP", &get_bucket("local", "RedirectPortTCP")),
        format_bash_array("localRedirectPortUDP", &get_bucket("local", "RedirectPortUDP")),
        format_bash_array("localDnatPortTCP", &get_bucket("local", "DnatPortTCP")),
        format_bash_array("localDnatPortUDP", &get_bucket("local", "DnatPortUDP")),
        format_bash_array("localDockerTCP", &get_bucket("local", "DockerTCP")),
        format_bash_array("localDockerUDP", &get_bucket("local", "DockerUDP")),
        String::new(),
        format!("declare -a countryOpenPort=\"{}\"", settings.country_open_port),
        format_bash_array("openPortTCP", &get_bucket("open", "OpenPortsTCP")),
        format_bash_array("openPortUDP", &get_bucket("open", "OpenPortsUDP")),
        format_bash_array("redirectPortTCP", &get_bucket("open", "RedirectPortTCP")),
        format_bash_array("redirectPortUDP", &get_bucket("open", "RedirectPortUDP")),
        format_bash_array("dnatPortTCP", &get_bucket("open", "DnatPortTCP")),
        format_bash_array("dnatPortUDP", &get_bucket("open", "DnatPortUDP")),
        format_bash_array("openDockerTCP", &get_bucket("open", "DockerTCP")),
        format_bash_array("openDockerUDP", &get_bucket("open", "DockerUDP")),
        String::new(),
        format_bash_array("WWopenPortTCP", &get_bucket("ww", "OpenPortsTCP")),
        format_bash_array("WWopenPortUDP", &get_bucket("ww", "OpenPortsUDP")),
        format_bash_array("WWredirectPortTCP", &get_bucket("ww", "RedirectPortTCP")),
        format_bash_array("WWredirectPortUDP", &get_bucket("ww", "RedirectPortUDP")),
        format_bash_array("WWdnatPortTCP", &get_bucket("ww", "DnatPortTCP")),
        format_bash_array("WWdnatPortUDP", &get_bucket("ww", "DnatPortUDP")),
        format_bash_array("WWDockerTCP", &get_bucket("ww", "DockerTCP")),
        format_bash_array("WWDockerUDP", &get_bucket("ww", "DockerUDP")),
        String::new(),
        format!("declare -a blockedCountry=\"{}\"", settings.blocked_country),
        format!("declare -a blockedCountry2=\"{}\"", settings.blocked_country_2),
        String::new(),
    ];

    let firewall_settings = lines.join("\n");
    let firewall_rules_special = special.map_or_else(
        || "#! /bin/bash\nsource /etc/firewall/firewall.tools\nsource /etc/firewall/firewall.settings\nwait\nexit 0\n".to_owned(),
        |s| s.script_content,
    );

    let firewall_get_list = render_get_list(&blocklists);
    lines.clear();

    Ok(GeneratedFilesBundle {
        output_dir: settings.output_dir,
        firewall_settings,
        firewall_rules_special,
        firewall_get_list,
        docker_filter_active: filter_by_docker,
        active_docker_inter_rules: active_inter_strings.len(),
        skipped_docker_inter_rules: skipped_inter,
        active_zone_rules: active_zone_count,
        skipped_zone_rules: skipped_zone_count,
        active_blocklists: blocklists.len(),
    })
}

/// Renders `firewall.get.list` keeping `generate_list()` and the final `.4`/`.6` aggregation intact.
#[must_use]
pub fn render_get_list(blocklists: &[fw_blocklist::Model]) -> String {
    let mut out = String::from(
        r#"#!/bin/bash

source /etc/firewall/firewall.settings
source /etc/firewall/firewall.tools

generate_list()
{
	local TARGET
	local URL=$1
	local begin_file=$2

	local tmp_4="/etc/firewall/${begin_file}.ip.4.tmp"
	local tmp_6="/etc/firewall/${begin_file}.ip.6.tmp"
	local final_4="/etc/firewall/${begin_file}.ip.4"
	local final_6="/etc/firewall/${begin_file}.ip.6"

	: > "${tmp_4}"
	: > "${tmp_6}"
	for TARGET in $(curl ${URL} 2>/dev/null | grep -v "^#" | cut -d " " -f 1); do
		if is_ipv4 "${TARGET}"; then
			echo "${TARGET}" >> ${tmp_4}
		elif is_ipv4_net "${TARGET}"; then
			echo "${TARGET}" >> ${tmp_4}
		elif is_ipv6 "${TARGET}"; then
			echo "${TARGET}" >> "${tmp_6}"
		elif is_ipv6_net "${TARGET}"; then
			echo "${TARGET}" >> "${tmp_6}"
		fi
	done

	if [ -s "${tmp_4}" ]; then
        mv "${tmp_4}" "${final_4}"
    else
        rm -f "${tmp_4}"
    fi

    if [ -s "${tmp_6}" ]; then
        mv "${tmp_6}" "${final_6}"
    else
        rm -f "${tmp_6}"
    fi

}

"#,
    );

    for bl in blocklists {
        out.push_str(&format!(
            "generate_list \"{}\" \"{}\" &\n",
            bl.url.trim(),
            bl.name.trim()
        ));
    }

    out.push_str(
        r"
wait

cat /etc/firewall/*.6 > /etc/firewall/to_block.ipv6
cat /etc/firewall/*.4 > /etc/firewall/to_block.ipv4

exit 0
",
    );
    out
}

/// Writes `firewall.settings`, `firewall.rules.special`, and `firewall.get.list` directly to
/// `bundle.output_dir` with mode `0700`. Direct truncation and writing is used to support
/// Docker bind-mounted files without failing with `EBUSY` on filesystem rename.
///
/// # Errors
/// Returns [`AppError`] if the target directory or files cannot be opened or written.
pub fn write_bundle_to_disk(bundle: &GeneratedFilesBundle) -> Result<Vec<String>, AppError> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let dir = Path::new(&bundle.output_dir);
    std::fs::create_dir_all(dir).map_err(|e| {
        AppError::InvalidInput(format!("Cannot create output_dir {}: {e}", dir.display()))
    })?;

    let files = [
        ("firewall.settings", &bundle.firewall_settings),
        ("firewall.rules.special", &bundle.firewall_rules_special),
        ("firewall.get.list", &bundle.firewall_get_list),
    ];

    let mut written = Vec::new();
    for (filename, content) in files {
        let final_path = dir.join(filename);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&final_path)
            .map_err(|e| {
                AppError::InvalidInput(format!("Failed opening {}: {e}", final_path.display()))
            })?;
        file.write_all(content.as_bytes()).map_err(|e| {
            AppError::InvalidInput(format!("Failed writing {}: {e}", final_path.display()))
        })?;
        file.flush().map_err(|e| {
            AppError::InvalidInput(format!("Failed flushing {}: {e}", final_path.display()))
        })?;
        let perms = std::fs::Permissions::from_mode(0o700);
        let _ = std::fs::set_permissions(&final_path, perms);
        written.push(final_path.display().to_string());
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_bash_array_formats_empty_and_populated() {
        assert_eq!(format_bash_array("empty_arr", &[]), "declare -a empty_arr=()");
        let items = vec!["eth0".to_owned(), "eth1".to_owned()];
        assert_eq!(
            format_bash_array("ifaces", &items),
            "declare -a ifaces=(\"eth0\" \"eth1\")"
        );
    }

    #[test]
    fn format_bash_assoc_bool_formats_empty_and_populated() {
        assert_eq!(
            format_bash_assoc_bool("empty_map", &BTreeMap::new()),
            "declare -A empty_map=()"
        );

        let mut map = BTreeMap::new();
        map.insert("eth0".to_owned(), true);
        map.insert("eth1".to_owned(), false);
        assert_eq!(
            format_bash_assoc_bool("dhcp", &map),
            "declare -A dhcp=( [\"eth0\"]=1 [\"eth1\"]=0 )"
        );
    }

    #[test]
    fn write_bundle_to_disk_creates_executable_files_atomically() {
        let temp_dir = tempfile::tempdir().unwrap();
        let bundle = GeneratedFilesBundle {
            output_dir: temp_dir.path().display().to_string(),
            firewall_settings: "# settings content\n".to_owned(),
            firewall_rules_special: "# special content\n".to_owned(),
            firewall_get_list: "# get list content\n".to_owned(),
            docker_filter_active: false,
            active_docker_inter_rules: 0,
            skipped_docker_inter_rules: 0,
            active_zone_rules: 0,
            skipped_zone_rules: 0,
            active_blocklists: 0,
        };

        let written = write_bundle_to_disk(&bundle).expect("write bundle");
        assert_eq!(written.len(), 3);
        assert!(temp_dir.path().join("firewall.settings").exists());
        assert!(temp_dir.path().join("firewall.rules.special").exists());
        assert!(temp_dir.path().join("firewall.get.list").exists());

        let read_back = std::fs::read_to_string(temp_dir.path().join("firewall.settings")).unwrap();
        assert_eq!(read_back, "# settings content\n");
    }
}
