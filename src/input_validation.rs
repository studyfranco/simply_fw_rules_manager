//! Strict grammar validation and SSRF guards for firewall settings, rules, paths, and URLs.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Component, Path, PathBuf};

use ipnet::IpNet;
use reqwest::Url;

use crate::error::AppError;

const FORBIDDEN_BASH_CHARS: &[char] = &[
    '"', '\'', '`', '$', '&', '|', '<', '>', '\\', '\r', '\n', '\0', '(', ')', '{', '}', '*', '?',
    '!', '#',
];

const FORBIDDEN_URL_CHARS: &[char] = &[
    '"', '\'', '`', '$', ';', '&', '|', '\\', '<', '>', '(', ')', '{', '}', '\r', '\n', '\0',
];

/// Returns `true` when `raw` contains ASCII control chars, whitespace, or Bash metacharacters.
#[must_use]
pub fn has_shell_metachars(raw: &str, allow_semicolon: bool) -> bool {
    raw.chars().any(|c| {
        c.is_ascii_control()
            || c.is_whitespace()
            || FORBIDDEN_BASH_CHARS.contains(&c)
            || (!allow_semicolon && c == ';')
    })
}

/// Validates a Linux network interface identifier (e.g. `out`, `eth0`, `enp0s3.10`).
///
/// # Errors
/// Returns [`AppError::InvalidInput`] if empty, too long, or containing illegal characters.
pub fn validate_interface_name(field: &str, raw: &str) -> Result<String, AppError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 32 {
        return Err(AppError::InvalidInput(format!(
            "{field} must be between 1 and 32 characters"
        )));
    }
    let mut chars = trimmed.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_ascii_alphanumeric());
    let rest_ok = chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'));
    if !first_ok || !rest_ok {
        return Err(AppError::InvalidInput(format!(
            "{field} contains invalid interface name '{trimmed}'"
        )));
    }
    Ok(trimmed.to_owned())
}

/// Validates an interface specification entry (`iface` or `iface;cidr_or_set;cidr6_or_set`).
///
/// # Errors
/// Returns [`AppError::InvalidInput`] if malformed or containing shell metacharacters.
pub fn validate_interface_spec(field: &str, raw: &str) -> Result<String, AppError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || has_shell_metachars(trimmed, true) {
        return Err(AppError::InvalidInput(format!(
            "{field} contains invalid characters in interface spec"
        )));
    }
    let parts: Vec<&str> = trimmed.split(';').collect();
    if parts.is_empty() || parts.len() > 3 {
        return Err(AppError::InvalidInput(format!(
            "{field} entry '{trimmed}' must have 1 to 3 semicolon-separated parts"
        )));
    }
    let _ = validate_interface_name(field, parts[0])?;
    for extra in &parts[1..] {
        if extra.is_empty() {
            continue;
        }
        if extra.parse::<IpNet>().is_ok() {
            continue;
        }
        let ok = extra
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
            && extra
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '/' | '-'));
        if !ok {
            return Err(AppError::InvalidInput(format!(
                "{field} contains invalid subnet/set token '{extra}'"
            )));
        }
    }
    Ok(trimmed.to_owned())
}

/// Validates a Docker container or network name (`[a-zA-Z0-9][a-zA-Z0-9._-]*`).
///
/// # Errors
/// Returns [`AppError::InvalidInput`] if empty or containing invalid characters.
pub fn validate_docker_name(field: &str, raw: &str) -> Result<String, AppError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 128 {
        return Err(AppError::InvalidInput(format!(
            "{field} must be between 1 and 128 characters"
        )));
    }
    let mut chars = trimmed.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_ascii_alphanumeric());
    let rest_ok = chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !first_ok || !rest_ok {
        return Err(AppError::InvalidInput(format!(
            "{field} contains invalid identifier '{trimmed}'"
        )));
    }
    Ok(trimmed.to_owned())
}

/// Validates a hook identifier (`[a-zA-Z0-9][a-zA-Z0-9._-]*`).
///
/// # Errors
/// Returns [`AppError::InvalidInput`] if malformed.
pub fn validate_hook_name(field: &str, raw: &str) -> Result<String, AppError> {
    validate_docker_name(field, raw)
}

/// Validates an IPv4/IPv6 address or CIDR range via [`IpNet`] / [`IpAddr`].
///
/// # Errors
/// Returns [`AppError::InvalidInput`] if unparseable.
pub fn validate_ip_or_cidr(field: &str, raw: &str) -> Result<String, AppError> {
    let trimmed = raw.trim();
    if trimmed.parse::<IpNet>().is_ok() || trimmed.parse::<IpAddr>().is_ok() {
        Ok(trimmed.to_owned())
    } else {
        Err(AppError::InvalidInput(format!(
            "{field} contains invalid IP or CIDR '{trimmed}'"
        )))
    }
}

/// Validates a TCP/UDP port (`1..=65535`) or iptables range (`start:end` or `start-end`).
///
/// # Errors
/// Returns [`AppError::InvalidInput`] if invalid or inverted.
pub fn validate_port_or_range(field: &str, raw: &str) -> Result<String, AppError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AppError::InvalidInput(format!(
            "{field} port cannot be empty"
        )));
    }
    let sep = if trimmed.contains(':') {
        Some(':')
    } else if trimmed.contains('-') {
        Some('-')
    } else {
        None
    };

    if let Some(delim) = sep {
        let Some((left, right)) = trimmed.split_once(delim) else {
            return Err(AppError::InvalidInput(format!(
                "{field} invalid port range '{trimmed}'"
            )));
        };
        if !left.bytes().all(|b| b.is_ascii_digit()) || !right.bytes().all(|b| b.is_ascii_digit()) {
            return Err(AppError::InvalidInput(format!(
                "{field} invalid port range '{trimmed}'"
            )));
        }
        let start: u16 = left
            .parse()
            .map_err(|_| AppError::InvalidInput(format!("{field} invalid port '{left}'")))?;
        let end: u16 = right
            .parse()
            .map_err(|_| AppError::InvalidInput(format!("{field} invalid port '{right}'")))?;
        if start == 0 || start > end {
            return Err(AppError::InvalidInput(format!(
                "{field} port range '{trimmed}' must satisfy 1 <= start <= end <= 65535"
            )));
        }
        Ok(trimmed.to_owned())
    } else {
        if !trimmed.bytes().all(|b| b.is_ascii_digit()) {
            return Err(AppError::InvalidInput(format!(
                "{field} invalid port '{trimmed}'"
            )));
        }
        let port: u16 = trimmed
            .parse()
            .map_err(|_| AppError::InvalidInput(format!("{field} invalid port '{trimmed}'")))?;
        if port == 0 {
            return Err(AppError::InvalidInput(format!("{field} port must be >= 1")));
        }
        Ok(trimmed.to_owned())
    }
}

/// Validates a `portIN,portTarget` redirect rule.
///
/// # Errors
/// Returns [`AppError::InvalidInput`] if malformed.
pub fn validate_redirect_spec(field: &str, raw: &str) -> Result<String, AppError> {
    let trimmed = raw.trim();
    let parts: Vec<&str> = trimmed.split(',').collect();
    if parts.len() != 2 {
        return Err(AppError::InvalidInput(format!(
            "{field} RedirectPort rule must have format 'port_in,port_target'"
        )));
    }
    let p_in = validate_port_or_range(field, parts[0])?;
    let p_out = validate_port_or_range(field, parts[1])?;
    Ok(format!("{p_in},{p_out}"))
}

/// Validates a `portIN,interOUT,IPv4,IPv6,portTarget` DNAT rule.
///
/// # Errors
/// Returns [`AppError::InvalidInput`] if any field violates iptables/ip6tables grammar.
pub fn validate_dnat_spec(field: &str, raw: &str) -> Result<String, AppError> {
    let trimmed = raw.trim();
    let parts: Vec<&str> = trimmed.split(',').map(str::trim).collect();
    if parts.len() != 5 {
        return Err(AppError::InvalidInput(format!(
            "{field} DNAT rule must have 5 fields 'portIN,interOUT,IPv4,IPv6,portTarget'"
        )));
    }
    let port_in = validate_port_or_range(field, parts[0])?;
    let inter_out = if parts[1].is_empty() {
        String::new()
    } else {
        validate_interface_name(field, parts[1])?
    };
    let ipv4 = if parts[2].is_empty() {
        String::new()
    } else {
        parts[2]
            .parse::<Ipv4Addr>()
            .map_err(|_| AppError::InvalidInput(format!("{field} invalid IPv4 '{}'", parts[2])))?
            .to_string()
    };
    let ipv6 = if parts[3].is_empty() {
        String::new()
    } else {
        parts[3]
            .parse::<Ipv6Addr>()
            .map_err(|_| AppError::InvalidInput(format!("{field} invalid IPv6 '{}'", parts[3])))?
            .to_string()
    };
    if ipv4.is_empty() && ipv6.is_empty() {
        return Err(AppError::InvalidInput(format!(
            "{field} DNAT rule must specify IPv4 and/or IPv6 target"
        )));
    }
    let port_target = validate_port_or_range(field, parts[4])?;
    Ok(format!("{port_in},{inter_out},{ipv4},{ipv6},{port_target}"))
}

/// Validates a `portIN,network,container,portTarget` Docker zone rule, returning `(normalized, container)`.
///
/// # Errors
/// Returns [`AppError::InvalidInput`] if any component violates syntax rules.
pub fn validate_docker_port_rule(field: &str, raw: &str) -> Result<(String, String), AppError> {
    let trimmed = raw.trim();
    let parts: Vec<&str> = trimmed.split(',').map(str::trim).collect();
    if parts.len() != 4 {
        return Err(AppError::InvalidInput(format!(
            "{field} rule must have format 'ext_port,network,container,container_port'"
        )));
    }
    let ext_port = validate_port_or_range(field, parts[0])?;
    let network = validate_docker_name("network", parts[1])?;
    let container = validate_docker_name("container", parts[2])?;
    let target_port = validate_port_or_range(field, parts[3])?;
    Ok((
        format!("{ext_port},{network},{container},{target_port}"),
        container,
    ))
}

/// Validates any zone rule value according to its `rule_kind`.
///
/// # Errors
/// Returns [`AppError::InvalidInput`] if the value does not match `rule_kind` grammar.
pub fn validate_zone_rule_value(
    rule_kind: &str,
    raw_value: &str,
) -> Result<(String, Option<String>), AppError> {
    match rule_kind {
        "OpenPortsTCP" | "OpenPortsUDP" => {
            let norm = validate_port_or_range(rule_kind, raw_value)?;
            Ok((norm, None))
        }
        "RedirectPortTCP" | "RedirectPortUDP" => {
            let norm = validate_redirect_spec(rule_kind, raw_value)?;
            Ok((norm, None))
        }
        "DnatPortTCP" | "DnatPortUDP" => {
            let norm = validate_dnat_spec(rule_kind, raw_value)?;
            Ok((norm, None))
        }
        "DockerTCP" | "DockerUDP" => {
            let (norm, container) = validate_docker_port_rule(rule_kind, raw_value)?;
            Ok((norm, Some(container)))
        }
        other => Err(AppError::InvalidInput(format!(
            "Unsupported rule_kind '{other}'"
        ))),
    }
}

/// Validates all fields of an inter-container Docker rule (`fw_docker_inter_rules`).
///
/// # Errors
/// Returns [`AppError::InvalidInput`] if any container/network/proto/port token is invalid.
pub fn validate_docker_inter_rule(
    src: &str,
    dst: &str,
    net: &str,
    proto: &str,
    ports: &str,
) -> Result<(String, String, String, String, String), AppError> {
    let src = validate_docker_name("source_container", src)?;
    let dst = validate_docker_name("destination_container", dst)?;
    let net = validate_docker_name("network_name", net)?;
    let proto_norm = proto.trim().to_ascii_lowercase();
    if proto_norm != "tcp" && proto_norm != "udp" {
        return Err(AppError::InvalidInput(
            "proto must be 'tcp' or 'udp'".to_owned(),
        ));
    }
    let trimmed_ports = ports.trim();
    if trimmed_ports.is_empty() {
        return Err(AppError::InvalidInput("ports cannot be empty".to_owned()));
    }
    let mut norm_ports = Vec::new();
    for seg in trimmed_ports.split(';') {
        norm_ports.push(validate_port_or_range("ports", seg)?);
    }
    Ok((src, dst, net, proto_norm, norm_ports.join(";")))
}

/// Validates comma-separated uppercase ISO 3166-1 alpha-2 country codes (e.g. `FR,CH` or empty).
///
/// # Errors
/// Returns [`AppError::InvalidInput`] if any segment is not `[A-Z]{2}`.
pub fn validate_country_codes(field: &str, raw: &str) -> Result<String, AppError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    let mut normalized = Vec::new();
    for seg in trimmed.split(',').map(str::trim) {
        if seg.len() != 2 || !seg.bytes().all(|b| b.is_ascii_uppercase()) {
            return Err(AppError::InvalidInput(format!(
                "{field} must be a comma-separated list of 2-letter uppercase country codes (e.g. 'FR,CH'); got '{seg}'"
            )));
        }
        normalized.push(seg.to_owned());
    }
    Ok(normalized.join(","))
}

/// Validates filesystem path settings (`output_dir`, `tools_script_path`) against metachars and `..`.
///
/// # Errors
/// Returns [`AppError::InvalidInput`] if unsafe characters or parent-directory traversal is present.
pub fn validate_safe_path(field: &str, raw: &str) -> Result<String, AppError> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('-')
        || has_shell_metachars(trimmed, false)
        || Path::new(trimmed)
            .components()
            .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(AppError::InvalidInput(format!(
            "{field} contains an unsafe or disallowed path '{trimmed}'"
        )));
    }
    Ok(trimmed.to_owned())
}

/// Validates Docker daemon endpoint (`unix:///...`, `http://...`, `https://...`, `tcp://...`).
///
/// # Errors
/// Returns [`AppError::InvalidInput`] if malformed or containing unsafe shell characters.
pub fn validate_docker_endpoint(raw: &str) -> Result<String, AppError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || has_shell_metachars(trimmed, false) {
        return Err(AppError::InvalidInput(
            "docker_endpoint contains invalid characters".to_owned(),
        ));
    }
    if let Some(socket_path) = trimmed.strip_prefix("unix://") {
        if !socket_path.starts_with('/')
            || Path::new(socket_path)
                .components()
                .any(|c| matches!(c, Component::ParentDir))
        {
            return Err(AppError::InvalidInput(
                "docker_endpoint unix:// path must be absolute without '..'".to_owned(),
            ));
        }
        return Ok(trimmed.to_owned());
    }
    let parsed = Url::parse(trimmed)
        .map_err(|_| AppError::InvalidInput("Invalid docker_endpoint URL".to_owned()))?;
    match parsed.scheme() {
        "http" | "https" | "tcp" if parsed.has_host() => Ok(trimmed.to_owned()),
        _ => Err(AppError::InvalidInput(
            "docker_endpoint must use unix://, http://, https://, or tcp://".to_owned(),
        )),
    }
}

/// Validates an HTTP/HTTPS URL and ensures it contains no Bash metacharacters or userinfo.
///
/// Query delimiters such as `?` and `=` are allowed for legitimate feed URLs (e.g. `?full`),
/// while quotes, whitespace, control characters, command substitutions (`$`, `` ` ``), escapes
/// (`\`), and shell control operators (`;`, `&`, `|`, `<`, `>`, `(`, `)`, `{`, `}`) are rejected.
///
/// # Errors
/// Returns [`AppError::InvalidInput`] if the URL is invalid, non-HTTP(S), or unsafe.
pub fn validate_http_url(field: &str, raw: &str) -> Result<String, AppError> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed
            .chars()
            .any(|c| c.is_ascii_control() || c.is_whitespace() || FORBIDDEN_URL_CHARS.contains(&c))
    {
        return Err(AppError::InvalidInput(format!(
            "{field} contains invalid URL characters"
        )));
    }
    let parsed = Url::parse(trimmed)
        .map_err(|_| AppError::InvalidInput(format!("{field} is not a valid URL")))?;
    if (parsed.scheme() != "http" && parsed.scheme() != "https") || !parsed.has_host() {
        return Err(AppError::InvalidInput(format!(
            "{field} must use http:// or https:// with a valid host"
        )));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(AppError::InvalidInput(format!(
            "{field} must not embed credentials in the URL"
        )));
    }
    Ok(trimmed.to_owned())
}

/// Returns `true` if `ip` belongs to loopback, private RFC1918, CGNAT, link-local, ULA,
/// documentation, unspecified, multicast, or reserved ranges.
#[must_use]
pub fn is_non_public_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let [a, b, _, _] = v4.octets();
            let is_cgnat = a == 100 && (64..=127).contains(&b);
            let is_benchmark = a == 198 && (b == 18 || b == 19);
            let is_ietf_protocol = a == 192 && b == 0 && v4.octets()[2] == 0;
            let is_reserved = a >= 240;
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || is_cgnat
                || is_benchmark
                || is_ietf_protocol
                || is_reserved
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            let is_doc = segs[0] == 0x2001 && segs[1] == 0x0db8;
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || is_doc
        }
    }
}

/// Checks syntactic SSRF host restrictions (literal private/loopback IPs and local hostnames).
///
/// # Errors
/// Returns [`AppError::InvalidInput`] if `allow_private_urls` is `false` and the host targets a
/// local or non-public destination.
pub fn validate_blocklist_host_ssrf(url: &str, allow_private_urls: bool) -> Result<(), AppError> {
    if allow_private_urls {
        return Ok(());
    }
    let parsed =
        Url::parse(url).map_err(|_| AppError::InvalidInput("Invalid blocklist URL".to_owned()))?;
    let Some(host_str) = parsed.host_str() else {
        return Err(AppError::InvalidInput(
            "Blocklist URL missing host".to_owned(),
        ));
    };
    let clean_host = host_str.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = clean_host.parse::<IpAddr>() {
        if is_non_public_ip(ip) {
            return Err(AppError::InvalidInput(format!(
                "Blocklist host IP '{ip}' is in a restricted internal/private range"
            )));
        }
        return Ok(());
    }
    let lower = clean_host.to_ascii_lowercase();
    if lower == "localhost"
        || lower.ends_with(".localhost")
        || Path::new(&lower)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("local"))
        || lower.ends_with(".internal")
    {
        return Err(AppError::InvalidInput(format!(
            "Blocklist host '{clean_host}' is restricted"
        )));
    }
    Ok(())
}

/// Resolves DNS for `url` and validates that EVERY resolved address is globally routable when
/// `allow_private_urls` is `false`, returning `(host, resolved_socket_addrs)` for pinned HTTP calls.
///
/// # Errors
/// Returns [`AppError::InvalidInput`] on SSRF-restricted targets or [`AppError::Upstream`] if DNS
/// resolution fails.
pub async fn resolve_safe_blocklist_addrs(
    url: &str,
    allow_private_urls: bool,
) -> Result<Option<(String, Vec<SocketAddr>)>, AppError> {
    validate_blocklist_host_ssrf(url, allow_private_urls)?;
    if allow_private_urls {
        return Ok(None);
    }

    let parsed =
        Url::parse(url).map_err(|_| AppError::InvalidInput("Invalid blocklist URL".to_owned()))?;
    let host_str = parsed
        .host_str()
        .ok_or_else(|| AppError::InvalidInput("Blocklist URL missing host".to_owned()))?;
    let clean_host = host_str
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let port = parsed.port_or_known_default().unwrap_or(80);

    if let Ok(ip) = clean_host.parse::<IpAddr>() {
        if is_non_public_ip(ip) {
            return Err(AppError::InvalidInput(format!(
                "Blocklist host IP '{ip}' is in a restricted internal/private range"
            )));
        }
        return Ok(Some((clean_host, vec![SocketAddr::new(ip, port)])));
    }

    let resolved: Vec<SocketAddr> = tokio::net::lookup_host((clean_host.as_str(), port))
        .await
        .map_err(|e| AppError::Upstream(format!("DNS lookup failed for {clean_host}: {e}")))?
        .collect();

    if resolved.is_empty() {
        return Err(AppError::Upstream(format!(
            "DNS lookup returned no addresses for {clean_host}"
        )));
    }
    for sa in &resolved {
        if is_non_public_ip(sa.ip()) {
            return Err(AppError::InvalidInput(format!(
                "Blocklist host '{clean_host}' resolved to restricted IP {}",
                sa.ip()
            )));
        }
    }
    Ok(Some((clean_host, resolved)))
}

/// Validates and confines `POST /api/firewall/import` `source_dir` against arbitrary host path
/// traversal / file disclosure.
///
/// # Errors
/// Returns [`AppError::InvalidInput`] or [`AppError::Forbidden`] if `raw_dir` attempts parent
/// traversal or escapes allowed import directories.
pub fn confine_import_dir(raw_dir: &str) -> Result<PathBuf, AppError> {
    let trimmed = raw_dir.trim();
    if trimmed.is_empty()
        || has_shell_metachars(trimmed, false)
        || Path::new(trimmed)
            .components()
            .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(AppError::InvalidInput(
            "Invalid source_dir: traversal or unsafe characters are disallowed".to_owned(),
        ));
    }

    let configured_import = std::env::var("FW_IMPORT_DIR")
        .unwrap_or_else(|_| "example/MainServ/etc_firewall".to_owned());
    let candidate = Path::new(trimmed);

    // Allow the non-existent embedded-fixture sentinel paths cleanly.
    if trimmed == configured_import || trimmed == "example/MainServ/etc_firewall" {
        return Ok(candidate.to_path_buf());
    }

    if !candidate.exists() || !candidate.is_dir() {
        return Err(AppError::InvalidInput(format!(
            "Import directory '{}' does not exist",
            candidate.display()
        )));
    }

    let canon_target = std::fs::canonicalize(candidate).map_err(|e| {
        AppError::InvalidInput(format!(
            "Cannot access import directory '{}': {e}",
            candidate.display()
        ))
    })?;

    let mut allowed_bases: Vec<PathBuf> = vec![PathBuf::from("/etc/firewall")];
    if let Ok(cwd) = std::env::current_dir() {
        allowed_bases.push(cwd.join("fixtures"));
        allowed_bases.push(cwd.join("example"));
    }
    allowed_bases.push(PathBuf::from(&configured_import));

    for base in allowed_bases {
        if let Ok(canon_base) = std::fs::canonicalize(&base)
            && canon_target.starts_with(&canon_base)
        {
            return Ok(canon_target);
        }
    }

    Err(AppError::Forbidden(
        "Import directory is outside permitted configuration roots".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bash_injection_in_settings_and_rules() {
        assert!(validate_interface_name("main_inter", "out$(id)").is_err());
        assert!(validate_interface_name("main_inter", "out\"; touch /tmp/pwn; #").is_err());
        assert!(validate_interface_spec("inter_out", "eth0;id>/tmp/pwn").is_err());
        assert!(validate_ip_or_cidr("ip_autor", "1.2.3.4;id").is_err());
        assert!(validate_port_or_range("openPortTCP", "80;curl evil").is_err());
        assert!(validate_country_codes("blocked_country", "CN,RU;id").is_err());
        assert!(validate_country_codes("blocked_country", "cn").is_err());
        assert!(validate_docker_name("network", "ext$(whoami)").is_err());
        assert!(validate_http_url("url", "https://example.org/$(id).txt").is_err());
        assert!(validate_http_url("url", "https://example.org/a\"b.txt").is_err());
        assert!(validate_zone_rule_value("DockerTCP", "443,ext,traefik$(id),443").is_err());
        assert!(validate_docker_inter_rule("traefik", "app", "ext", "tcp", "80;id").is_err());
    }

    #[test]
    fn preserves_all_legitimate_fixture_formats() {
        assert_eq!(validate_interface_name("main_inter", "out").unwrap(), "out");
        assert_eq!(
            validate_interface_spec("inter_out", "eth0;192.168.1.0/24;2001:db8::/64").unwrap(),
            "eth0;192.168.1.0/24;2001:db8::/64"
        );
        assert_eq!(
            validate_country_codes("country_open_port", "FR,CH").unwrap(),
            "FR,CH"
        );
        assert_eq!(validate_country_codes("blocked_country_2", "").unwrap(), "");
        assert_eq!(
            validate_zone_rule_value("DockerTCP", "443,ext,traefik,443").unwrap(),
            ("443,ext,traefik,443".to_owned(), Some("traefik".to_owned()))
        );
        assert_eq!(
            validate_zone_rule_value("DnatPortTCP", "8080,eth0,192.168.1.10,,80")
                .unwrap()
                .0,
            "8080,eth0,192.168.1.10,,80"
        );
        assert_eq!(
            validate_docker_inter_rule(
                "traefik",
                "jellyfin_theatre",
                "isolate",
                "tcp",
                "8096;8443"
            )
            .unwrap()
            .4,
            "8096;8443"
        );
    }

    #[test]
    fn ssrf_blocks_private_loopback_link_local_cgnat_and_ula() {
        assert!(validate_blocklist_host_ssrf("http://127.0.0.1:8080/list.txt", false).is_err());
        assert!(
            validate_blocklist_host_ssrf("http://169.254.169.254/latest/meta-data/", false)
                .is_err()
        );
        assert!(validate_blocklist_host_ssrf("http://10.0.0.1/feed.txt", false).is_err());
        assert!(validate_blocklist_host_ssrf("http://172.16.5.4/feed.txt", false).is_err());
        assert!(validate_blocklist_host_ssrf("http://192.168.1.1/feed.txt", false).is_err());
        assert!(validate_blocklist_host_ssrf("http://100.64.0.1/feed.txt", false).is_err());
        assert!(validate_blocklist_host_ssrf("http://[fc00::1]/feed.txt", false).is_err());
        assert!(validate_blocklist_host_ssrf("http://[::ffff:127.0.0.1]/feed.txt", false).is_err());
        assert!(validate_blocklist_host_ssrf("http://localhost/feed.txt", false).is_err());
        assert!(validate_blocklist_host_ssrf("https://rules.example.org/drop.txt", false).is_ok());
    }
}
