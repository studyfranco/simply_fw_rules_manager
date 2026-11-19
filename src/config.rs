//! Environment configuration and trusted-proxy client IP resolution.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::HeaderMap;
use ipnet::IpNet;
use tokio::sync::RwLock;

/// Default maximum request body size in bytes (10 MiB).
pub const DEFAULT_MAX_BODY_MIB: usize = 10;

/// Environment variable for initial Master API key.
pub const INITIAL_MASTER_KEY_ENV: &str = "INITIAL_MASTER_KEY";

/// Environment variable for initial Master HMAC signing secret.
pub const INITIAL_MASTER_SIGNING_SECRET_ENV: &str = "INITIAL_MASTER_SIGNING_SECRET";

/// Reads a secret using an explicit environment-lookup closure and secrets directory.
#[must_use]
pub fn get_secret_from<F>(
    var_name: &str,
    lookup_env: F,
    secrets_dir: &std::path::Path,
) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(file_path) = lookup_env(&format!("{var_name}_FILE")) {
        let trimmed = file_path.trim();
        if !trimmed.is_empty()
            && let Ok(content) = std::fs::read_to_string(trimmed)
        {
            let trimmed_content = content.trim().to_owned();
            if !trimmed_content.is_empty() {
                return Some(trimmed_content);
            }
        }
    }

    let default_path = secrets_dir.join(var_name.to_ascii_lowercase());
    if let Ok(content) = std::fs::read_to_string(&default_path) {
        let trimmed_content = content.trim().to_owned();
        if !trimmed_content.is_empty() {
            return Some(trimmed_content);
        }
    }

    lookup_env(var_name)
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// Reads a secret from an environment variable pointing to a file (`_FILE`),
/// directly from `/run/secrets/<name>`, or from a direct environment variable.
///
/// Precedence:
/// 1. `<VAR_NAME>_FILE` path content (if set, non-empty, and file exists)
/// 2. `/run/secrets/<lowercase_var_name>` (if file exists)
/// 3. `<VAR_NAME>` direct environment variable (if set and non-empty)
#[must_use]
pub fn get_secret_or_env(var_name: &str) -> Option<String> {
    get_secret_from(
        var_name,
        |key| std::env::var(key).ok(),
        std::path::Path::new("/run/secrets"),
    )
}

/// Returns maximum request body bytes from `MAX_BODY_SIZE_MIB` (default 10 MiB).
#[must_use]
pub fn max_body_bytes() -> usize {
    std::env::var("MAX_BODY_SIZE_MIB")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .filter(|&mib| (1..=100).contains(&mib))
        .unwrap_or(DEFAULT_MAX_BODY_MIB)
        * 1024
        * 1024
}

/// Unwraps IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) to canonical IPv4.
#[must_use]
pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

/// A single parsed `TRUSTED_PROXIES` entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyMatcher {
    /// Literal IPv4/IPv6 network CIDR.
    Network(IpNet),
    /// Hostname (e.g. a Docker service name `traefik`) resolved asynchronously with caching.
    Hostname(String),
}

impl std::fmt::Display for ProxyMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network(net) => write!(f, "{net}"),
            Self::Hostname(host) => write!(f, "{host}"),
        }
    }
}

/// Startup refusal: `TRUSTED_PROXIES` contains syntactically invalid entry/entries.
#[derive(Debug, Clone, thiserror::Error)]
#[error("invalid TRUSTED_PROXIES configuration: {details}")]
pub struct InvalidTrustedProxies {
    /// Human-readable description of invalid entries.
    details: String,
}

fn is_valid_proxy_hostname(token: &str) -> bool {
    if token.is_empty() || token.len() > 253 || token.starts_with('.') || token.ends_with('.') {
        return false;
    }
    let labels: Vec<&str> = token.split('.').collect();
    // Require at least one alphabetic character in the final label so malformed IPs (e.g.
    // `999.999.999.999`) or bad CIDRs are never misclassified as hostnames.
    let Some(last) = labels.last() else {
        return false;
    };
    if !last.chars().any(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

/// Cached DNS resolution result for hostname-based `TRUSTED_PROXIES` entries.
#[derive(Debug, Default)]
struct DnsCache {
    entries: RwLock<HashMap<String, (Vec<IpNet>, Instant)>>,
}

impl DnsCache {
    const POSITIVE_TTL: Duration = Duration::from_secs(30);
    const NEGATIVE_TTL: Duration = Duration::from_secs(5);

    async fn resolve(&self, host: &str) -> Vec<IpNet> {
        let now = Instant::now();
        {
            let guard = self.entries.read().await;
            if let Some((nets, expires_at)) = guard.get(host)
                && *expires_at > now
            {
                return nets.clone();
            }
        }

        let resolved: Vec<IpNet> = match tokio::net::lookup_host((host, 0)).await {
            Ok(addrs) => addrs.map(|sa| IpNet::from(normalize_ip(sa.ip()))).collect(),
            Err(err) => {
                tracing::debug!(proxy_host = %host, "DNS lookup failed for trusted proxy: {err}");
                Vec::new()
            }
        };
        let ttl = if resolved.is_empty() {
            Self::NEGATIVE_TTL
        } else {
            Self::POSITIVE_TTL
        };
        let mut guard = self.entries.write().await;
        guard.insert(host.to_owned(), (resolved.clone(), Instant::now() + ttl));
        resolved
    }
}

/// Trusted reverse proxy networks/hostnames permitted to supply `X-Forwarded-For` / `X-Real-IP`.
#[derive(Clone, Debug, Default)]
pub struct TrustedProxies {
    matchers: Arc<Vec<ProxyMatcher>>,
    dns_cache: Arc<DnsCache>,
}

impl TrustedProxies {
    /// Parses `TRUSTED_PROXIES` environment variable (comma-separated IPs, CIDRs, or hostnames).
    ///
    /// # Errors
    /// Returns [`InvalidTrustedProxies`] if any token is syntactically invalid.
    pub fn from_env() -> Result<Self, InvalidTrustedProxies> {
        let raw = std::env::var("TRUSTED_PROXIES").unwrap_or_default();
        Self::parse_list(&raw)
    }

    /// Parses a comma-separated list of IP/CIDR/hostname entries.
    ///
    /// # Errors
    /// Returns [`InvalidTrustedProxies`] if any entry is invalid.
    pub fn parse_list(raw: &str) -> Result<Self, InvalidTrustedProxies> {
        let mut matchers = Vec::new();
        let mut invalid = Vec::new();
        for token in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if let Ok(net) = token.parse::<IpNet>() {
                let normalized =
                    IpNet::new(normalize_ip(net.addr()), net.prefix_len()).unwrap_or(net);
                matchers.push(ProxyMatcher::Network(normalized));
            } else if let Ok(ip) = token.parse::<IpAddr>() {
                matchers.push(ProxyMatcher::Network(IpNet::from(normalize_ip(ip))));
            } else if is_valid_proxy_hostname(token) {
                matchers.push(ProxyMatcher::Hostname(token.to_owned()));
            } else {
                invalid.push(token.to_owned());
            }
        }
        if !invalid.is_empty() {
            return Err(InvalidTrustedProxies {
                details: invalid.join(", "),
            });
        }
        Ok(Self {
            matchers: Arc::new(matchers),
            dns_cache: Arc::new(DnsCache::default()),
        })
    }

    /// Returns static CIDR/IP networks configured in `TRUSTED_PROXIES`.
    #[must_use]
    pub fn networks(&self) -> Vec<IpNet> {
        self.matchers
            .iter()
            .filter_map(|m| match m {
                ProxyMatcher::Network(net) => Some(*net),
                ProxyMatcher::Hostname(_) => None,
            })
            .collect()
    }

    /// Returns display strings for all configured `TRUSTED_PROXIES` entries.
    #[must_use]
    pub fn matchers_display(&self) -> Vec<String> {
        self.matchers.iter().map(ToString::to_string).collect()
    }

    /// Resolves all configured `TRUSTED_PROXIES` entries (including DNS hostnames) to IP networks.
    pub async fn resolved(&self) -> Vec<IpNet> {
        let mut out = Vec::new();
        for matcher in self.matchers.iter() {
            match matcher {
                ProxyMatcher::Network(net) => out.push(*net),
                ProxyMatcher::Hostname(host) => out.extend(self.dns_cache.resolve(host).await),
            }
        }
        out
    }

    /// Spawns a non-blocking boot probe for configured hostnames, retrying once after a 60s grace
    /// period to handle container startup ordering cleanly.
    pub fn prime_with_grace(&self) {
        let hosts: Vec<String> = self
            .matchers
            .iter()
            .filter_map(|m| match m {
                ProxyMatcher::Hostname(h) => Some(h.clone()),
                ProxyMatcher::Network(_) => None,
            })
            .collect();
        if hosts.is_empty() {
            return;
        }
        let cache = Arc::clone(&self.dns_cache);
        tokio::spawn(async move {
            let mut unresolved = Vec::new();
            for host in &hosts {
                if cache.resolve(host).await.is_empty() {
                    unresolved.push(host.clone());
                }
            }
            if unresolved.is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_secs(60)).await;
            for host in unresolved {
                if cache.resolve(&host).await.is_empty() {
                    tracing::warn!(
                        proxy_host = %host,
                        "TRUSTED_PROXIES hostname did not resolve after 60s boot grace period"
                    );
                }
            }
        });
    }
}

/// Resolves the listening [`SocketAddr`] from `LISTEN_ADDR` or `BIND_HOST`/`HOST` + `PORT`.
///
/// # Errors
/// Returns an error string if the configured bind address or port cannot be parsed.
pub fn resolve_bind_addr() -> Result<SocketAddr, String> {
    if let Ok(raw) = std::env::var("LISTEN_ADDR") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return trimmed
                .parse::<SocketAddr>()
                .map_err(|e| format!("invalid LISTEN_ADDR '{trimmed}': {e}"));
        }
    }

    let host_raw = std::env::var("BIND_HOST")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "0.0.0.0".to_owned());
    let host_trimmed = host_raw.trim();
    let host: IpAddr = if host_trimmed.is_empty() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        host_trimmed
            .parse()
            .map_err(|e| format!("invalid BIND_HOST/HOST '{host_trimmed}': {e}"))?
    };

    let port: u16 = match std::env::var("PORT") {
        Ok(raw) if !raw.trim().is_empty() => raw
            .trim()
            .parse()
            .map_err(|e| format!("invalid PORT '{}': {e}", raw.trim()))?,
        _ => 3000,
    };

    Ok(SocketAddr::new(host, port))
}

/// Resolves the effective client IP from socket peer address and forwarding headers when the
/// peer is in `trusted`.
#[must_use]
pub fn resolve_client_ip(peer_ip: IpAddr, headers: &HeaderMap, trusted: &[IpNet]) -> IpAddr {
    let peer = normalize_ip(peer_ip);
    if !trusted.iter().any(|net| net.contains(&peer)) {
        return peer;
    }
    let hops: Vec<IpAddr> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|xff| xff.split(','))
        .filter_map(|s| s.trim().parse::<IpAddr>().ok())
        .map(normalize_ip)
        .collect();
    for hop in hops.into_iter().rev() {
        if !trusted.iter().any(|net| net.contains(&hop)) {
            return hop;
        }
    }
    if let Some(real_ip) = headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
    {
        return normalize_ip(real_ip);
    }
    peer
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use std::str::FromStr;

    #[test]
    fn normalize_ip_unwraps_ipv4_mapped_ipv6() {
        let mapped = IpAddr::from_str("::ffff:192.168.1.10").unwrap();
        assert_eq!(
            normalize_ip(mapped),
            IpAddr::from_str("192.168.1.10").unwrap()
        );

        let pure_v4 = IpAddr::from_str("10.0.0.1").unwrap();
        assert_eq!(normalize_ip(pure_v4), pure_v4);

        let pure_v6 = IpAddr::from_str("2001:db8::1").unwrap();
        assert_eq!(normalize_ip(pure_v6), pure_v6);
    }

    #[test]
    fn trusted_proxies_parse_list_cidrs_and_bare_ips() {
        let trusted =
            TrustedProxies::parse_list(" 10.0.0.0/8, 192.168.1.1 ,, 2001:db8::/64 , traefik ")
                .unwrap();
        let nets = trusted.networks();
        assert_eq!(nets.len(), 3);
        assert_eq!(nets[0], "10.0.0.0/8".parse::<IpNet>().unwrap());
        assert_eq!(nets[1], "192.168.1.1/32".parse::<IpNet>().unwrap());
        assert_eq!(nets[2], "2001:db8::/64".parse::<IpNet>().unwrap());
        assert_eq!(
            trusted.matchers_display(),
            vec!["10.0.0.0/8", "192.168.1.1/32", "2001:db8::/64", "traefik"]
        );

        assert!(TrustedProxies::parse_list("10.0.0.0/99").is_err());
        assert!(TrustedProxies::parse_list("999.999.999.999").is_err());
        assert!(TrustedProxies::parse_list("bad host!").is_err());
    }

    #[test]
    fn resolve_client_ip_walks_multiple_xff_headers() {
        let trusted = vec![
            "10.0.0.0/8".parse::<IpNet>().unwrap(),
            "172.16.0.0/12".parse::<IpNet>().unwrap(),
        ];
        let mut headers = HeaderMap::new();
        headers.append(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.77, 10.0.0.5"),
        );
        headers.append("x-forwarded-for", HeaderValue::from_static("172.16.1.2"));

        let trusted_peer = IpAddr::from_str("10.0.0.1").unwrap();
        let client = resolve_client_ip(trusted_peer, &headers, &trusted);
        assert_eq!(client, IpAddr::from_str("198.51.100.77").unwrap());
    }

    #[test]
    fn resolve_client_ip_ignores_untrusted_peer_headers() {
        let trusted = vec!["10.0.0.0/8".parse::<IpNet>().unwrap()];
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("1.2.3.4"));
        headers.insert("x-real-ip", HeaderValue::from_static("5.6.7.8"));

        let untrusted_peer = IpAddr::from_str("198.51.100.1").unwrap();
        let client = resolve_client_ip(untrusted_peer, &headers, &trusted);
        assert_eq!(client, untrusted_peer);
    }

    #[test]
    fn resolve_client_ip_walks_xff_right_to_left_skipping_trusted_hops() {
        let trusted = vec![
            "10.0.0.0/8".parse::<IpNet>().unwrap(),
            "172.16.0.0/12".parse::<IpNet>().unwrap(),
        ];
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.195, 10.0.0.5, 172.16.1.2"),
        );

        let trusted_peer = IpAddr::from_str("10.0.0.1").unwrap();
        let client = resolve_client_ip(trusted_peer, &headers, &trusted);
        assert_eq!(client, IpAddr::from_str("203.0.113.195").unwrap());
    }

    #[test]
    fn resolve_client_ip_falls_back_to_x_real_ip_when_xff_absent() {
        let trusted = vec!["10.0.0.0/8".parse::<IpNet>().unwrap()];
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", HeaderValue::from_static("198.51.100.42"));

        let trusted_peer = IpAddr::from_str("10.0.0.1").unwrap();
        let client = resolve_client_ip(trusted_peer, &headers, &trusted);
        assert_eq!(client, IpAddr::from_str("198.51.100.42").unwrap());
    }

    #[test]
    fn resolve_client_ip_falls_back_to_peer_when_headers_empty_or_all_trusted() {
        let trusted = vec!["10.0.0.0/8".parse::<IpNet>().unwrap()];
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("10.0.0.99, 10.0.0.88"),
        );

        let trusted_peer = IpAddr::from_str("10.0.0.1").unwrap();
        let client = resolve_client_ip(trusted_peer, &headers, &trusted);
        assert_eq!(client, trusted_peer);
    }

    #[test]
    fn get_secret_or_env_reads_env_and_file() {
        let mut env_map = std::collections::BTreeMap::new();
        let temp_dir = tempfile::tempdir().unwrap();
        let secrets_dir = temp_dir.path().join("run_secrets");
        std::fs::create_dir_all(&secrets_dir).unwrap();

        let test_var = "TEST_SECRET_DIRECT_VAL_123";
        env_map.insert(test_var.to_owned(), "direct_secret_value".to_owned());
        assert_eq!(
            get_secret_from(test_var, |k| env_map.get(k).cloned(), &secrets_dir),
            Some("direct_secret_value".to_owned())
        );

        // /run/secrets/<lowercase> overrides direct env
        std::fs::write(
            secrets_dir.join("test_secret_direct_val_123"),
            "dir_secret\n",
        )
        .unwrap();
        assert_eq!(
            get_secret_from(test_var, |k| env_map.get(k).cloned(), &secrets_dir),
            Some("dir_secret".to_owned())
        );

        // <VAR>_FILE overrides both
        let file_path = temp_dir.path().join("secret.txt");
        std::fs::write(&file_path, "file_secret_value\n").unwrap();
        env_map.insert(format!("{test_var}_FILE"), file_path.display().to_string());
        assert_eq!(
            get_secret_from(test_var, |k| env_map.get(k).cloned(), &secrets_dir),
            Some("file_secret_value".to_owned())
        );
    }
}
