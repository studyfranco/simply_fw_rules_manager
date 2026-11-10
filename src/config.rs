//! Environment configuration and trusted-proxy client IP resolution.

use std::net::IpAddr;
use std::sync::Arc;

use axum::http::HeaderMap;
use ipnet::IpNet;

/// Default maximum request body size in bytes (10 MiB).
pub const DEFAULT_MAX_BODY_MIB: usize = 10;

/// Environment variable for initial Master API key.
pub const INITIAL_MASTER_KEY_ENV: &str = "INITIAL_MASTER_KEY";

/// Environment variable for initial Master HMAC signing secret.
pub const INITIAL_MASTER_SIGNING_SECRET_ENV: &str = "INITIAL_MASTER_SIGNING_SECRET";

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

/// Trusted reverse proxy networks permitted to supply `X-Forwarded-For` / `X-Real-IP`.
#[derive(Clone, Debug, Default)]
pub struct TrustedProxies {
    networks: Arc<Vec<IpNet>>,
}

impl TrustedProxies {
    /// Parses `TRUSTED_PROXIES` environment variable (comma-separated IPs or CIDRs).
    #[must_use]
    pub fn from_env() -> Self {
        let raw = std::env::var("TRUSTED_PROXIES").unwrap_or_default();
        Self::parse_list(&raw)
    }

    /// Parses a comma-separated list of IP/CIDR entries.
    #[must_use]
    pub fn parse_list(raw: &str) -> Self {
        let mut networks = Vec::new();
        for token in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if let Ok(net) = token.parse::<IpNet>() {
                networks.push(net);
            } else if let Ok(ip) = token.parse::<IpAddr>() {
                networks.push(IpNet::from(normalize_ip(ip)));
            }
        }
        Self {
            networks: Arc::new(networks),
        }
    }

    /// Returns the list of trusted networks.
    #[must_use]
    pub fn networks(&self) -> &[IpNet] {
        &self.networks
    }
}

/// Resolves the effective client IP from socket peer address and forwarding headers when the
/// peer is in `trusted`.
#[must_use]
pub fn resolve_client_ip(peer_ip: IpAddr, headers: &HeaderMap, trusted: &[IpNet]) -> IpAddr {
    let peer = normalize_ip(peer_ip);
    if !trusted.iter().any(|net| net.contains(&peer)) {
        return peer;
    }
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        let hops: Vec<IpAddr> = xff
            .split(',')
            .filter_map(|s| s.trim().parse::<IpAddr>().ok())
            .map(normalize_ip)
            .collect();
        for hop in hops.into_iter().rev() {
            if !trusted.iter().any(|net| net.contains(&hop)) {
                return hop;
            }
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
        assert_eq!(normalize_ip(mapped), IpAddr::from_str("192.168.1.10").unwrap());

        let pure_v4 = IpAddr::from_str("10.0.0.1").unwrap();
        assert_eq!(normalize_ip(pure_v4), pure_v4);

        let pure_v6 = IpAddr::from_str("2001:db8::1").unwrap();
        assert_eq!(normalize_ip(pure_v6), pure_v6);
    }

    #[test]
    fn trusted_proxies_parse_list_cidrs_and_bare_ips() {
        let trusted = TrustedProxies::parse_list(" 10.0.0.0/8, 192.168.1.1 ,, 2001:db8::/64 , invalid ");
        let nets = trusted.networks();
        assert_eq!(nets.len(), 3);
        assert_eq!(nets[0], "10.0.0.0/8".parse::<IpNet>().unwrap());
        assert_eq!(nets[1], "192.168.1.1/32".parse::<IpNet>().unwrap());
        assert_eq!(nets[2], "2001:db8::/64".parse::<IpNet>().unwrap());
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
        headers.insert("x-forwarded-for", HeaderValue::from_static("10.0.0.99, 10.0.0.88"));

        let trusted_peer = IpAddr::from_str("10.0.0.1").unwrap();
        let client = resolve_client_ip(trusted_peer, &headers, &trusted);
        assert_eq!(client, trusted_peer);
    }
}
