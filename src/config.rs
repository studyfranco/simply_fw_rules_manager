//! Environment configuration and trusted-proxy client IP resolution.

use std::net::IpAddr;
use std::sync::Arc;

use axum::http::HeaderMap;
use ipnetwork::IpNetwork;

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
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    }
}

/// Trusted reverse proxy networks permitted to supply `X-Forwarded-For` / `X-Real-IP`.
#[derive(Clone, Debug, Default)]
pub struct TrustedProxies {
    networks: Arc<Vec<IpNetwork>>,
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
            if let Ok(net) = token.parse::<IpNetwork>() {
                networks.push(net);
            } else if let Ok(ip) = token.parse::<IpAddr>() {
                networks.push(IpNetwork::from(normalize_ip(ip)));
            }
        }
        Self {
            networks: Arc::new(networks),
        }
    }

    /// Returns the list of trusted networks.
    #[must_use]
    pub fn networks(&self) -> &[IpNetwork] {
        &self.networks
    }
}

/// Resolves the effective client IP from socket peer address and forwarding headers when the
/// peer is in `trusted`.
#[must_use]
pub fn resolve_client_ip(peer_ip: IpAddr, headers: &HeaderMap, trusted: &[IpNetwork]) -> IpAddr {
    let peer = normalize_ip(peer_ip);
    if !trusted.iter().any(|net| net.contains(peer)) {
        return peer;
    }
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        let hops: Vec<IpAddr> = xff
            .split(',')
            .filter_map(|s| s.trim().parse::<IpAddr>().ok())
            .map(normalize_ip)
            .collect();
        for hop in hops.into_iter().rev() {
            if !trusted.iter().any(|net| net.contains(hop)) {
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
