//! Docker Engine discovery client supporting both local Unix domain sockets
//! (`unix:///var/run/docker.sock` or `/var/run/docker.sock`) and TCP/HTTP endpoints
//! (`http://127.0.0.1:2375` / `tcp://dockersocprox:2375`).

use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Summary of one discovered Docker container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredContainer {
    /// Primary container name (without leading `/`).
    pub name: String,
    /// Container state (`running`, `exited`, `paused`, etc.).
    pub state: String,
    /// Human-readable status string (`Up 2 hours`, `Exited (0) ...`).
    pub status: String,
    /// Image name.
    pub image: String,
    /// Attached networks and the container's IPv4/IPv6 addresses on each.
    pub networks: BTreeMap<String, ContainerNetworkAttachment>,
}

/// Network attachment details for a container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerNetworkAttachment {
    /// Assigned IPv4 address, if any.
    pub ipv4: String,
    /// Assigned global IPv6 address, if any.
    pub ipv6: String,
}

/// Summary of one discovered Docker network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredNetwork {
    /// Network name (`ext`, `isolate`, `pihole`, `bridge`, etc.).
    pub name: String,
    /// Network driver (`bridge`, `host`, `macvlan`, etc.).
    pub driver: String,
    /// Configured IPv4/IPv6 subnets.
    pub subnets: Vec<String>,
}

/// Complete Docker discovery snapshot returned to the `WebUI` and generator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerDiscoverySnapshot {
    /// Endpoint queried.
    pub endpoint: String,
    /// True if the Docker daemon responded successfully.
    pub reachable: bool,
    /// Optional error message if unreachable.
    pub error: Option<String>,
    /// Discovered containers (running and stopped).
    pub containers: Vec<DiscoveredContainer>,
    /// Discovered networks.
    pub networks: Vec<DiscoveredNetwork>,
}

impl DockerDiscoverySnapshot {
    /// Returns the set of container names whose state is `"running"`.
    #[must_use]
    pub fn running_container_names(&self) -> HashSet<String> {
        self.containers
            .iter()
            .filter(|c| c.state.eq_ignore_ascii_case("running"))
            .map(|c| c.name.clone())
            .collect()
    }

    /// Returns the state of `container_name`: `"running"`, `"stopped"`, or `"unknown"` when
    /// the Docker daemon is unreachable.
    #[must_use]
    pub fn container_status(&self, container_name: &str) -> &'static str {
        if !self.reachable {
            return "unknown";
        }
        match self.containers.iter().find(|c| c.name == container_name) {
            Some(c) if c.state.eq_ignore_ascii_case("running") => "running",
            Some(_) => "stopped",
            None => "missing",
        }
    }
}

#[derive(Deserialize)]
struct RawDockerContainer {
    #[serde(rename = "Names", default)]
    names: Vec<String>,
    #[serde(rename = "Image", default)]
    image: String,
    #[serde(rename = "State", default)]
    state: String,
    #[serde(rename = "Status", default)]
    status: String,
    #[serde(rename = "NetworkSettings")]
    network_settings: Option<RawNetworkSettings>,
}

#[derive(Deserialize)]
struct RawNetworkSettings {
    #[serde(rename = "Networks", default)]
    networks: BTreeMap<String, RawEndpointSettings>,
}

#[derive(Deserialize)]
struct RawEndpointSettings {
    #[serde(rename = "IPAddress", default)]
    ip_address: String,
    #[serde(rename = "GlobalIPv6Address", default)]
    global_ipv6_address: String,
}

#[derive(Deserialize)]
struct RawDockerNetwork {
    #[serde(rename = "Name", default)]
    name: String,
    #[serde(rename = "Driver", default)]
    driver: String,
    #[serde(rename = "IPAM")]
    ipam: Option<RawIpam>,
}

#[derive(Deserialize)]
struct RawIpam {
    #[serde(rename = "Config", default)]
    config: Vec<RawIpamConfig>,
}

#[derive(Deserialize)]
struct RawIpamConfig {
    #[serde(rename = "Subnet")]
    subnet: Option<String>,
}

/// Queries the configured Docker endpoint (`unix://...` or `http://...` / `tcp://...`)
/// for all containers (`?all=1`) and networks.
pub async fn discover_docker(http: &Client, endpoint: &str) -> DockerDiscoverySnapshot {
    let endpoint = endpoint.trim();
    let result = if let Some(sock_path) = endpoint
        .strip_prefix("unix://")
        .or_else(|| endpoint.starts_with('/').then_some(endpoint))
    {
        fetch_via_unix_socket(Path::new(sock_path)).await
    } else {
        let base = endpoint
            .strip_prefix("tcp://")
            .map_or_else(|| endpoint.to_owned(), |rest| format!("http://{rest}"));
        fetch_via_http(http, base.trim_end_matches('/')).await
    };

    match result {
        Ok((containers, networks)) => DockerDiscoverySnapshot {
            endpoint: endpoint.to_owned(),
            reachable: true,
            error: None,
            containers,
            networks,
        },
        Err(err) => DockerDiscoverySnapshot {
            endpoint: endpoint.to_owned(),
            reachable: false,
            error: Some(err),
            containers: Vec::new(),
            networks: Vec::new(),
        },
    }
}

async fn fetch_via_http(
    http: &Client,
    base_url: &str,
) -> Result<(Vec<DiscoveredContainer>, Vec<DiscoveredNetwork>), String> {
    let containers_url = format!("{base_url}/containers/json?all=1");
    let networks_url = format!("{base_url}/networks");

    let c_resp = http
        .get(&containers_url)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| format!("Docker HTTP request failed: {e}"))?;
    if !c_resp.status().is_success() {
        return Err(format!(
            "Docker HTTP containers returned {}",
            c_resp.status()
        ));
    }
    let c_bytes = c_resp
        .bytes()
        .await
        .map_err(|e| format!("Failed reading Docker containers body: {e}"))?;

    let n_resp = http
        .get(&networks_url)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| format!("Docker HTTP networks request failed: {e}"))?;
    let n_bytes = n_resp
        .bytes()
        .await
        .map_err(|e| format!("Failed reading Docker networks body: {e}"))?;

    parse_docker_payloads(&c_bytes, &n_bytes)
}

async fn fetch_via_unix_socket(
    socket_path: &Path,
) -> Result<(Vec<DiscoveredContainer>, Vec<DiscoveredNetwork>), String> {
    let c_bytes = unix_http_get(socket_path, "/containers/json?all=1").await?;
    let n_bytes = unix_http_get(socket_path, "/networks").await?;
    parse_docker_payloads(&c_bytes, &n_bytes)
}

async fn unix_http_get(socket_path: &Path, path: &str) -> Result<Vec<u8>, String> {
    let mut stream = tokio::time::timeout(Duration::from_secs(4), UnixStream::connect(socket_path))
        .await
        .map_err(|_| format!("Timed out connecting to {}", socket_path.display()))?
        .map_err(|e| format!("Cannot connect to {}: {e}", socket_path.display()))?;

    let request = format!("GET {path} HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("Socket write error: {e}"))?;

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .await
        .map_err(|e| format!("Socket read error: {e}"))?;

    let Some(header_end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Err("Malformed HTTP response from Docker socket".to_owned());
    };
    Ok(raw[header_end + 4..].to_vec())
}

fn parse_docker_payloads(
    containers_json: &[u8],
    networks_json: &[u8],
) -> Result<(Vec<DiscoveredContainer>, Vec<DiscoveredNetwork>), String> {
    let raw_containers: Vec<RawDockerContainer> = serde_json::from_slice(containers_json)
        .map_err(|e| format!("Failed parsing Docker containers JSON: {e}"))?;
    let raw_networks: Vec<RawDockerNetwork> = serde_json::from_slice(networks_json)
        .map_err(|e| format!("Failed parsing Docker networks JSON: {e}"))?;

    let mut containers: Vec<DiscoveredContainer> = raw_containers
        .into_iter()
        .map(|rc| {
            let name = rc
                .names
                .first()
                .map(|n| n.trim_start_matches('/').to_owned())
                .unwrap_or_default();
            let mut networks = BTreeMap::new();
            if let Some(ns) = rc.network_settings {
                for (net_name, ep) in ns.networks {
                    networks.insert(
                        net_name,
                        ContainerNetworkAttachment {
                            ipv4: ep.ip_address,
                            ipv6: ep.global_ipv6_address,
                        },
                    );
                }
            }
            DiscoveredContainer {
                name,
                state: rc.state,
                status: rc.status,
                image: rc.image,
                networks,
            }
        })
        .collect();
    containers.sort_by(|a, b| a.name.cmp(&b.name));

    let mut networks: Vec<DiscoveredNetwork> = raw_networks
        .into_iter()
        .map(|rn| {
            let subnets = rn
                .ipam
                .map(|ipam| {
                    ipam.config
                        .into_iter()
                        .filter_map(|c| c.subnet)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            DiscoveredNetwork {
                name: rn.name,
                driver: rn.driver,
                subnets,
            }
        })
        .collect();
    networks.sort_by(|a, b| a.name.cmp(&b.name));

    Ok((containers, networks))
}
