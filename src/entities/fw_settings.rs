//! `fw_settings` singleton entity model (`id = 1`).

use sea_orm::entity::prelude::*;

/// The `fw_settings` singleton row.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "fw_settings")]
pub struct Model {
    /// Singleton primary key (`1`).
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: i32,
    /// Primary external network interface (`mainInter`, e.g. `"out"`).
    pub main_inter: String,
    /// JSON array of `"iface;ipv4_cidr;ipv6_cidr"` (`INTEROut`).
    #[sea_orm(column_type = "Text")]
    pub inter_out_json: String,
    /// JSON array of `"iface;ipv4_cidr;ipv6_cidr"` (`interfaceToGoOutSide`).
    #[sea_orm(column_type = "Text")]
    pub interface_to_go_outside_json: String,
    /// JSON array of `"iface;ipv4_cidr;ipv6_cidr"` (`internInterfaceHaveAccessAsLocal`).
    #[sea_orm(column_type = "Text")]
    pub intern_interface_have_access_as_local_json: String,
    /// JSON array of `"iface;ipv4_cidr;ipv6_cidr"` (`interfaceLocal`).
    #[sea_orm(column_type = "Text")]
    pub interface_local_json: String,
    /// JSON object mapping `"iface;ipv4_cidr;ipv6_cidr"` to `bool` (`interfaceWithDHCP`).
    #[sea_orm(column_type = "Text")]
    pub interface_with_dhcp_json: String,
    /// JSON array of `"iface;ipv4_cidr;ipv6_cidr"` (`interfaceWithNoRules`).
    #[sea_orm(column_type = "Text")]
    pub interface_with_no_rules_json: String,
    /// JSON array of Docker network names (`dockerNetworkWithInternetAccess`).
    #[sea_orm(column_type = "Text")]
    pub docker_network_with_internet_access_json: String,
    /// JSON array of Docker network names (`dockerNetworkWithAccess`).
    #[sea_orm(column_type = "Text")]
    pub docker_network_with_access_json: String,
    /// JSON array of trusted IPv4/IPv6 addresses (`IPAutor`).
    #[sea_orm(column_type = "Text")]
    pub ip_autor_json: String,
    /// JSON array of `"port,iface,ipv4,ipv6,dest_port"` (`IPAutorDnatPortTCP`).
    #[sea_orm(column_type = "Text")]
    pub ip_autor_dnat_port_tcp_json: String,
    /// JSON array of `"port,iface,ipv4,ipv6,dest_port"` (`IPAutorDnatPortUDP`).
    #[sea_orm(column_type = "Text")]
    pub ip_autor_dnat_port_udp_json: String,
    /// Comma-separated ISO country codes (`countryOpenPort`, e.g. `"FR,CH"`).
    pub country_open_port: String,
    /// Comma-separated ISO country codes (`blockedCountry`).
    pub blocked_country: String,
    /// Comma-separated ISO country codes (`blockedCountry2`).
    pub blocked_country_2: String,
    /// Docker daemon endpoint (`unix:///var/run/docker.sock` or `http://...:2375`).
    pub docker_endpoint: String,
    /// Target directory where `firewall.settings`, `firewall.rules.special`, `firewall.get.list` are written.
    pub output_dir: String,
    /// Path to `firewall.tools` for parsing utility function documentation and constants.
    pub tools_script_path: String,
    /// Optional base URL of `simply_hook_executor`.
    pub hook_executor_url: Option<String>,
    /// Optional API key for `simply_hook_executor`.
    pub hook_executor_api_key: Option<String>,
    /// Optional `SecretCipher`-sealed signing secret for `simply_hook_executor`.
    pub hook_executor_signing_secret: Option<String>,
    /// Hook name in `simply_hook_executor` to reload the firewall.
    pub hook_reload_name: String,
    /// Hook name in `simply_hook_executor` to update Docker containers.
    pub hook_update_containers_name: String,
    /// Last update timestamp.
    pub updated_at: DateTimeUtc,
}

/// Relations from `fw_settings`.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
