//! Endpoints for global `firewall.settings` parameters, zone rules (`fw_zone_rules`),
//! and Docker inter-container rules (`fw_docker_inter_rules`).

use std::collections::BTreeMap;

use axum::Extension;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use sea_orm::{ActiveModelTrait, EntityTrait, QueryOrder, Set};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::audit::record_audit;
use crate::docker::discover_docker;
use crate::entities::{api_key, fw_docker_inter_rule, fw_settings, fw_zone_rule};
use crate::error::AppError;
use crate::extract::{StrictJson, StrictPath};
use crate::input_validation::{
    validate_country_codes, validate_dnat_spec, validate_docker_endpoint,
    validate_docker_inter_rule, validate_docker_name, validate_hook_name, validate_http_url,
    validate_interface_name, validate_interface_spec, validate_ip_or_cidr, validate_safe_path,
    validate_zone_rule_value,
};
use crate::middleware::ClientIp;
use crate::state::AppState;

const VALID_ZONES: &[&str] = &["ip_autor", "internal", "local", "open", "ww"];
const VALID_RULE_KINDS: &[&str] = &[
    "OpenPortsTCP",
    "OpenPortsUDP",
    "RedirectPortTCP",
    "RedirectPortUDP",
    "DnatPortTCP",
    "DnatPortUDP",
    "DockerTCP",
    "DockerUDP",
];

fn ensure_can_manage_settings(caller: &api_key::Model) -> Result<(), AppError> {
    if caller.is_master || caller.can_manage_settings.is_granted() {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "Missing can_manage_settings permission".to_owned(),
        ))
    }
}

/// Serialized representation of global `firewall.settings` configuration.
#[derive(Debug, Serialize)]
pub struct FwSettingsResponse {
    /// Primary outbound network interface (`mainInter`).
    pub main_inter: String,
    /// Outbound NAT interfaces (`INTEROut`).
    pub inter_out: Vec<String>,
    /// Outbound-routed interfaces (`interfaceToGoOutSide`).
    pub interface_to_go_outside: Vec<String>,
    /// Internal interfaces with local access (`internInterfaceHaveAccessAsLocal`).
    pub intern_interface_have_access_as_local: Vec<String>,
    /// Local host interfaces (`interfaceLocal`).
    pub interface_local: Vec<String>,
    /// DHCP flag per interface (`interfaceWithDHCP`).
    pub interface_with_dhcp: BTreeMap<String, bool>,
    /// Unfiltered interfaces (`interfaceWithNoRules`).
    pub interface_with_no_rules: Vec<String>,
    /// Docker networks with Internet egress (`dockerNetworkWithInternetAccess`).
    pub docker_network_with_internet_access: Vec<String>,
    /// Docker networks with host access (`dockerNetworkWithAccess`).
    pub docker_network_with_access: Vec<String>,
    /// Trusted administrator IP/CIDRs (`IPAutor`).
    pub ip_autor: Vec<String>,
    /// Trusted DNAT TCP rules (`IPAutorDnatPortTCP`).
    pub ip_autor_dnat_port_tcp: Vec<String>,
    /// Trusted DNAT UDP rules (`IPAutorDnatPortUDP`).
    pub ip_autor_dnat_port_udp: Vec<String>,
    /// GeoIP-allowed country codes (`countryOpenPort`).
    pub country_open_port: String,
    /// Primary GeoIP-blocked country codes (`blockedCountry`).
    pub blocked_country: String,
    /// Secondary GeoIP-blocked country codes (`blockedCountry2`).
    pub blocked_country_2: String,
    /// Docker daemon discovery endpoint.
    pub docker_endpoint: String,
    /// Target directory where generated scripts are written.
    pub output_dir: String,
    /// Host path to `firewall.tools`.
    pub tools_script_path: String,
    /// Base URL of `simply_hook_executor`.
    pub hook_executor_url: Option<String>,
    /// Whether an encrypted `simply_hook_executor` API key is stored.
    pub has_hook_api_key: bool,
    /// Whether an encrypted `simply_hook_executor` signing secret is stored.
    pub has_hook_signing_secret: bool,
    /// Hook name triggered for firewall reload.
    pub hook_reload_name: String,
    /// Hook name triggered for Docker container sync.
    pub hook_update_containers_name: String,
    /// UTC timestamp of the last update.
    pub updated_at: DateTime<Utc>,
}

impl From<fw_settings::Model> for FwSettingsResponse {
    fn from(m: fw_settings::Model) -> Self {
        Self {
            main_inter: m.main_inter,
            inter_out: serde_json::from_str(&m.inter_out_json).unwrap_or_default(),
            interface_to_go_outside: serde_json::from_str(&m.interface_to_go_outside_json)
                .unwrap_or_default(),
            intern_interface_have_access_as_local: serde_json::from_str(
                &m.intern_interface_have_access_as_local_json,
            )
            .unwrap_or_default(),
            interface_local: serde_json::from_str(&m.interface_local_json).unwrap_or_default(),
            interface_with_dhcp: serde_json::from_str(&m.interface_with_dhcp_json)
                .unwrap_or_default(),
            interface_with_no_rules: serde_json::from_str(&m.interface_with_no_rules_json)
                .unwrap_or_default(),
            docker_network_with_internet_access: serde_json::from_str(
                &m.docker_network_with_internet_access_json,
            )
            .unwrap_or_default(),
            docker_network_with_access: serde_json::from_str(&m.docker_network_with_access_json)
                .unwrap_or_default(),
            ip_autor: serde_json::from_str(&m.ip_autor_json).unwrap_or_default(),
            ip_autor_dnat_port_tcp: serde_json::from_str(&m.ip_autor_dnat_port_tcp_json)
                .unwrap_or_default(),
            ip_autor_dnat_port_udp: serde_json::from_str(&m.ip_autor_dnat_port_udp_json)
                .unwrap_or_default(),
            country_open_port: m.country_open_port,
            blocked_country: m.blocked_country,
            blocked_country_2: m.blocked_country_2,
            docker_endpoint: m.docker_endpoint,
            output_dir: m.output_dir,
            tools_script_path: m.tools_script_path,
            hook_executor_url: m.hook_executor_url,
            has_hook_api_key: m
                .hook_executor_api_key
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty()),
            has_hook_signing_secret: m
                .hook_executor_signing_secret
                .as_deref()
                .is_some_and(|s| !s.is_empty()),
            hook_reload_name: m.hook_reload_name,
            hook_update_containers_name: m.hook_update_containers_name,
            updated_at: m.updated_at,
        }
    }
}

/// Request payload for `PUT /api/firewall/settings`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateFwSettingsRequest {
    /// Updated `mainInter`.
    pub main_inter: Option<String>,
    /// Updated `INTEROut` list.
    pub inter_out: Option<Vec<String>>,
    /// Updated `interfaceToGoOutSide` list.
    pub interface_to_go_outside: Option<Vec<String>>,
    /// Updated `internInterfaceHaveAccessAsLocal` list.
    pub intern_interface_have_access_as_local: Option<Vec<String>>,
    /// Updated `interfaceLocal` list.
    pub interface_local: Option<Vec<String>>,
    /// Updated `interfaceWithDHCP` flags.
    pub interface_with_dhcp: Option<BTreeMap<String, bool>>,
    /// Updated `interfaceWithNoRules` list.
    pub interface_with_no_rules: Option<Vec<String>>,
    /// Updated `dockerNetworkWithInternetAccess` list.
    pub docker_network_with_internet_access: Option<Vec<String>>,
    /// Updated `dockerNetworkWithAccess` list.
    pub docker_network_with_access: Option<Vec<String>>,
    /// Updated `IPAutor` allowlist.
    pub ip_autor: Option<Vec<String>>,
    /// Updated `IPAutorDnatPortTCP` list.
    pub ip_autor_dnat_port_tcp: Option<Vec<String>>,
    /// Updated `IPAutorDnatPortUDP` list.
    pub ip_autor_dnat_port_udp: Option<Vec<String>>,
    /// Updated `countryOpenPort` codes.
    pub country_open_port: Option<String>,
    /// Updated `blockedCountry` codes.
    pub blocked_country: Option<String>,
    /// Updated `blockedCountry2` codes.
    pub blocked_country_2: Option<String>,
    /// Updated Docker daemon endpoint.
    pub docker_endpoint: Option<String>,
    /// Updated generated output directory.
    pub output_dir: Option<String>,
    /// Updated `firewall.tools` script path.
    pub tools_script_path: Option<String>,
    /// Updated `simply_hook_executor` URL.
    pub hook_executor_url: Option<String>,
    /// New `simply_hook_executor` API key (empty string preserves existing).
    pub hook_executor_api_key: Option<String>,
    /// New `simply_hook_executor` signing secret (empty string preserves existing).
    pub hook_executor_signing_secret: Option<String>,
    /// Updated firewall reload hook name.
    pub hook_reload_name: Option<String>,
    /// Updated container sync hook name.
    pub hook_update_containers_name: Option<String>,
}

fn validate_string_list<F>(items: Vec<String>, validator: F) -> Result<Vec<String>, AppError>
where
    F: Fn(&str) -> Result<String, AppError>,
{
    let mut out = Vec::new();
    for raw in items {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        out.push(validator(trimmed)?);
    }
    Ok(out)
}

/// `GET /api/firewall/settings` — Retrieve global firewall settings.
///
/// # Errors
/// Returns [`AppError`] if the caller lacks permissions or the database lookup fails.
pub async fn get_settings(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
) -> Result<Json<FwSettingsResponse>, AppError> {
    ensure_can_manage_settings(&caller)?;
    let model = fw_settings::Entity::find_by_id(1)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(FwSettingsResponse::from(model)))
}

fn apply_interface_settings(
    active: &mut fw_settings::ActiveModel,
    payload: UpdateFwSettingsRequest,
) -> Result<UpdateFwSettingsRequest, AppError> {
    let mut rest = payload;
    if let Some(main_inter) = rest.main_inter.take() {
        active.main_inter = Set(validate_interface_name("main_inter", &main_inter)?);
    }
    if let Some(v) = rest.inter_out.take() {
        let valid = validate_string_list(v, |s| validate_interface_spec("inter_out", s))?;
        active.inter_out_json =
            Set(serde_json::to_string(&valid).unwrap_or_else(|_| "[]".to_owned()));
    }
    if let Some(v) = rest.interface_to_go_outside.take() {
        let valid =
            validate_string_list(v, |s| validate_interface_spec("interface_to_go_outside", s))?;
        active.interface_to_go_outside_json =
            Set(serde_json::to_string(&valid).unwrap_or_else(|_| "[]".to_owned()));
    }
    if let Some(v) = rest.intern_interface_have_access_as_local.take() {
        let valid = validate_string_list(v, |s| {
            validate_interface_spec("intern_interface_have_access_as_local", s)
        })?;
        active.intern_interface_have_access_as_local_json =
            Set(serde_json::to_string(&valid).unwrap_or_else(|_| "[]".to_owned()));
    }
    if let Some(v) = rest.interface_local.take() {
        let valid = validate_string_list(v, |s| validate_interface_spec("interface_local", s))?;
        active.interface_local_json =
            Set(serde_json::to_string(&valid).unwrap_or_else(|_| "[]".to_owned()));
    }
    if let Some(v) = rest.interface_with_dhcp.take() {
        let mut clean_map = BTreeMap::new();
        for (iface, enabled) in v {
            let clean_iface = validate_interface_spec("interface_with_dhcp", &iface)?;
            clean_map.insert(clean_iface, enabled);
        }
        active.interface_with_dhcp_json =
            Set(serde_json::to_string(&clean_map).unwrap_or_else(|_| "{}".to_owned()));
    }
    if let Some(v) = rest.interface_with_no_rules.take() {
        let valid =
            validate_string_list(v, |s| validate_interface_spec("interface_with_no_rules", s))?;
        active.interface_with_no_rules_json =
            Set(serde_json::to_string(&valid).unwrap_or_else(|_| "[]".to_owned()));
    }
    Ok(rest)
}

fn apply_network_and_country_settings(
    active: &mut fw_settings::ActiveModel,
    payload: &mut UpdateFwSettingsRequest,
) -> Result<(), AppError> {
    if let Some(v) = payload.docker_network_with_internet_access.take() {
        let valid = validate_string_list(v, |s| {
            validate_docker_name("docker_network_with_internet_access", s)
        })?;
        active.docker_network_with_internet_access_json =
            Set(serde_json::to_string(&valid).unwrap_or_else(|_| "[]".to_owned()));
    }
    if let Some(v) = payload.docker_network_with_access.take() {
        let valid =
            validate_string_list(v, |s| validate_docker_name("docker_network_with_access", s))?;
        active.docker_network_with_access_json =
            Set(serde_json::to_string(&valid).unwrap_or_else(|_| "[]".to_owned()));
    }
    if let Some(v) = payload.ip_autor.take() {
        let valid = validate_string_list(v, |s| validate_ip_or_cidr("ip_autor", s))?;
        active.ip_autor_json =
            Set(serde_json::to_string(&valid).unwrap_or_else(|_| "[]".to_owned()));
    }
    if let Some(v) = payload.ip_autor_dnat_port_tcp.take() {
        let valid = validate_string_list(v, |s| validate_dnat_spec("ip_autor_dnat_port_tcp", s))?;
        active.ip_autor_dnat_port_tcp_json =
            Set(serde_json::to_string(&valid).unwrap_or_else(|_| "[]".to_owned()));
    }
    if let Some(v) = payload.ip_autor_dnat_port_udp.take() {
        let valid = validate_string_list(v, |s| validate_dnat_spec("ip_autor_dnat_port_udp", s))?;
        active.ip_autor_dnat_port_udp_json =
            Set(serde_json::to_string(&valid).unwrap_or_else(|_| "[]".to_owned()));
    }
    if let Some(v) = payload.country_open_port.take() {
        active.country_open_port = Set(validate_country_codes("country_open_port", &v)?);
    }
    if let Some(v) = payload.blocked_country.take() {
        active.blocked_country = Set(validate_country_codes("blocked_country", &v)?);
    }
    if let Some(v) = payload.blocked_country_2.take() {
        active.blocked_country_2 = Set(validate_country_codes("blocked_country_2", &v)?);
    }
    Ok(())
}

fn apply_infra_and_hook_settings(
    state: &AppState,
    active: &mut fw_settings::ActiveModel,
    payload: &mut UpdateFwSettingsRequest,
) -> Result<(), AppError> {
    if let Some(v) = payload.docker_endpoint.take() {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            active.docker_endpoint = Set(validate_docker_endpoint(trimmed)?);
        }
    }
    if let Some(v) = payload.output_dir.take() {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            active.output_dir = Set(validate_safe_path("output_dir", trimmed)?);
        }
    }
    if let Some(v) = payload.tools_script_path.take() {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            active.tools_script_path = Set(validate_safe_path("tools_script_path", trimmed)?);
        }
    }
    if let Some(v) = payload.hook_executor_url.take() {
        let trimmed = v.trim();
        if trimmed.is_empty() {
            active.hook_executor_url = Set(None);
        } else {
            active.hook_executor_url = Set(Some(validate_http_url("hook_executor_url", trimmed)?));
        }
    }
    if let Some(v) = payload.hook_executor_api_key.take() {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            active.hook_executor_api_key = Set(Some(state.cipher.seal(trimmed)?));
        }
    }
    if let Some(v) = payload.hook_executor_signing_secret.take() {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            active.hook_executor_signing_secret = Set(Some(state.cipher.seal(trimmed)?));
        }
    }
    if let Some(v) = payload.hook_reload_name.take() {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            active.hook_reload_name = Set(validate_hook_name("hook_reload_name", trimmed)?);
        }
    }
    if let Some(v) = payload.hook_update_containers_name.take() {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            active.hook_update_containers_name =
                Set(validate_hook_name("hook_update_containers_name", trimmed)?);
        }
    }
    Ok(())
}

/// `PUT /api/firewall/settings` — Update global firewall settings.
///
/// # Errors
/// Returns [`AppError`] if the caller lacks permissions or inputs are invalid.
pub async fn update_settings(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictJson(payload): StrictJson<UpdateFwSettingsRequest>,
) -> Result<Json<FwSettingsResponse>, AppError> {
    ensure_can_manage_settings(&caller)?;

    let existing = fw_settings::Entity::find_by_id(1)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    let mut active: fw_settings::ActiveModel = existing.into();
    let mut rest = apply_interface_settings(&mut active, payload)?;
    apply_network_and_country_settings(&mut active, &mut rest)?;
    apply_infra_and_hook_settings(&state, &mut active, &mut rest)?;

    active.updated_at = Set(Utc::now());
    let updated = active.update(&state.db).await?;

    record_audit(
        &state.db,
        &caller,
        client_ip,
        "UPDATE_SETTINGS",
        Some("fw_settings:1".to_owned()),
        Some("Updated global firewall.settings parameters".to_owned()),
    )
    .await?;

    Ok(Json(FwSettingsResponse::from(updated)))
}

/// Serialized zone rule with live Docker status.
#[derive(Debug, Serialize)]
pub struct ZoneRuleResponse {
    /// Zone rule UUID.
    pub id: Uuid,
    /// Target firewall zone (`ip_autor`, `internal`, `local`, `open`, `ww`).
    pub zone: String,
    /// Rule kind (`OpenPortsTCP`, `DockerTCP`, etc.).
    pub rule_kind: String,
    /// Rule parameter string.
    pub value: String,
    /// Target container name for Docker rules.
    pub container_name: Option<String>,
    /// Live container state reported by Docker discovery.
    pub container_status: Option<String>,
    /// Whether the rule is active.
    pub enabled: bool,
    /// Optional operator comment.
    pub comment: Option<String>,
    /// Sort index within the zone.
    pub sort_order: i32,
    /// UTC creation timestamp.
    pub created_at: DateTime<Utc>,
    /// UTC modification timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Request payload for creating/updating a zone rule.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpsertZoneRuleRequest {
    /// Target firewall zone.
    pub zone: String,
    /// Rule kind.
    pub rule_kind: String,
    /// Rule specification value.
    pub value: String,
    /// Whether the rule is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Optional operator comment.
    pub comment: Option<String>,
    /// Ordering priority.
    #[serde(default)]
    pub sort_order: i32,
}

const fn default_true() -> bool {
    true
}

/// `GET /api/firewall/zones` — List all zone rules enriched with live Docker container state.
///
/// # Errors
/// Returns [`AppError`] if the caller lacks permissions or the database lookup fails.
pub async fn list_zone_rules(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
) -> Result<Json<Vec<ZoneRuleResponse>>, AppError> {
    ensure_can_manage_settings(&caller)?;
    let settings = fw_settings::Entity::find_by_id(1).one(&state.db).await?;
    let endpoint = settings
        .as_ref()
        .map_or("unix:///var/run/docker.sock", |s| {
            s.docker_endpoint.as_str()
        });
    let docker = discover_docker(&state.http, endpoint).await;

    let rules = fw_zone_rule::Entity::find()
        .order_by_asc(fw_zone_rule::Column::SortOrder)
        .all(&state.db)
        .await?;

    let out = rules
        .into_iter()
        .map(|r| {
            let status = r
                .container_name
                .as_deref()
                .map(|c| docker.container_status(c).to_owned());
            ZoneRuleResponse {
                id: r.id,
                zone: r.zone,
                rule_kind: r.rule_kind,
                value: r.value,
                container_name: r.container_name,
                container_status: status,
                enabled: r.enabled,
                comment: r.comment,
                sort_order: r.sort_order,
                created_at: r.created_at,
                updated_at: r.updated_at,
            }
        })
        .collect();
    Ok(Json(out))
}

/// `POST /api/firewall/zones` — Create a zone rule.
///
/// # Errors
/// Returns [`AppError`] if the caller lacks permissions or inputs are invalid.
pub async fn create_zone_rule(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictJson(payload): StrictJson<UpsertZoneRuleRequest>,
) -> Result<(StatusCode, Json<ZoneRuleResponse>), AppError> {
    ensure_can_manage_settings(&caller)?;

    let zone = payload.zone.trim().to_owned();
    if !VALID_ZONES.contains(&zone.as_str()) {
        return Err(AppError::InvalidInput(format!(
            "Invalid zone '{zone}'; expected one of {VALID_ZONES:?}"
        )));
    }
    let rule_kind = payload.rule_kind.trim().to_owned();
    if !VALID_RULE_KINDS.contains(&rule_kind.as_str()) {
        return Err(AppError::InvalidInput(format!(
            "Invalid rule_kind '{rule_kind}'; expected one of {VALID_RULE_KINDS:?}"
        )));
    }
    if zone == "ip_autor" && rule_kind != "DockerTCP" && rule_kind != "DockerUDP" {
        return Err(AppError::InvalidInput(
            "Zone 'ip_autor' only supports DockerTCP and DockerUDP zone rules (use IPAutor settings for DNAT/trusted IPs)"
                .to_owned(),
        ));
    }
    let (value, container_name) = validate_zone_rule_value(&rule_kind, &payload.value)?;

    let now = Utc::now();
    let id = Uuid::new_v4();
    let model = fw_zone_rule::ActiveModel {
        id: Set(id),
        zone: Set(zone.clone()),
        rule_kind: Set(rule_kind.clone()),
        value: Set(value.clone()),
        container_name: Set(container_name.clone()),
        enabled: Set(payload.enabled),
        comment: Set(payload
            .comment
            .map(|c| c.trim().to_owned())
            .filter(|c| !c.is_empty())),
        sort_order: Set(payload.sort_order),
        created_at: Set(now),
        updated_at: Set(now),
    };
    let inserted = model.insert(&state.db).await?;

    record_audit(
        &state.db,
        &caller,
        client_ip,
        "CREATE_ZONE_RULE",
        Some(id.to_string()),
        Some(format!("Created zone rule {zone}:{rule_kind}={value}")),
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(ZoneRuleResponse {
            id: inserted.id,
            zone: inserted.zone,
            rule_kind: inserted.rule_kind,
            value: inserted.value,
            container_name: inserted.container_name,
            container_status: None,
            enabled: inserted.enabled,
            comment: inserted.comment,
            sort_order: inserted.sort_order,
            created_at: inserted.created_at,
            updated_at: inserted.updated_at,
        }),
    ))
}

/// `PUT /api/firewall/zones/{id}` — Update an existing zone rule.
///
/// # Errors
/// Returns [`AppError`] if the rule is not found or inputs are invalid.
pub async fn update_zone_rule(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
    StrictJson(payload): StrictJson<UpsertZoneRuleRequest>,
) -> Result<Json<ZoneRuleResponse>, AppError> {
    ensure_can_manage_settings(&caller)?;

    let existing = fw_zone_rule::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    let zone = payload.zone.trim().to_owned();
    if !VALID_ZONES.contains(&zone.as_str()) {
        return Err(AppError::InvalidInput(format!("Invalid zone '{zone}'")));
    }
    let rule_kind = payload.rule_kind.trim().to_owned();
    if !VALID_RULE_KINDS.contains(&rule_kind.as_str()) {
        return Err(AppError::InvalidInput(format!(
            "Invalid rule_kind '{rule_kind}'"
        )));
    }
    if zone == "ip_autor" && rule_kind != "DockerTCP" && rule_kind != "DockerUDP" {
        return Err(AppError::InvalidInput(
            "Zone 'ip_autor' only supports DockerTCP and DockerUDP zone rules (use IPAutor settings for DNAT/trusted IPs)"
                .to_owned(),
        ));
    }
    let (value, container_name) = validate_zone_rule_value(&rule_kind, &payload.value)?;

    let mut active: fw_zone_rule::ActiveModel = existing.into();
    active.zone = Set(zone.clone());
    active.rule_kind = Set(rule_kind.clone());
    active.value = Set(value.clone());
    active.container_name = Set(container_name);
    active.enabled = Set(payload.enabled);
    active.comment = Set(payload
        .comment
        .map(|c| c.trim().to_owned())
        .filter(|c| !c.is_empty()));
    active.sort_order = Set(payload.sort_order);
    active.updated_at = Set(Utc::now());

    let updated = active.update(&state.db).await?;

    record_audit(
        &state.db,
        &caller,
        client_ip,
        "UPDATE_ZONE_RULE",
        Some(id.to_string()),
        Some(format!(
            "Updated zone rule {zone}:{rule_kind}={value} (enabled={})",
            updated.enabled
        )),
    )
    .await?;

    Ok(Json(ZoneRuleResponse {
        id: updated.id,
        zone: updated.zone,
        rule_kind: updated.rule_kind,
        value: updated.value,
        container_name: updated.container_name,
        container_status: None,
        enabled: updated.enabled,
        comment: updated.comment,
        sort_order: updated.sort_order,
        created_at: updated.created_at,
        updated_at: updated.updated_at,
    }))
}

/// `DELETE /api/firewall/zones/{id}` — Delete a zone rule.
///
/// # Errors
/// Returns [`AppError`] if the rule does not exist.
pub async fn delete_zone_rule(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
) -> Result<StatusCode, AppError> {
    ensure_can_manage_settings(&caller)?;

    let existing = fw_zone_rule::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    fw_zone_rule::Entity::delete_by_id(id)
        .exec(&state.db)
        .await?;

    record_audit(
        &state.db,
        &caller,
        client_ip,
        "DELETE_ZONE_RULE",
        Some(id.to_string()),
        Some(format!(
            "Deleted zone rule {}:{}={}",
            existing.zone, existing.rule_kind, existing.value
        )),
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Serialized inter-container flow rule (`dockerAccessBetweenThem`).
#[derive(Debug, Serialize)]
pub struct DockerInterRuleResponse {
    /// Inter-container rule UUID.
    pub id: Uuid,
    /// Source container name.
    pub source_container: String,
    /// Live Docker status of the source container.
    pub source_status: String,
    /// Destination container name.
    pub destination_container: String,
    /// Live Docker status of the destination container.
    pub destination_status: String,
    /// Shared Docker bridge network name.
    pub network_name: String,
    /// Transport protocol (`tcp` or `udp`).
    pub proto: String,
    /// Semicolon-delimited destination ports or ranges.
    pub ports: String,
    /// Whether the rule is active.
    pub enabled: bool,
    /// Optional operator comment.
    pub comment: Option<String>,
    /// Ordering priority.
    pub sort_order: i32,
    /// UTC creation timestamp.
    pub created_at: DateTime<Utc>,
    /// UTC modification timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Request payload for creating/updating a Docker inter-container rule.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpsertDockerInterRuleRequest {
    /// Source container name.
    pub source_container: String,
    /// Destination container name.
    pub destination_container: String,
    /// Shared Docker network name.
    pub network_name: String,
    /// Transport protocol (`tcp` or `udp`).
    pub proto: String,
    /// Semicolon-separated destination ports or ranges.
    pub ports: String,
    /// Whether the rule is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Optional operator comment.
    pub comment: Option<String>,
    /// Ordering priority.
    #[serde(default)]
    pub sort_order: i32,
}

/// `GET /api/firewall/docker-rules` — List all inter-container rules with live container statuses.
///
/// # Errors
/// Returns [`AppError`] if the caller lacks permissions or the database lookup fails.
pub async fn list_docker_inter_rules(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
) -> Result<Json<Vec<DockerInterRuleResponse>>, AppError> {
    ensure_can_manage_settings(&caller)?;
    let settings = fw_settings::Entity::find_by_id(1).one(&state.db).await?;
    let endpoint = settings
        .as_ref()
        .map_or("unix:///var/run/docker.sock", |s| {
            s.docker_endpoint.as_str()
        });
    let docker = discover_docker(&state.http, endpoint).await;

    let rules = fw_docker_inter_rule::Entity::find()
        .order_by_asc(fw_docker_inter_rule::Column::SortOrder)
        .all(&state.db)
        .await?;

    let out = rules
        .into_iter()
        .map(|r| {
            let src_status = docker.container_status(&r.source_container).to_owned();
            let dst_status = docker.container_status(&r.destination_container).to_owned();
            DockerInterRuleResponse {
                id: r.id,
                source_container: r.source_container,
                source_status: src_status,
                destination_container: r.destination_container,
                destination_status: dst_status,
                network_name: r.network_name,
                proto: r.proto,
                ports: r.ports,
                enabled: r.enabled,
                comment: r.comment,
                sort_order: r.sort_order,
                created_at: r.created_at,
                updated_at: r.updated_at,
            }
        })
        .collect();
    Ok(Json(out))
}

/// `POST /api/firewall/docker-rules` — Create an inter-container rule.
///
/// # Errors
/// Returns [`AppError`] if inputs are invalid.
pub async fn create_docker_inter_rule(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictJson(payload): StrictJson<UpsertDockerInterRuleRequest>,
) -> Result<(StatusCode, Json<DockerInterRuleResponse>), AppError> {
    ensure_can_manage_settings(&caller)?;

    let (src, dst, net, proto, ports) = validate_docker_inter_rule(
        &payload.source_container,
        &payload.destination_container,
        &payload.network_name,
        &payload.proto,
        &payload.ports,
    )?;

    let now = Utc::now();
    let id = Uuid::new_v4();
    let model = fw_docker_inter_rule::ActiveModel {
        id: Set(id),
        source_container: Set(src.clone()),
        destination_container: Set(dst.clone()),
        network_name: Set(net.clone()),
        proto: Set(proto.clone()),
        ports: Set(ports.clone()),
        enabled: Set(payload.enabled),
        comment: Set(payload
            .comment
            .map(|c| c.trim().to_owned())
            .filter(|c| !c.is_empty())),
        sort_order: Set(payload.sort_order),
        created_at: Set(now),
        updated_at: Set(now),
    };
    let inserted = model.insert(&state.db).await?;

    record_audit(
        &state.db,
        &caller,
        client_ip,
        "CREATE_DOCKER_RULE",
        Some(id.to_string()),
        Some(format!(
            "Created Docker rule {src};{dst};{net};{proto};{ports}"
        )),
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(DockerInterRuleResponse {
            id: inserted.id,
            source_container: inserted.source_container,
            source_status: "unknown".to_owned(),
            destination_container: inserted.destination_container,
            destination_status: "unknown".to_owned(),
            network_name: inserted.network_name,
            proto: inserted.proto,
            ports: inserted.ports,
            enabled: inserted.enabled,
            comment: inserted.comment,
            sort_order: inserted.sort_order,
            created_at: inserted.created_at,
            updated_at: inserted.updated_at,
        }),
    ))
}

/// `PUT /api/firewall/docker-rules/{id}` — Update an inter-container rule.
///
/// # Errors
/// Returns [`AppError`] if the rule is not found or inputs are invalid.
pub async fn update_docker_inter_rule(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
    StrictJson(payload): StrictJson<UpsertDockerInterRuleRequest>,
) -> Result<Json<DockerInterRuleResponse>, AppError> {
    ensure_can_manage_settings(&caller)?;

    let existing = fw_docker_inter_rule::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    let (src, dst, net, proto, ports) = validate_docker_inter_rule(
        &payload.source_container,
        &payload.destination_container,
        &payload.network_name,
        &payload.proto,
        &payload.ports,
    )?;

    let mut active: fw_docker_inter_rule::ActiveModel = existing.into();
    active.source_container = Set(src.clone());
    active.destination_container = Set(dst.clone());
    active.network_name = Set(net.clone());
    active.proto = Set(proto.clone());
    active.ports = Set(ports.clone());
    active.enabled = Set(payload.enabled);
    active.comment = Set(payload
        .comment
        .map(|c| c.trim().to_owned())
        .filter(|c| !c.is_empty()));
    active.sort_order = Set(payload.sort_order);
    active.updated_at = Set(Utc::now());

    let updated = active.update(&state.db).await?;

    record_audit(
        &state.db,
        &caller,
        client_ip,
        "UPDATE_DOCKER_RULE",
        Some(id.to_string()),
        Some(format!(
            "Updated Docker rule {src};{dst};{net};{proto};{ports} (enabled={})",
            updated.enabled
        )),
    )
    .await?;

    Ok(Json(DockerInterRuleResponse {
        id: updated.id,
        source_container: updated.source_container,
        source_status: "unknown".to_owned(),
        destination_container: updated.destination_container,
        destination_status: "unknown".to_owned(),
        network_name: updated.network_name,
        proto: updated.proto,
        ports: updated.ports,
        enabled: updated.enabled,
        comment: updated.comment,
        sort_order: updated.sort_order,
        created_at: updated.created_at,
        updated_at: updated.updated_at,
    }))
}

/// `DELETE /api/firewall/docker-rules/{id}` — Delete an inter-container rule.
///
/// # Errors
/// Returns [`AppError`] if the rule does not exist.
pub async fn delete_docker_inter_rule(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
) -> Result<StatusCode, AppError> {
    ensure_can_manage_settings(&caller)?;

    let existing = fw_docker_inter_rule::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    fw_docker_inter_rule::Entity::delete_by_id(id)
        .exec(&state.db)
        .await?;

    record_audit(
        &state.db,
        &caller,
        client_ip,
        "DELETE_DOCKER_RULE",
        Some(id.to_string()),
        Some(format!(
            "Deleted Docker rule {};{};{};{};{}",
            existing.source_container,
            existing.destination_container,
            existing.network_name,
            existing.proto,
            existing.ports
        )),
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}
