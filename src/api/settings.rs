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
    if caller.is_master || caller.can_manage_settings {
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
    pub main_inter: String,
    pub inter_out: Vec<String>,
    pub interface_to_go_outside: Vec<String>,
    pub intern_interface_have_access_as_local: Vec<String>,
    pub interface_local: Vec<String>,
    pub interface_with_dhcp: BTreeMap<String, bool>,
    pub interface_with_no_rules: Vec<String>,
    pub docker_network_with_internet_access: Vec<String>,
    pub docker_network_with_access: Vec<String>,
    pub ip_autor: Vec<String>,
    pub ip_autor_dnat_port_tcp: Vec<String>,
    pub ip_autor_dnat_port_udp: Vec<String>,
    pub country_open_port: String,
    pub blocked_country: String,
    pub blocked_country_2: String,
    pub docker_endpoint: String,
    pub output_dir: String,
    pub tools_script_path: String,
    pub hook_executor_url: Option<String>,
    pub hook_executor_api_key: Option<String>,
    pub has_hook_signing_secret: bool,
    pub hook_reload_name: String,
    pub hook_update_containers_name: String,
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
            hook_executor_api_key: m.hook_executor_api_key,
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
    pub main_inter: Option<String>,
    pub inter_out: Option<Vec<String>>,
    pub interface_to_go_outside: Option<Vec<String>>,
    pub intern_interface_have_access_as_local: Option<Vec<String>>,
    pub interface_local: Option<Vec<String>>,
    pub interface_with_dhcp: Option<BTreeMap<String, bool>>,
    pub interface_with_no_rules: Option<Vec<String>>,
    pub docker_network_with_internet_access: Option<Vec<String>>,
    pub docker_network_with_access: Option<Vec<String>>,
    pub ip_autor: Option<Vec<String>>,
    pub ip_autor_dnat_port_tcp: Option<Vec<String>>,
    pub ip_autor_dnat_port_udp: Option<Vec<String>>,
    pub country_open_port: Option<String>,
    pub blocked_country: Option<String>,
    pub blocked_country_2: Option<String>,
    pub docker_endpoint: Option<String>,
    pub output_dir: Option<String>,
    pub tools_script_path: Option<String>,
    pub hook_executor_url: Option<String>,
    pub hook_executor_api_key: Option<String>,
    pub hook_executor_signing_secret: Option<String>,
    pub hook_reload_name: Option<String>,
    pub hook_update_containers_name: Option<String>,
}

fn sanitize_string_list(items: Vec<String>) -> Vec<String> {
    items
        .into_iter()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect()
}

/// `GET /api/firewall/settings` — Retrieve global firewall settings.
///
/// # Errors
/// Returns [`AppError`] if the database lookup fails.
pub async fn get_settings(
    State(state): State<AppState>,
) -> Result<Json<FwSettingsResponse>, AppError> {
    let model = fw_settings::Entity::find_by_id(1)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(FwSettingsResponse::from(model)))
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

    if let Some(main_inter) = payload.main_inter {
        let trimmed = main_inter.trim().to_owned();
        if trimmed.is_empty() {
            return Err(AppError::InvalidInput(
                "mainInter cannot be empty".to_owned(),
            ));
        }
        active.main_inter = Set(trimmed);
    }
    if let Some(v) = payload.inter_out {
        active.inter_out_json = Set(
            serde_json::to_string(&sanitize_string_list(v)).unwrap_or_else(|_| "[]".to_owned())
        );
    }
    if let Some(v) = payload.interface_to_go_outside {
        active.interface_to_go_outside_json = Set(
            serde_json::to_string(&sanitize_string_list(v)).unwrap_or_else(|_| "[]".to_owned())
        );
    }
    if let Some(v) = payload.intern_interface_have_access_as_local {
        active.intern_interface_have_access_as_local_json = Set(serde_json::to_string(
            &sanitize_string_list(v),
        )
        .unwrap_or_else(|_| "[]".to_owned()));
    }
    if let Some(v) = payload.interface_local {
        active.interface_local_json = Set(
            serde_json::to_string(&sanitize_string_list(v)).unwrap_or_else(|_| "[]".to_owned())
        );
    }
    if let Some(v) = payload.interface_with_dhcp {
        active.interface_with_dhcp_json =
            Set(serde_json::to_string(&v).unwrap_or_else(|_| "{}".to_owned()));
    }
    if let Some(v) = payload.interface_with_no_rules {
        active.interface_with_no_rules_json = Set(
            serde_json::to_string(&sanitize_string_list(v)).unwrap_or_else(|_| "[]".to_owned())
        );
    }
    if let Some(v) = payload.docker_network_with_internet_access {
        active.docker_network_with_internet_access_json = Set(serde_json::to_string(
            &sanitize_string_list(v),
        )
        .unwrap_or_else(|_| "[]".to_owned()));
    }
    if let Some(v) = payload.docker_network_with_access {
        active.docker_network_with_access_json = Set(serde_json::to_string(&sanitize_string_list(
            v,
        ))
        .unwrap_or_else(|_| "[]".to_owned()));
    }
    if let Some(v) = payload.ip_autor {
        active.ip_autor_json = Set(
            serde_json::to_string(&sanitize_string_list(v)).unwrap_or_else(|_| "[]".to_owned())
        );
    }
    if let Some(v) = payload.ip_autor_dnat_port_tcp {
        active.ip_autor_dnat_port_tcp_json = Set(
            serde_json::to_string(&sanitize_string_list(v)).unwrap_or_else(|_| "[]".to_owned())
        );
    }
    if let Some(v) = payload.ip_autor_dnat_port_udp {
        active.ip_autor_dnat_port_udp_json = Set(
            serde_json::to_string(&sanitize_string_list(v)).unwrap_or_else(|_| "[]".to_owned())
        );
    }
    if let Some(v) = payload.country_open_port {
        active.country_open_port = Set(v.trim().to_owned());
    }
    if let Some(v) = payload.blocked_country {
        active.blocked_country = Set(v.trim().to_owned());
    }
    if let Some(v) = payload.blocked_country_2 {
        active.blocked_country_2 = Set(v.trim().to_owned());
    }
    if let Some(v) = payload.docker_endpoint {
        let trimmed = v.trim().to_owned();
        if !trimmed.is_empty() {
            active.docker_endpoint = Set(trimmed);
        }
    }
    if let Some(v) = payload.output_dir {
        let trimmed = v.trim().to_owned();
        if !trimmed.is_empty() {
            active.output_dir = Set(trimmed);
        }
    }
    if let Some(v) = payload.tools_script_path {
        let trimmed = v.trim().to_owned();
        if !trimmed.is_empty() {
            active.tools_script_path = Set(trimmed);
        }
    }
    if let Some(v) = payload.hook_executor_url {
        let trimmed = v.trim().to_owned();
        active.hook_executor_url = Set((!trimmed.is_empty()).then_some(trimmed));
    }
    if let Some(v) = payload.hook_executor_api_key {
        let trimmed = v.trim().to_owned();
        active.hook_executor_api_key = Set((!trimmed.is_empty()).then_some(trimmed));
    }
    if let Some(v) = payload.hook_executor_signing_secret {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            let sealed = state.cipher.seal(trimmed)?;
            active.hook_executor_signing_secret = Set(Some(sealed));
        }
    }
    if let Some(v) = payload.hook_reload_name {
        let trimmed = v.trim().to_owned();
        if !trimmed.is_empty() {
            active.hook_reload_name = Set(trimmed);
        }
    }
    if let Some(v) = payload.hook_update_containers_name {
        let trimmed = v.trim().to_owned();
        if !trimmed.is_empty() {
            active.hook_update_containers_name = Set(trimmed);
        }
    }

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
    pub id: Uuid,
    pub zone: String,
    pub rule_kind: String,
    pub value: String,
    pub container_name: Option<String>,
    pub container_status: Option<String>,
    pub enabled: bool,
    pub comment: Option<String>,
    pub sort_order: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request payload for creating/updating a zone rule.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpsertZoneRuleRequest {
    pub zone: String,
    pub rule_kind: String,
    pub value: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub comment: Option<String>,
    #[serde(default)]
    pub sort_order: i32,
}

const fn default_true() -> bool {
    true
}

fn extract_container_from_rule(rule_kind: &str, value: &str) -> Option<String> {
    if rule_kind != "DockerTCP" && rule_kind != "DockerUDP" {
        return None;
    }
    let parts: Vec<&str> = value.split(',').map(str::trim).collect();
    // Format in firewall.settings: "external_port,network,container_name,container_port"
    parts
        .get(2)
        .and_then(|c| (!c.is_empty()).then(|| (*c).to_owned()))
}

/// `GET /api/firewall/zones` — List all zone rules enriched with live Docker container state.
///
/// # Errors
/// Returns [`AppError`] if the database lookup fails.
pub async fn list_zone_rules(
    State(state): State<AppState>,
) -> Result<Json<Vec<ZoneRuleResponse>>, AppError> {
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
    let value = payload.value.trim().to_owned();
    if value.is_empty() {
        return Err(AppError::InvalidInput(
            "Rule value cannot be empty".to_owned(),
        ));
    }
    let container_name = extract_container_from_rule(&rule_kind, &value);
    if (rule_kind == "DockerTCP" || rule_kind == "DockerUDP") && container_name.is_none() {
        return Err(AppError::InvalidInput(
            "DockerTCP/DockerUDP rule must have format 'ext_port,network,container,container_port'"
                .to_owned(),
        ));
    }

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
    let value = payload.value.trim().to_owned();
    if value.is_empty() {
        return Err(AppError::InvalidInput(
            "Rule value cannot be empty".to_owned(),
        ));
    }
    let container_name = extract_container_from_rule(&rule_kind, &value);

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
    pub id: Uuid,
    pub source_container: String,
    pub source_status: String,
    pub destination_container: String,
    pub destination_status: String,
    pub network_name: String,
    pub proto: String,
    pub ports: String,
    pub enabled: bool,
    pub comment: Option<String>,
    pub sort_order: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request payload for creating/updating a Docker inter-container rule.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpsertDockerInterRuleRequest {
    pub source_container: String,
    pub destination_container: String,
    pub network_name: String,
    pub proto: String,
    pub ports: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub comment: Option<String>,
    #[serde(default)]
    pub sort_order: i32,
}

/// `GET /api/firewall/docker-rules` — List all inter-container rules with live container statuses.
///
/// # Errors
/// Returns [`AppError`] if the database lookup fails.
pub async fn list_docker_inter_rules(
    State(state): State<AppState>,
) -> Result<Json<Vec<DockerInterRuleResponse>>, AppError> {
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

    let src = payload.source_container.trim().to_owned();
    let dst = payload.destination_container.trim().to_owned();
    let net = payload.network_name.trim().to_owned();
    let proto = payload.proto.trim().to_ascii_lowercase();
    let ports = payload.ports.trim().to_owned();

    if src.is_empty() || dst.is_empty() || net.is_empty() || ports.is_empty() {
        return Err(AppError::InvalidInput(
            "source_container, destination_container, network_name, and ports are required"
                .to_owned(),
        ));
    }
    if proto != "tcp" && proto != "udp" {
        return Err(AppError::InvalidInput(
            "proto must be 'tcp' or 'udp'".to_owned(),
        ));
    }

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

    let src = payload.source_container.trim().to_owned();
    let dst = payload.destination_container.trim().to_owned();
    let net = payload.network_name.trim().to_owned();
    let proto = payload.proto.trim().to_ascii_lowercase();
    let ports = payload.ports.trim().to_owned();

    if src.is_empty() || dst.is_empty() || net.is_empty() || ports.is_empty() {
        return Err(AppError::InvalidInput(
            "source_container, destination_container, network_name, and ports are required"
                .to_owned(),
        ));
    }
    if proto != "tcp" && proto != "udp" {
        return Err(AppError::InvalidInput(
            "proto must be 'tcp' or 'udp'".to_owned(),
        ));
    }

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
