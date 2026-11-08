//! Blocklist feeds (`firewall.get.list`) CRUD and live HTTP feed tester (`/api/firewall/blocklists`).

use std::net::IpAddr;

use axum::Extension;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::audit::record_audit;
use crate::entities::{api_key, fw_blocklist};
use crate::error::AppError;
use crate::extract::{StrictJson, StrictPath};
use crate::generator::render_get_list;
use crate::middleware::ClientIp;
use crate::state::AppState;

fn ensure_can_manage_blocklists(caller: &api_key::Model) -> Result<(), AppError> {
    if caller.is_master || caller.can_manage_blocklists {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "Missing can_manage_blocklists permission".to_owned(),
        ))
    }
}

/// Serialized blocklist entry.
#[derive(Debug, Serialize)]
pub struct BlocklistResponse {
    pub id: Uuid,
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub description: Option<String>,
    pub last_test_ok: Option<bool>,
    pub last_test_entries: Option<i32>,
    pub last_test_at: Option<DateTime<Utc>>,
    pub sort_order: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<fw_blocklist::Model> for BlocklistResponse {
    fn from(m: fw_blocklist::Model) -> Self {
        Self {
            id: m.id,
            name: m.name,
            url: m.url,
            enabled: m.enabled,
            description: m.description,
            last_test_ok: m.last_test_ok,
            last_test_entries: m.last_test_entries,
            last_test_at: m.last_test_at,
            sort_order: m.sort_order,
            created_at: m.created_at,
            updated_at: m.updated_at,
        }
    }
}

/// Full list response including the rendered `firewall.get.list` preview.
#[derive(Debug, Serialize)]
pub struct BlocklistsOverviewResponse {
    pub items: Vec<BlocklistResponse>,
    pub script_preview: String,
}

/// Request payload for creating/updating a blocklist entry.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpsertBlocklistRequest {
    pub name: String,
    pub url: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub description: Option<String>,
    #[serde(default)]
    pub sort_order: i32,
}

const fn default_true() -> bool {
    true
}

fn validate_blocklist_inputs(name: &str, url: &str) -> Result<(String, String), AppError> {
    let trimmed_name = name.trim().to_owned();
    if trimmed_name.is_empty()
        || !trimmed_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(AppError::InvalidInput(
            "Blocklist name must be non-empty and contain only alphanumeric, '_', '-', or '.' characters"
                .to_owned(),
        ));
    }
    let trimmed_url = url.trim().to_owned();
    if !trimmed_url.starts_with("http://") && !trimmed_url.starts_with("https://") {
        return Err(AppError::InvalidInput(
            "Blocklist URL must start with http:// or https://".to_owned(),
        ));
    }
    Ok((trimmed_name, trimmed_url))
}

/// `GET /api/firewall/blocklists` — List all blocklists and preview `firewall.get.list`.
///
/// # Errors
/// Returns [`AppError`] if querying the database fails.
pub async fn list_blocklists(
    State(state): State<AppState>,
) -> Result<Json<BlocklistsOverviewResponse>, AppError> {
    let models = fw_blocklist::Entity::find()
        .order_by_asc(fw_blocklist::Column::SortOrder)
        .all(&state.db)
        .await?;

    let enabled_only: Vec<fw_blocklist::Model> =
        models.iter().filter(|m| m.enabled).cloned().collect();
    let script_preview = render_get_list(&enabled_only);
    let items = models.into_iter().map(BlocklistResponse::from).collect();

    Ok(Json(BlocklistsOverviewResponse {
        items,
        script_preview,
    }))
}

/// `POST /api/firewall/blocklists` — Create a new blocklist feed entry.
///
/// # Errors
/// Returns [`AppError`] if inputs are invalid or the name already exists.
pub async fn create_blocklist(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictJson(payload): StrictJson<UpsertBlocklistRequest>,
) -> Result<(StatusCode, Json<BlocklistResponse>), AppError> {
    ensure_can_manage_blocklists(&caller)?;
    let (name, url) = validate_blocklist_inputs(&payload.name, &payload.url)?;

    if fw_blocklist::Entity::find()
        .filter(fw_blocklist::Column::Name.eq(&name))
        .one(&state.db)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict(format!(
            "A blocklist named '{name}' already exists"
        )));
    }

    let now = Utc::now();
    let id = Uuid::new_v4();
    let model = fw_blocklist::ActiveModel {
        id: Set(id),
        name: Set(name.clone()),
        url: Set(url.clone()),
        enabled: Set(payload.enabled),
        description: Set(payload
            .description
            .map(|d| d.trim().to_owned())
            .filter(|d| !d.is_empty())),
        last_test_ok: Set(None),
        last_test_entries: Set(None),
        last_test_at: Set(None),
        sort_order: Set(payload.sort_order),
        created_at: Set(now),
        updated_at: Set(now),
    };
    let inserted = model.insert(&state.db).await?;

    record_audit(
        &state.db,
        &caller,
        client_ip,
        "CREATE_BLOCKLIST",
        Some(id.to_string()),
        Some(format!("Added blocklist '{name}' ({url})")),
    )
    .await?;

    Ok((StatusCode::CREATED, Json(BlocklistResponse::from(inserted))))
}

/// `PUT /api/firewall/blocklists/{id}` — Update an existing blocklist feed entry.
///
/// # Errors
/// Returns [`AppError`] if the entry does not exist or inputs are invalid.
pub async fn update_blocklist(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
    StrictJson(payload): StrictJson<UpsertBlocklistRequest>,
) -> Result<Json<BlocklistResponse>, AppError> {
    ensure_can_manage_blocklists(&caller)?;
    let (name, url) = validate_blocklist_inputs(&payload.name, &payload.url)?;

    let existing = fw_blocklist::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    if existing.name != name
        && fw_blocklist::Entity::find()
            .filter(fw_blocklist::Column::Name.eq(&name))
            .one(&state.db)
            .await?
            .is_some()
    {
        return Err(AppError::Conflict(format!(
            "A blocklist named '{name}' already exists"
        )));
    }

    let mut active: fw_blocklist::ActiveModel = existing.into();
    active.name = Set(name.clone());
    active.url = Set(url.clone());
    active.enabled = Set(payload.enabled);
    active.description = Set(payload
        .description
        .map(|d| d.trim().to_owned())
        .filter(|d| !d.is_empty()));
    active.sort_order = Set(payload.sort_order);
    active.updated_at = Set(Utc::now());

    let updated = active.update(&state.db).await?;

    record_audit(
        &state.db,
        &caller,
        client_ip,
        "UPDATE_BLOCKLIST",
        Some(id.to_string()),
        Some(format!(
            "Updated blocklist '{name}' ({url}, enabled={})",
            updated.enabled
        )),
    )
    .await?;

    Ok(Json(BlocklistResponse::from(updated)))
}

/// `DELETE /api/firewall/blocklists/{id}` — Delete a blocklist feed entry.
///
/// # Errors
/// Returns [`AppError`] if the entry does not exist.
pub async fn delete_blocklist(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
) -> Result<StatusCode, AppError> {
    ensure_can_manage_blocklists(&caller)?;

    let existing = fw_blocklist::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    fw_blocklist::Entity::delete_by_id(id)
        .exec(&state.db)
        .await?;

    record_audit(
        &state.db,
        &caller,
        client_ip,
        "DELETE_BLOCKLIST",
        Some(id.to_string()),
        Some(format!(
            "Deleted blocklist '{}' ({})",
            existing.name, existing.url
        )),
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Result of a live HTTP test against a blocklist feed URL.
#[derive(Debug, Serialize)]
pub struct BlocklistTestResponse {
    pub id: Uuid,
    pub name: String,
    pub url: String,
    pub valid: bool,
    pub status_code: u16,
    pub valid_ipv4_count: usize,
    pub valid_ipv6_count: usize,
    pub invalid_line_count: usize,
    pub sample_entries: Vec<String>,
    pub message: String,
}

fn parse_ip_or_cidr_token(line: &str) -> Option<IpNetwork> {
    // Strip trailing comments (`; ...` or `# ...`) used by Spamhaus DROP/EDROP and similar feeds
    let before_comment = line.split([';', '#']).next().map_or("", str::trim);
    if before_comment.is_empty() {
        return None;
    }
    before_comment
        .parse::<IpNetwork>()
        .ok()
        .or_else(|| before_comment.parse::<IpAddr>().ok().map(IpNetwork::from))
}

/// `POST /api/firewall/blocklists/{id}/test` — Fetch the blocklist URL and verify that it returns
/// a valid plaintext list of IPv4/IPv6/CIDR addresses.
///
/// # Errors
/// Returns [`AppError`] if the blocklist does not exist or the HTTP request fails.
pub async fn test_blocklist(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
) -> Result<Json<BlocklistTestResponse>, AppError> {
    ensure_can_manage_blocklists(&caller)?;

    let existing = fw_blocklist::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    let response = state
        .http
        .get(&existing.url)
        .send()
        .await
        .map_err(|e| AppError::Upstream(format!("Failed fetching {}: {e}", existing.url)))?;

    let status_code = response.status().as_u16();
    let body = response
        .text()
        .await
        .map_err(|e| AppError::Upstream(format!("Failed reading body: {e}")))?;

    let mut valid_ipv4_count = 0usize;
    let mut valid_ipv6_count = 0usize;
    let mut invalid_line_count = 0usize;
    let mut sample_entries = Vec::new();

    for raw_line in body.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some(net) = parse_ip_or_cidr_token(trimmed) {
            match net {
                IpNetwork::V4(_) => valid_ipv4_count += 1,
                IpNetwork::V6(_) => valid_ipv6_count += 1,
            }
            if sample_entries.len() < 5 {
                sample_entries.push(net.to_string());
            }
        } else {
            invalid_line_count += 1;
        }
    }

    let total_valid = valid_ipv4_count + valid_ipv6_count;
    let valid = (200..300).contains(&status_code) && total_valid > 0 && invalid_line_count == 0;
    let message = if valid {
        format!(
            "HTTP {status_code}: {total_valid} valid IP/CIDR entries ({valid_ipv4_count} IPv4, {valid_ipv6_count} IPv6)"
        )
    } else {
        format!(
            "HTTP {status_code}: {total_valid} valid entries, {invalid_line_count} unparseable lines"
        )
    };

    let now = Utc::now();
    let mut active: fw_blocklist::ActiveModel = existing.clone().into();
    active.last_test_ok = Set(Some(valid));
    active.last_test_entries = Set(Some(i32::try_from(total_valid).unwrap_or(i32::MAX)));
    active.last_test_at = Set(Some(now));
    active.updated_at = Set(now);
    let _ = active.update(&state.db).await?;

    record_audit(
        &state.db,
        &caller,
        client_ip,
        "TEST_BLOCKLIST",
        Some(id.to_string()),
        Some(format!("{}: {message}", existing.name)),
    )
    .await?;

    Ok(Json(BlocklistTestResponse {
        id: existing.id,
        name: existing.name,
        url: existing.url,
        valid,
        status_code,
        valid_ipv4_count,
        valid_ipv6_count,
        invalid_line_count,
        sample_entries,
        message,
    }))
}
