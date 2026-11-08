//! Unified API Key management endpoints (`/api/keys`).

use std::net::IpAddr;

use axum::Extension;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, EntityTrait, QueryFilter, QueryOrder, Set,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::api::audit::record_audit;
use crate::crypto::generate_signing_secret;
use crate::entities::api_key;
use crate::entities::prelude::ApiKey;
use crate::error::AppError;
use crate::extract::{StrictJson, StrictPath};
use crate::middleware::ClientIp;
use crate::state::AppState;

/// Serialized API key summary (never exposes key hash or signing secret).
#[derive(Debug, Serialize)]
pub struct ApiKeyResponse {
    pub id: Uuid,
    pub name: String,
    pub prefix: String,
    pub is_master: bool,
    pub can_manage_keys: bool,
    pub can_manage_settings: bool,
    pub can_manage_special_rules: bool,
    pub can_manage_blocklists: bool,
    pub can_deploy_and_reload: bool,
    pub parent_key_id: Option<Uuid>,
    pub bound_ips: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<api_key::Model> for ApiKeyResponse {
    fn from(m: api_key::Model) -> Self {
        Self {
            id: m.id,
            name: m.name,
            prefix: m.prefix,
            is_master: m.is_master,
            can_manage_keys: m.can_manage_keys,
            can_manage_settings: m.can_manage_settings,
            can_manage_special_rules: m.can_manage_special_rules,
            can_manage_blocklists: m.can_manage_blocklists,
            can_deploy_and_reload: m.can_deploy_and_reload,
            parent_key_id: m.parent_key_id,
            bound_ips: m.bound_ips,
            created_at: m.created_at,
            updated_at: m.updated_at,
        }
    }
}

/// One-time response returned on key creation or rotation.
#[derive(Debug, Serialize)]
pub struct CreatedApiKeyResponse {
    pub id: Uuid,
    pub name: String,
    pub prefix: String,
    pub raw_key: String,
    pub signing_secret: String,
    pub can_manage_keys: bool,
    pub can_manage_settings: bool,
    pub can_manage_special_rules: bool,
    pub can_manage_blocklists: bool,
    pub can_deploy_and_reload: bool,
    pub bound_ips: Option<String>,
}

/// Request payload for `POST /api/keys`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateApiKeyRequest {
    pub name: String,
    #[serde(default)]
    pub can_manage_keys: bool,
    #[serde(default)]
    pub can_manage_settings: bool,
    #[serde(default)]
    pub can_manage_special_rules: bool,
    #[serde(default)]
    pub can_manage_blocklists: bool,
    #[serde(default)]
    pub can_deploy_and_reload: bool,
    pub bound_ips: Option<String>,
}

/// Request payload for `PUT /api/keys/{id}` and `PATCH /api/keys/{id}`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateApiKeyRequest {
    pub name: Option<String>,
    pub can_manage_keys: Option<bool>,
    pub can_manage_settings: Option<bool>,
    pub can_manage_special_rules: Option<bool>,
    pub can_manage_blocklists: Option<bool>,
    pub can_deploy_and_reload: Option<bool>,
    pub bound_ips: Option<String>,
}

fn validate_bound_ips(raw: Option<&str>) -> Result<Option<String>, AppError> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let mut normalized = Vec::new();
    for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if let Ok(net) = entry.parse::<IpNetwork>() {
            normalized.push(net.to_string());
        } else if let Ok(ip) = entry.parse::<IpAddr>() {
            normalized.push(crate::config::normalize_ip(ip).to_string());
        } else {
            return Err(AppError::InvalidInput(format!(
                "Invalid IP or CIDR in bound_ips: '{entry}'"
            )));
        }
    }
    Ok(Some(normalized.join(",")))
}

fn check_subset_delegation(
    caller: &api_key::Model,
    can_manage_keys: bool,
    can_manage_settings: bool,
    can_manage_special_rules: bool,
    can_manage_blocklists: bool,
    can_deploy_and_reload: bool,
) -> Result<(), AppError> {
    if caller.is_master {
        return Ok(());
    }
    if (can_manage_keys && !caller.can_manage_keys)
        || (can_manage_settings && !caller.can_manage_settings)
        || (can_manage_special_rules && !caller.can_manage_special_rules)
        || (can_manage_blocklists && !caller.can_manage_blocklists)
        || (can_deploy_and_reload && !caller.can_deploy_and_reload)
    {
        return Err(AppError::Forbidden(
            "Cannot grant permissions that the delegating key does not possess".to_owned(),
        ));
    }
    Ok(())
}

/// `GET /api/auth/me` — Return the authenticated caller's API key profile.
pub async fn get_me(Extension(caller): Extension<api_key::Model>) -> Json<ApiKeyResponse> {
    Json(ApiKeyResponse::from(caller))
}

/// `GET /api/keys` — List API keys visible to the caller.
///
/// # Errors
/// Returns [`AppError`] if the caller lacks permissions or the query fails.
pub async fn list_api_keys(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
) -> Result<Json<Vec<ApiKeyResponse>>, AppError> {
    let mut select = ApiKey::find().order_by_asc(api_key::Column::CreatedAt);
    if !caller.is_master {
        if caller.can_manage_keys {
            select = select.filter(
                Condition::any()
                    .add(api_key::Column::Id.eq(caller.id))
                    .add(api_key::Column::ParentKeyId.eq(caller.id)),
            );
        } else {
            select = select.filter(api_key::Column::Id.eq(caller.id));
        }
    }
    let rows = select.all(&state.db).await?;
    Ok(Json(rows.into_iter().map(ApiKeyResponse::from).collect()))
}

/// `POST /api/keys` — Create a new API key.
///
/// # Errors
/// Returns [`AppError`] if validation or delegation checks fail.
pub async fn create_api_key(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictJson(payload): StrictJson<CreateApiKeyRequest>,
) -> Result<(StatusCode, Json<CreatedApiKeyResponse>), AppError> {
    if !caller.is_master && !caller.can_manage_keys {
        return Err(AppError::Forbidden(
            "Missing can_manage_keys permission".to_owned(),
        ));
    }
    let name = payload.name.trim().to_owned();
    if name.is_empty() {
        return Err(AppError::InvalidInput(
            "Key name cannot be empty".to_owned(),
        ));
    }

    check_subset_delegation(
        &caller,
        payload.can_manage_keys,
        payload.can_manage_settings,
        payload.can_manage_special_rules,
        payload.can_manage_blocklists,
        payload.can_deploy_and_reload,
    )?;

    let bound_ips = validate_bound_ips(payload.bound_ips.as_deref())?;

    let raw_key = generate_signing_secret();
    let raw_secret = generate_signing_secret();
    let mut hasher = Sha256::new();
    hasher.update(raw_key.as_bytes());
    let key_hash = hex::encode(hasher.finalize());
    let prefix: String = raw_key.chars().take(8).collect();
    let sealed_secret = state.cipher.seal(&raw_secret)?;

    let id = Uuid::new_v4();
    let now = Utc::now();
    let model = api_key::ActiveModel {
        id: Set(id),
        name: Set(name.clone()),
        key_hash: Set(key_hash),
        signing_secret: Set(Some(sealed_secret)),
        prefix: Set(prefix.clone()),
        is_master: Set(false),
        can_manage_keys: Set(payload.can_manage_keys),
        can_manage_settings: Set(payload.can_manage_settings),
        can_manage_special_rules: Set(payload.can_manage_special_rules),
        can_manage_blocklists: Set(payload.can_manage_blocklists),
        can_deploy_and_reload: Set(payload.can_deploy_and_reload),
        parent_key_id: Set(Some(caller.id)),
        bound_ips: Set(bound_ips.clone()),
        created_at: Set(now),
        updated_at: Set(now),
    };
    model.insert(&state.db).await?;

    record_audit(
        &state.db,
        &caller,
        client_ip,
        "CREATE_KEY",
        Some(id.to_string()),
        Some(format!("Created API key '{name}' (prefix={prefix})")),
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(CreatedApiKeyResponse {
            id,
            name,
            prefix,
            raw_key,
            signing_secret: raw_secret,
            can_manage_keys: payload.can_manage_keys,
            can_manage_settings: payload.can_manage_settings,
            can_manage_special_rules: payload.can_manage_special_rules,
            can_manage_blocklists: payload.can_manage_blocklists,
            can_deploy_and_reload: payload.can_deploy_and_reload,
            bound_ips,
        }),
    ))
}

/// `PUT /api/keys/{id}` and `PATCH /api/keys/{id}` — Update an API key.
///
/// # Errors
/// Returns [`AppError`] if the key does not exist or permission checks fail.
pub async fn update_api_key(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
    StrictJson(payload): StrictJson<UpdateApiKeyRequest>,
) -> Result<Json<ApiKeyResponse>, AppError> {
    if !caller.is_master && !caller.can_manage_keys {
        return Err(AppError::Forbidden(
            "Missing can_manage_keys permission".to_owned(),
        ));
    }

    let target = ApiKey::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    if target.is_master {
        if !caller.is_master {
            return Err(AppError::NotFound);
        }
        if payload.name.is_some()
            || payload.can_manage_keys.is_some()
            || payload.can_manage_settings.is_some()
            || payload.can_manage_special_rules.is_some()
            || payload.can_manage_blocklists.is_some()
            || payload.can_deploy_and_reload.is_some()
        {
            return Err(AppError::Forbidden(
                "Only bound_ips may be modified on the Master key".to_owned(),
            ));
        }
        let bound_ips = validate_bound_ips(payload.bound_ips.as_deref())?;
        let mut active: api_key::ActiveModel = target.into();
        active.bound_ips = Set(bound_ips.clone());
        active.updated_at = Set(Utc::now());
        let updated = active.update(&state.db).await?;
        record_audit(
            &state.db,
            &caller,
            client_ip,
            "UPDATE_KEY",
            Some(id.to_string()),
            Some(format!("Updated Master key bound_ips to {bound_ips:?}")),
        )
        .await?;
        return Ok(Json(ApiKeyResponse::from(updated)));
    }

    if !caller.is_master && target.parent_key_id != Some(caller.id) {
        return Err(AppError::NotFound);
    }

    let new_manage_keys = payload.can_manage_keys.unwrap_or(target.can_manage_keys);
    let new_settings = payload
        .can_manage_settings
        .unwrap_or(target.can_manage_settings);
    let new_special = payload
        .can_manage_special_rules
        .unwrap_or(target.can_manage_special_rules);
    let new_blocklists = payload
        .can_manage_blocklists
        .unwrap_or(target.can_manage_blocklists);
    let new_deploy = payload
        .can_deploy_and_reload
        .unwrap_or(target.can_deploy_and_reload);

    check_subset_delegation(
        &caller,
        new_manage_keys,
        new_settings,
        new_special,
        new_blocklists,
        new_deploy,
    )?;

    let mut active: api_key::ActiveModel = target.into();
    if let Some(name) = payload.name {
        let trimmed = name.trim().to_owned();
        if trimmed.is_empty() {
            return Err(AppError::InvalidInput(
                "Key name cannot be empty".to_owned(),
            ));
        }
        active.name = Set(trimmed);
    }
    active.can_manage_keys = Set(new_manage_keys);
    active.can_manage_settings = Set(new_settings);
    active.can_manage_special_rules = Set(new_special);
    active.can_manage_blocklists = Set(new_blocklists);
    active.can_deploy_and_reload = Set(new_deploy);
    if payload.bound_ips.is_some() {
        active.bound_ips = Set(validate_bound_ips(payload.bound_ips.as_deref())?);
    }
    active.updated_at = Set(Utc::now());

    let updated = active.update(&state.db).await?;
    record_audit(
        &state.db,
        &caller,
        client_ip,
        "UPDATE_KEY",
        Some(id.to_string()),
        Some(format!("Updated API key '{}'", updated.name)),
    )
    .await?;

    Ok(Json(ApiKeyResponse::from(updated)))
}

/// `DELETE /api/keys/{id}` — Revoke and delete a sub-key.
///
/// # Errors
/// Returns [`AppError`] if the key is the Master key or does not belong to the caller.
pub async fn delete_api_key(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
) -> Result<StatusCode, AppError> {
    if !caller.is_master && !caller.can_manage_keys {
        return Err(AppError::Forbidden(
            "Missing can_manage_keys permission".to_owned(),
        ));
    }

    let target = ApiKey::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    if target.is_master {
        return Err(AppError::Forbidden(
            "The Master key cannot be deleted".to_owned(),
        ));
    }
    if !caller.is_master && target.parent_key_id != Some(caller.id) {
        return Err(AppError::NotFound);
    }

    let name = target.name.clone();
    ApiKey::delete_by_id(id).exec(&state.db).await?;

    record_audit(
        &state.db,
        &caller,
        client_ip,
        "DELETE_KEY",
        Some(id.to_string()),
        Some(format!("Deleted API key '{name}'")),
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/keys/{id}/rotate` — Rotate a sub-key's bearer API key.
///
/// # Errors
/// Returns [`AppError`] if the key is the Master key or does not belong to the caller.
pub async fn rotate_api_key(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !caller.is_master && !caller.can_manage_keys {
        return Err(AppError::Forbidden(
            "Missing can_manage_keys permission".to_owned(),
        ));
    }

    let target = ApiKey::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    if target.is_master {
        return Err(AppError::Forbidden(
            "The Master key cannot be rotated via the API".to_owned(),
        ));
    }
    if !caller.is_master && target.parent_key_id != Some(caller.id) {
        return Err(AppError::NotFound);
    }

    let raw_key = generate_signing_secret();
    let mut hasher = Sha256::new();
    hasher.update(raw_key.as_bytes());
    let key_hash = hex::encode(hasher.finalize());
    let prefix: String = raw_key.chars().take(8).collect();

    let mut active: api_key::ActiveModel = target.into();
    active.key_hash = Set(key_hash);
    active.prefix = Set(prefix.clone());
    active.updated_at = Set(Utc::now());
    let updated = active.update(&state.db).await?;

    record_audit(
        &state.db,
        &caller,
        client_ip,
        "ROTATE_KEY",
        Some(id.to_string()),
        Some(format!(
            "Rotated API key '{}' (new prefix={prefix})",
            updated.name
        )),
    )
    .await?;

    Ok(Json(serde_json::json!({
        "id": updated.id,
        "prefix": prefix,
        "raw_key": raw_key,
        "plaintext_key": raw_key,
    })))
}

/// `POST /api/keys/{id}/rotate-secret` — Rotate a sub-key's HMAC signing secret.
///
/// # Errors
/// Returns [`AppError`] if the key is the Master key or does not belong to the caller.
pub async fn rotate_signing_secret(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !caller.is_master && !caller.can_manage_keys {
        return Err(AppError::Forbidden(
            "Missing can_manage_keys permission".to_owned(),
        ));
    }

    let target = ApiKey::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    if target.is_master {
        return Err(AppError::Forbidden(
            "The Master key signing secret cannot be rotated via the API".to_owned(),
        ));
    }
    if !caller.is_master && target.parent_key_id != Some(caller.id) {
        return Err(AppError::NotFound);
    }

    let raw_secret = generate_signing_secret();
    let sealed_secret = state.cipher.seal(&raw_secret)?;

    let mut active: api_key::ActiveModel = target.into();
    active.signing_secret = Set(Some(sealed_secret));
    active.updated_at = Set(Utc::now());
    let updated = active.update(&state.db).await?;

    record_audit(
        &state.db,
        &caller,
        client_ip,
        "ROTATE_SECRET",
        Some(id.to_string()),
        Some(format!(
            "Rotated signing secret for API key '{}'",
            updated.name
        )),
    )
    .await?;

    Ok(Json(serde_json::json!({
        "id": updated.id,
        "signing_secret": raw_secret,
        "plaintext_signing_secret": raw_secret,
    })))
}
