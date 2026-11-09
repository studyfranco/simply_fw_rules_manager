//! System settings & introspection endpoint (`GET /api/system/settings`).
//! Master-only: reports daemon configuration, trusted proxies, and entity counts.

use axum::Extension;
use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use sea_orm::{EntityTrait, PaginatorTrait};
use serde::Serialize;

use crate::entities::prelude::*;
use crate::entities::api_key;
use crate::error::AppError;
use crate::state::AppState;

/// System settings and counters visible to Master keys only.
#[derive(Debug, Serialize)]
pub struct SystemSettingsResponse {
    /// Peers whose forwarding headers are trusted.
    pub trusted_proxies: Vec<String>,
    /// Whether secrets-at-rest encryption is active.
    pub encryption_enabled: bool,
    /// Destination directory for generated firewall files.
    pub output_dir: String,
    /// URL of `simply_hook_executor`, if configured.
    pub hook_executor_url: Option<String>,
    /// Total zone rules configured.
    pub zone_rules_count: u64,
    /// Total Docker inter-container rules configured.
    pub docker_rules_count: u64,
    /// Total blocklists defined.
    pub blocklists_count: u64,
    /// Total special rules defined.
    pub special_rules_count: u64,
    /// Total active API keys.
    pub api_key_count: u64,
    /// Total audit log entries retained.
    pub audit_log_count: u64,
}

/// Handles `GET /api/system/settings`. Master-only.
///
/// # Errors
///
/// Returns `AppError::Forbidden` if caller is not master, or `AppError::Database` on DB query failure.
pub async fn get_system_settings(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
) -> Result<impl IntoResponse, AppError> {
    if !caller.is_master {
        return Err(AppError::Forbidden(
            "System settings are visible to the Master key only".to_owned(),
        ));
    }

    let zone_rules_count = FwZoneRule::find().count(&state.db).await?;
    let docker_rules_count = FwDockerInterRule::find().count(&state.db).await?;
    let blocklists_count = FwBlocklist::find().count(&state.db).await?;
    let special_rules_count = FwSpecialRules::find().count(&state.db).await?;
    let api_key_count = ApiKey::find().count(&state.db).await?;
    let audit_log_count = AuditLog::find().count(&state.db).await?;

    Ok(Json(SystemSettingsResponse {
        trusted_proxies: state
            .trusted_proxies
            .networks()
            .iter()
            .map(ToString::to_string)
            .collect(),
        encryption_enabled: state.cipher.is_encrypting(),
        output_dir: std::env::var("FW_OUTPUT_DIR")
            .unwrap_or_else(|_| "/etc/firewall".to_owned()),
        hook_executor_url: std::env::var("HOOK_EXECUTOR_URL").ok(),
        zone_rules_count,
        docker_rules_count,
        blocklists_count,
        special_rules_count,
        api_key_count,
        audit_log_count,
    }))
}
