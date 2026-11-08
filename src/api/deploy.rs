//! File preview, bootstrap import, atomic disk generation, and `simply_hook_executor` trigger endpoints.

use std::path::Path;

use axum::Extension;
use axum::Json;
use axum::extract::State;
use sea_orm::EntityTrait;
use serde::{Deserialize, Serialize};

use crate::api::audit::record_audit;
use crate::docker::discover_docker;
use crate::entities::{api_key, fw_settings};
use crate::error::AppError;
use crate::extract::StrictJson;
use crate::generator::{GeneratedFilesBundle, build_files_bundle, write_bundle_to_disk};
use crate::hook_client::{HookTriggerResult, trigger_hook};
use crate::importer::{ImportSummary, import_from_directory};
use crate::middleware::ClientIp;
use crate::state::AppState;

fn ensure_can_deploy(caller: &api_key::Model) -> Result<(), AppError> {
    if caller.is_master || caller.can_deploy_and_reload {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "Missing can_deploy_and_reload permission".to_owned(),
        ))
    }
}

/// Optional request body for `POST /api/firewall/import`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportRequest {
    /// Optional path override (defaults to `example/MainServ/etc_firewall`).
    pub source_dir: Option<String>,
}

/// Response returned by `POST /api/firewall/generate`.
#[derive(Debug, Serialize)]
pub struct GenerateDiskResponse {
    pub files_written: Vec<String>,
    pub bundle: GeneratedFilesBundle,
}

/// Response returned by `POST /api/firewall/generate-and-reload`.
#[derive(Debug, Serialize)]
pub struct GenerateAndReloadResponse {
    pub files_written: Vec<String>,
    pub bundle: GeneratedFilesBundle,
    pub hook_result: HookTriggerResult,
}

/// `GET /api/firewall/preview` — Render a live preview of `firewall.settings`,
/// `firewall.rules.special`, and `firewall.get.list` filtered against live Docker container state.
///
/// # Errors
/// Returns [`AppError`] if reading from the database fails.
pub async fn preview_generated_files(
    State(state): State<AppState>,
) -> Result<Json<GeneratedFilesBundle>, AppError> {
    let settings = fw_settings::Entity::find_by_id(1)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;
    let snapshot = discover_docker(&state.http, &settings.docker_endpoint).await;
    let bundle = build_files_bundle(&state.db, &snapshot).await?;
    Ok(Json(bundle))
}

/// `POST /api/firewall/import` — Import/re-import configuration files from `/example/MainServ/etc_firewall/`.
///
/// # Errors
/// Returns [`AppError`] if the caller lacks permissions or import fails.
pub async fn import_example_files(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictJson(payload): StrictJson<ImportRequest>,
) -> Result<Json<ImportSummary>, AppError> {
    ensure_can_deploy(&caller)?;

    let dir_str = payload
        .source_dir
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map_or_else(
            || {
                std::env::var("FW_IMPORT_DIR")
                    .unwrap_or_else(|_| "example/MainServ/etc_firewall".to_owned())
            },
            str::to_owned,
        );

    let dir = Path::new(&dir_str);
    if !dir.exists() {
        return Err(AppError::InvalidInput(format!(
            "Import directory '{}' does not exist",
            dir.display()
        )));
    }

    let summary = import_from_directory(&state.db, dir, true).await?;

    record_audit(
        &state.db,
        &caller,
        client_ip,
        "IMPORT_EXAMPLE",
        Some(summary.source_dir.clone()),
        Some(format!(
            "Imported {} zone rules, {} Docker rules, {} blocklists",
            summary.zone_rules_imported,
            summary.docker_inter_rules_imported,
            summary.blocklists_imported
        )),
    )
    .await?;

    Ok(Json(summary))
}

/// `POST /api/firewall/generate` — Atomically write `firewall.settings`, `firewall.rules.special`,
/// and `firewall.get.list` to `output_dir` (filtering out stopped containers).
///
/// # Errors
/// Returns [`AppError`] if the caller lacks permissions or writing to disk fails.
pub async fn generate_files_on_disk(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
) -> Result<Json<GenerateDiskResponse>, AppError> {
    ensure_can_deploy(&caller)?;

    let settings = fw_settings::Entity::find_by_id(1)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    let snapshot = discover_docker(&state.http, &settings.docker_endpoint).await;
    let bundle = build_files_bundle(&state.db, &snapshot).await?;
    let files_written = write_bundle_to_disk(&bundle)?;

    record_audit(
        &state.db,
        &caller,
        client_ip,
        "GENERATE_FILES",
        Some(bundle.output_dir.clone()),
        Some(format!(
            "Wrote {} files (docker_filter={}, active_docker_rules={}, skipped_docker_rules={}, active_zone_rules={}, skipped_zone_rules={})",
            files_written.len(),
            bundle.docker_filter_active,
            bundle.active_docker_inter_rules,
            bundle.skipped_docker_inter_rules,
            bundle.active_zone_rules,
            bundle.skipped_zone_rules
        )),
    )
    .await?;

    Ok(Json(GenerateDiskResponse {
        files_written,
        bundle,
    }))
}

/// `POST /api/firewall/reload` — Trigger the configured `simply_hook_executor` firewall reload hook.
///
/// # Errors
/// Returns [`AppError`] if `simply_hook_executor` is not configured or returns an error.
pub async fn reload_firewall(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
) -> Result<Json<HookTriggerResult>, AppError> {
    ensure_can_deploy(&caller)?;

    let settings = fw_settings::Entity::find_by_id(1)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    let result = trigger_hook(
        &state.http,
        &state.cipher,
        &settings,
        &settings.hook_reload_name,
    )
    .await?;

    record_audit(
        &state.db,
        &caller,
        client_ip,
        "RELOAD_FIREWALL",
        Some(result.hook_name.clone()),
        Some(format!(
            "Triggered simply_hook_executor '{}' (HTTP {})",
            result.hook_name, result.status_code
        )),
    )
    .await?;

    Ok(Json(result))
}

/// `POST /api/firewall/generate-and-reload` — Atomically write all 3 files and immediately trigger
/// the `simply_hook_executor` firewall reload hook.
///
/// # Errors
/// Returns [`AppError`] if file generation or hook execution fails.
pub async fn generate_and_reload(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
) -> Result<Json<GenerateAndReloadResponse>, AppError> {
    ensure_can_deploy(&caller)?;

    let settings = fw_settings::Entity::find_by_id(1)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    let snapshot = discover_docker(&state.http, &settings.docker_endpoint).await;
    let bundle = build_files_bundle(&state.db, &snapshot).await?;
    let files_written = write_bundle_to_disk(&bundle)?;

    let hook_result = trigger_hook(
        &state.http,
        &state.cipher,
        &settings,
        &settings.hook_reload_name,
    )
    .await?;

    record_audit(
        &state.db,
        &caller,
        client_ip,
        "GENERATE_AND_RELOAD",
        Some(bundle.output_dir.clone()),
        Some(format!(
            "Generated {} files and triggered hook '{}' (HTTP {})",
            files_written.len(),
            hook_result.hook_name,
            hook_result.status_code
        )),
    )
    .await?;

    Ok(Json(GenerateAndReloadResponse {
        files_written,
        bundle,
        hook_result,
    }))
}

/// `POST /api/firewall/update-containers` — Trigger the configured `simply_hook_executor`
/// container-update hook (`hook_update_containers_name`).
///
/// # Errors
/// Returns [`AppError`] if `simply_hook_executor` is not configured or returns an error.
pub async fn update_containers(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
) -> Result<Json<HookTriggerResult>, AppError> {
    ensure_can_deploy(&caller)?;

    let settings = fw_settings::Entity::find_by_id(1)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    let result = trigger_hook(
        &state.http,
        &state.cipher,
        &settings,
        &settings.hook_update_containers_name,
    )
    .await?;

    record_audit(
        &state.db,
        &caller,
        client_ip,
        "UPDATE_CONTAINERS_HOOK",
        Some(result.hook_name.clone()),
        Some(format!(
            "Triggered container update hook '{}' (HTTP {})",
            result.hook_name, result.status_code
        )),
    )
    .await?;

    Ok(Json(result))
}
