//! `firewall.rules.special` editor, `firewall.tools` helper parser, and 3-stage validation endpoints.

use std::path::Path;

use axum::Extension;
use axum::Json;
use axum::extract::State;
use chrono::{DateTime, Utc};
use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use serde::{Deserialize, Serialize};

use crate::api::audit::record_audit;
use crate::entities::{api_key, fw_settings, fw_special_rules};
use crate::error::AppError;
use crate::extract::StrictJson;
use crate::middleware::ClientIp;
use crate::state::AppState;
use crate::validator::{
    ToolFunctionDoc, ValidationReport, collect_known_variables, parse_tools_functions,
    validate_special_rules,
};

fn ensure_can_manage_special_rules(caller: &api_key::Model) -> Result<(), AppError> {
    if caller.is_master || caller.can_manage_special_rules {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "Missing can_manage_special_rules permission".to_owned(),
        ))
    }
}

/// Response returned by `GET /api/firewall/special-rules`.
#[derive(Debug, Serialize)]
pub struct SpecialRulesResponse {
    pub script_content: String,
    pub last_validation_ok: bool,
    pub validation: ValidationReport,
    pub tools_functions: Vec<ToolFunctionDoc>,
    pub known_variables: Vec<String>,
    pub updated_at: DateTime<Utc>,
}

/// Request payload for `POST /api/firewall/special-rules/validate` and `PUT /api/firewall/special-rules`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpecialRulesRequest {
    pub script_content: String,
    /// When `true`, allows saving a script that passes `bash -n` and variable resolution even if
    /// `shellcheck` reported style/error diagnostics.
    #[serde(default)]
    pub allow_warnings: bool,
}

async fn resolve_tools_path(state: &AppState) -> String {
    fw_settings::Entity::find_by_id(1)
        .one(&state.db)
        .await
        .ok()
        .flatten()
        .map_or_else(
            || "scripts_etc/firewall.tools".to_owned(),
            |s| s.tools_script_path,
        )
}

/// `GET /api/firewall/special-rules` — Return the current `firewall.rules.special` script,
/// its live 3-stage validation report, and the parsed `firewall.tools` helper reference.
///
/// # Errors
/// Returns [`AppError`] if the database lookup fails.
pub async fn get_special_rules(
    State(state): State<AppState>,
) -> Result<Json<SpecialRulesResponse>, AppError> {
    let tools_path_str = resolve_tools_path(&state).await;
    let tools_path = Path::new(&tools_path_str);

    let row = fw_special_rules::Entity::find_by_id(1)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    let validation = validate_special_rules(&row.script_content, tools_path);
    let tools_functions = parse_tools_functions(tools_path);
    let mut known_variables: Vec<String> =
        collect_known_variables(tools_path).into_iter().collect();
    known_variables.sort();

    Ok(Json(SpecialRulesResponse {
        script_content: row.script_content,
        last_validation_ok: validation.valid,
        validation,
        tools_functions,
        known_variables,
        updated_at: row.updated_at,
    }))
}

/// `GET /api/firewall/tools-functions` — Return the parsed `firewall.tools` helper functions.
pub async fn list_tools_functions(State(state): State<AppState>) -> Json<Vec<ToolFunctionDoc>> {
    let tools_path_str = resolve_tools_path(&state).await;
    Json(parse_tools_functions(Path::new(&tools_path_str)))
}

/// `POST /api/firewall/special-rules/validate` — Run the 3-stage validation pipeline without saving.
///
/// # Errors
/// Returns [`AppError`] if recording the audit log fails.
pub async fn validate_special_rules_endpoint(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictJson(payload): StrictJson<SpecialRulesRequest>,
) -> Result<Json<ValidationReport>, AppError> {
    let tools_path_str = resolve_tools_path(&state).await;
    let report = validate_special_rules(&payload.script_content, Path::new(&tools_path_str));

    record_audit(
        &state.db,
        &caller,
        client_ip,
        "VALIDATE_SPECIAL_RULES",
        Some("fw_special_rules:1".to_owned()),
        Some(format!(
            "3-stage check: valid={}, bash_n={}, undefined_vars={}, shellcheck_ok={}",
            report.valid,
            report.bash_n_ok,
            report.undefined_variables.len(),
            report.shellcheck_ok
        )),
    )
    .await?;

    Ok(Json(report))
}

/// `PUT /api/firewall/special-rules` — Validate and persist `firewall.rules.special`.
///
/// Rejects with `422 Unprocessable Entity` if `bash -n` or variable resolution fails (or if
/// `shellcheck` reports errors and `allow_warnings` is `false`).
///
/// # Errors
/// Returns [`AppError`] if validation fails or caller lacks permissions.
pub async fn update_special_rules(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictJson(payload): StrictJson<SpecialRulesRequest>,
) -> Result<Json<SpecialRulesResponse>, AppError> {
    ensure_can_manage_special_rules(&caller)?;

    let tools_path_str = resolve_tools_path(&state).await;
    let tools_path = Path::new(&tools_path_str);
    let report = validate_special_rules(&payload.script_content, tools_path);

    let acceptable =
        report.bash_n_ok && report.variables_ok && (report.shellcheck_ok || payload.allow_warnings);

    if !acceptable {
        record_audit(
            &state.db,
            &caller,
            client_ip,
            "REJECT_SPECIAL_RULES",
            Some("fw_special_rules:1".to_owned()),
            Some(format!(
                "Rejected save: bash_n_ok={}, undefined_vars={}, shellcheck_ok={}",
                report.bash_n_ok,
                report.undefined_variables.len(),
                report.shellcheck_ok
            )),
        )
        .await?;

        return Err(AppError::ValidationFailed {
            message: "firewall.rules.special failed the 3-stage integrity check".to_owned(),
            report: serde_json::to_value(&report).unwrap_or_default(),
        });
    }

    let existing = fw_special_rules::Entity::find_by_id(1)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    let now = Utc::now();
    let mut active: fw_special_rules::ActiveModel = existing.into();
    active.script_content = Set(payload.script_content);
    active.last_validation_ok = Set(report.valid);
    active.last_validation_json = Set(serde_json::to_string(&report).ok());
    active.updated_at = Set(now);

    let updated = active.update(&state.db).await?;

    record_audit(
        &state.db,
        &caller,
        client_ip,
        "UPDATE_SPECIAL_RULES",
        Some("fw_special_rules:1".to_owned()),
        Some(format!(
            "Saved firewall.rules.special ({} bytes, valid={})",
            updated.script_content.len(),
            report.valid
        )),
    )
    .await?;

    let tools_functions = parse_tools_functions(tools_path);
    let mut known_variables: Vec<String> =
        collect_known_variables(tools_path).into_iter().collect();
    known_variables.sort();

    Ok(Json(SpecialRulesResponse {
        script_content: updated.script_content,
        last_validation_ok: report.valid,
        validation: report,
        tools_functions,
        known_variables,
        updated_at: updated.updated_at,
    }))
}
