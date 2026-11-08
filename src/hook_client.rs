//! Signed `CANONICAL_V1` HTTP client for triggering hooks on `simply_hook_executor`.

use chrono::Utc;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::crypto::{SecretCipher, compute_signature};
use crate::entities::fw_settings;
use crate::error::AppError;

/// Outcome returned when triggering a hook on `simply_hook_executor`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookTriggerResult {
    /// Hook name triggered.
    pub hook_name: String,
    /// HTTP status code returned by `simply_hook_executor`.
    pub status_code: u16,
    /// Parsed response body from `simply_hook_executor`.
    pub response: serde_json::Value,
}

/// Triggers `hook_name` on the `simply_hook_executor` endpoint configured in `settings`.
///
/// # Errors
/// Returns [`AppError`] if `simply_hook_executor` is not configured or returns an error.
pub async fn trigger_hook(
    http: &Client,
    cipher: &SecretCipher,
    settings: &fw_settings::Model,
    hook_name: &str,
) -> Result<HookTriggerResult, AppError> {
    let base_url = settings
        .hook_executor_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AppError::InvalidInput(
                "simply_hook_executor URL is not configured in Firewall Settings".to_owned(),
            )
        })?;

    let api_key = settings
        .hook_executor_api_key
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AppError::InvalidInput(
                "simply_hook_executor API Key is not configured in Firewall Settings".to_owned(),
            )
        })?;

    let signing_secret = settings
        .hook_executor_signing_secret
        .as_deref()
        .ok_or_else(|| {
            AppError::InvalidInput(
                "simply_hook_executor Signing Secret is not configured in Firewall Settings"
                    .to_owned(),
            )
        })
        .and_then(|sealed| cipher.open(sealed).map_err(AppError::from))?;

    let trimmed_base = base_url.trim_end_matches('/');
    // Extract any path prefix on base_url so CANONICAL_V1 signs the exact request path
    let base_path = extract_path_prefix(trimmed_base);
    let target_path = format!("{base_path}/api/hooks/{hook_name}/execute");
    let full_url = format!("{trimmed_base}/api/hooks/{hook_name}/execute");

    let body_bytes = b"{}";
    let timestamp = Utc::now().timestamp().to_string();
    let signature = compute_signature(
        &signing_secret,
        "POST",
        &target_path,
        &timestamp,
        body_bytes,
    )
    .map_err(AppError::from)?;

    let response = http
        .post(&full_url)
        .header("X-API-Key", api_key)
        .header("X-Timestamp", &timestamp)
        .header("X-Signature-256", &signature)
        .header("Content-Type", "application/json")
        .body(body_bytes.to_vec())
        .send()
        .await
        .map_err(|e| AppError::Upstream(format!("Failed calling simply_hook_executor: {e}")))?;

    let status_code = response.status().as_u16();
    let raw_text = response.text().await.unwrap_or_default();
    let parsed_json: serde_json::Value = serde_json::from_str(&raw_text)
        .unwrap_or_else(|_| serde_json::json!({ "raw_output": raw_text }));

    if !(200..300).contains(&status_code) {
        return Err(AppError::Upstream(format!(
            "simply_hook_executor returned HTTP {status_code}: {raw_text}"
        )));
    }

    Ok(HookTriggerResult {
        hook_name: hook_name.to_owned(),
        status_code,
        response: parsed_json,
    })
}

fn extract_path_prefix(url: &str) -> &str {
    let Some(after_scheme) = url.split_once("://").map(|(_, rest)| rest) else {
        return "";
    };
    let Some(slash_idx) = after_scheme.find('/') else {
        return "";
    };
    &after_scheme[slash_idx..]
}
