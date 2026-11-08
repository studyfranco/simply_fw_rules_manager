//! HTTP handler modules and unauthenticated health/readiness probes.

pub mod audit;
pub mod blocklists;
pub mod deploy;
pub mod docker;
pub mod keys;
pub mod settings;
pub mod special_rules;

use axum::Json;
use axum::extract::State;
use sea_orm::ConnectionTrait;
use serde_json::{Value, json};

use crate::error::AppError;
use crate::state::AppState;

/// `GET /health` and `GET /healthz` — Liveness probe.
pub async fn health_check() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

/// `GET /ready` and `GET /readyz` — Readiness probe verifying database connectivity.
///
/// # Errors
/// Returns [`AppError::DbError`] if `SELECT 1` fails.
pub async fn readiness_check(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    state.db.execute_unprepared("SELECT 1").await?;
    Ok(Json(json!({ "status": "ready" })))
}
