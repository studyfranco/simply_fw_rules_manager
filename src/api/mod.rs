//! HTTP handler modules and unauthenticated health/readiness probes.

pub mod audit;
pub mod blocklists;
pub mod deploy;
pub mod docker;
pub mod keys;
pub mod settings;
pub mod special_rules;
pub mod system;

pub use system::get_system_settings;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde_json::{Value, json};

use crate::state::AppState;

/// `GET /health` and `GET /healthz` — Liveness probe.
pub async fn health_check() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

/// `GET /ready` and `GET /readyz` — Readiness probe verifying database connectivity and Master pin.
pub async fn readiness_check(State(state): State<AppState>) -> impl IntoResponse {
    let db_ok = crate::db::check_ready(&state.db).await.is_ok();
    let master_ok = state.master_pin.get().is_some();
    if db_ok && master_ok {
        (StatusCode::OK, Json(json!({ "status": "ready" })))
    } else {
        tracing::warn!(db_ok, master_ok, "Readiness probe failed");
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "not_ready" })),
        )
    }
}
