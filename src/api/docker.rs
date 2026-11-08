//! Docker discovery endpoint (`GET /api/docker/discovery`).

use axum::Json;
use axum::extract::State;
use sea_orm::EntityTrait;

use crate::docker::{DockerDiscoverySnapshot, discover_docker};
use crate::entities::fw_settings;
use crate::error::AppError;
use crate::state::AppState;

/// `GET /api/docker/discovery` — Inspect the configured Docker daemon and return all containers
/// (running and stopped) and Docker networks.
///
/// # Errors
/// Returns [`AppError`] if reading settings from the database fails.
pub async fn get_docker_discovery(
    State(state): State<AppState>,
) -> Result<Json<DockerDiscoverySnapshot>, AppError> {
    let settings = fw_settings::Entity::find_by_id(1).one(&state.db).await?;
    let endpoint = settings
        .as_ref()
        .map_or("unix:///var/run/docker.sock", |s| {
            s.docker_endpoint.as_str()
        });
    let snapshot = discover_docker(&state.http, endpoint).await;
    Ok(Json(snapshot))
}
