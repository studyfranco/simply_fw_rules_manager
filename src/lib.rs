//! `simply_fw_rules_manager` — Linux Netfilter/ipset & Docker firewall rule manager.

pub mod api;
pub mod config;
pub mod crypto;
pub mod db;
pub mod docker;
pub mod entities;
pub mod error;
pub mod extract;
pub mod generator;
pub mod hook_client;
pub mod importer;
pub mod master;
pub mod middleware;
pub mod migration;
pub mod replay;
pub mod state;
pub mod validator;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post, put};
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

/// Assembles the full Axum router with `CANONICAL_V1` authentication middleware and static asset serving.
pub fn create_app(state: AppState) -> Router {
    let api_routes = Router::new()
        .route("/auth/me", get(api::keys::get_me))
        .route(
            "/keys",
            get(api::keys::list_api_keys).post(api::keys::create_api_key),
        )
        .route(
            "/keys/{id}",
            put(api::keys::update_api_key)
                .patch(api::keys::update_api_key)
                .delete(api::keys::delete_api_key),
        )
        .route("/keys/{id}/rotate", post(api::keys::rotate_api_key))
        .route(
            "/keys/{id}/rotate-secret",
            post(api::keys::rotate_signing_secret),
        )
        .route("/audit", get(api::audit::list_audit_logs))
        .route("/audit-logs", get(api::audit::list_audit_logs))
        .route("/system/settings", get(api::get_system_settings))
        .route("/settings", get(api::get_system_settings))
        .route(
            "/firewall/settings",
            get(api::settings::get_settings).put(api::settings::update_settings),
        )
        .route(
            "/firewall/zones",
            get(api::settings::list_zone_rules).post(api::settings::create_zone_rule),
        )
        .route(
            "/firewall/zones/{id}",
            put(api::settings::update_zone_rule).delete(api::settings::delete_zone_rule),
        )
        .route(
            "/firewall/docker-rules",
            get(api::settings::list_docker_inter_rules)
                .post(api::settings::create_docker_inter_rule),
        )
        .route(
            "/firewall/docker-rules/{id}",
            put(api::settings::update_docker_inter_rule)
                .delete(api::settings::delete_docker_inter_rule),
        )
        .route("/docker/discovery", get(api::docker::get_docker_discovery))
        .route(
            "/firewall/special-rules",
            get(api::special_rules::get_special_rules)
                .put(api::special_rules::update_special_rules),
        )
        .route(
            "/firewall/special-rules/validate",
            post(api::special_rules::validate_special_rules_endpoint),
        )
        .route(
            "/firewall/tools-functions",
            get(api::special_rules::list_tools_functions),
        )
        .route(
            "/firewall/blocklists",
            get(api::blocklists::list_blocklists).post(api::blocklists::create_blocklist),
        )
        .route(
            "/firewall/blocklists/{id}",
            put(api::blocklists::update_blocklist).delete(api::blocklists::delete_blocklist),
        )
        .route(
            "/firewall/blocklists/{id}/test",
            post(api::blocklists::test_blocklist),
        )
        .route(
            "/firewall/preview",
            get(api::deploy::preview_generated_files),
        )
        .route("/firewall/import", post(api::deploy::import_example_files))
        .route(
            "/firewall/generate",
            post(api::deploy::generate_files_on_disk),
        )
        .route("/firewall/reload", post(api::deploy::reload_firewall))
        .route(
            "/firewall/generate-and-reload",
            post(api::deploy::generate_and_reload),
        )
        .route(
            "/firewall/update-containers",
            post(api::deploy::update_containers),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth_middleware,
        ));

    Router::new()
        .route("/health", get(api::health_check))
        .route("/healthz", get(api::health_check))
        .route("/ready", get(api::readiness_check))
        .route("/readyz", get(api::readiness_check))
        .nest("/api", api_routes)
        .fallback_service(ServeDir::new("static"))
        .layer(DefaultBodyLimit::max(config::max_body_bytes()))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
