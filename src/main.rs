//! Binary entrypoint for `simply_fw_rules_manager`.

use std::net::SocketAddr;

use sea_orm_migration::MigratorTrait;
use tracing_subscriber::EnvFilter;

use simply_fw_rules_manager::db::connect;
use simply_fw_rules_manager::importer::seed_if_empty;
use simply_fw_rules_manager::master::ensure_master_key;
use simply_fw_rules_manager::migration::Migrator;
use simply_fw_rules_manager::state::AppState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = dotenvy::dotenv();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,simply_fw_rules_manager=info")),
        )
        .init();

    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://data/fw_rules_manager.db?mode=rwc".to_owned());
    if let Some(sqlite_path) = db_url
        .strip_prefix("sqlite://")
        .and_then(|s| s.split('?').next())
        && sqlite_path != ":memory:"
        && let Some(parent) = std::path::Path::new(sqlite_path).parent()
        && !parent.as_os_str().is_empty()
    {
        let _ = std::fs::create_dir_all(parent);
    }

    let db = connect(&db_url).await?;
    Migrator::up(&db, None).await?;

    let state = AppState::new(db.clone())?;
    let master_id = ensure_master_key(&db, &state.cipher).await?;
    let _ = state.master_pin.pin_at_boot(&db).await?;
    tracing::info!("Pinned Master API Key identity: {master_id}");

    if let Some(summary) = seed_if_empty(&db).await? {
        tracing::info!(
            "Seeded initial firewall configuration from '{}': {} zone rules, {} Docker rules, {} blocklists",
            summary.source_dir,
            summary.zone_rules_imported,
            summary.docker_inter_rules_imported,
            summary.blocklists_imported
        );
    }

    let listen_addr: SocketAddr = std::env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:3000".to_owned())
        .parse()?;

    let app = simply_fw_rules_manager::create_app(state);
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    tracing::info!("simply_fw_rules_manager listening on http://{listen_addr}");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}
