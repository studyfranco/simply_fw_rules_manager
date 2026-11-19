//! Database connection setup, `SQLite` session pragmas, and migration runner.

use std::str::FromStr;
use std::time::Duration;

use sea_orm::sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous,
};
use sea_orm::{ConnectionTrait, DatabaseConnection, DbErr, Statement};

/// `SQLite` permits a single writer connection to avoid DDL/transaction races.
pub const SQLITE_MAX_CONNECTIONS: u32 = 1;

/// Busy-wait timeout before `SQLite` gives up waiting for a lock to clear.
pub const SQLITE_BUSY_TIMEOUT_MS: u64 = 5_000;

/// Connects to `database_url`.
///
/// # Errors
/// Returns [`DbErr`] if the connection or pool initialization fails.
pub async fn connect(database_url: &str) -> Result<DatabaseConnection, DbErr> {
    if database_url.starts_with("sqlite:") {
        let connect_options = SqliteConnectOptions::from_str(database_url)
            .map_err(|e| DbErr::Custom(format!("invalid DATABASE_URL: {e}")))?
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_millis(SQLITE_BUSY_TIMEOUT_MS))
            .pragma("temp_store", "MEMORY")
            .pragma("mmap_size", "268435456")
            .pragma("cache_size", "-64000")
            .pragma("analysis_limit", "1000");
        let pool = SqlitePoolOptions::new()
            .max_connections(SQLITE_MAX_CONNECTIONS)
            .connect_with(connect_options)
            .await
            .map_err(|e| DbErr::Custom(format!("failed to connect to SQLite: {e}")))?;
        return Ok(sea_orm::SqlxSqliteConnector::from_sqlx_sqlite_pool(pool));
    }
    sea_orm::Database::connect(database_url).await
}

/// Runs all pending database migrations.
///
/// # Errors
/// Returns [`DbErr`] if any migration fails.
pub async fn run_migrations(db: &DatabaseConnection) -> Result<(), DbErr> {
    use sea_orm_migration::MigratorTrait;
    crate::migration::Migrator::up(db, None).await
}

/// Checks whether an index named `index` exists on `table` via backend catalog queries.
///
/// # Errors
/// Returns [`DbErr`] if the backend catalog query fails or the backend is unsupported.
pub async fn has_index(db: &DatabaseConnection, table: &str, index: &str) -> Result<bool, DbErr> {
    sea_orm_migration::SchemaManager::new(db)
        .has_index(table, index)
        .await
}

/// Executes a lightweight health query (`SELECT 1`) for readiness probes.
///
/// # Errors
/// Returns [`DbErr`] if the database is unreachable.
pub async fn check_ready(db: &DatabaseConnection) -> Result<(), DbErr> {
    let backend = db.get_database_backend();
    db.query_one_raw(Statement::from_string(backend, "SELECT 1".to_owned()))
        .await?;
    Ok(())
}
