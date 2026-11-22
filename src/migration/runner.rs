//! Executes versioned `SeaQuery` migrations and probes database catalogs.

use std::{collections::HashSet, future::Future, pin::Pin};

use sea_orm::{
    ConnectionTrait, DatabaseBackend, DatabaseConnection, DatabaseExecutor, DbErr, Schema, Set,
    StatementBuilder, TransactionTrait, entity::prelude::*,
};
use sea_schema::probe::SchemaProbe;
use time::OffsetDateTime;

use super::{
    m20260101_000001_create_tables, m20261109_000002_add_performance_indexes,
    m20261110_000003_add_query_optimization_indexes, m20261115_000004_master_marker,
    m20261119_000005_unify_text_columns,
};

mod history {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "seaql_migrations")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub version: String,
        pub applied_at: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// Executes typed schema statements and backend catalog probes.
pub struct SchemaManager<'a> {
    db: DatabaseExecutor<'a>,
}

impl<'a> SchemaManager<'a> {
    /// Creates a manager over a database connection or transaction.
    pub fn new(db: impl Into<DatabaseExecutor<'a>>) -> Self {
        Self { db: db.into() }
    }

    pub(super) fn get_database_backend(&self) -> DatabaseBackend {
        self.db.get_database_backend()
    }

    pub(super) async fn execute(&self, statement: impl StatementBuilder) -> Result<(), DbErr> {
        self.db.execute(&statement).await.map(|_| ())
    }

    /// Checks whether the named table has the named index.
    ///
    /// # Errors
    /// Returns a database error if the catalog cannot be queried.
    pub async fn has_index(&self, table: &str, index: &str) -> Result<bool, DbErr> {
        let query = match self.get_database_backend() {
            DatabaseBackend::Sqlite => sea_schema::sqlite::Sqlite.has_index(table, index),
            DatabaseBackend::Postgres => sea_schema::postgres::Postgres.has_index(table, index),
            DatabaseBackend::MySql => sea_schema::mysql::MySql.has_index(table, index),
            other => {
                return Err(DbErr::BackendNotSupported {
                    db: other.as_str(),
                    ctx: "has_index",
                });
            }
        };
        self.db
            .query_one(&query)
            .await?
            .ok_or_else(|| DbErr::Custom("Index probe returned no rows".to_owned()))?
            .try_get("", "has_index")
    }
}

type MigrationStep = for<'a> fn(
    &'a SchemaManager<'_>,
) -> Pin<Box<dyn Future<Output = Result<(), DbErr>> + Send + 'a>>;

/// A versioned schema change.
pub struct Migration {
    version: &'static str,
    up: MigrationStep,
    down: MigrationStep,
}

macro_rules! migration {
    ($module:ident) => {
        Migration {
            version: stringify!($module),
            up: |manager| Box::pin($module::up(manager)),
            down: |manager| Box::pin($module::down(manager)),
        }
    };
}

/// Applies and reverts schema changes using the original migration ledger.
pub struct Migrator;

impl Migrator {
    /// Returns the migration registry in application order.
    #[must_use]
    pub const fn migrations() -> [Migration; 5] {
        [
            migration!(m20260101_000001_create_tables),
            migration!(m20261109_000002_add_performance_indexes),
            migration!(m20261110_000003_add_query_optimization_indexes),
            migration!(m20261115_000004_master_marker),
            migration!(m20261119_000005_unify_text_columns),
        ]
    }

    /// Applies up to `steps` pending migrations, or all pending migrations for `None`.
    ///
    /// # Errors
    /// Returns a database error if migration or ledger operations fail.
    pub async fn up(db: &DatabaseConnection, steps: Option<u32>) -> Result<(), DbErr> {
        Self::run(db, steps, true).await
    }

    /// Reverts up to `steps` applied migrations, or all applied migrations for `None`.
    ///
    /// # Errors
    /// Returns a database error if migration or ledger operations fail.
    pub async fn down(db: &DatabaseConnection, steps: Option<u32>) -> Result<(), DbErr> {
        Self::run(db, steps, false).await
    }

    async fn run(db: &DatabaseConnection, steps: Option<u32>, up: bool) -> Result<(), DbErr> {
        if db.get_database_backend() == DatabaseBackend::MySql {
            // MySQL implicitly commits DDL.
            return Self::apply(&SchemaManager::new(db), steps, up).await;
        }
        let transaction = db.begin().await?;
        Self::apply(&SchemaManager::new(&transaction), steps, up).await?;
        transaction.commit().await
    }

    async fn apply(manager: &SchemaManager<'_>, steps: Option<u32>, up: bool) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        let mut ledger = Schema::new(backend).create_table_from_entity(history::Entity);
        ledger.if_not_exists();
        manager.execute(ledger).await?;

        let applied: HashSet<_> = history::Entity::find()
            .all(&manager.db)
            .await?
            .into_iter()
            .map(|row| row.version)
            .collect();
        let mut migrations = Self::migrations();
        if let Some(unknown) = applied.iter().find(|version| {
            !migrations
                .iter()
                .any(|migration| migration.version == *version)
        }) {
            return Err(DbErr::Custom(format!(
                "Applied migration {unknown} is missing from the registry"
            )));
        }
        if !up {
            migrations.reverse();
        }
        for migration in migrations
            .into_iter()
            .filter(|migration| applied.contains(migration.version) != up)
            .take(steps.map_or(usize::MAX, |count| count as usize))
        {
            if up {
                (migration.up)(manager).await?;
                history::ActiveModel {
                    version: Set(migration.version.to_owned()),
                    applied_at: Set(OffsetDateTime::now_utc().unix_timestamp()),
                }
                .insert(&manager.db)
                .await?;
            } else {
                (migration.down)(manager).await?;
                history::Entity::delete_by_id(migration.version)
                    .exec(&manager.db)
                    .await?;
            }
        }
        Ok(())
    }
}
