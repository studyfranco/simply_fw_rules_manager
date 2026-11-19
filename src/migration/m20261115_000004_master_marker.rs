//! Enforces single-Master uniqueness via a database-derived generated column and unique index.

use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::DatabaseBackend;

const MARKER_COLUMN: &str = "master_marker";
const MARKER_INDEX: &str = "idx_api_keys_master_marker";

#[derive(DeriveIden)]
enum ApiKeys {
    Table,
}

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let storage = match manager.get_database_backend() {
            DatabaseBackend::Postgres => "STORED",
            _ => "VIRTUAL",
        };
        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeys::Table)
                    .add_column(
                        ColumnDef::new(Alias::new(MARKER_COLUMN)).integer().extra(format!(
                            "GENERATED ALWAYS AS (CASE WHEN is_master THEN 1 ELSE NULL END) {storage}"
                        )),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name(MARKER_INDEX)
                    .table(ApiKeys::Table)
                    .col(Alias::new(MARKER_COLUMN))
                    .unique()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name(MARKER_INDEX)
                    .table(ApiKeys::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeys::Table)
                    .drop_column(Alias::new(MARKER_COLUMN))
                    .to_owned(),
            )
            .await
    }
}
