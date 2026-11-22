//! Enforces single-Master uniqueness via a database-derived generated column and unique index.

use sea_orm::{
    DbErr, DeriveIden,
    sea_query::{Alias, ColumnDef, Expr, Index, Table},
};

use super::runner::SchemaManager;
use sea_orm::DatabaseBackend;

const MARKER_COLUMN: &str = "master_marker";
const MARKER_INDEX: &str = "idx_api_keys_master_marker";

#[derive(DeriveIden)]
enum ApiKeys {
    Table,
}

pub(super) async fn up(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let stored = manager.get_database_backend() == DatabaseBackend::Postgres;
    let marker =
        Expr::case(Expr::col(Alias::new("is_master")), 1).finally(Expr::val(Option::<i32>::None));
    manager
        .execute(
            Table::alter()
                .table(ApiKeys::Table)
                .add_column(
                    ColumnDef::new(Alias::new(MARKER_COLUMN))
                        .integer()
                        .generated(marker, stored),
                )
                .to_owned(),
        )
        .await?;

    manager
        .execute(
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

pub(super) async fn down(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .execute(
            Index::drop()
                .name(MARKER_INDEX)
                .table(ApiKeys::Table)
                .to_owned(),
        )
        .await?;

    manager
        .execute(
            Table::alter()
                .table(ApiKeys::Table)
                .drop_column(Alias::new(MARKER_COLUMN))
                .to_owned(),
        )
        .await
}
