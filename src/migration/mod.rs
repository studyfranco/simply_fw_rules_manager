//! `SeaORM` migration registry.

use sea_orm_migration::prelude::*;

mod m20260101_000001_create_tables;
mod m20261109_000002_add_performance_indexes;
mod m20261110_000003_add_query_optimization_indexes;

/// Migrator executing all schema migrations in order.
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260101_000001_create_tables::Migration),
            Box::new(m20261109_000002_add_performance_indexes::Migration),
            Box::new(m20261110_000003_add_query_optimization_indexes::Migration),
        ]
    }
}
