//! `SeaORM` migration registry.

use sea_orm_migration::prelude::*;

mod m20260101_000001_create_tables;

/// Migrator executing all schema migrations in order.
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(m20260101_000001_create_tables::Migration)]
    }
}
