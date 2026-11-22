//! Database schema migrations and their runner.

mod m20260101_000001_create_tables;
mod m20261109_000002_add_performance_indexes;
mod m20261110_000003_add_query_optimization_indexes;
mod m20261115_000004_master_marker;
mod m20261119_000005_unify_text_columns;
pub mod runner;

pub use runner::Migrator;
