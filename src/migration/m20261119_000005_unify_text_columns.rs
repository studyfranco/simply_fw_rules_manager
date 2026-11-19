//! Widens variable-length columns on existing PostgreSQL and MySQL databases.

use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::DatabaseBackend;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DatabaseBackend::Sqlite {
            return Ok(());
        }

        for (table, column, nullable) in [
            ("api_keys", "signing_secret", true),
            ("api_keys", "bound_ips", true),
            ("audit_logs", "target_resource", true),
            ("fw_settings", "hook_executor_url", true),
            ("fw_settings", "hook_executor_api_key", true),
            ("fw_settings", "hook_executor_signing_secret", true),
            ("fw_settings", "docker_endpoint", false),
            ("fw_settings", "output_dir", false),
            ("fw_settings", "tools_script_path", false),
            ("fw_docker_inter_rules", "comment", true),
            ("fw_docker_inter_rules", "ports", false),
            ("fw_zone_rules", "comment", true),
            ("fw_zone_rules", "value", false),
            ("fw_blocklists", "description", true),
            ("fw_blocklists", "url", false),
        ] {
            let mut definition = ColumnDef::new(Alias::new(column));
            definition.text();
            if nullable {
                definition.null();
            } else {
                definition.not_null();
            }
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new(table))
                        .modify_column(definition)
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // Narrowing could truncate existing values.
        Ok(())
    }
}
