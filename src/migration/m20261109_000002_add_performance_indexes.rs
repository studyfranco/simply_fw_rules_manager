//! Adds performance and covering indexes across core firewall and operational tables.

use sea_orm_migration::prelude::*;

#[derive(DeriveIden)]
enum ApiKeys {
    Table,
    ParentKeyId,
    Prefix,
}

#[derive(DeriveIden)]
enum AuditLogs {
    Table,
    Timestamp,
    Action,
    ApiKeyId,
}

#[derive(DeriveIden)]
enum FwZoneRules {
    Table,
    Zone,
    ContainerName,
}

#[derive(DeriveIden)]
enum FwDockerInterRules {
    Table,
    SourceContainer,
    DestinationContainer,
}

#[derive(DeriveIden)]
enum FwBlocklists {
    Table,
    Enabled,
}

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 1. Audit logs: newest-first ordering, action filter, and key attribution
        manager
            .create_index(
                Index::create()
                    .name("idx_audit_logs_timestamp")
                    .table(AuditLogs::Table)
                    .col((AuditLogs::Timestamp, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_audit_logs_action_timestamp")
                    .table(AuditLogs::Table)
                    .col(AuditLogs::Action)
                    .col((AuditLogs::Timestamp, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_audit_logs_api_key_id")
                    .table(AuditLogs::Table)
                    .col(AuditLogs::ApiKeyId)
                    .to_owned(),
            )
            .await?;

        // 2. Zone rules: zone and container lookups for rule generation
        manager
            .create_index(
                Index::create()
                    .name("idx_fw_zone_rules_zone")
                    .table(FwZoneRules::Table)
                    .col(FwZoneRules::Zone)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_fw_zone_rules_container_name")
                    .table(FwZoneRules::Table)
                    .col(FwZoneRules::ContainerName)
                    .to_owned(),
            )
            .await?;

        // 3. Docker rules: container lookups for generation and container updates
        manager
            .create_index(
                Index::create()
                    .name("idx_fw_docker_inter_rules_source")
                    .table(FwDockerInterRules::Table)
                    .col(FwDockerInterRules::SourceContainer)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_fw_docker_inter_rules_dest")
                    .table(FwDockerInterRules::Table)
                    .col(FwDockerInterRules::DestinationContainer)
                    .to_owned(),
            )
            .await?;

        // 4. Blocklists: enabled filter lookup
        manager
            .create_index(
                Index::create()
                    .name("idx_fw_blocklists_enabled")
                    .table(FwBlocklists::Table)
                    .col(FwBlocklists::Enabled)
                    .to_owned(),
            )
            .await?;

        // 5. API keys: parent foreign key and prefix lookups
        manager
            .create_index(
                Index::create()
                    .name("idx_api_keys_parent_key_id")
                    .table(ApiKeys::Table)
                    .col(ApiKeys::ParentKeyId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_api_keys_prefix")
                    .table(ApiKeys::Table)
                    .col(ApiKeys::Prefix)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let indexes = [
            ("idx_audit_logs_timestamp", AuditLogs::Table.into_iden()),
            ("idx_audit_logs_action_timestamp", AuditLogs::Table.into_iden()),
            ("idx_audit_logs_api_key_id", AuditLogs::Table.into_iden()),
            ("idx_fw_zone_rules_zone", FwZoneRules::Table.into_iden()),
            ("idx_fw_zone_rules_container_name", FwZoneRules::Table.into_iden()),
            ("idx_fw_docker_inter_rules_source", FwDockerInterRules::Table.into_iden()),
            ("idx_fw_docker_inter_rules_dest", FwDockerInterRules::Table.into_iden()),
            ("idx_fw_blocklists_enabled", FwBlocklists::Table.into_iden()),
            ("idx_api_keys_parent_key_id", ApiKeys::Table.into_iden()),
            ("idx_api_keys_prefix", ApiKeys::Table.into_iden()),
        ];

        for (name, table) in indexes {
            manager
                .drop_index(Index::drop().name(name).table(table).to_owned())
                .await?;
        }

        Ok(())
    }
}
