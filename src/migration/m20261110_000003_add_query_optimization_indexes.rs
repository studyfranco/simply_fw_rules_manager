//! Adds advanced lookup, covering, and composite sort-filtering indexes across all tables.

use sea_orm_migration::prelude::*;

#[derive(DeriveIden)]
enum ApiKeys {
    Table,
    IsMaster,
    Name,
    CreatedAt,
    ParentKeyId,
}

#[derive(DeriveIden)]
enum AuditLogs {
    Table,
    ApiKeyId,
    Timestamp,
    ClientIp,
    ApiKeyName,
    ApiKeyPrefix,
}

#[derive(DeriveIden)]
enum FwZoneRules {
    Table,
    Enabled,
    SortOrder,
    Zone,
    RuleKind,
}

#[derive(DeriveIden)]
enum FwDockerInterRules {
    Table,
    Enabled,
    SortOrder,
    NetworkName,
}

#[derive(DeriveIden)]
enum FwBlocklists {
    Table,
    Enabled,
    SortOrder,
}

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 1. ApiKeys: lookup by is_master, name, and sorted by created_at / parent delegation
        manager
            .create_index(
                Index::create()
                    .name("idx_api_keys_is_master")
                    .table(ApiKeys::Table)
                    .col(ApiKeys::IsMaster)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_api_keys_name")
                    .table(ApiKeys::Table)
                    .col(ApiKeys::Name)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_api_keys_created_at")
                    .table(ApiKeys::Table)
                    .col(ApiKeys::CreatedAt)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_api_keys_parent_created")
                    .table(ApiKeys::Table)
                    .col(ApiKeys::ParentKeyId)
                    .col(ApiKeys::CreatedAt)
                    .to_owned(),
            )
            .await?;

        // 2. AuditLogs: composite key+timestamp, client_ip+timestamp, and key search filters
        manager
            .create_index(
                Index::create()
                    .name("idx_audit_logs_key_timestamp")
                    .table(AuditLogs::Table)
                    .col(AuditLogs::ApiKeyId)
                    .col((AuditLogs::Timestamp, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_audit_logs_client_ip_timestamp")
                    .table(AuditLogs::Table)
                    .col(AuditLogs::ClientIp)
                    .col((AuditLogs::Timestamp, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_audit_logs_key_name")
                    .table(AuditLogs::Table)
                    .col(AuditLogs::ApiKeyName)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_audit_logs_key_prefix")
                    .table(AuditLogs::Table)
                    .col(AuditLogs::ApiKeyPrefix)
                    .to_owned(),
            )
            .await?;

        // 3. FwZoneRules: enabled+sort for generator, sort_order, zone+sort, and rule_kind
        manager
            .create_index(
                Index::create()
                    .name("idx_fw_zone_rules_enabled_sort")
                    .table(FwZoneRules::Table)
                    .col(FwZoneRules::Enabled)
                    .col(FwZoneRules::SortOrder)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_fw_zone_rules_sort_order")
                    .table(FwZoneRules::Table)
                    .col(FwZoneRules::SortOrder)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_fw_zone_rules_zone_sort")
                    .table(FwZoneRules::Table)
                    .col(FwZoneRules::Zone)
                    .col(FwZoneRules::SortOrder)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_fw_zone_rules_rule_kind")
                    .table(FwZoneRules::Table)
                    .col(FwZoneRules::RuleKind)
                    .to_owned(),
            )
            .await?;

        // 4. FwDockerInterRules: enabled+sort for generator, sort_order, and network_name
        manager
            .create_index(
                Index::create()
                    .name("idx_fw_docker_inter_rules_enabled_sort")
                    .table(FwDockerInterRules::Table)
                    .col(FwDockerInterRules::Enabled)
                    .col(FwDockerInterRules::SortOrder)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_fw_docker_inter_rules_sort_order")
                    .table(FwDockerInterRules::Table)
                    .col(FwDockerInterRules::SortOrder)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_fw_docker_inter_rules_network")
                    .table(FwDockerInterRules::Table)
                    .col(FwDockerInterRules::NetworkName)
                    .to_owned(),
            )
            .await?;

        // 5. FwBlocklists: composite enabled+sort for generator, and sort_order
        manager
            .create_index(
                Index::create()
                    .name("idx_fw_blocklists_enabled_sort")
                    .table(FwBlocklists::Table)
                    .col(FwBlocklists::Enabled)
                    .col(FwBlocklists::SortOrder)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_fw_blocklists_sort_order")
                    .table(FwBlocklists::Table)
                    .col(FwBlocklists::SortOrder)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let indexes = [
            ("idx_api_keys_is_master", ApiKeys::Table.into_iden()),
            ("idx_api_keys_name", ApiKeys::Table.into_iden()),
            ("idx_api_keys_created_at", ApiKeys::Table.into_iden()),
            ("idx_api_keys_parent_created", ApiKeys::Table.into_iden()),
            ("idx_audit_logs_key_timestamp", AuditLogs::Table.into_iden()),
            (
                "idx_audit_logs_client_ip_timestamp",
                AuditLogs::Table.into_iden(),
            ),
            ("idx_audit_logs_key_name", AuditLogs::Table.into_iden()),
            ("idx_audit_logs_key_prefix", AuditLogs::Table.into_iden()),
            (
                "idx_fw_zone_rules_enabled_sort",
                FwZoneRules::Table.into_iden(),
            ),
            ("idx_fw_zone_rules_sort_order", FwZoneRules::Table.into_iden()),
            ("idx_fw_zone_rules_zone_sort", FwZoneRules::Table.into_iden()),
            ("idx_fw_zone_rules_rule_kind", FwZoneRules::Table.into_iden()),
            (
                "idx_fw_docker_inter_rules_enabled_sort",
                FwDockerInterRules::Table.into_iden(),
            ),
            (
                "idx_fw_docker_inter_rules_sort_order",
                FwDockerInterRules::Table.into_iden(),
            ),
            (
                "idx_fw_docker_inter_rules_network",
                FwDockerInterRules::Table.into_iden(),
            ),
            (
                "idx_fw_blocklists_enabled_sort",
                FwBlocklists::Table.into_iden(),
            ),
            ("idx_fw_blocklists_sort_order", FwBlocklists::Table.into_iden()),
        ];

        for (name, table) in indexes {
            manager
                .drop_index(Index::drop().name(name).table(table).to_owned())
                .await?;
        }

        Ok(())
    }
}
