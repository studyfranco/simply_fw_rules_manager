//! Initial schema migration creating all `simply_fw_rules_manager` tables.

use sea_orm::{
    DbErr, DeriveIden,
    sea_query::{ColumnDef, ForeignKey, ForeignKeyAction, IntoTableRef, Table},
};

use super::runner::SchemaManager;

async fn create_api_keys_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .execute(
            Table::create()
                .table(ApiKeys::Table)
                .if_not_exists()
                .col(ColumnDef::new(ApiKeys::Id).uuid().not_null().primary_key())
                .col(ColumnDef::new(ApiKeys::Name).string().not_null())
                .col(
                    ColumnDef::new(ApiKeys::KeyHash)
                        .string()
                        .not_null()
                        .unique_key(),
                )
                .col(ColumnDef::new(ApiKeys::SigningSecret).text().null())
                .col(ColumnDef::new(ApiKeys::Prefix).string().not_null())
                .col(
                    ColumnDef::new(ApiKeys::IsMaster)
                        .boolean()
                        .not_null()
                        .default(false),
                )
                .col(
                    ColumnDef::new(ApiKeys::CanManageKeys)
                        .boolean()
                        .not_null()
                        .default(false),
                )
                .col(
                    ColumnDef::new(ApiKeys::CanManageSettings)
                        .boolean()
                        .not_null()
                        .default(false),
                )
                .col(
                    ColumnDef::new(ApiKeys::CanManageSpecialRules)
                        .boolean()
                        .not_null()
                        .default(false),
                )
                .col(
                    ColumnDef::new(ApiKeys::CanManageBlocklists)
                        .boolean()
                        .not_null()
                        .default(false),
                )
                .col(
                    ColumnDef::new(ApiKeys::CanDeployAndReload)
                        .boolean()
                        .not_null()
                        .default(false),
                )
                .col(ColumnDef::new(ApiKeys::ParentKeyId).uuid().null())
                .col(ColumnDef::new(ApiKeys::BoundIps).text().null())
                .col(
                    ColumnDef::new(ApiKeys::CreatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ApiKeys::UpdatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_api_keys_parent")
                        .from(ApiKeys::Table, ApiKeys::ParentKeyId)
                        .to(ApiKeys::Table, ApiKeys::Id)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .to_owned(),
        )
        .await
}

async fn create_audit_logs_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .execute(
            Table::create()
                .table(AuditLogs::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(AuditLogs::Id)
                        .uuid()
                        .not_null()
                        .primary_key(),
                )
                .col(ColumnDef::new(AuditLogs::ApiKeyId).uuid().null())
                .col(ColumnDef::new(AuditLogs::ApiKeyName).string().not_null())
                .col(ColumnDef::new(AuditLogs::ApiKeyPrefix).string().not_null())
                .col(ColumnDef::new(AuditLogs::Action).string().not_null())
                .col(ColumnDef::new(AuditLogs::TargetResource).text().null())
                .col(ColumnDef::new(AuditLogs::Details).text().null())
                .col(ColumnDef::new(AuditLogs::ClientIp).string().not_null())
                .col(
                    ColumnDef::new(AuditLogs::Timestamp)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_audit_logs_api_key")
                        .from(AuditLogs::Table, AuditLogs::ApiKeyId)
                        .to(ApiKeys::Table, ApiKeys::Id)
                        .on_delete(ForeignKeyAction::SetNull),
                )
                .to_owned(),
        )
        .await
}

async fn create_fw_settings_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let mut table = Table::create();
    table.table(FwSettings::Table).if_not_exists().col(
        ColumnDef::new(FwSettings::Id)
            .integer()
            .not_null()
            .primary_key(),
    );
    for col in [
        FwSettings::MainInter,
        FwSettings::CountryOpenPort,
        FwSettings::BlockedCountry,
        FwSettings::BlockedCountry2,
        FwSettings::HookReloadName,
        FwSettings::HookUpdateContainersName,
    ] {
        table.col(ColumnDef::new(col).string().not_null());
    }
    for col in [
        FwSettings::DockerEndpoint,
        FwSettings::OutputDir,
        FwSettings::ToolsScriptPath,
        FwSettings::InterOutJson,
        FwSettings::InterfaceToGoOutsideJson,
        FwSettings::InternInterfaceHaveAccessAsLocalJson,
        FwSettings::InterfaceLocalJson,
        FwSettings::InterfaceWithDhcpJson,
        FwSettings::InterfaceWithNoRulesJson,
        FwSettings::DockerNetworkWithInternetAccessJson,
        FwSettings::DockerNetworkWithAccessJson,
        FwSettings::IpAutorJson,
        FwSettings::IpAutorDnatPortTcpJson,
        FwSettings::IpAutorDnatPortUdpJson,
    ] {
        table.col(ColumnDef::new(col).text().not_null());
    }
    for col in [
        FwSettings::HookExecutorUrl,
        FwSettings::HookExecutorApiKey,
        FwSettings::HookExecutorSigningSecret,
    ] {
        table.col(ColumnDef::new(col).text().null());
    }
    table.col(
        ColumnDef::new(FwSettings::UpdatedAt)
            .timestamp_with_time_zone()
            .not_null(),
    );
    manager.execute(table).await
}

async fn create_fw_docker_inter_rules_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .execute(
            Table::create()
                .table(FwDockerInterRules::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(FwDockerInterRules::Id)
                        .uuid()
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(FwDockerInterRules::SourceContainer)
                        .string()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(FwDockerInterRules::DestinationContainer)
                        .string()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(FwDockerInterRules::NetworkName)
                        .string()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(FwDockerInterRules::Proto)
                        .string()
                        .not_null(),
                )
                .col(ColumnDef::new(FwDockerInterRules::Ports).text().not_null())
                .col(
                    ColumnDef::new(FwDockerInterRules::Enabled)
                        .boolean()
                        .not_null()
                        .default(true),
                )
                .col(ColumnDef::new(FwDockerInterRules::Comment).text().null())
                .col(
                    ColumnDef::new(FwDockerInterRules::SortOrder)
                        .integer()
                        .not_null()
                        .default(0),
                )
                .col(
                    ColumnDef::new(FwDockerInterRules::CreatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(FwDockerInterRules::UpdatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .to_owned(),
        )
        .await
}

async fn create_fw_zone_rules_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .execute(
            Table::create()
                .table(FwZoneRules::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(FwZoneRules::Id)
                        .uuid()
                        .not_null()
                        .primary_key(),
                )
                .col(ColumnDef::new(FwZoneRules::Zone).string().not_null())
                .col(ColumnDef::new(FwZoneRules::RuleKind).string().not_null())
                .col(ColumnDef::new(FwZoneRules::Value).text().not_null())
                .col(ColumnDef::new(FwZoneRules::ContainerName).string().null())
                .col(
                    ColumnDef::new(FwZoneRules::Enabled)
                        .boolean()
                        .not_null()
                        .default(true),
                )
                .col(ColumnDef::new(FwZoneRules::Comment).text().null())
                .col(
                    ColumnDef::new(FwZoneRules::SortOrder)
                        .integer()
                        .not_null()
                        .default(0),
                )
                .col(
                    ColumnDef::new(FwZoneRules::CreatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(FwZoneRules::UpdatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .to_owned(),
        )
        .await
}

async fn create_fw_special_rules_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .execute(
            Table::create()
                .table(FwSpecialRules::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(FwSpecialRules::Id)
                        .integer()
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(FwSpecialRules::ScriptContent)
                        .text()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(FwSpecialRules::LastValidationOk)
                        .boolean()
                        .not_null()
                        .default(true),
                )
                .col(
                    ColumnDef::new(FwSpecialRules::LastValidationJson)
                        .text()
                        .null(),
                )
                .col(
                    ColumnDef::new(FwSpecialRules::UpdatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .to_owned(),
        )
        .await
}

async fn create_fw_blocklists_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .execute(
            Table::create()
                .table(FwBlocklists::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(FwBlocklists::Id)
                        .uuid()
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(FwBlocklists::Name)
                        .string()
                        .not_null()
                        .unique_key(),
                )
                .col(ColumnDef::new(FwBlocklists::Url).text().not_null())
                .col(
                    ColumnDef::new(FwBlocklists::Enabled)
                        .boolean()
                        .not_null()
                        .default(true),
                )
                .col(ColumnDef::new(FwBlocklists::Description).text().null())
                .col(ColumnDef::new(FwBlocklists::LastTestOk).boolean().null())
                .col(
                    ColumnDef::new(FwBlocklists::LastTestEntries)
                        .integer()
                        .null(),
                )
                .col(
                    ColumnDef::new(FwBlocklists::LastTestAt)
                        .timestamp_with_time_zone()
                        .null(),
                )
                .col(
                    ColumnDef::new(FwBlocklists::SortOrder)
                        .integer()
                        .not_null()
                        .default(0),
                )
                .col(
                    ColumnDef::new(FwBlocklists::CreatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(FwBlocklists::UpdatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .to_owned(),
        )
        .await
}

pub(super) async fn up(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    create_api_keys_table(manager).await?;
    create_audit_logs_table(manager).await?;
    create_fw_settings_table(manager).await?;
    create_fw_docker_inter_rules_table(manager).await?;
    create_fw_zone_rules_table(manager).await?;
    create_fw_special_rules_table(manager).await?;
    create_fw_blocklists_table(manager).await
}

pub(super) async fn down(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    for table in [
        FwBlocklists::Table.into_table_ref(),
        FwSpecialRules::Table.into_table_ref(),
        FwZoneRules::Table.into_table_ref(),
        FwDockerInterRules::Table.into_table_ref(),
        FwSettings::Table.into_table_ref(),
        AuditLogs::Table.into_table_ref(),
        ApiKeys::Table.into_table_ref(),
    ] {
        manager
            .execute(Table::drop().table(table).if_exists().to_owned())
            .await?;
    }
    Ok(())
}

#[derive(DeriveIden)]
enum ApiKeys {
    Table,
    Id,
    Name,
    KeyHash,
    SigningSecret,
    Prefix,
    IsMaster,
    CanManageKeys,
    CanManageSettings,
    CanManageSpecialRules,
    CanManageBlocklists,
    CanDeployAndReload,
    ParentKeyId,
    BoundIps,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum AuditLogs {
    Table,
    Id,
    ApiKeyId,
    ApiKeyName,
    ApiKeyPrefix,
    Action,
    TargetResource,
    Details,
    ClientIp,
    Timestamp,
}

#[derive(DeriveIden)]
enum FwSettings {
    Table,
    Id,
    MainInter,
    InterOutJson,
    InterfaceToGoOutsideJson,
    InternInterfaceHaveAccessAsLocalJson,
    InterfaceLocalJson,
    InterfaceWithDhcpJson,
    InterfaceWithNoRulesJson,
    DockerNetworkWithInternetAccessJson,
    DockerNetworkWithAccessJson,
    IpAutorJson,
    IpAutorDnatPortTcpJson,
    IpAutorDnatPortUdpJson,
    CountryOpenPort,
    BlockedCountry,
    #[sea_orm(iden = "blocked_country_2")]
    BlockedCountry2,
    DockerEndpoint,
    OutputDir,
    ToolsScriptPath,
    HookExecutorUrl,
    HookExecutorApiKey,
    HookExecutorSigningSecret,
    HookReloadName,
    HookUpdateContainersName,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum FwDockerInterRules {
    Table,
    Id,
    SourceContainer,
    DestinationContainer,
    NetworkName,
    Proto,
    Ports,
    Enabled,
    Comment,
    SortOrder,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum FwZoneRules {
    Table,
    Id,
    Zone,
    RuleKind,
    Value,
    ContainerName,
    Enabled,
    Comment,
    SortOrder,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum FwSpecialRules {
    Table,
    Id,
    ScriptContent,
    LastValidationOk,
    LastValidationJson,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum FwBlocklists {
    Table,
    Id,
    Name,
    Url,
    Enabled,
    Description,
    LastTestOk,
    LastTestEntries,
    LastTestAt,
    SortOrder,
    CreatedAt,
    UpdatedAt,
}
