//! `audit_logs` entity model.

use sea_orm::entity::prelude::*;

/// The `audit_logs` row.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "audit_logs")]
pub struct Model {
    /// Primary key.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Originating API key UUID (`ON DELETE SET NULL`).
    pub api_key_id: Option<Uuid>,
    /// Denormalized key name at action time.
    pub api_key_name: String,
    /// Denormalized key prefix at action time.
    pub api_key_prefix: String,
    /// Standardized action code.
    pub action: String,
    /// Target resource identifier.
    pub target_resource: Option<String>,
    /// Structured details of the action.
    #[sea_orm(column_type = "Text", nullable)]
    pub details: Option<String>,
    /// Client IP address.
    pub client_ip: String,
    /// Event timestamp.
    pub timestamp: DateTimeUtc,
}

/// Relations from `audit_logs`.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// Optional relation to `api_keys`.
    #[sea_orm(
        belongs_to = "super::api_key::Entity",
        from = "Column::ApiKeyId",
        to = "super::api_key::Column::Id",
        on_delete = "SetNull"
    )]
    ApiKey,
}

impl Related<super::api_key::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ApiKey.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
