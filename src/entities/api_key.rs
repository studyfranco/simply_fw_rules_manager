//! `api_keys` entity model.

use sea_orm::entity::prelude::*;

/// The `api_keys` row.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "api_keys")]
pub struct Model {
    /// Primary key.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Human-readable account/key name.
    pub name: String,
    /// Unsalted SHA-256 hex digest of the bearer API key.
    #[sea_orm(unique)]
    pub key_hash: String,
    /// Sealed (`v1.xchacha20poly1305...` or `v1.plain...`) HMAC signing secret.
    pub signing_secret: Option<String>,
    /// First 8 characters of the API key for audit attribution.
    pub prefix: String,
    /// Full administrative bypass flag.
    pub is_master: bool,
    /// Allows creating, viewing, updating, and revoking sub-keys.
    pub can_manage_keys: bool,
    /// Allows editing `firewall.settings`, zone rules, and Docker inter-container rules.
    pub can_manage_settings: bool,
    /// Allows editing and validating `firewall.rules.special`.
    pub can_manage_special_rules: bool,
    /// Allows editing and testing `firewall.get.list` blocklist feeds.
    pub can_manage_blocklists: bool,
    /// Allows generating files on disk and triggering `simply_hook_executor`.
    pub can_deploy_and_reload: bool,
    /// Delegating parent key (`ON DELETE CASCADE`).
    pub parent_key_id: Option<Uuid>,
    /// Comma-separated IP/CIDR allowlist.
    pub bound_ips: Option<String>,
    /// Creation timestamp.
    pub created_at: DateTimeUtc,
    /// Last update timestamp.
    pub updated_at: DateTimeUtc,
}

/// Relations from `api_keys`.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// Self-referential parent key relation.
    #[sea_orm(
        belongs_to = "Entity",
        from = "Column::ParentKeyId",
        to = "Column::Id",
        on_delete = "Cascade"
    )]
    Parent,
}

impl ActiveModelBehavior for ActiveModel {}
