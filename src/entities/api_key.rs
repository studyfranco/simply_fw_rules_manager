//! `api_keys` entity model.

use sea_orm::entity::prelude::*;
use sea_orm::sea_query::{ArrayType, ColumnType, Nullable, ValueType, ValueTypeErr};
use sea_orm::{ColIdx, QueryResult, TryGetError, TryGetable};
use serde::{Deserialize, Serialize};

/// Semantic two-variant API key capability flag persisted as SQL `BOOLEAN`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "bool", into = "bool")]
pub enum ScopeAccess {
    /// Permission is not granted.
    #[default]
    Denied,
    /// Permission is granted.
    Granted,
}

impl ScopeAccess {
    /// Returns `true` when this scope permission is granted.
    #[must_use]
    pub const fn is_granted(self) -> bool {
        matches!(self, Self::Granted)
    }
}

impl From<bool> for ScopeAccess {
    fn from(value: bool) -> Self {
        if value { Self::Granted } else { Self::Denied }
    }
}

impl From<ScopeAccess> for bool {
    fn from(value: ScopeAccess) -> Self {
        value.is_granted()
    }
}

impl From<ScopeAccess> for sea_orm::Value {
    fn from(value: ScopeAccess) -> Self {
        Self::Bool(Some(value.is_granted()))
    }
}

impl TryGetable for ScopeAccess {
    fn try_get_by<I: ColIdx>(res: &QueryResult, index: I) -> Result<Self, TryGetError> {
        bool::try_get_by(res, index).map(Self::from)
    }
}

impl ValueType for ScopeAccess {
    fn try_from(v: sea_orm::Value) -> Result<Self, ValueTypeErr> {
        <bool as ValueType>::try_from(v).map(Self::from)
    }

    fn type_name() -> String {
        "ScopeAccess".to_owned()
    }

    fn array_type() -> ArrayType {
        <bool as ValueType>::array_type()
    }

    fn column_type() -> ColumnType {
        <bool as ValueType>::column_type()
    }
}

impl Nullable for ScopeAccess {
    fn null() -> sea_orm::Value {
        sea_orm::Value::Bool(None)
    }
}

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
    pub can_manage_keys: ScopeAccess,
    /// Allows editing `firewall.settings`, zone rules, and Docker inter-container rules.
    pub can_manage_settings: ScopeAccess,
    /// Allows editing and validating `firewall.rules.special`.
    pub can_manage_special_rules: ScopeAccess,
    /// Allows editing and testing `firewall.get.list` blocklist feeds.
    pub can_manage_blocklists: ScopeAccess,
    /// Allows generating files on disk and triggering `simply_hook_executor`.
    pub can_deploy_and_reload: ScopeAccess,
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
