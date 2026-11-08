//! `fw_blocklists` entity model (`firewall.get.list` feeds).

use sea_orm::entity::prelude::*;

/// The `fw_blocklists` row.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "fw_blocklists")]
pub struct Model {
    /// Primary key.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Unique list identifier passed as the 2nd argument to `generate_list`.
    #[sea_orm(unique)]
    pub name: String,
    /// HTTP/HTTPS URL of the raw IPv4/IPv6/CIDR blocklist feed.
    pub url: String,
    /// Whether this entry is emitted in `firewall.get.list`.
    pub enabled: bool,
    /// Optional human-readable description.
    pub description: Option<String>,
    /// Result of the last live HTTP validation test.
    pub last_test_ok: Option<bool>,
    /// Count of valid IPv4/IPv6/CIDR entries parsed during the last live test.
    pub last_test_entries: Option<i32>,
    /// Timestamp of the last live HTTP validation test.
    pub last_test_at: Option<DateTimeUtc>,
    /// Deterministic ordering in `firewall.get.list`.
    pub sort_order: i32,
    /// Creation timestamp.
    pub created_at: DateTimeUtc,
    /// Last update timestamp.
    pub updated_at: DateTimeUtc,
}

/// Relations from `fw_blocklists`.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
