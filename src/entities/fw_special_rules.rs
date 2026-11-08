//! `fw_special_rules` singleton entity model (`id = 1`).

use sea_orm::entity::prelude::*;

/// The `fw_special_rules` singleton row.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "fw_special_rules")]
pub struct Model {
    /// Singleton primary key (`1`).
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: i32,
    /// Full Bash script content of `firewall.rules.special`.
    #[sea_orm(column_type = "Text")]
    pub script_content: String,
    /// Whether the most recent 3-stage validation passed.
    pub last_validation_ok: bool,
    /// Serialized JSON diagnostic report of the last 3-stage check.
    #[sea_orm(column_type = "Text", nullable)]
    pub last_validation_json: Option<String>,
    /// Last update timestamp.
    pub updated_at: DateTimeUtc,
}

/// Relations from `fw_special_rules`.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
