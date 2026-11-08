//! `fw_zone_rules` entity model (`ip_autor`, `internal`, `local`, `open`, `ww`).

use sea_orm::entity::prelude::*;

/// The `fw_zone_rules` row.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "fw_zone_rules")]
pub struct Model {
    /// Primary key.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Security zone (`ip_autor`, `internal`, `local`, `open`, `ww`).
    pub zone: String,
    /// Rule kind (`OpenPortsTCP`, `OpenPortsUDP`, `RedirectPortTCP`, `RedirectPortUDP`, `DnatPortTCP`, `DnatPortUDP`, `DockerTCP`, `DockerUDP`).
    pub rule_kind: String,
    /// Raw rule value (e.g. `"443"` or `"443,ext,traefik,443"`).
    pub value: String,
    /// Extracted target container name when `rule_kind` is `DockerTCP` or `DockerUDP`.
    pub container_name: Option<String>,
    /// Administrative enable flag.
    pub enabled: bool,
    /// Optional operator comment.
    pub comment: Option<String>,
    /// Sort order for deterministic output in `firewall.settings`.
    pub sort_order: i32,
    /// Creation timestamp.
    pub created_at: DateTimeUtc,
    /// Last update timestamp.
    pub updated_at: DateTimeUtc,
}

/// Relations from `fw_zone_rules`.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
