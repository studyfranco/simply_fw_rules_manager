//! `fw_docker_inter_rules` entity model (`dockerAccessBetweenThem`).

use sea_orm::entity::prelude::*;

/// The `fw_docker_inter_rules` row.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "fw_docker_inter_rules")]
pub struct Model {
    /// Primary key.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Source container name.
    pub source_container: String,
    /// Destination container name.
    pub destination_container: String,
    /// Shared Docker network name (`isolate`, `ext`, etc.).
    pub network_name: String,
    /// Protocol (`tcp` or `udp`).
    pub proto: String,
    /// Semicolon-separated list of destination ports (e.g. `"8096"` or `"80;443"`).
    pub ports: String,
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

/// Relations from `fw_docker_inter_rules`.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
