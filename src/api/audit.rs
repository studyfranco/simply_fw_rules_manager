//! Standardized Audit Log recording and querying (`GET /api/audit`).

use axum::Extension;
use axum::Json;
use axum::extract::State;
use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, DatabaseConnection, EntityTrait, QueryFilter,
    QueryOrder, QuerySelect, Set,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::prelude::AuditLog;
use crate::entities::{api_key, audit_log};
use crate::error::AppError;
use crate::extract::StrictQuery;
use crate::middleware::ClientIp;
use crate::state::AppState;

/// Writes a standardized audit log row.
///
/// # Errors
/// Returns [`sea_orm::DbErr`] if inserting the row fails.
pub async fn record_audit(
    db: &DatabaseConnection,
    caller: &api_key::Model,
    ClientIp(client_ip): ClientIp,
    action: &str,
    target_resource: Option<String>,
    details: Option<String>,
) -> Result<(), sea_orm::DbErr> {
    let row = audit_log::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(Some(caller.id)),
        api_key_name: Set(caller.name.clone()),
        api_key_prefix: Set(caller.prefix.clone()),
        action: Set(action.to_owned()),
        target_resource: Set(target_resource),
        details: Set(details),
        client_ip: Set(client_ip.to_string()),
        timestamp: Set(Utc::now()),
    };
    row.insert(db).await?;
    Ok(())
}

/// Query parameters for `GET /api/audit`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditLogQuery {
    /// Exact action code filter.
    pub action: Option<String>,
    /// Client IP filter.
    pub client_ip: Option<String>,
    /// Matches `api_key_name`, `api_key_prefix`, or `api_key_id`.
    pub api_key: Option<String>,
    /// Lower timestamp bound (RFC 3339).
    pub since: Option<String>,
    /// Upper timestamp bound (RFC 3339).
    pub until: Option<String>,
    /// Maximum rows to return (1..=500, default 100).
    pub limit: Option<u64>,
    /// Row offset (default 0).
    pub offset: Option<u64>,
}

/// Serialized audit log entry returned by `GET /api/audit`.
#[derive(Debug, Serialize)]
pub struct AuditLogResponse {
    pub id: Uuid,
    pub api_key_id: Option<Uuid>,
    pub api_key_name: String,
    pub api_key_prefix: String,
    pub action: String,
    pub target_resource: Option<String>,
    pub details: Option<String>,
    pub client_ip: String,
    pub timestamp: DateTime<Utc>,
}

/// `GET /api/audit` — List audit logs with standardized filtering.
///
/// # Errors
/// Returns [`AppError`] if query parameters are malformed or the caller lacks permissions.
pub async fn list_audit_logs(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    StrictQuery(query): StrictQuery<AuditLogQuery>,
) -> Result<Json<Vec<AuditLogResponse>>, AppError> {
    if !caller.is_master {
        return Err(AppError::Forbidden(
            "Only master keys can view audit logs".to_owned(),
        ));
    }

    let mut select = AuditLog::find();

    if let Some(action) = query
        .action
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        select = select.filter(audit_log::Column::Action.eq(action));
    }
    if let Some(ip) = query
        .client_ip
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        select = select.filter(audit_log::Column::ClientIp.eq(ip));
    }
    if let Some(key_filter) = query
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let mut cond = Condition::any()
            .add(audit_log::Column::ApiKeyName.eq(key_filter))
            .add(audit_log::Column::ApiKeyPrefix.eq(key_filter));
        if let Ok(uuid) = key_filter.parse::<Uuid>() {
            cond = cond.add(audit_log::Column::ApiKeyId.eq(uuid));
        }
        select = select.filter(cond);
    }
    if let Some(since_raw) = query
        .since
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let since = DateTime::parse_from_rfc3339(since_raw)
            .map_err(|_| AppError::InvalidInput("Malformed 'since' RFC 3339 timestamp".to_owned()))?
            .with_timezone(&Utc);
        select = select.filter(audit_log::Column::Timestamp.gte(since));
    }
    if let Some(until_raw) = query
        .until
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let until = DateTime::parse_from_rfc3339(until_raw)
            .map_err(|_| AppError::InvalidInput("Malformed 'until' RFC 3339 timestamp".to_owned()))?
            .with_timezone(&Utc);
        select = select.filter(audit_log::Column::Timestamp.lte(until));
    }

    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let offset = query.offset.unwrap_or(0);

    let rows = select
        .order_by_desc(audit_log::Column::Timestamp)
        .limit(limit)
        .offset(offset)
        .all(&state.db)
        .await?;

    Ok(Json(
        rows.into_iter()
            .map(|r| AuditLogResponse {
                id: r.id,
                api_key_id: r.api_key_id,
                api_key_name: r.api_key_name,
                api_key_prefix: r.api_key_prefix,
                action: r.action,
                target_resource: r.target_resource,
                details: r.details,
                client_ip: r.client_ip,
                timestamp: r.timestamp,
            })
            .collect(),
    ))
}
