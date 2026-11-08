//! Inbound `CANONICAL_V1` HMAC-SHA256 request authentication middleware.

use std::net::{IpAddr, SocketAddr};

use axum::body::Body;
use axum::extract::{ConnectInfo, OriginalUri, Request, State};
use axum::middleware::Next;
use axum::response::Response;
use chrono::Utc;
use ipnetwork::IpNetwork;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use sha2::{Digest, Sha256};

use crate::crypto::{self, MAX_TIMESTAMP_SKEW_SECS};
use crate::entities::api_key;
use crate::entities::prelude::ApiKey;
use crate::error::AppError;
use crate::state::AppState;

/// The resolved client IP address inserted into request extensions by [`auth_middleware`].
#[derive(Debug, Clone, Copy)]
pub struct ClientIp(pub IpAddr);

fn signed_target(parts: &axum::http::request::Parts) -> String {
    let uri = parts
        .extensions
        .get::<OriginalUri>()
        .map_or(&parts.uri, |original| &original.0);
    uri.path_and_query()
        .map_or_else(|| uri.path().to_owned(), |pq| pq.as_str().to_owned())
}

fn validate_timestamp(headers: &axum::http::HeaderMap) -> Result<String, AppError> {
    let raw = headers
        .get("X-Timestamp")
        .and_then(|h| h.to_str().ok())
        .map(str::trim)
        .ok_or_else(|| AppError::Unauthorized("Missing X-Timestamp header".to_owned()))?;
    let supplied: i64 = raw
        .parse()
        .map_err(|_| AppError::Unauthorized("Malformed X-Timestamp header".to_owned()))?;
    let skew = (Utc::now().timestamp() - supplied).abs();
    if skew > MAX_TIMESTAMP_SKEW_SECS {
        return Err(AppError::Unauthorized(format!(
            "Request timestamp outside the permitted {MAX_TIMESTAMP_SKEW_SECS}s window"
        )));
    }
    Ok(raw.to_owned())
}

fn extract_api_key(headers: &axum::http::HeaderMap) -> Option<&str> {
    if let Some(k) = headers
        .get("X-API-Key")
        .and_then(|h| h.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return Some(k);
    }
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.trim().strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Authenticates every inbound `/api/*` request using `CANONICAL_V1` HMAC-SHA256, anti-replay,
/// and `bound_ips` CIDR enforcement.
///
/// # Errors
/// Returns [`AppError::Unauthorized`] or [`AppError::Forbidden`] when authentication fails.
pub async fn auth_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    let peer_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), |ci| ci.0.ip());
    let headers = req.headers().clone();
    let client_ip =
        crate::config::resolve_client_ip(peer_ip, &headers, state.trusted_proxies.networks());

    let timestamp = validate_timestamp(&headers)?;

    let provided_key = extract_api_key(&headers)
        .ok_or_else(|| AppError::Unauthorized("Missing X-API-Key header".to_owned()))?;

    let provided_signature = headers
        .get("X-Signature-256")
        .or_else(|| headers.get("X-Signature"))
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned)
        .ok_or_else(|| AppError::Unauthorized("Missing X-Signature-256 header".to_owned()))?;
    if !provided_signature
        .trim()
        .starts_with(crypto::SIGNATURE_PREFIX)
    {
        return Err(AppError::Unauthorized(
            "X-Signature-256 must be formatted as sha256=<hex>".to_owned(),
        ));
    }

    let mut hasher = Sha256::new();
    hasher.update(provided_key.as_bytes());
    let key_hash = hex::encode(hasher.finalize());

    let mut key_record = ApiKey::find()
        .filter(api_key::Column::KeyHash.eq(key_hash))
        .one(&state.db)
        .await
        .map_err(AppError::DbError)?
        .ok_or_else(|| AppError::Unauthorized("Invalid API Key".to_owned()))?;

    let signing_secret = key_record
        .signing_secret
        .as_deref()
        .ok_or_else(|| {
            AppError::Unauthorized(
                "This API key has no signing secret; rotate it to obtain one".to_owned(),
            )
        })
        .and_then(|stored| state.cipher.open(stored).map_err(AppError::from))?;

    let method = req.method().as_str().to_owned();
    let (parts, body) = req.into_parts();
    let target = signed_target(&parts);

    let max_bytes = crate::config::max_body_bytes();
    let body_bytes = axum::body::to_bytes(body, max_bytes).await.map_err(|_| {
        AppError::BodyRejected(
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            "Request body exceeds the maximum allowed size".to_owned(),
        )
    })?;

    let Some(digest) = crypto::verify_signature(
        &signing_secret,
        &method,
        &target,
        &timestamp,
        &body_bytes,
        &provided_signature,
    ) else {
        return Err(AppError::Unauthorized(
            "Invalid request signature".to_owned(),
        ));
    };

    if !state.replay.check_and_record(key_record.id, &digest) {
        return Err(AppError::Unauthorized(
            "This request signature has already been used; sign a fresh request".to_owned(),
        ));
    }

    let bound_ips_raw = key_record.bound_ips.as_deref().unwrap_or("");
    let networks: Vec<IpNetwork> = bound_ips_raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<IpNetwork>().or_else(|_| {
                s.parse::<IpAddr>()
                    .map(|ip| IpNetwork::from(crate::config::normalize_ip(ip)))
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AppError::Internal)?;
    if !networks.is_empty() && !networks.iter().any(|net| net.contains(client_ip)) {
        return Err(AppError::Forbidden("Client IP not allowed".to_owned()));
    }

    state.master_pin.authenticate(&mut key_record);

    let mut req = Request::from_parts(parts, Body::from(body_bytes));
    req.extensions_mut().insert(key_record);
    req.extensions_mut().insert(ClientIp(client_ip));
    Ok(next.run(req).await)
}
