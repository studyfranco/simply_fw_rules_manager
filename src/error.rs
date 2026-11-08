//! Centralized error type mapped to HTTP status codes and JSON envelopes.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// Every failure an HTTP handler or domain engine in this crate can return.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// A database operation failed.
    #[error("database error")]
    DbError(#[from] sea_orm::DbErr),
    /// The caller supplied a malformed or invalid payload.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// Validation failure carrying structured diagnostic details (e.g. 3-stage script check).
    #[error("validation failed: {message}")]
    ValidationFailed {
        /// Human-readable summary.
        message: String,
        /// Structured diagnostic report.
        report: serde_json::Value,
    },
    /// The caller did not authenticate successfully.
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    /// The caller authenticated but may not perform the requested action.
    #[error("forbidden: {0}")]
    Forbidden(String),
    /// The requested resource does not exist.
    #[error("not found")]
    NotFound,
    /// The request conflicts with existing state.
    #[error("conflict: {0}")]
    Conflict(String),
    /// A request extractor rejected the body with its own status code.
    #[error("body rejected: {1}")]
    BodyRejected(StatusCode, String),
    /// Upstream service (Docker / `simply_hook_executor` / blocklist feed) returned an error.
    #[error("upstream error: {0}")]
    Upstream(String),
    /// An internal failure with no detail safe to disclose to the caller.
    #[error("internal error")]
    Internal,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            Self::DbError(err) => {
                tracing::error!("database error: {err}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({ "error": "Internal server error" }),
                )
            }
            Self::InvalidInput(msg) => (StatusCode::BAD_REQUEST, json!({ "error": msg })),
            Self::ValidationFailed { message, report } => (
                StatusCode::UNPROCESSABLE_ENTITY,
                json!({ "error": message, "validation": report }),
            ),
            Self::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, json!({ "error": msg })),
            Self::Forbidden(msg) => (StatusCode::FORBIDDEN, json!({ "error": msg })),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                json!({ "error": "Resource not found" }),
            ),
            Self::Conflict(msg) => (StatusCode::CONFLICT, json!({ "error": msg })),
            Self::BodyRejected(status, msg) => (status, json!({ "error": msg })),
            Self::Upstream(msg) => (StatusCode::BAD_GATEWAY, json!({ "error": msg })),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "error": "Internal server error" }),
            ),
        };
        (status, Json(body)).into_response()
    }
}

impl From<crate::crypto::CryptoError> for AppError {
    fn from(err: crate::crypto::CryptoError) -> Self {
        tracing::error!("crypto error: {err}");
        Self::Internal
    }
}
