//! Strict request extractors producing JSON error responses.

use axum::extract::{FromRequest, Json, Request};
use axum::http::StatusCode;
use serde::de::DeserializeOwned;

use crate::error::AppError;

/// `Json<T>` whose rejection is rendered as [`AppError`].
pub struct StrictJson<T>(pub T);

impl<S, T> FromRequest<S> for StrictJson<T>
where
    Json<T>: FromRequest<S, Rejection = axum::extract::rejection::JsonRejection>,
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) => match rejection {
                axum::extract::rejection::JsonRejection::BytesRejection(e) => Err(
                    AppError::BodyRejected(StatusCode::PAYLOAD_TOO_LARGE, e.to_string()),
                ),
                other => Err(AppError::InvalidInput(other.to_string())),
            },
        }
    }
}

/// `Path<T>` whose rejection is rendered as [`AppError::NotFound`].
pub struct StrictPath<T>(pub T);

impl<S, T> axum::extract::FromRequestParts<S> for StrictPath<T>
where
    axum::extract::Path<T>:
        axum::extract::FromRequestParts<S, Rejection = axum::extract::rejection::PathRejection>,
    T: Send,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        match axum::extract::Path::<T>::from_request_parts(parts, state).await {
            Ok(axum::extract::Path(value)) => Ok(Self(value)),
            Err(_) => Err(AppError::NotFound),
        }
    }
}

/// `Query<T>` whose rejection is rendered as [`AppError::InvalidInput`].
pub struct StrictQuery<T>(pub T);

impl<S, T> axum::extract::FromRequestParts<S> for StrictQuery<T>
where
    axum::extract::Query<T>:
        axum::extract::FromRequestParts<S, Rejection = axum::extract::rejection::QueryRejection>,
    T: Send,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        match axum::extract::Query::<T>::from_request_parts(parts, state).await {
            Ok(axum::extract::Query(value)) => Ok(Self(value)),
            Err(rejection) => Err(AppError::InvalidInput(rejection.body_text())),
        }
    }
}
