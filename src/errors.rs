use askama::Template;
use axum::{
    Json,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use fulgur_common::api::sync::ErrorResponse;

use crate::templates::ErrorMessageTemplate;

#[derive(Debug)]
pub enum AppError {
    NotFound,
    DatabaseError(sqlx::Error),
    TemplateError(askama::Error),
    ApiKeyError(anyhow::Error),
    InternalError(anyhow::Error),
    Unauthorized,
    Forbidden,
    MaxDevicesPerUserReached(i32),
    TooManyConnections,
    ValidationError(String),
}

impl std::fmt::Display for AppError {
    /// Format an `AppError` as a string
    ///
    /// ### Arguments
    /// - `f`: The formatter to use
    ///
    /// ### Returns
    /// - `std::fmt::Result`: The result of the formatting
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::NotFound => write!(f, "Entity not found"),
            AppError::DatabaseError(e) => write!(f, "Database error: {e}"),
            AppError::TemplateError(e) => write!(f, "Template error: {e}"),
            AppError::ApiKeyError(e) => write!(f, "API key error: {e}"),
            AppError::InternalError(e) => write!(f, "Internal error: {e}"),
            AppError::Unauthorized => write!(f, "Unauthorized"),
            AppError::Forbidden => write!(f, "Forbidden"),
            AppError::MaxDevicesPerUserReached(max) => {
                write!(f, "Max number of devices per user reached: {max}")
            }
            AppError::TooManyConnections => write!(f, "Too many concurrent connections"),
            AppError::ValidationError(msg) => write!(f, "Validation error: {msg}"),
        }
    }
}

impl AppError {
    /// Resolve the HTTP status and user-facing message of an `AppError`
    ///
    /// Internal errors are logged here and replaced by a generic message so
    /// that no implementation detail leaks to the client.
    ///
    /// ### Returns
    /// - `(StatusCode, String)`: The status code and the message to show
    pub fn status_and_message(self) -> (StatusCode, String) {
        match self {
            AppError::NotFound => (StatusCode::NOT_FOUND, "Entity not found".to_string()),
            AppError::DatabaseError(e) => {
                tracing::error!("Database error: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Database error occurred".to_string(),
                )
            }
            AppError::TemplateError(e) => {
                tracing::error!("Template error: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Template rendering error".to_string(),
                )
            }
            AppError::ApiKeyError(e) => {
                tracing::error!("API key error: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "API key error".to_string(),
                )
            }
            AppError::InternalError(e) => {
                tracing::error!("Internal error: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error".to_string(),
                )
            }
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "Forbidden".to_string()),
            AppError::MaxDevicesPerUserReached(max_number_of_devices) => (
                StatusCode::FORBIDDEN,
                format!("Max number of devices per user reached: {max_number_of_devices}"),
            ),
            AppError::TooManyConnections => (
                StatusCode::TOO_MANY_REQUESTS,
                "Too many concurrent connections".to_string(),
            ),
            AppError::ValidationError(msg) => (StatusCode::BAD_REQUEST, msg),
        }
    }
}

impl IntoResponse for AppError {
    /// Convert an `AppError` to a Response
    ///
    /// ### Returns
    /// - `Response`: The converted Response
    fn into_response(self) -> Response {
        let (status, message) = self.status_and_message();
        let template = ErrorMessageTemplate {
            message: message.clone(),
        };
        match template.render() {
            Ok(html) => (status, Html(html)).into_response(),
            Err(_) => (status, message).into_response(),
        }
    }
}

/// `AppError` rendered as a JSON body (`{"error": "..."}`) instead of an HTML partial
///
/// Used by session-authenticated endpoints driven by `fetch` rather than HTMX.
#[derive(Debug)]
pub struct JsonAppError(pub AppError);

impl<E: Into<AppError>> From<E> for JsonAppError {
    /// Wrap anything convertible to an `AppError`
    ///
    /// ### Arguments
    /// - `err`: The error to wrap
    ///
    /// ### Returns
    /// - `JsonAppError`: The wrapped error
    fn from(err: E) -> Self {
        JsonAppError(err.into())
    }
}

impl IntoResponse for JsonAppError {
    /// Convert a `JsonAppError` to a JSON Response
    ///
    /// ### Returns
    /// - `Response`: The response with a JSON error body
    fn into_response(self) -> Response {
        let (status, message) = self.0.status_and_message();
        (status, Json(ErrorResponse { error: message })).into_response()
    }
}

impl From<sqlx::Error> for AppError {
    /// Convert a `sqlx::Error` to an `AppError`
    ///
    /// ### Arguments
    /// - `err`: The `sqlx::Error` to convert
    ///
    /// ### Returns
    /// - `AppError`: The converted `AppError`
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::RowNotFound => AppError::NotFound,
            _ => AppError::DatabaseError(err),
        }
    }
}

impl From<askama::Error> for AppError {
    /// Convert an `askama::Error` to an `AppError`
    ///
    /// ### Arguments
    /// - `err`: The `askama::Error` to convert
    ///
    /// ### Returns
    /// - `AppError`: The converted `AppError`
    fn from(err: askama::Error) -> Self {
        AppError::TemplateError(err)
    }
}
