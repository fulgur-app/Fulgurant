use askama::Template;
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};

use crate::templates::ErrorMessageTemplate;

#[derive(Debug)]
pub enum AppError {
    NotFound,
    DatabaseError(sqlx::Error),
    TemplateError(askama::Error),
    ApiKeyError(anyhow::Error),
    InternalError(anyhow::Error),
    Unauthorized,
    MaxDevicesPerUserReached(i32),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::NotFound => write!(f, "Entity not found"),
            AppError::DatabaseError(e) => write!(f, "Database error: {}", e),
            AppError::TemplateError(e) => write!(f, "Template error: {}", e),
            AppError::ApiKeyError(e) => write!(f, "API key error: {}", e),
            AppError::InternalError(e) => write!(f, "Internal error: {}", e),
            AppError::Unauthorized => write!(f, "Unauthorized"),
            AppError::MaxDevicesPerUserReached(max) => {
                write!(f, "Max number of devices per user reached: {}", max)
            }
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
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
            AppError::MaxDevicesPerUserReached(max_number_of_devices) => (
                StatusCode::FORBIDDEN,
                format!("Max number of devices per user reached: {max_number_of_devices}"),
            ),
        };

        let template = ErrorMessageTemplate {
            message: message.clone(),
        };
        match template.render() {
            Ok(html) => (status, Html(html)).into_response(),
            Err(_) => (status, message).into_response(),
        }
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::RowNotFound => AppError::NotFound,
            _ => AppError::DatabaseError(err),
        }
    }
}

impl From<askama::Error> for AppError {
    fn from(err: askama::Error) -> Self {
        AppError::TemplateError(err)
    }
}
