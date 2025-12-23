// src/api/middleware.rs
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use crate::{api_key::verify_api_key, handlers::AppState, users::User};

#[derive(Clone, Debug)]
pub struct AuthenticatedUser {
    pub user: User,
    pub device_id: String,
    pub device_name: String,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

/// Middleware that authenticates API requests via headers
///
/// ### Description
/// This middleware authenticates API requests via headers.
/// It validates the X-User-Email and Authorization headers.
/// It checks if the user exists and if the email is verified.
/// It verifies if the API key is valid for one of the user's devices.
/// On success, it injects the AuthenticatedUser into the request extensions for handlers to use.
///
/// ### Arguments
/// - state: The state of the application
/// - headers: The headers of the request
/// - request: The request
/// - next: The next middleware
///
/// ### Returns
/// - Ok(Response): The response
/// - Err((StatusCode, Json(ErrorResponse))): The error response if the authentication fails
pub async fn require_api_auth(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, Response> {
    let email = headers
        .get("X-User-Email")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Missing X-User-Email header".to_string(),
                }),
            )
                .into_response()
        })?
        .trim()
        .to_lowercase();
    let auth_header = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Missing Authorization header".to_string(),
                }),
            )
                .into_response()
        })?;
    let device_key = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid Authorization header format. Expected: Bearer <api_key>"
                        .to_string(),
                }),
            )
                .into_response()
        })?
        .trim();
    let user = match state.user_repository.get_by_email(email.clone()).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid credentials".to_string(),
                }),
            )
                .into_response())
        }
        Err(e) => {
            tracing::error!("Database error getting user: {:?}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Internal server error".to_string(),
                }),
            )
                .into_response());
        }
    };
    if !user.email_verified {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Email not verified".to_string(),
            }),
        )
            .into_response());
    }
    let devices = match state.device_repository.get_all_for_user(user.id).await {
        Ok(devices) => devices,
        Err(e) => {
            tracing::error!("Database error getting devices: {:?}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Internal server error".to_string(),
                }),
            )
                .into_response());
        }
    };
    let mut authenticated_device = None;
    for device in &devices {
        match verify_api_key(device_key, &device.device_key) {
            Ok(true) => {
                authenticated_device = Some((device.device_id.clone(), device.name.clone()));
                tracing::info!(
                    "Authenticated API request for user {} with device {}: {}",
                    user.email,
                    device.name,
                    request.uri()
                );
                break;
            }
            Ok(false) => continue,
            Err(e) => {
                tracing::error!("Error verifying API key: {:?}", e);
                continue;
            }
        }
    }
    let (device_id, device_name) = authenticated_device.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid credentials".to_string(),
            }),
        )
            .into_response()
    })?;
    request.extensions_mut().insert(AuthenticatedUser {
        user,
        device_id,
        device_name: device_name,
    });
    Ok(next.run(request).await)
}
