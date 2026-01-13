// src/api/middleware.rs
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use crate::{handlers::AppState, users::User};

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

/// Middleware that authenticates API requests via JWT access tokens
///
/// ### Description
/// This middleware validates JWT access tokens in the Authorization header:
/// 1. Extracts JWT from Authorization: Bearer <token>
/// 2. Validates JWT signature and expiry using JWT_SECRET
/// 3. Extracts claims (user_id, device_id, device_name)
/// 4. Loads User record from database by user_id
/// 5. Injects AuthenticatedUser into request extensions
///
/// ### Arguments
/// - `state`: The state of the application
/// - `headers`: The headers of the request
/// - `request`: The request
/// - `next`: The next middleware
///
/// ### Returns
/// - `Ok(Response)`: The response if authentication succeeds
/// - `Err(Response)`: Error response if authentication fails
pub async fn require_api_auth(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, Response> {
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
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid Authorization header format. Expected: Bearer <token>"
                        .to_string(),
                }),
            )
                .into_response()
        })?
        .trim();
    let claims = match crate::access_token::validate_access_token(token, &state.jwt_secret) {
        Ok(claims) => claims,
        Err(e) => {
            let error_msg = e.to_string().to_lowercase();
            if error_msg.contains("expired") || error_msg.contains("exp") {
                tracing::debug!("Expired access token");
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "Access token has expired".to_string(),
                    }),
                )
                    .into_response());
            } else {
                tracing::warn!("Request headers: {:?}", headers);
                tracing::warn!("Invalid access token: {:?}", e);
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "Invalid access token".to_string(),
                    }),
                )
                    .into_response());
            }
        }
    };
    let user_id: i32 = claims.sub.parse().map_err(|e| {
        tracing::error!("Invalid user_id in JWT claims: {:?}", e);
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid token claims".to_string(),
            }),
        )
            .into_response()
    })?;
    let user = match state.user_repository.get_by_id(user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            tracing::warn!("User not found for valid JWT: user_id={}", user_id);
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "User not found".to_string(),
                }),
            )
                .into_response());
        }
        Err(e) => {
            tracing::error!("Database error getting user by ID: {:?}", e);
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
        tracing::warn!("Access token used for unverified user: {}", user.id);
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Email not verified".to_string(),
            }),
        )
            .into_response());
    }
    tracing::debug!(
        "Authenticated API request for user {} with device {}: {}",
        user.id,
        claims.device_id,
        request.uri()
    );

    request.extensions_mut().insert(AuthenticatedUser {
        user,
        device_id: claims.device_id,
        device_name: claims.device_name,
    });
    Ok(next.run(request).await)
}
