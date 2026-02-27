// src/api/middleware.rs
use axum::{
    Json,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::Serialize;

use crate::handlers::AppState;

/// Lightweight user data injected into API request extensions.
/// Contains only the fields actually used by API handlers, avoiding
/// sensitive fields like `password_hash` being passed through the request pipeline.
#[derive(Clone, Debug)]
pub struct AuthenticatedApiUser {
    pub id: i32,
    pub email: String,
}

#[derive(Clone, Debug)]
pub struct AuthenticatedUser {
    pub user: AuthenticatedApiUser,
    pub device_id: String,
    pub device_name: String,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

/// Build a log-safe header list by redacting sensitive values.
///
/// ### Arguments
/// - `headers`: Incoming request headers
///
/// ### Returns
/// - `Vec<(String, String)>`: Header name/value pairs with sensitive values redacted
fn redact_headers_for_log(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            let key = name.as_str().to_ascii_lowercase();
            let is_sensitive = matches!(
                key.as_str(),
                "authorization" | "cookie" | "set-cookie" | "x-api-key" | "x-auth-token"
            );
            if is_sensitive {
                (name.to_string(), "[REDACTED]".to_string())
            } else {
                let value = value.to_str().unwrap_or("[NON-UTF8]").to_string();
                (name.to_string(), value)
            }
        })
        .collect()
}

/// Middleware that authenticates API requests via JWT access tokens
///
/// ### Description
/// This middleware validates JWT access tokens in the Authorization header:
/// 1. Extracts JWT from Authorization header
/// 2. Validates JWT signature and expiry using JWT_SECRET
/// 3. Extracts claims (user_id, device_id, device_name)
/// 4. Loads User record from database by user_id
/// 5. Loads Device record from database by device_id
/// 6. Verifies the device belongs to the user and is not expired
/// 7. Injects AuthenticatedUser into request extensions
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
                let safe_headers = redact_headers_for_log(&headers);
                tracing::warn!("Request headers (redacted): {:?}", safe_headers);
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
    let device = match state
        .device_repository
        .get_by_device_id(&claims.device_id)
        .await
    {
        Ok(device) => device,
        Err(sqlx::Error::RowNotFound) => {
            tracing::warn!(
                "Device not found for JWT claims: device_id={}, user_id={}",
                claims.device_id,
                user.id
            );
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Device not found".to_string(),
                }),
            )
                .into_response());
        }
        Err(e) => {
            tracing::error!("Database error getting device by device_id: {:?}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Internal server error".to_string(),
                }),
            )
                .into_response());
        }
    };
    if device.user_id != user.id {
        tracing::warn!(
            "Device/user mismatch in JWT claims: device_id={}, device_user_id={}, token_user_id={}",
            claims.device_id,
            device.user_id,
            user.id
        );
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid token claims".to_string(),
            }),
        )
            .into_response());
    }
    if device.is_expired() {
        tracing::warn!(
            "Expired device used with valid JWT: device_id={}, user_id={}",
            device.device_id,
            user.id
        );
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Device has expired".to_string(),
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
        user: AuthenticatedApiUser {
            id: user.id,
            email: user.email,
        },
        device_id: claims.device_id,
        device_name: claims.device_name,
    });
    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::{AUTHORIZATION, COOKIE, USER_AGENT};
    use axum::http::{HeaderMap, HeaderValue};

    #[test]
    fn redact_headers_for_log_redacts_sensitive_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer super_secret"),
        );
        headers.insert(COOKIE, HeaderValue::from_static("session=secret"));
        headers.insert(USER_AGENT, HeaderValue::from_static("fulgur-test-client"));

        let redacted = redact_headers_for_log(&headers);

        assert!(
            redacted
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case("authorization") && v == "[REDACTED]")
        );
        assert!(
            redacted
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case("cookie") && v == "[REDACTED]")
        );
        assert!(
            redacted
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case("user-agent") && v == "fulgur-test-client")
        );
    }
}
