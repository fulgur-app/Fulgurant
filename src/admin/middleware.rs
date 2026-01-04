// src/admin/middleware.rs
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use tower_sessions::Session;

use crate::{errors::AppError, handlers::AppState};

const SESSION_USER_ID: &str = "user_id";

/// Middleware that requires admin role
///
/// ### Description
/// This middleware checks if the authenticated user has the "Admin" role.
/// If the user is not authenticated or does not have admin privileges,
/// they are forbidden from accessing the route.
///
/// ### Arguments
/// - `state`: The application state
/// - `session`: The session
/// - `request`: The request
/// - `next`: The next middleware
///
/// ### Returns
/// - `Ok(Response)`: The response if the user is an admin
/// - `Err(Response)`: Forbidden error if the user is not an admin or not authenticated
pub async fn require_admin(
    State(state): State<AppState>,
    session: Session,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    let user_id: Option<i32> = session
        .get(SESSION_USER_ID)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get user_id from session: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            )
                .into_response()
        })?;
    let user_id = match user_id {
        Some(id) => id,
        None => {
            tracing::warn!("Unauthenticated user attempted to access admin route");
            return Err((StatusCode::UNAUTHORIZED, "Unauthorized").into_response());
        }
    };
    let user = state
        .user_repository
        .get_by_id(user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get user by id: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            )
                .into_response()
        })?;
    let user = match user {
        Some(user) => user,
        None => {
            tracing::warn!("User {} not found in database", user_id);
            return Err((StatusCode::UNAUTHORIZED, "Unauthorized").into_response());
        }
    };
    if user.role != "Admin" {
        tracing::warn!(
            "Non-admin user {} ({}) attempted to access admin route: {}",
            user.email,
            user_id,
            request.uri().path()
        );
        let error = AppError::InternalError(anyhow::anyhow!(
            "You do not have permission to access this resource. Admin privileges required."
        ));
        return Err(error.into_response());
    }
    Ok(next.run(request).await)
}
