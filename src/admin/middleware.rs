// src/admin/middleware.rs
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use tower_sessions::Session;

use crate::{errors::AppError, handlers::AppState, session};

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
/// - `Err(AppError)`: Error if the user is not an admin or not authenticated
pub async fn require_admin(
    State(state): State<AppState>,
    session: Session,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let user_id = session::get_session_user_id(&session).await.map_err(|e| {
        tracing::warn!("Unauthenticated user attempted to access admin route");
        match e {
            AppError::Unauthorized => AppError::Unauthorized,
            other => {
                tracing::error!("Failed to get user_id from session: {}", other);
                AppError::InternalError(anyhow::anyhow!("Internal server error"))
            }
        }
    })?;
    let user = state
        .user_repository
        .get_by_id(user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get user by id: {}", e);
            AppError::InternalError(anyhow::anyhow!("Internal server error"))
        })?;
    let Some(user) = user else {
        tracing::warn!("User {} not found in database", user_id);
        return Err(AppError::Unauthorized);
    };
    if user.role != "Admin" {
        tracing::warn!(
            "Non-admin user {} attempted to access admin route: {}",
            user_id,
            request.uri().path()
        );
        let error = AppError::InternalError(anyhow::anyhow!(
            "You do not have permission to access this resource. Admin privileges required."
        ));
        return Err(error);
    }
    Ok(next.run(request).await)
}
