// src/setup/middleware.rs
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use tower_sessions::Session;

use crate::handlers::AppState;

const SESSION_USER_ID: &str = "user_id";

/// Middleware that redirects to setup if no admin exists
///
/// ### Description
/// This middleware dynamically checks if initial setup is required (no admin user exists).
/// If setup is needed and the user is not authenticated, they are redirected to /setup.
/// Users who are already logged in bypass this check.
///
/// ### Arguments
/// - `state`: The application state
/// - `session`: The session
/// - `request`: The request
/// - `next`: The next middleware
///
/// ### Returns
/// - `Ok(Response)`: The response (either redirect or next middleware)
/// - `Err(StatusCode)`: The error response if the setup is not complete
pub async fn require_setup_complete(
    State(state): State<AppState>,
    session: Session,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let path = request.uri().path();
    if path.starts_with("/setup") {
        return Ok(next.run(request).await);
    }
    let has_admin = !state
        .setup_needed
        .load(std::sync::atomic::Ordering::Relaxed);
    if !has_admin {
        let user_id: Option<i32> = session
            .get(SESSION_USER_ID)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if user_id.is_none() {
            return Ok(Redirect::to("/setup").into_response());
        }
    }
    Ok(next.run(request).await)
}
