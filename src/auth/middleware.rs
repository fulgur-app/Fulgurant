// src/auth/middleware.rs
use axum::response::IntoResponse;
use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{Redirect, Response},
};
use tower_sessions::Session;

const SESSION_USER_ID: &str = "user_id";

/// Middleware that requires authentication
///
/// Checks for a valid session with a user_id. If the user has the force_password_update
/// flag set in their session, they are redirected to /force-password-update for all
/// paths except /force-password-update, /logout, and static assets.
///
/// ### Arguments
/// - `session`: The session
/// - `request`: The request
/// - `next`: The next middleware
///
/// ### Returns
/// - `Ok(Response)`: The response
/// - `Err(StatusCode)`: The error response if the authentication fails
pub async fn require_auth(
    session: Session,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let user_id: Option<i32> = session
        .get(SESSION_USER_ID)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if user_id.is_none() {
        return Ok(Redirect::to("/login").into_response());
    }
    let force_password_update: Option<bool> = session
        .get("force_password_update")
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if force_password_update == Some(true) {
        let path = request.uri().path();
        if path != "/force-password-update" && path != "/logout" && !path.starts_with("/assets/") {
            return Ok(Redirect::to("/force-password-update").into_response());
        }
    }

    Ok(next.run(request).await)
}
