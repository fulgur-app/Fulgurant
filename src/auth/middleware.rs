// src/auth/middleware.rs
use axum::response::IntoResponse;
use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{Redirect, Response},
};
use tower_sessions::Session;

use crate::session;

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
    if session::get_session_user_id(&session).await.is_err() {
        return Ok(Redirect::to("/login").into_response());
    }
    let force_password_update: Option<bool> = session
        .get(session::SESSION_FORCE_PASSWORD_UPDATE)
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
