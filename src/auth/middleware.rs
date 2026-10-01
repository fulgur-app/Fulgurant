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
/// Checks for a valid session with a `user_id`. If the user has the `force_password_update`
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

/// Middleware that slides the session idle timeout on activity.
///
/// Must sit inside the session layer. Before the handler it records the activity of an
/// authenticated session (throttled), and after the handler it pins the expiry of any
/// session about to be saved to 1 hour, or 30 days for "Remember me" sessions.
///
/// ### Arguments
/// - `session`: The session
/// - `request`: The request
/// - `next`: The next middleware
///
/// ### Returns
/// - `Ok(Response)`: The response
/// - `Err(StatusCode)`: `500` if the session cannot be read or written
pub async fn slide_session_expiry(
    session: Session,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    session::record_activity(&session).await.map_err(|e| {
        tracing::error!("Failed to record session activity: {e:?}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let response = next.run(request).await;
    session::apply_idle_expiry(&session).await.map_err(|e| {
        tracing::error!("Failed to apply session expiry: {e:?}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(response)
}
