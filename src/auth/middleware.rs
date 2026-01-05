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
        let redirect_url = "/login".to_string();

        return Ok(Redirect::to(&redirect_url).into_response());
    }

    Ok(next.run(request).await)
}
