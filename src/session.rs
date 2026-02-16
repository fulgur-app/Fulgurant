use tower_sessions::Session;

use crate::errors::AppError;

/// Session key for storing user ID
pub const SESSION_USER_ID: &str = "user_id";

/// Session key for storing force password update flag
pub const SESSION_FORCE_PASSWORD_UPDATE: &str = "force_password_update";

/// Extracts the authenticated user ID from the session
///
/// ### Arguments
/// - `session`: The session to extract the user ID from
///
/// ### Returns
/// - `Ok(i32)`: The user ID if authenticated
/// - `Err(AppError::Unauthorized)`: If user is not authenticated
/// - `Err(AppError::InternalError)`: If session access fails
pub async fn get_session_user_id(session: &Session) -> Result<i32, AppError> {
    let user_id: Option<i32> = session.get(SESSION_USER_ID).await.map_err(|e| {
        AppError::InternalError(anyhow::anyhow!("Failed to get user id from session: {}", e))
    })?;

    user_id.ok_or(AppError::Unauthorized)
}
