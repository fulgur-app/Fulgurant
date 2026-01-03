
use askama::Template;
use axum::{extract::{Query, State}, response::Html};
use serde::Deserialize;
use tower_sessions::Session;

use crate::{errors::AppError, handlers::AppState, templates};

const SESSION_USER_ID: &str = "user_id";

#[derive(Deserialize)]
pub struct UserSearchParams {
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default = "default_page")]
    pub page: i32,
    #[serde(default = "default_page_size")]
    pub page_size: i32,
}

fn default_page() -> i32 {
    1
}

fn default_page_size() -> i32 {
    50
}

/// GET /admin - Returns the admin page
///
/// ### Arguments
/// - `state`: The state of the application
/// - `session`: The session
///
/// ### Returns
/// - `Ok(Html<String>)`: The admin page as formatted HTML
/// - `Err(AppError)`: Error that occurred while rendering the template
pub async fn get_admin(
    State(state): State<AppState>,
    session: Session,   
) -> Result<Html<String>, AppError> {
    let user_id: Option<i32> = session.get(SESSION_USER_ID).await.map_err(|e| {
        AppError::InternalError(anyhow::anyhow!("Failed to get user id from session: {}", e))
    })?;
    let user_id = match user_id {
        Some(id) => id,
        None => return Err(AppError::Unauthorized),
    };
    let user = state.user_repository.get_by_id(user_id).await?;
    let user = match user {
        Some(user) => user,
        None => return Err(AppError::Unauthorized),
    };
    let total_users = state.user_repository.count_all().await?;
    let paginated_users = state.user_repository.get_all(1, 50).await?; //TODO: add page size parameter
    let template = templates::AdminTemplate {
        user: templates::UserContext::new(user_id, user.first_name, user.role),
        users: paginated_users,
        total_users,
    };
    Ok(Html(template.render()?))
}

/// GET /admin/users/search - Search users with filters
///
/// ### Arguments
/// - `state`: The state of the application
/// - `session`: The session
/// - `params`: The search parameters (email, first_name, last_name, role, page, page_size)
///
/// ### Returns
/// - `Ok(Html<String>)`: The user list partial as formatted HTML
/// - `Err(AppError)`: Error that occurred while rendering the template
pub async fn search_users(
    State(state): State<AppState>,
    session: Session,
    Query(params): Query<UserSearchParams>,
) -> Result<Html<String>, AppError> {
    let user_id: Option<i32> = session.get(SESSION_USER_ID).await.map_err(|e| {
        AppError::InternalError(anyhow::anyhow!("Failed to get user id from session: {}", e))
    })?;
    let user_id = match user_id {
        Some(id) => id,
        None => return Err(AppError::Unauthorized),
    };
    let user = state.user_repository.get_by_id(user_id).await?;
    let user = match user {
        Some(user) => user,
        None => return Err(AppError::Unauthorized),
    };
    let paginated_users = state
        .user_repository
        .search(
            params.email,
            params.first_name,
            params.last_name,
            params.role,
            params.page,
            params.page_size,
        )
        .await?;
    let template = templates::AdminUserListTemplate {
        user: templates::UserContext::new(user_id, user.first_name, user.role),
        users: paginated_users.users,
    };
    Ok(Html(template.render()?))
}
