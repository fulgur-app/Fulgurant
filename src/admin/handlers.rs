
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
    20
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
    let paginated_users = state.user_repository.get_all(1, 20).await?;
    let template = templates::AdminTemplate {
        user: templates::UserContext::from(&user),
        users: paginated_users.users,
        total_users,
        page: paginated_users.page,
        total_pages: paginated_users.total_pages,
        email: None,
        first_name: None,
        last_name: None,
        role: None,
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
            params.email.clone(),
            params.first_name.clone(),
            params.last_name.clone(),
            params.role.clone(),
            params.page,
            params.page_size,
        )
        .await?;
    let template = templates::AdminUserListTemplate {
        user: templates::UserContext::from(&user),
        users: paginated_users.users,
        page: paginated_users.page,
        total_pages: paginated_users.total_pages,
        email: params.email,
        first_name: params.first_name,
        last_name: params.last_name,
        role: params.role,
    };
    Ok(Html(template.render()?))
}

/// GET /user/{id}/change-role - Toggle a user's role
///
/// ### Arguments
/// - `state`: The state of the application
/// - `session`: The session
/// - `id`: The ID of the user to change role for
///
/// ### Returns
/// - `Ok(Html<String>)`: The role change success message as formatted HTML
/// - `Err(AppError)`: Error that occurred while changing the role
pub async fn change_user_role(
    State(state): State<AppState>,
    session: Session,
    axum::extract::Path(id): axum::extract::Path<i32>,
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
    let updated_user = state.user_repository.toggle_role(id).await?;

    let template = templates::RoleChangeSuccessTemplate {
        display_user: updated_user,
        user: templates::UserContext::from(&user),
    };
    Ok(Html(template.render()?))
}

/// DELETE /user/{id} - Delete a user
///
/// ### Arguments
/// - `state`: The state of the application
/// - `session`: The session
/// - `id`: The ID of the user to delete
///
/// ### Returns
/// - `Ok(Html<String>)`: The delete success message as formatted HTML
/// - `Err(AppError)`: Error that occurred while deleting the user
pub async fn delete_user(
    State(state): State<AppState>,
    session: Session,
    axum::extract::Path(id): axum::extract::Path<i32>,
) -> Result<Html<String>, AppError> {
    let user_id: Option<i32> = session.get(SESSION_USER_ID).await.map_err(|e| {
        AppError::InternalError(anyhow::anyhow!("Failed to get user id from session: {}", e))
    })?;
    let _user_id = match user_id {
        Some(id) => id,
        None => return Err(AppError::Unauthorized),
    };
    let deleted_user = match state.user_repository.delete(id).await {
        Ok(deleted) => deleted,
        Err(e) => return Err(AppError::DatabaseError(e)),
    };
    let template = templates::DeleteUserSuccessTemplate {
        first_name: deleted_user.first_name,
        last_name: deleted_user.last_name,
    };
    Ok(Html(template.render()?))
}