use askama::Template;
use axum::{
    Form,
    extract::{Extension, Query, State},
    response::Html,
};
use serde::Deserialize;
use tower_sessions::Session;

use crate::{
    auth::handlers::hash_password,
    errors::AppError,
    handlers::AppState,
    session, templates,
    users::MAX_NAME_LEN,
    utils::{generate_valid_password, is_valid_email},
};

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
    Extension(csp_nonce): Extension<crate::csp::CspNonce>,
    session: Session,
) -> Result<Html<String>, AppError> {
    let user_id = session::get_session_user_id(&session).await?;
    let user = state.user_repository.get_by_id(user_id).await?;
    let user = match user {
        Some(user) => user,
        None => return Err(AppError::Unauthorized),
    };
    let csrf_token = axum_tower_sessions_csrf::get_or_create_token(&session)
        .await
        .map_err(|e| {
            AppError::InternalError(anyhow::anyhow!("Failed to generate CSRF token: {}", e))
        })?;
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
        csrf_token,
        csp_nonce: csp_nonce.0,
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
    let user_id = session::get_session_user_id(&session).await?;
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

/// POST /user/{id}/change-role - Toggle a user's role
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
    let user_id = session::get_session_user_id(&session).await?;
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

/// POST /user/{id}/toggle-force-password-update - Toggle the force_password_update flag for a user
///
/// ### Arguments
/// - `state`: The state of the application
/// - `session`: The session
/// - `id`: The ID of the user to toggle force password update for
///
/// ### Returns
/// - `Ok(Html<String>)`: The updated user row as formatted HTML
/// - `Err(AppError)`: Error that occurred while toggling the flag
pub async fn toggle_force_password_update(
    State(state): State<AppState>,
    session: Session,
    axum::extract::Path(id): axum::extract::Path<i32>,
) -> Result<Html<String>, AppError> {
    let user_id = session::get_session_user_id(&session).await?;
    let user = state.user_repository.get_by_id(user_id).await?;
    let user = match user {
        Some(user) => user,
        None => return Err(AppError::Unauthorized),
    };
    let updated_user = state
        .user_repository
        .toggle_force_password_update(id)
        .await?;
    let template = templates::UserRowTemplate {
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
    let _user_id = session::get_session_user_id(&session).await?;
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

#[derive(Deserialize)]
pub struct CreateUserFromAdminRequest {
    email: String,
    first_name: String,
    last_name: String,
}

/// POST /user/create - Create a new user from admin
///
/// ### Arguments
/// - `state`: The state of the application
/// - `session`: The session
/// - `request`: The create user request
///
/// ### Returns
/// - `Ok(Html<String>)`: The user creation response as formatted HTML (user row + password display)
/// - `Err(AppError)`: Error that occurred while creating the user
pub async fn create_user_from_admin(
    State(state): State<AppState>,
    session: Session,
    Form(request): Form<CreateUserFromAdminRequest>,
) -> Result<Html<String>, AppError> {
    let user_id = session::get_session_user_id(&session).await?;
    let user = state.user_repository.get_by_id(user_id).await?;
    let user = match user {
        Some(user) => user,
        None => return Err(AppError::Unauthorized),
    };
    let first_name = request.first_name.trim();
    let last_name = request.last_name.trim();
    let email = request.email.trim();
    if first_name.is_empty() {
        return Err(AppError::ValidationError(
            "First name cannot be empty".to_string(),
        ));
    }
    if first_name.len() > MAX_NAME_LEN {
        return Err(AppError::ValidationError(format!(
            "First name cannot exceed {} characters",
            MAX_NAME_LEN
        )));
    }
    if last_name.is_empty() {
        return Err(AppError::ValidationError(
            "Last name cannot be empty".to_string(),
        ));
    }
    if last_name.len() > MAX_NAME_LEN {
        return Err(AppError::ValidationError(format!(
            "Last name cannot exceed {} characters",
            MAX_NAME_LEN
        )));
    }
    if !is_valid_email(email) {
        return Err(AppError::InternalError(anyhow::anyhow!(
            "Invalid email address"
        )));
    }
    if (state
        .user_repository
        .get_by_email(email.to_string())
        .await?)
        .is_some()
    {
        return Err(AppError::InternalError(anyhow::anyhow!(
            "A user with this email already exists"
        )));
    }
    let password = generate_valid_password();
    let password_hash = hash_password(&password)
        .map_err(|e| AppError::InternalError(anyhow::anyhow!("Failed to hash password: {}", e)))?;
    let new_user_id = state
        .user_repository
        .create(
            email.to_string(),
            first_name.to_string(),
            last_name.to_string(),
            password_hash,
            true,
            true,
        )
        .await?;
    let new_user = state
        .user_repository
        .get_by_id(new_user_id)
        .await?
        .ok_or_else(|| {
            AppError::InternalError(anyhow::anyhow!("Failed to retrieve created user"))
        })?;
    if state.is_prod {
        let subject = "Your Fulgurant Account".to_string();
        let text_body = format!(
            "Hello {} {},\n\nYour Fulgurant account has been created by an administrator.\n\nYour login credentials are:\nEmail: {}\nPassword: {}\n\nYou will be required to set a new password when you first log in.",
            first_name, last_name, email, password
        );
        let html_body = format!(
            r#"<!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Your Fulgurant Account</title>
            </head>
            <body>
                <div style="display: flex; flex-direction: column; align-items: center; font-family: Arial, Helvetica, sans-serif;">
                    <h2>Hello {} {},</h2>
                    <p>Your Fulgurant account has been created by an administrator.</p>
                    <div style="margin: 20px 0;">
                        <p><strong>Your login credentials are:</strong></p>
                        <p>Email: <code>{}</code></p>
                        <p>Password: <code style="background-color: #f0f0f0; padding: 5px 10px; border-radius: 4px;">{}</code></p>
                    </div>
                    <p style="color: #666;">You will be required to set a new password when you first log in.</p>
                </div>
            </body>
            </html>"#,
            first_name, last_name, email, password
        );
        state
            .mailer
            .send_email(email.to_string(), subject, text_body, html_body)
            .await
            .map_err(|e| {
                tracing::error!("Failed to send account creation email: {}", e);
                AppError::InternalError(anyhow::anyhow!("Failed to send email: {}", e))
            })?;
        tracing::info!(
            "Account creation email sent to {}",
            crate::logging::sanitize_for_log(email)
        );
    } else {
        tracing::info!(
            "Development mode - account creation email not sent\nPassword for {}: {}",
            crate::logging::sanitize_for_log(email),
            &password
        );
    }
    let template = templates::UserCreationResponseTemplate {
        display_user: new_user.into(),
        user: templates::UserContext::from(&user),
    };
    Ok(Html(template.render()?))
}
