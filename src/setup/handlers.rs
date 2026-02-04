use crate::utils::{is_password_valid, is_valid_email};
use crate::{auth::handlers::hash_password, errors::AppError, handlers::AppState, templates};
use askama::Template;
use axum::{
    extract::State,
    http::{HeaderValue, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use serde::Deserialize;
use tower_sessions::Session;

const SESSION_USER_ID: &str = "user_id";

#[derive(Deserialize)]
pub struct SetupRequest {
    email: String,
    first_name: String,
    last_name: String,
    password: String,
}

/// GET /setup - Returns the initial setup page
///
/// ### Arguments
/// - `state`: The state of the application
/// - `session`: The session
///
/// ### Returns
/// - `Ok(Html<String>)`: The setup page
/// - `Err(AppError)`: An error occurred while rendering the template
pub async fn get_setup_page(
    State(state): State<AppState>,
    session: Session,
) -> Result<Response, AppError> {
    let has_admin = state.user_repository.has_admin().await.map_err(|e| {
        AppError::InternalError(anyhow::anyhow!("Failed to check for admin: {}", e))
    })?;
    if has_admin {
        tracing::warn!(
            "Attempted access to /setup but admin already exists - redirecting to /login"
        );
        return Ok(Redirect::to("/login").into_response());
    }
    let csrf_token = axum_tower_sessions_csrf::get_or_create_token(&session)
        .await
        .map_err(|e| {
            AppError::InternalError(anyhow::anyhow!("Failed to generate CSRF token: {}", e))
        })?;
    let template = templates::SetupTemplate {
        error_message: String::new(),
        email: String::new(),
        first_name: String::new(),
        last_name: String::new(),
        csrf_token,
    };
    Ok(Html(template.render()?).into_response())
}

/// POST /setup - Creates the initial admin user
///
/// ### Arguments
/// - `state`: The state of the application
/// - `session`: The session
/// - `request`: The setup request
///
/// ### Returns
/// - `Ok(Response)`: Redirect to index page after successful setup
/// - `Err(AppError)`: An error occurred while creating the admin user
pub async fn create_admin(
    State(state): State<AppState>,
    session: Session,
    Form(request): Form<SetupRequest>,
) -> Result<Response, AppError> {
    let csrf_token = axum_tower_sessions_csrf::get_or_create_token(&session)
        .await
        .map_err(|e| {
            AppError::InternalError(anyhow::anyhow!("Failed to generate CSRF token: {}", e))
        })?;

    let has_admin = state.user_repository.has_admin().await.map_err(|e| {
        AppError::InternalError(anyhow::anyhow!("Failed to check for admin: {}", e))
    })?;
    if has_admin {
        tracing::warn!(
            "Attempted to create admin via /setup but admin already exists - rejecting request"
        );
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .body("".to_string())
            .unwrap();
        response
            .headers_mut()
            .insert("HX-Redirect", HeaderValue::from_static("/login"));
        return Ok(response.into_response());
    }
    let first_name = request.first_name.trim();
    let last_name = request.last_name.trim();
    let password = request.password.trim();
    let email = request.email.trim().to_lowercase();
    if !is_valid_email(&email) {
        let template = templates::SetupFormTemplate {
            error_message: "Invalid email address".to_string(),
            email: email.clone(),
            first_name: first_name.to_string(),
            last_name: last_name.to_string(),
            csrf_token,
        };
        return Ok(Html(template.render()?).into_response());
    }
    if !is_password_valid(password) {
        let template = templates::SetupFormTemplate {
            error_message: "Password must be 8-64 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character".to_string(),
            email: email.clone(),
            first_name: first_name.to_string(),
            last_name: last_name.to_string(),
            csrf_token,
        };
        return Ok(Html(template.render()?).into_response());
    }
    if first_name.is_empty() || last_name.is_empty() {
        let template = templates::SetupFormTemplate {
            error_message: "First name and last name are required".to_string(),
            email: email.clone(),
            first_name: first_name.to_string(),
            last_name: last_name.to_string(),
            csrf_token,
        };
        return Ok(Html(template.render()?).into_response());
    }
    let password_hash = hash_password(password)
        .map_err(|e| AppError::InternalError(anyhow::anyhow!("Failed to hash password: {}", e)))?;
    let user_id = state
        .user_repository
        .create_admin(
            email.clone(),
            first_name.to_string(),
            last_name.to_string(),
            password_hash,
        )
        .await
        .map_err(|e| {
            if matches!(e, sqlx::Error::RowNotFound) {
                tracing::warn!("Admin already exists, rejecting duplicate creation");
                AppError::InternalError(anyhow::anyhow!("Admin user already exists"))
            } else {
                tracing::error!("Failed to create admin user: {}", e);
                AppError::InternalError(anyhow::anyhow!("Failed to create admin user: {}", e))
            }
        })?;
    tracing::info!("Initial admin user created with ID: {}", user_id);
    session
        .insert(SESSION_USER_ID, user_id)
        .await
        .map_err(|e| {
            AppError::InternalError(anyhow::anyhow!("Failed to set user id in session: {}", e))
        })?;
    state
        .setup_needed
        .store(false, std::sync::atomic::Ordering::Relaxed);
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .body("".to_string())
        .unwrap();
    response
        .headers_mut()
        .insert("HX-Redirect", HeaderValue::from_static("/"));
    Ok(response.into_response())
}
