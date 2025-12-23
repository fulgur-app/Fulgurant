use askama::Template;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Form,
};
use tower_sessions::Session;

use crate::{
    api_key::{self},
    devices::{CreateDevice, Device, DeviceRepository, UpdateDevice},
    mail::Mailer,
    shares::{DisplayShare, ShareRepository},
    templates::{self, ErrorMessageTemplate},
    users::UserRepository,
    verification_code::{self, VerificationCodeRepository},
};

const SESSION_USER_ID: &str = "user_id";

pub enum AppError {
    NotFound,
    DatabaseError(sqlx::Error),
    TemplateError(askama::Error),
    ApiKeyError(anyhow::Error),
    InternalError(anyhow::Error),
    Unauthorized,
}

impl IntoResponse for AppError {
    /// Converts an AppError to a response
    ///
    /// ### Arguments
    /// - `self`: The AppError
    ///
    /// ### Returns
    /// - `Response`: The response
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::NotFound => (StatusCode::NOT_FOUND, "Entity not found".to_string()),
            AppError::DatabaseError(e) => {
                tracing::error!("Database error: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Database error occurred".to_string(),
                )
            }
            AppError::TemplateError(e) => {
                tracing::error!("Template error: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Template rendering error".to_string(),
                )
            }
            AppError::ApiKeyError(e) => {
                tracing::error!("API key error: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "API key error".to_string(),
                )
            }
            AppError::InternalError(e) => {
                tracing::error!("Internal error: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error".to_string(),
                )
            }
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()),
        };

        let template = ErrorMessageTemplate {
            message: message.clone(),
        };
        match template.render() {
            Ok(html) => (status, Html(html)).into_response(),
            Err(_) => (status, message).into_response(),
        }
    }
}

impl From<sqlx::Error> for AppError {
    /// Converts a sqlx::Error to an AppError
    ///
    /// ### Arguments
    /// - `err`: The sqlx::Error
    ///
    /// ### Returns
    /// - `AppError`: The AppError
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::RowNotFound => AppError::NotFound,
            _ => AppError::DatabaseError(err),
        }
    }
}

impl From<askama::Error> for AppError {
    /// Converts an askama::Error to an AppError
    ///
    /// ### Arguments
    /// - `err`: The askama::Error
    ///
    /// ### Returns
    /// - `AppError`: The AppError
    fn from(err: askama::Error) -> Self {
        AppError::TemplateError(err)
    }
}

#[derive(Clone)]
pub struct AppState {
    pub device_repository: DeviceRepository,
    pub user_repository: UserRepository,
    pub verification_code_repository: VerificationCodeRepository,
    pub share_repository: ShareRepository,
    pub mailer: Mailer,
    pub is_prod: bool,
    pub can_register: bool,
    pub share_validity_days: i64,
}

/// GET / - Returns the index page
///
/// ### Arguments
/// - `state`: The state of the application
/// - `session`: The session
///
/// ### Returns
/// - `Ok(Html<String>)`: The index page
/// - `Err(AppError)`: Error that occurred while rendering the template
pub async fn index(
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
    let devices = match state.device_repository.get_all_for_user(user_id).await {
        Ok(devices) => devices.into_iter().rev().collect::<Vec<Device>>(),
        Err(e) => {
            tracing::error!("Error getting devices: {:?}", e);
            return Err(AppError::DatabaseError(e));
        }
    };
    let raw_shares = match state.share_repository.get_all_for_user(user_id).await {
        Ok(shares) => shares,
        Err(e) => {
            tracing::error!("Error getting shares: {:?}", e);
            return Err(AppError::DatabaseError(e));
        }
    };
    let shares = raw_shares
        .into_iter()
        .map(|s| s.to_display_shares(devices.clone()))
        .collect::<Vec<DisplayShare>>();
    let template = templates::IndexTemplate {
        devices,
        shares,
        user_id,
        first_name: user.first_name,
    };
    Ok(Html(template.render()?))
}

/// POST /device/{user_id}/create - Creates a new device
///
/// ### Arguments
/// - `state`: The state of the application
/// - `user_id`: The ID of the user
/// - `request`: The create device request
///
/// ### Returns
/// - `Ok(Html<String>)`: The response
/// - `Err(AppError)`: Error that occurred while creating the device
pub async fn create_device(
    State(state): State<AppState>,
    Path(user_id): Path<i32>,
    Form(request): Form<CreateDevice>,
) -> Result<Html<String>, AppError> {
    let api_key = api_key::generate_api_key();
    let hash = api_key::hash_api_key(&api_key)
        .map_err(|e| AppError::ApiKeyError(anyhow::anyhow!("Failed to hash API key: {}", e)))?;
    let device = state
        .device_repository
        .create(user_id, hash, request.clone())
        .await?;
    tracing::info!("Device created: {:?}", device);
    let template = templates::DeviceCreationResponseTemplate { device, api_key };
    Ok(Html(template.render()?))
}

/// GET /device/{id}/edit - Returns the device edit form
///
/// ### Arguments
/// - `state`: The state of the application
/// - `id`: The ID of the device
///
/// ### Returns
/// - `Ok(Html<String>)`: The device edit form
/// - `Err(AppError)`: Error that occurred while rendering the template
pub async fn get_device_edit_form(
    State(state): State<AppState>,
    Path(id): Path<i32>,
) -> Result<Html<String>, AppError> {
    let device = state.device_repository.get_by_id(id).await?;
    let template = templates::DeviceEditFormTemplate { device };
    Ok(Html(template.render()?))
}

/// PUT /device/{id} - Updates a device
///
/// ### Arguments
/// - `state`: The state of the application
/// - `id`: The ID of the device
/// - `request`: The update device request
///
/// ### Returns
/// - `Ok(Html<String>)`: The response
/// - `Err(AppError)`: Error that occurred while updating the device
pub async fn update_device(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    Form(request): Form<UpdateDevice>,
) -> Result<Html<String>, AppError> {
    let device = state.device_repository.update(id, request).await?;
    let template = templates::DeviceRowTemplate { device };
    Ok(Html(template.render()?))
}

/// DELETE /device/{id} - Deletes a device
///
/// ### Arguments
/// - `state`: The state of the application
/// - `id`: The ID of the device
///
/// ### Returns
/// - `Ok(StatusCode)`: The response
/// - `Err(AppError)`: Error that occurred while deleting the device
pub async fn delete_device(
    State(state): State<AppState>,
    Path(id): Path<i32>,
) -> Result<StatusCode, AppError> {
    match state.device_repository.delete(id).await {
        Ok(_) => Ok(StatusCode::OK),
        Err(e) => {
            tracing::error!("Error deleting device: {:?}", e);
            return Err(AppError::DatabaseError(e));
        }
    }
}

/// GET /device/{id}/cancel - Cancels the device edit
///
/// ### Arguments
/// - `state`: The state of the application
/// - `id`: The ID of the device
///
/// ### Returns
/// - `Ok(Html<String>)`: The response
/// - `Err(AppError)`: Error that occurred while rendering the template
pub async fn cancel_edit_device(
    State(state): State<AppState>,
    Path(id): Path<i32>,
) -> Result<Html<String>, AppError> {
    let device = state.device_repository.get_by_id(id).await?;
    let template = templates::DeviceRowTemplate { device };
    Ok(Html(template.render()?))
}

/// DELETE /device/{id} - Deletes a device
///
/// ### Arguments
/// - `state`: The state of the application
/// - `id`: The ID of the device
///
/// ### Returns
/// - `Ok(StatusCode)`: The response
/// - `Err(AppError)`: Error that occurred while deleting the share
pub async fn delete_share(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    match state.share_repository.delete(&id).await {
        Ok(_) => Ok(StatusCode::OK),
        Err(e) => {
            tracing::error!("Error deleting share: {:?}", e);
            return Err(AppError::DatabaseError(e));
        }
    }
}

/// GET /settings - Returns the settings page
///
/// ### Arguments
/// - `state`: The state of the application
/// - `session`: The session
///
/// ### Returns
/// - `Ok(Html<String>)`: The settings page
/// - `Err(AppError)`: Error that occurred while rendering the template
pub async fn get_settings(
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
    let template = templates::SettingsTemplate {
        user_id,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
    };
    Ok(Html(template.render()?))
}

#[derive(serde::Deserialize)]
pub struct UpdateNameRequest {
    first_name: String,
    last_name: String,
}

/// POST /settings/update-name - Updates user's name
///
/// ### Arguments
/// - `state`: The state of the application
/// - `session`: The session
/// - `request`: The update name request
///
/// ### Returns
/// - `Ok(Html<String>)`: Success message
/// - `Err(AppError)`: Error that occurred while updating the name
pub async fn update_name(
    State(state): State<AppState>,
    session: Session,
    Form(request): Form<UpdateNameRequest>,
) -> Result<Html<String>, AppError> {
    let user_id: Option<i32> = session.get(SESSION_USER_ID).await.map_err(|e| {
        AppError::InternalError(anyhow::anyhow!("Failed to get user id from session: {}", e))
    })?;
    let user_id = match user_id {
        Some(id) => id,
        None => return Err(AppError::Unauthorized),
    };
    state
        .user_repository
        .update_name(
            user_id,
            request.first_name.clone(),
            request.last_name.clone(),
        )
        .await?;
    tracing::info!("User {} updated their name", user_id);
    let template = templates::UpdateNameSuccessTemplate {
        first_name: request.first_name,
        last_name: request.last_name,
    };
    Ok(Html(template.render()?))
}

#[derive(serde::Deserialize)]
pub struct UpdateEmailRequest {
    email: String,
}

/// POST /settings/update-email - Initiates email update process
///
/// ### Arguments
/// - `state`: The state of the application
/// - `session`: The session
/// - `request`: The update email request
///
/// ### Returns
/// - `Ok(Html<String>)`: Verification code form
/// - `Err(AppError)`: Error that occurred while initiating email update
pub async fn update_email_step_1(
    State(state): State<AppState>,
    session: Session,
    Form(request): Form<UpdateEmailRequest>,
) -> Result<Html<String>, AppError> {
    let user_id: Option<i32> = session.get(SESSION_USER_ID).await.map_err(|e| {
        AppError::InternalError(anyhow::anyhow!("Failed to get user id from session: {}", e))
    })?;
    let user_id = match user_id {
        Some(id) => id,
        None => return Err(AppError::Unauthorized),
    };
    if !request.email.contains('@') || !request.email.contains('.') {
        let template = templates::EmailChangeStep2Template {
            new_email: request.email,
            error_message: "Invalid email format".to_string(),
        };
        return Ok(Html(template.render()?));
    }
    if let Ok(Some(_)) = state
        .user_repository
        .get_by_email(request.email.clone())
        .await
    {
        let template = templates::EmailChangeStep2Template {
            new_email: request.email,
            error_message: "This email is already registered".to_string(),
        };
        return Ok(Html(template.render()?));
    }
    let code = verification_code::generate_code();
    state
        .verification_code_repository
        .create(
            request.email.clone(),
            code.clone(),
            "email_change".to_string(),
        )
        .await
        .map_err(|e| {
            AppError::InternalError(anyhow::anyhow!("Failed to create verification code: {}", e))
        })?;
    if state.is_prod {
        state
            .mailer
            .send_verification_email(request.email.clone(), code.clone())
            .await
            .map_err(|e| AppError::InternalError(anyhow::anyhow!("Failed to send email: {}", e)))?;
        tracing::info!("Verification email sent to {}", request.email);
    } else {
        tracing::info!(
            "Not sending verification email in non-production environment\nVerification code: {}",
            code
        );
    }
    let template = templates::EmailChangeStep2Template {
        new_email: request.email,
        error_message: String::new(),
    };
    Ok(Html(template.render()?))
}

#[derive(serde::Deserialize)]
pub struct VerifyEmailChangeRequest {
    email: String,
    code: String,
}

/// POST /settings/verify-email-change - Verifies email change code
///
/// ### Arguments
/// - `state`: The state of the application
/// - `session`: The session
/// - `request`: The verification request
///
/// ### Returns
/// - `Ok(Html<String>)`: Success message
/// - `Err(AppError)`: Error that occurred while verifying the code
pub async fn update_email_step_2(
    State(state): State<AppState>,
    session: Session,
    Form(request): Form<VerifyEmailChangeRequest>,
) -> Result<Html<String>, AppError> {
    let user_id: Option<i32> = session.get(SESSION_USER_ID).await.map_err(|e| {
        AppError::InternalError(anyhow::anyhow!("Failed to get user id from session: {}", e))
    })?;
    let user_id = match user_id {
        Some(id) => id,
        None => return Err(AppError::Unauthorized),
    };
    let result = state
        .verification_code_repository
        .verify_code(
            request.code.clone(),
            request.email.clone(),
            "email_change".to_string(),
        )
        .await
        .map_err(|e| AppError::InternalError(anyhow::anyhow!("Failed to verify code: {}", e)))?;
    match result {
        verification_code::VerificationResult::Verified => {
            state
                .user_repository
                .update_email(user_id, request.email.clone())
                .await?;
            tracing::info!("User {} changed their email to {}", user_id, request.email);
            let template = templates::EmailChangeSuccessTemplate {
                email: request.email,
            };
            Ok(Html(template.render()?))
        }
        verification_code::VerificationResult::Invalid { attempts_remaining } => {
            let error_msg = if attempts_remaining > 0 {
                format!(
                    "Invalid verification code. {} attempts remaining.",
                    attempts_remaining
                )
            } else {
                "Too many failed attempts. Please request a new code.".to_string()
            };
            let template = templates::EmailChangeStep2Template {
                new_email: request.email,
                error_message: error_msg,
            };
            Ok(Html(template.render()?))
        }
        verification_code::VerificationResult::TooManyAttempts => {
            let template = templates::EmailChangeStep2Template {
                new_email: request.email,
                error_message: "Too many failed attempts. Please request a new code.".to_string(),
            };
            Ok(Html(template.render()?))
        }
        verification_code::VerificationResult::Expired => {
            let template = templates::EmailChangeStep2Template {
                new_email: request.email,
                error_message: "Verification code has expired. Please request a new code."
                    .to_string(),
            };
            Ok(Html(template.render()?))
        }
        verification_code::VerificationResult::NotFound => {
            let template = templates::EmailChangeStep2Template {
                new_email: request.email,
                error_message: "No verification code found. Please request a new code.".to_string(),
            };
            Ok(Html(template.render()?))
        }
    }
}
