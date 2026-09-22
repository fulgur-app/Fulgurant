use askama::Template;
use axum::{
    Form, Json,
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse},
};
use fulgur_common::api::shares::ShareFileResponse;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, atomic::AtomicBool};
use tokio::sync::RwLock;
use tower_sessions::Session;

use crate::{
    api::sse::{ChannelTag, ShareNotification, SseChannelManager, SseConnectionLimiter},
    api_key::{self},
    devices::{
        self, CreateDevice, Device, DeviceRepository, MAX_DEVICE_NAME_LEN, MAX_DEVICE_TYPE_LEN,
        UpdateDevice,
    },
    errors::{AppError, JsonAppError},
    mail,
    session::{self, SessionRepository},
    settings::SettingsRepository,
    shares::{CreateShare, DisplayShare, ShareRepository},
    templates::{self},
    users::{MAX_NAME_LEN, UserRepository},
    utils::{is_valid_email, is_valid_file_name},
    verification_code::{self, VerificationCodeRepository},
};

#[derive(Clone)]
pub struct AppState {
    pub device_repository: DeviceRepository,
    pub user_repository: UserRepository,
    pub verification_code_repository: VerificationCodeRepository,
    pub share_repository: ShareRepository,
    pub settings_repository: SettingsRepository,
    pub session_repository: SessionRepository,
    pub mailer: Arc<mail::Mailer>,
    pub is_prod: bool,
    pub can_register: bool,
    pub setup_needed: Arc<AtomicBool>,
    pub share_validity_days: i64,
    pub max_devices_per_user: i32,
    pub sse_manager: Arc<SseChannelManager>,
    pub sse_connection_limiter: Arc<SseConnectionLimiter>,
    pub sse_heartbeat_seconds: u64,
    pub jwt_secret: String,
    pub jwt_expiry_seconds: i64,
    /// Maximum share file size in bytes. `None` means no limit.
    /// Wrapped in Arc<`RwLock`<>> to allow live updates from the admin settings page.
    pub max_file_size_bytes: Arc<RwLock<Option<u64>>>,
}

/// GET /healthz - Unauthenticated liveness probe for container orchestration
///
/// Registered at the top level of the router, outside the API auth middleware
/// and the rate limiter, so health checks succeed without credentials and are
/// never throttled.
///
/// ### Returns
/// - `(StatusCode, &'static str)`: `200 OK` with a plain-text body
pub async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

/// Fallback handler for 404 Not Found
///
/// ### Returns
/// - `(StatusCode, Html<String>)`: The 404 page with proper status code
pub async fn not_found() -> impl IntoResponse {
    let template = templates::NotFoundTemplate {};
    match template.render() {
        Ok(html) => (StatusCode::NOT_FOUND, Html(html)),
        Err(_) => (StatusCode::NOT_FOUND, Html("404 - Not Found".to_string())),
    }
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
    let user_id = session::get_session_user_id(&session).await?;
    let user = state.user_repository.get_by_id(user_id).await?;
    let Some(user) = user else {
        return Err(AppError::Unauthorized);
    };
    let csrf_token = axum_tower_sessions_csrf::get_or_create_token(&session)
        .await
        .map_err(|e| {
            AppError::InternalError(anyhow::anyhow!("Failed to generate CSRF token: {e}"))
        })?;
    let devices = match state.device_repository.get_all_for_user(user_id).await {
        Ok(devices) => devices,
        Err(e) => {
            tracing::error!("Error getting devices: {:?}", e);
            return Err(AppError::DatabaseError(e));
        }
    };
    let raw_shares = match state.share_repository.get_available_for_user(user_id).await {
        Ok(shares) => shares,
        Err(e) => {
            tracing::error!("Error getting shares: {:?}", e);
            return Err(AppError::DatabaseError(e));
        }
    };
    let web_device = state.device_repository.get_web_device(user_id).await?;
    let device_names = devices
        .iter()
        .chain(web_device.iter())
        .map(|device| (device.device_id.clone(), device.name.clone()))
        .collect::<HashMap<String, String>>();
    let shares = raw_shares
        .into_iter()
        .map(|s| s.to_display_shares(&device_names))
        .collect::<Vec<DisplayShare>>();
    let template = templates::IndexTemplate {
        devices,
        shares,
        user: templates::UserContext::from(&user),
        max_devices_per_user: if state.max_devices_per_user == devices::MAX_DEVICES_PER_USER {
            None
        } else {
            Some(state.max_devices_per_user)
        },
        csrf_token,
    };
    Ok(Html(template.render()?))
}

/// Check that a device may be managed by the session user
///
/// ### Arguments
/// - `device`: The device being accessed
/// - `session_user_id`: The ID of the logged-in user
///
/// ### Returns
/// - `Ok(())`: The user owns the device and it is a regular device
/// - `Err(AppError::Forbidden)`: The device belongs to another user
/// - `Err(AppError::NotFound)`: The device is the synthetic web device
fn authorize_device_access(device: &Device, session_user_id: i32) -> Result<(), AppError> {
    if device.user_id != session_user_id {
        return Err(AppError::Forbidden);
    }
    if device.device_type == devices::WEB_DEVICE_TYPE {
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// POST /`device/{user_id}/create` - Creates a new device
///
/// ### Arguments
/// - `state`: The state of the application
/// - `user_id`: The ID of the user
/// - `session`: The session
/// - `request`: The create device request
///
/// ### Returns
/// - `Ok(Html<String>)`: The response as formatted HTML
/// - `Err(AppError)`: Error that occurred while creating the device
pub async fn create_device(
    State(state): State<AppState>,
    Path(user_id): Path<i32>,
    session: Session,
    Form(mut request): Form<CreateDevice>,
) -> Result<Html<String>, AppError> {
    let session_user_id = session::get_session_user_id(&session).await?;
    if session_user_id != user_id {
        return Err(AppError::Forbidden);
    }
    let name = request.name.trim().to_string();
    let device_type = request.device_type.trim().to_string();
    if name.is_empty() {
        return Err(AppError::ValidationError(
            "Device name cannot be empty".to_string(),
        ));
    }
    if name.len() > MAX_DEVICE_NAME_LEN {
        return Err(AppError::ValidationError(format!(
            "Device name cannot exceed {MAX_DEVICE_NAME_LEN} characters"
        )));
    }
    if devices::is_reserved_device_name(&name) {
        return Err(AppError::ValidationError(
            "This device name is reserved".to_string(),
        ));
    }
    if device_type.is_empty() {
        return Err(AppError::ValidationError(
            "Device type cannot be empty".to_string(),
        ));
    }
    if device_type.len() > MAX_DEVICE_TYPE_LEN {
        return Err(AppError::ValidationError(format!(
            "Device type cannot exceed {MAX_DEVICE_TYPE_LEN} characters"
        )));
    }
    if devices::is_reserved_device_type(&device_type) {
        return Err(AppError::ValidationError(
            "This device type is reserved".to_string(),
        ));
    }
    if !devices::is_valid_api_key_lifetime(request.api_key_lifetime) {
        return Err(AppError::ValidationError(
            "Invalid API key lifetime".to_string(),
        ));
    }
    request.name = name;
    request.device_type = device_type;
    let api_key = api_key::generate_api_key();
    let hash = api_key::hash_api_key(&api_key)
        .map_err(|e| AppError::ApiKeyError(anyhow::anyhow!("Failed to hash API key: {e}")))?;
    let device = state
        .device_repository
        .create(user_id, hash, request.clone(), state.max_devices_per_user)
        .await
        .map_err(|e| match e {
            devices::CreateDeviceError::LimitReached(max) => {
                tracing::error!("Max devices per user reached for user: {}", user_id);
                AppError::MaxDevicesPerUserReached(max)
            }
            devices::CreateDeviceError::Database(e) => AppError::from(e),
        })?;
    tracing::info!("Device created: id={} for user {}", device.id, user_id);
    let template = templates::DeviceCreationResponseTemplate { device, api_key };
    Ok(Html(template.render()?))
}

/// GET /device/{id}/edit - Returns the inline device edit form
///
/// ### Arguments
/// - `state`: The state of the application
/// - `id`: The ID of the device
/// - `session`: The session
///
/// ### Returns
/// - `Ok(Html<String>)`: The inline device edit form as formatted HTML
/// - `Err(AppError)`: Error that occurred while rendering the template
pub async fn get_device_edit_form(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    session: Session,
) -> Result<Html<String>, AppError> {
    let session_user_id = session::get_session_user_id(&session).await?;
    let device = state.device_repository.get_by_id(id).await?;
    authorize_device_access(&device, session_user_id)?;
    let template = templates::InlineEditFormTemplate { device };
    Ok(Html(template.render()?))
}

/// PUT /device/{id} - Updates a device
///
/// ### Arguments
/// - `state`: The state of the application
/// - `id`: The ID of the device
/// - `session`: The session
/// - `request`: The update device request
///
/// ### Returns
/// - `Ok(Html<String>)`: The response as formatted HTML
/// - `Err(AppError)`: Error that occurred while updating the device
pub async fn update_device(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    session: Session,
    Form(mut request): Form<UpdateDevice>,
) -> Result<Html<String>, AppError> {
    let session_user_id = session::get_session_user_id(&session).await?;
    let existing_device = state.device_repository.get_by_id(id).await?;
    authorize_device_access(&existing_device, session_user_id)?;
    let name = request.name.trim().to_string();
    let device_type = request.device_type.trim().to_string();
    if name.is_empty() {
        return Err(AppError::ValidationError(
            "Device name cannot be empty".to_string(),
        ));
    }
    if name.len() > MAX_DEVICE_NAME_LEN {
        return Err(AppError::ValidationError(format!(
            "Device name cannot exceed {MAX_DEVICE_NAME_LEN} characters"
        )));
    }
    if devices::is_reserved_device_name(&name) {
        return Err(AppError::ValidationError(
            "This device name is reserved".to_string(),
        ));
    }
    if device_type.is_empty() {
        return Err(AppError::ValidationError(
            "Device type cannot be empty".to_string(),
        ));
    }
    if device_type.len() > MAX_DEVICE_TYPE_LEN {
        return Err(AppError::ValidationError(format!(
            "Device type cannot exceed {MAX_DEVICE_TYPE_LEN} characters"
        )));
    }
    if devices::is_reserved_device_type(&device_type) {
        return Err(AppError::ValidationError(
            "This device type is reserved".to_string(),
        ));
    }
    request.name = name;
    request.device_type = device_type;
    let device = state.device_repository.update(id, request).await?;
    let template = templates::DeviceRowEditResponseTemplate { device };
    Ok(Html(template.render()?))
}

/// DELETE /device/{id} - Deletes a device
///
/// ### Arguments
/// - `state`: The state of the application
/// - `id`: The ID of the device
/// - `session`: The session
///
/// ### Returns
/// - `Ok(StatusCode)`: The response as status code (when not last device)
/// - `Ok(Html<String>)`: The empty state row HTML (when deleting last device)
/// - `Err(AppError)`: Error that occurred while deleting the device
pub async fn delete_device(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    session: Session,
) -> Result<axum::response::Response, AppError> {
    let session_user_id = session::get_session_user_id(&session).await?;
    let device = state.device_repository.get_by_id(id).await?;
    authorize_device_access(&device, session_user_id)?;
    let user_id = device.user_id;

    // Count how many devices this user has
    let device_count = state
        .device_repository
        .get_all_for_user(user_id)
        .await?
        .len();

    // Delete the device
    match state.device_repository.delete(id).await {
        Ok(()) => {
            // If this was the last device, return the empty state row
            if device_count == 1 {
                let template = templates::DeviceEmptyStateRowTemplate;
                Ok(Html(template.render()?).into_response())
            } else {
                Ok(StatusCode::OK.into_response())
            }
        }
        Err(e) => {
            tracing::error!("Error deleting device: {:?}", e);
            Err(AppError::DatabaseError(e))
        }
    }
}

/// GET /device/{id}/renew - Returns the inline device renew form
///
/// ### Arguments
/// - `state`: The state of the application
/// - `id`: The ID of the device
/// - `session`: The session
///
/// ### Returns
/// - `Ok(Html<String>)`: The inline device renew form as formatted HTML
/// - `Err(AppError)`: Error that occurred while rendering the template
pub async fn get_device_renew_form(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    session: Session,
) -> Result<Html<String>, AppError> {
    let session_user_id = session::get_session_user_id(&session).await?;
    let device = state.device_repository.get_by_id(id).await?;
    authorize_device_access(&device, session_user_id)?;
    let template = templates::InlineRenewFormTemplate { device };
    Ok(Html(template.render()?))
}

/// POST /device/{id}/renew - Renews a device
///
/// ### Arguments
/// - `state`: The state of the application
/// - `id`: The ID of the device
/// - `session`: The session
/// - `request`: The renew device request
///
/// ### Returns
/// - `Ok(Html<String>)`: The updated device row as formatted HTML
/// - `Err(AppError)`: Error that occurred while renewing the device
pub async fn renew_device(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    session: Session,
    Form(request): Form<devices::RenewDevice>,
) -> Result<Html<String>, AppError> {
    let session_user_id = session::get_session_user_id(&session).await?;
    if !devices::is_valid_api_key_lifetime(request.api_key_lifetime) {
        return Err(AppError::ValidationError(
            "Invalid API key lifetime".to_string(),
        ));
    }
    let existing_device = state.device_repository.get_by_id(id).await?;
    authorize_device_access(&existing_device, session_user_id)?;
    let device = state.device_repository.renew(id, request).await?;
    let template = templates::DeviceRowRenewResponseTemplate { device };
    Ok(Html(template.render()?))
}

/// GET /device/{id}/cancel - Cancels the device edit
///
/// ### Arguments
/// - `state`: The state of the application
/// - `id`: The ID of the device
/// - `session`: The session
///
/// ### Returns
/// - `Ok(Html<String>)`: The response as formatted HTML
/// - `Err(AppError)`: Error that occurred while rendering the template
pub async fn cancel_edit_device(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    session: Session,
) -> Result<Html<String>, AppError> {
    let session_user_id = session::get_session_user_id(&session).await?;
    let device = state.device_repository.get_by_id(id).await?;
    authorize_device_access(&device, session_user_id)?;
    let template = templates::DeviceRowTemplate { device };
    Ok(Html(template.render()?))
}

/// DELETE /share/{id} - Deletes a share
///
/// ### Arguments
/// - `state`: The state of the application
/// - `id`: The ID of the share
/// - `session`: The session
///
/// ### Returns
/// - `Ok(StatusCode)`: The response as status code
/// - `Err(AppError)`: Error that occurred while deleting the share
pub async fn delete_share(
    State(state): State<AppState>,
    Path(id): Path<String>,
    session: Session,
) -> Result<StatusCode, AppError> {
    let session_user_id = session::get_session_user_id(&session).await?;
    let share = state.share_repository.get_by_id(&id).await?;
    if share.user_id != session_user_id {
        return Err(AppError::Forbidden);
    }
    match state.share_repository.mark_deleted(&id).await {
        Ok(()) => Ok(StatusCode::OK),
        Err(e) => {
            tracing::error!("Error deleting share: {:?}", e);
            Err(AppError::DatabaseError(e))
        }
    }
}

/// Request body of `POST /share`, one destination per request
///
/// `content` is the age ciphertext produced in the browser for
/// `destination_device_id`, base64-encoded, exactly as the Fulgur client
/// sends it to `POST /api/share`.
#[derive(Debug, Deserialize)]
pub struct WebShareRequest {
    pub destination_device_id: String,
    pub file_name: String,
    pub content: String,
}

/// GET /share/new - Returns the page to send a file from the browser to a device
///
/// ### Arguments
/// - `state`: The state of the application
/// - `session`: The session
///
/// ### Returns
/// - `Ok(Html<String>)`: The new share page as formatted HTML
/// - `Err(AppError)`: Error that occurred while rendering the template
pub async fn get_new_share(
    State(state): State<AppState>,
    session: Session,
) -> Result<Html<String>, AppError> {
    let user_id = session::get_session_user_id(&session).await?;
    let user = state.user_repository.get_by_id(user_id).await?;
    let Some(user) = user else {
        return Err(AppError::Unauthorized);
    };
    let csrf_token = axum_tower_sessions_csrf::get_or_create_token(&session)
        .await
        .map_err(|e| {
            AppError::InternalError(anyhow::anyhow!("Failed to generate CSRF token: {e}"))
        })?;
    let devices = state.device_repository.get_all_for_user(user_id).await?;
    let max_file_size_bytes = *state.max_file_size_bytes.read().await;
    let template = templates::NewShareTemplate {
        devices,
        max_file_size_bytes,
        max_file_size_display: max_file_size_bytes.map(crate::utils::format_bytes),
        share_validity_days: state.share_validity_days,
        user: templates::UserContext::from(&user),
        csrf_token,
    };
    Ok(Html(template.render()?))
}

/// POST /share - Creates a share from the browser for a single destination device
///
/// The browser compresses and encrypts the file to the destination device's
/// age public key before calling this endpoint, so the server only ever
/// stores ciphertext. The synthetic per-user web device is used as the
/// source of the share (created on first use).
///
/// ### Arguments
/// - `state`: The state of the application
/// - `session`: The session
/// - `request`: The destination device, file name and encrypted content
///
/// ### Returns
/// - `Ok(Json<ShareFileResponse>)`: Confirmation with the share expiration date
/// - `Err(JsonAppError)`: Validation, authorization or database error as JSON
pub async fn create_web_share(
    State(state): State<AppState>,
    session: Session,
    Json(request): Json<WebShareRequest>,
) -> Result<Json<ShareFileResponse>, JsonAppError> {
    let user_id = session::get_session_user_id(&session).await?;
    if request.content.is_empty() {
        return Err(AppError::ValidationError("The file is empty".to_string()).into());
    }
    if let Some(max_size) = *state.max_file_size_bytes.read().await
        && request.content.len() > max_size as usize
    {
        return Err(AppError::ValidationError(format!(
            "Encrypted file ({}) exceeds the server limit of {}",
            crate::utils::format_bytes(request.content.len() as u64),
            crate::utils::format_bytes(max_size)
        ))
        .into());
    }
    if !is_valid_file_name(&request.file_name) {
        return Err(AppError::ValidationError(
            "File name is empty, too long, or contains invalid characters".to_string(),
        )
        .into());
    }
    let destination = match state
        .device_repository
        .get_by_device_id(&request.destination_device_id)
        .await
    {
        Ok(device) => device,
        Err(sqlx::Error::RowNotFound) => {
            return Err(
                AppError::ValidationError("Destination device does not exist".to_string()).into(),
            );
        }
        Err(e) => return Err(AppError::DatabaseError(e).into()),
    };
    if destination.user_id != user_id || destination.device_type == devices::WEB_DEVICE_TYPE {
        return Err(AppError::Forbidden.into());
    }
    if destination.public_key.is_none() {
        return Err(AppError::ValidationError(format!(
            "{} has never synced and cannot receive encrypted files yet",
            destination.name
        ))
        .into());
    }
    let discarded_key_hash = api_key::hash_api_key(&api_key::generate_api_key())
        .map_err(|e| AppError::ApiKeyError(anyhow::anyhow!("Failed to hash API key: {e}")))?;
    let web_device = state
        .device_repository
        .get_or_create_web_device(user_id, discarded_key_hash)
        .await?;
    let share = state
        .share_repository
        .create(
            user_id,
            CreateShare {
                source_device_id: web_device.device_id,
                destination_device_id: destination.device_id.clone(),
                file_name: request.file_name,
                content: request.content,
                deduplication_hash: None,
            },
            state.share_validity_days,
        )
        .await?;
    tracing::info!(
        "Created web share {} for user {} for device {}",
        share.id,
        user_id,
        destination.device_id
    );
    let notification = ShareNotification {
        share_id: share.id.clone(),
    };
    state
        .sse_manager
        .send_by_tag(&ChannelTag::DeviceId(destination.device_id), notification)
        .await;
    if let Err(e) = state.user_repository.increment_shares(user_id).await {
        tracing::error!("Failed to increment shares count: {}", e);
    }
    let date_format =
        time::format_description::parse_borrowed::<2>("[year]-[month]-[day]").unwrap();
    Ok(Json(ShareFileResponse {
        message: "Share created successfully".to_string(),
        expiration_date: share.expires_at.format(&date_format).unwrap_or_default(),
    }))
}

/// GET /settings - Returns the settings page
///
/// ### Arguments
/// - `state`: The state of the application
/// - `session`: The session
///
/// ### Returns
/// - `Ok(Html<String>)`: The settings page as formatted HTML
/// - `Err(AppError)`: Error that occurred while rendering the template
pub async fn get_settings(
    State(state): State<AppState>,
    session: Session,
) -> Result<Html<String>, AppError> {
    let user_id = session::get_session_user_id(&session).await?;
    let user = state.user_repository.get_by_id(user_id).await?;
    let Some(user) = user else {
        return Err(AppError::Unauthorized);
    };
    let csrf_token = axum_tower_sessions_csrf::get_or_create_token(&session)
        .await
        .map_err(|e| {
            AppError::InternalError(anyhow::anyhow!("Failed to generate CSRF token: {e}"))
        })?;
    let max_file_size_bytes = *state.max_file_size_bytes.read().await;
    let max_file_size_kb = max_file_size_bytes.map(|b| b / 1024);
    let template = templates::SettingsTemplate {
        user: templates::UserContext::from(&user),
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
        csrf_token,
        max_file_size_kb,
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
/// - `Ok(Html<String>)`: Success message as formatted HTML
/// - `Err(AppError)`: Error that occurred while updating the name
pub async fn update_name(
    State(state): State<AppState>,
    session: Session,
    Form(request): Form<UpdateNameRequest>,
) -> Result<Html<String>, AppError> {
    let user_id = session::get_session_user_id(&session).await?;
    let first_name = request.first_name.trim().to_string();
    let last_name = request.last_name.trim().to_string();
    if first_name.is_empty() {
        return Err(AppError::ValidationError(
            "First name cannot be empty".to_string(),
        ));
    }
    if first_name.len() > MAX_NAME_LEN {
        return Err(AppError::ValidationError(format!(
            "First name cannot exceed {MAX_NAME_LEN} characters"
        )));
    }
    if last_name.is_empty() {
        return Err(AppError::ValidationError(
            "Last name cannot be empty".to_string(),
        ));
    }
    if last_name.len() > MAX_NAME_LEN {
        return Err(AppError::ValidationError(format!(
            "Last name cannot exceed {MAX_NAME_LEN} characters"
        )));
    }
    state
        .user_repository
        .update_name(user_id, first_name.clone(), last_name.clone())
        .await?;
    tracing::info!("User {} updated their name", user_id);
    let template = templates::UpdateNameSuccessTemplate {
        first_name,
        last_name,
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
/// - `Ok(Html<String>)`: Verification code form as formatted HTML
/// - `Err(AppError)`: Error that occurred while initiating email update
pub async fn update_email_step_1(
    State(state): State<AppState>,
    session: Session,
    Form(request): Form<UpdateEmailRequest>,
) -> Result<Html<String>, AppError> {
    let user_id = session::get_session_user_id(&session).await?;
    let email = request.email.trim().to_lowercase();
    if !is_valid_email(&email) {
        let template = templates::EmailChangeStep2Template {
            new_email: email,
            error_message: "Invalid email format".to_string(),
        };
        return Ok(Html(template.render()?));
    }
    if let Ok(Some(_)) = state.user_repository.get_by_email(email.clone()).await {
        let template = templates::EmailChangeStep2Template {
            new_email: email,
            error_message: "This email is already registered".to_string(),
        };
        return Ok(Html(template.render()?));
    }
    let code = verification_code::generate_code();
    state
        .verification_code_repository
        .create(email.clone(), code.clone(), "email_change".to_string())
        .await
        .map_err(|e| {
            AppError::InternalError(anyhow::anyhow!("Failed to create verification code: {e}"))
        })?;
    if state.is_prod {
        state
            .mailer
            .send_verification_email(email.clone(), code.clone())
            .await
            .map_err(|e| AppError::InternalError(anyhow::anyhow!("Failed to send email: {e}")))?;
        tracing::info!("Verification email sent for user {}", user_id);
    } else {
        tracing::info!(
            "Not sending verification email in non-production environment\nVerification code: {}",
            code
        );
    }
    let template = templates::EmailChangeStep2Template {
        new_email: email,
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
/// - `Ok(Html<String>)`: Success message as formatted HTML
/// - `Err(AppError)`: Error that occurred while verifying the code
pub async fn update_email_step_2(
    State(state): State<AppState>,
    session: Session,
    Form(request): Form<VerifyEmailChangeRequest>,
) -> Result<Html<String>, AppError> {
    let user_id = session::get_session_user_id(&session).await?;
    let email = request.email.trim().to_lowercase();
    let result = state
        .verification_code_repository
        .verify_code(
            request.code.clone(),
            email.clone(),
            "email_change".to_string(),
        )
        .await
        .map_err(|e| AppError::InternalError(anyhow::anyhow!("Failed to verify code: {e}")))?;
    match result {
        verification_code::VerificationResult::Verified => {
            if let Ok(Some(_)) = state.user_repository.get_by_email(email.clone()).await {
                let template = templates::EmailChangeStep2Template {
                    new_email: email,
                    error_message: "This email is already registered".to_string(),
                };
                return Ok(Html(template.render()?));
            }
            state
                .user_repository
                .update_email(user_id, email.clone())
                .await?;
            tracing::info!("User {} changed their email", user_id);
            let template = templates::EmailChangeSuccessTemplate { email };
            Ok(Html(template.render()?))
        }
        verification_code::VerificationResult::Invalid { attempts_remaining } => {
            let error_msg = if attempts_remaining > 0 {
                format!("Invalid verification code. {attempts_remaining} attempts remaining.")
            } else {
                "Too many failed attempts. Please request a new code.".to_string()
            };
            let template = templates::EmailChangeStep2Template {
                new_email: email,
                error_message: error_msg,
            };
            Ok(Html(template.render()?))
        }
        verification_code::VerificationResult::TooManyAttempts => {
            let template = templates::EmailChangeStep2Template {
                new_email: email,
                error_message: "Too many failed attempts. Please request a new code.".to_string(),
            };
            Ok(Html(template.render()?))
        }
        verification_code::VerificationResult::Expired => {
            let template = templates::EmailChangeStep2Template {
                new_email: email,
                error_message: "Verification code has expired. Please request a new code."
                    .to_string(),
            };
            Ok(Html(template.render()?))
        }
        verification_code::VerificationResult::NotFound => {
            let template = templates::EmailChangeStep2Template {
                new_email: email,
                error_message: "No verification code found. Please request a new code.".to_string(),
            };
            Ok(Html(template.render()?))
        }
    }
}

/// POST /settings/sign-out-everywhere - Revokes all of the user's other web sessions
///
/// ### Arguments
/// - `state`: The state of the application
/// - `session`: The current session (preserved)
///
/// ### Returns
/// - `Ok(Html<String>)`: Success message as formatted HTML partial
/// - `Err(AppError)`: Error that occurred while revoking sessions
pub async fn sign_out_everywhere(
    State(state): State<AppState>,
    session: Session,
) -> Result<Html<String>, AppError> {
    let user_id = session::get_session_user_id(&session).await?;
    let current_id = session
        .id()
        .map(|id| id.to_string())
        .ok_or_else(|| AppError::InternalError(anyhow::anyhow!("Current session has no id")))?;
    let revoked = state
        .session_repository
        .delete_all_for_user_except(user_id, &current_id)
        .await
        .map_err(|e| AppError::InternalError(anyhow::anyhow!("Failed to revoke sessions: {e}")))?;
    tracing::info!(
        "User {} revoked {} other session(s) via sign-out-everywhere",
        user_id,
        revoked
    );
    let template = templates::SignOutEverywhereSuccessTemplate {
        revoked: revoked as i64,
    };
    Ok(Html(template.render()?))
}
