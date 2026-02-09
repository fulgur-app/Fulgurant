// src/api/handlers.rs
use crate::{
    api::sse::{ChannelTag, ShareNotification},
    devices::Device,
    handlers::AppState,
    shares::{CreateShare, MAX_FILE_SIZE, Share},
};
use axum::{Extension, Json, extract::State, http::StatusCode};
use fulgur_common::api::{
    devices::DeviceResponse,
    shares::{ShareFilePayload, ShareFileResponse, SharedFileResponse},
    sync::{
        AccessTokenResponse, BeginResponse, EncryptionKeyResponse, ErrorResponse,
        InitialSynchronizationPayload, PingResponse,
    },
};
use time::{Duration, OffsetDateTime};

use super::middleware::AuthenticatedUser;

/// GET /api/ping - Simple health check endpoint
///
/// ### Returns
/// - `Json(PingResponse)`: The response containing the status of the server
pub async fn ping() -> Json<PingResponse> {
    Json(PingResponse { ok: true })
}

impl From<Device> for DeviceResponse {
    /// Convert a Device to a DeviceResponse
    ///
    /// ### Arguments
    /// - `device`: The Device to convert
    ///
    /// ### Returns
    /// - `DeviceResponse`: The DeviceResponse
    fn from(device: Device) -> Self {
        let created_at = device.get_created_at_formatted();
        let expires_at = device.get_expires_at_formatted();
        Self {
            id: device.device_id,
            name: device.name,
            device_type: device.device_type,
            public_key: device.encryption_key,
            created_at,
            expires_at,
        }
    }
}

/// GET /api/devices - Returns all devices for the authenticated user, excluding the one used for authentication
///
/// ### Arguments
/// - `state`: The state of the application
/// - `auth_user`: The authenticated user
///
/// ### Returns
/// - `Ok(Json(Vec<DeviceResponse>))`: The response containing the devices
/// - `Err((StatusCode, Json(ErrorResponse)))`: The error response if the devices retrieval fails
pub async fn get_devices(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
) -> Result<Json<Vec<DeviceResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let devices: Vec<Device> = match state
        .device_repository
        .get_all_for_user(auth_user.user.id)
        .await
    {
        Ok(devices) => devices
            .into_iter()
            .filter(|device| device.device_id != auth_user.device_id)
            .collect(),
        Err(e) => {
            tracing::error!("Database error getting devices: {:?}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Internal server error".to_string(),
                }),
            ));
        }
    };
    let device_responses: Vec<DeviceResponse> =
        devices.into_iter().map(DeviceResponse::from).collect();

    Ok(Json(device_responses))
}

/// POST /api/share - Create a new share for a destination device
///
/// ### Arguments
/// - `state`: The state of the application
/// - `auth_user`: The authenticated user
/// - `payload`: The payload containing the file content, file name, and destination device
///
/// ### Returns
/// - `Ok(Json(ShareFileResponse))`: The response containing the share
/// - `Err((StatusCode, Json(ErrorResponse)))`: The error response if the share creation fails or if the file size exceeds the maximum allowed size
pub async fn share_file(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    Json(payload): Json<ShareFilePayload>,
) -> Result<Json<ShareFileResponse>, (StatusCode, Json<ErrorResponse>)> {
    let file_size = payload.content.len();
    if file_size > MAX_FILE_SIZE {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "File size ({} bytes) exceeds maximum of {} bytes (1 MB)",
                    file_size, MAX_FILE_SIZE
                ),
            }),
        ));
    }
    if payload.file_name.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "File name cannot be empty".to_string(),
            }),
        ));
    }
    if payload.device_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "A destination device is required".to_string(),
            }),
        ));
    }
    let expiration_date = OffsetDateTime::now_utc() + Duration::days(state.share_validity_days);
    let create_share = CreateShare {
        source_device_id: auth_user.device_id.clone(),
        destination_device_id: payload.device_id.clone(),
        file_name: payload.file_name.clone(),
        content: payload.content.clone(),
        deduplication_hash: payload.deduplication_hash.clone(),
    };
    let share = match state
        .share_repository
        .create(auth_user.user.id, create_share)
        .await
    {
        Ok(share) => {
            tracing::info!(
                "Created new share {} for user {} for device {}",
                share.id,
                auth_user.user.email,
                payload.device_id
            );
            share
        }
        Err(e) => {
            tracing::error!("Error creating share: {:?}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to create share".to_string(),
                }),
            ));
        }
    };
    let notification = ShareNotification {
        share_id: share.id.clone(),
        source_device_id: share.source_device_id.clone(),
        destination_device_id: share.destination_device_id.clone(),
        file_name: share.file_name.clone(),
        file_size: share.file_size as i64,
        file_hash: share.file_hash.clone(),
        content: share.content.clone(),
        created_at: share
            .created_at
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
        expires_at: share
            .expires_at
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
    };
    let tag = ChannelTag::DeviceId(share.destination_device_id.clone());
    state.sse_manager.send_by_tag(&tag, notification).await;
    tracing::info!(
        share_id = ?share.id,
        device_id = ?share.destination_device_id,
        "Share notification sent via SSE"
    );
    if let Err(e) = state
        .user_repository
        .increment_shares(auth_user.user.id)
        .await
    {
        tracing::error!("Failed to increment shares count: {}", e);
    }
    let date_format = time::format_description::parse("[year]-[month]-[day]").unwrap();
    Ok(Json(ShareFileResponse {
        message: "Share created successfully".to_string(),
        expiration_date: expiration_date.format(&date_format).unwrap_or_default(),
    }))
}

/// GET /api/encryption-key - Returns the user's encryption key for end-to-end encryption.
///
/// ### Description
/// The encryption key is a 256-bit (32-byte) AES key encoded as base64.
/// All devices for a user share the same encryption key to enable decryption of shared files.
///
/// ### Arguments
/// - `state`: The state of the application
/// - `auth_user`: The authenticated user
///
/// ### Returns
/// - `Ok(Json(EncryptionKeyResponse))`: The response containing the encryption key
/// - `Err((StatusCode, Json(ErrorResponse)))`: The error response if the encryption key retrieval fails
pub async fn get_encryption_key(
    State(_state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
) -> Result<Json<EncryptionKeyResponse>, (StatusCode, Json<ErrorResponse>)> {
    Ok(Json(EncryptionKeyResponse {
        encryption_key: auth_user.user.encryption_key.clone(),
    }))
}

impl From<Share> for SharedFileResponse {
    /// Converts a Share to a SharedFileResponse
    ///
    /// ### Arguments
    /// `share`: The Share to convert
    ///
    /// ### Returns
    /// - `SharedFileResponse`: The SharedFileResponse
    fn from(share: Share) -> Self {
        Self {
            id: share.id,
            source_device_id: share.source_device_id,
            file_name: share.file_name,
            file_size: share.file_size,
            content: share.content,
            created_at: share
                .created_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            expires_at: share
                .expires_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        }
    }
}

/// GET /api/shares - Returns all pending shares for the authenticated device
///
/// ### Arguments
/// - `state`: The state of the application
/// - `auth_user`: The authenticated user
///
/// ### Returns
/// - `Ok(Json(Vec<SharedFileResponse>))`: The response containing the shares
/// - `Err((StatusCode, Json(ErrorResponse)))`: The error response if the shares retrieval fails
pub async fn get_shares(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
) -> Result<Json<Vec<SharedFileResponse>>, (StatusCode, Json<ErrorResponse>)> {
    match state
        .share_repository
        .get_and_delete_shares_for_device(&auth_user.device_id)
        .await
    {
        Ok(shares) => {
            tracing::info!(
                "Retrieved {} shares for device {} (user: {})",
                shares.len(),
                auth_user.device_id,
                auth_user.user.email
            );
            let share_infos: Vec<SharedFileResponse> =
                shares.into_iter().map(SharedFileResponse::from).collect();
            Ok(Json(share_infos))
        }
        Err(e) => {
            tracing::error!("Error getting shares for device: {:?}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to retrieve shares".to_string(),
                }),
            ))
        }
    }
}

/// POST /api/begin - Initial synchronization endpoint that updates device encryption key and returns pending shares
///
/// ### Description
/// This endpoint is called during app startup to:
/// 1. Update the device's encryption key (if provided)
/// 2. Update user's last activity timestamp
/// 3. Return pending shares for the device
///
/// ### Arguments
/// - `state`: The state of the application
/// - `auth_user`: The authenticated user
/// - `payload`: The initial synchronization payload containing the public key (encryption key)
///
/// ### Returns
/// - `Ok(Json(BeginResponse))`: The response containing encryption key and shares
/// - `Err((StatusCode, Json(ErrorResponse)))`: The error response if the operation fails
pub async fn begin(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    Json(payload): Json<InitialSynchronizationPayload>,
) -> Result<Json<BeginResponse>, (StatusCode, Json<ErrorResponse>)> {
    if !payload.public_key.is_empty() {
        if let Err(e) = state
            .device_repository
            .update_encryption_key(&auth_user.device_id, payload.public_key.clone())
            .await
        {
            tracing::error!(
                "Failed to update encryption key for device {}: {}",
                auth_user.device_id,
                e
            );
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to update encryption key".to_string(),
                }),
            ));
        }
        tracing::debug!(
            "Updated encryption key for device {} (user: {})",
            auth_user.device_id,
            auth_user.user.email
        );
    }
    if let Err(e) = state
        .user_repository
        .update_last_activity(auth_user.user.id)
        .await
    {
        tracing::error!("Failed to update last_activity: {}", e);
    }
    let shares: Vec<SharedFileResponse> = match state
        .share_repository
        .get_and_delete_shares_for_device(&auth_user.device_id)
        .await
    {
        Ok(shares) => shares.into_iter().map(SharedFileResponse::from).collect(),
        Err(e) => {
            tracing::error!("Error getting shares for device: {:?}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to retrieve shares".to_string(),
                }),
            ));
        }
    };
    tracing::info!(
        "Begin session for device {}: {} pending shares",
        auth_user.device_id,
        shares.len()
    );

    Ok(Json(BeginResponse {
        device_name: auth_user.device_name,
        shares,
    }))
}

/// POST /api/token - Obtain a JWT access token using device key
///
/// ### Arguments
/// - `state`: The state of the application
/// - `headers`: Request headers containing email (`X-User-Email`) and device key (`Authorization`)
///
/// ### Returns
/// - `Ok(Json(AccessTokenResponse))`: The JWT access token with expiry information
/// - `Err((StatusCode, Json(ErrorResponse)))`: Authentication error or server error
pub async fn obtain_access_token(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<AccessTokenResponse>, (StatusCode, Json<ErrorResponse>)> {
    let email = headers
        .get("X-User-Email")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Missing X-User-Email header".to_string(),
                }),
            )
        })?
        .trim()
        .to_lowercase();
    let auth_header = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Missing Authorization header".to_string(),
                }),
            )
        })?;
    let device_key = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid Authorization header format. Expected: Bearer <device_key>"
                        .to_string(),
                }),
            )
        })?
        .trim();
    let user = match state.user_repository.get_by_email(email.clone()).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            tracing::warn!("Token request for non-existent user: {}", email);
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid credentials".to_string(),
                }),
            ));
        }
        Err(e) => {
            tracing::error!("Database error getting user for token: {:?}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Internal server error".to_string(),
                }),
            ));
        }
    };
    if !user.email_verified {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Email not verified".to_string(),
            }),
        ));
    }
    let devices = match state.device_repository.get_all_for_user(user.id).await {
        Ok(devices) => devices,
        Err(e) => {
            tracing::error!("Database error getting devices for token: {:?}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Internal server error".to_string(),
                }),
            ));
        }
    };
    let mut authenticated_device = None;
    for device in &devices {
        match crate::api_key::verify_api_key(device_key, &device.device_key) {
            Ok(true) => {
                authenticated_device = Some((device.device_id.clone(), device.name.clone()));
                tracing::debug!(
                    "Access token requested for user {} with device {}",
                    user.id,
                    device.device_id
                );
                break;
            }
            Ok(false) => continue,
            Err(e) => {
                tracing::error!("Error verifying device key for token: {:?}", e);
                continue;
            }
        }
    }
    let (device_id, device_name) = authenticated_device.ok_or_else(|| {
        tracing::warn!("Invalid device key for user: {}", email);
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid credentials".to_string(),
            }),
        )
    })?;
    let access_token = match crate::access_token::generate_access_token(
        user.id,
        device_id.clone(),
        device_name.clone(),
        &state.jwt_secret,
        state.jwt_expiry_seconds,
    ) {
        Ok(token) => token,
        Err(e) => {
            tracing::error!("Failed to generate access token: {:?}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to generate access token".to_string(),
                }),
            ));
        }
    };
    let expires_at = OffsetDateTime::now_utc() + Duration::seconds(state.jwt_expiry_seconds);
    let expires_at_str = expires_at
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    tracing::info!(
        "Access token issued for user {} (device: {}, expires: {})",
        user.id,
        device_id,
        expires_at_str
    );
    Ok(Json(AccessTokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: state.jwt_expiry_seconds,
        expires_at: expires_at_str,
    }))
}
