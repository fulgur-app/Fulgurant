// src/api/handlers.rs
use crate::{
    devices::Device,
    handlers::AppState,
    shares::{CreateShare, Share, MAX_FILE_SIZE},
};
use axum::{extract::State, http::StatusCode, Extension, Json};
use chrono::{Duration, Utc};
use fulgur_common::api::{
    devices::DeviceResponse,
    shares::{ShareFilePayload, ShareFileResponse, SharedFileResponse},
    BeginResponse, EncryptionKeyResponse, ErrorResponse, PingResponse,
};

use super::middleware::AuthenticatedUser;

/// GET /api/ping - Simple health check endpoint
///
/// ### Returns
/// - `Json(PingResponse)`: The response containing the status of the server
/// @return Json<PingResponse>: The response containing the status of the server
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
            created_at,
            expires_at,
        }
    }
}

/// GET /api/devices - Returns all devices for the authenticated user
/// Authentication is handled by the `require_api_auth` middleware
///
/// ### Arguments
/// - `state`: The state of the application
/// - `auth_user`: The authenticated user
///
/// ### Returns
/// - `Ok(Json(Vec<DeviceResponse>))`: The response containing the devices
/// - `Err((StatusCode, Json(ErrorResponse)))`: The error response if the devices retrieval fails
pub async fn get_all_devices(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
) -> Result<Json<Vec<DeviceResponse>>, (StatusCode, Json<ErrorResponse>)> {
    // Get all devices for the authenticated user
    let devices = match state
        .device_repository
        .get_all_for_user(auth_user.user.id)
        .await
    {
        Ok(devices) => devices,
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

    // Convert to response format
    let device_responses: Vec<DeviceResponse> =
        devices.into_iter().map(DeviceResponse::from).collect();

    Ok(Json(device_responses))
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
    // Get all devices for the authenticated user, excluding the one used for authentication
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

    // Convert to response format
    let device_responses: Vec<DeviceResponse> =
        devices.into_iter().map(DeviceResponse::from).collect();

    Ok(Json(device_responses))
}

/// POST /api/share - Create a new share, one per destination device
///
/// ### Arguments
/// - `state`: The state of the application
/// - `auth_user`: The authenticated user
/// - `payload`: The payload containing the file content, file name, and destination devices
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
    if payload.device_ids.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "A destination device is required".to_string(),
            }),
        ));
    }
    let mut is_error = false;
    let expiration_date = Utc::now() + Duration::days(crate::shares::SHARE_VALIDITY_DAYS);
    for device_id in &payload.device_ids {
        let create_share = CreateShare {
            source_device_id: auth_user.device_id.clone(),
            destination_device_id: device_id.clone(),
            file_name: payload.file_name.clone(),
            content: payload.content.clone(),
        };
        match state
            .share_repository
            .create(auth_user.user.id, create_share)
            .await
        {
            Ok(share) => {
                tracing::info!(
                    "Created new share {} for user {} for device {}",
                    share.id,
                    auth_user.user.email,
                    device_id
                );
            }
            Err(e) => {
                tracing::error!("Error creating share: {:?}", e);
                is_error = true;
            }
        }
    }

    if is_error {
        Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to create share".to_string(),
            }),
        ))
    } else {
        Ok(Json(ShareFileResponse {
            message: "Share created successfully".to_string(),
            expiration_date: expiration_date.format("%Y-%m-%d").to_string(),
        }))
    }
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
    /// @param share: The Share to convert
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
            created_at: share.created_at.to_rfc3339(),
            expires_at: share.expires_at.to_rfc3339(),
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

/// GET /api/begin - Returns encryption key and pending shares for the authenticated device
///
/// ### Description
/// This endpoint combines the functionality of /api/encryption-key and /api/shares
/// to reduce round trips during app startup.
/// Authentication is handled by the `require_api_auth` middleware
///
/// ### Arguments
/// - `state`: The state of the application
/// - `auth_user`: The authenticated user
///
/// ### Returns
/// - `Ok(Json(BeginResponse))`: The response containing encryption key and shares
/// - `Err((StatusCode, Json(ErrorResponse)))`: The error response if the shares retrieval fails
pub async fn begin(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
) -> Result<Json<BeginResponse>, (StatusCode, Json<ErrorResponse>)> {
    let encryption_key = auth_user.user.encryption_key.clone();
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
        "Begin session for device {} (user: {}): encryption key provided, {} pending shares",
        auth_user.device_id,
        auth_user.user.email,
        shares.len()
    );

    Ok(Json(BeginResponse {
        encryption_key,
        device_name: auth_user.device_name,
        shares,
    }))
}
