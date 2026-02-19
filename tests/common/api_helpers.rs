use axum::http::header::{AUTHORIZATION, HeaderName, HeaderValue};
use axum_test::TestServer;
use fulgur_common::api::sync::AccessTokenResponse;
use fulgurant::{
    access_token,
    api_key::{self, hash_api_key_fast},
    devices::{CreateDevice, DeviceRepository},
};
use sqlx::SqlitePool;

/// Create a device for a user directly in the database
///
/// ### Arguments
/// - `pool`: The SQLite connection pool
/// - `user_id`: The ID of the user who owns the device
/// - `name`: Human-readable device name
///
/// ### Returns
/// - `(device_id, raw_api_key)` — the device's public UUID and the unhashed API key
pub async fn create_device_for_user(
    pool: &SqlitePool,
    user_id: i32,
    name: &str,
) -> (String, String) {
    let api_key = api_key::generate_api_key();
    let hash = api_key::hash_api_key(&api_key).unwrap();
    let fast_hash = hash_api_key_fast(&api_key);
    let device_repo = DeviceRepository::new(pool.clone());
    let device = device_repo
        .create(
            user_id,
            hash,
            CreateDevice {
                name: name.to_string(),
                device_type: "Desktop".to_string(),
                api_key_lifetime: 365,
            },
        )
        .await
        .unwrap();
    // Populate fast hash for efficient lookups
    device_repo
        .update_fast_hash(device.id, fast_hash)
        .await
        .unwrap();
    (device.device_id, api_key)
}

/// Obtain a JWT access token via the /api/token endpoint
///
/// ### Arguments
/// - `server`: The test server instance
/// - `email`: The user's email address (sent in `X-User-Email` header)
/// - `api_key`: The raw (unhashed) device API key (sent in `Authorization: Bearer` header)
///
/// ### Returns
/// - `String`: The JWT access token string
pub async fn get_jwt_token(server: &TestServer, email: &str, api_key: &str) -> String {
    let response = server
        .post("/api/token")
        .add_header(
            HeaderName::from_static("x-user-email"),
            HeaderValue::from_str(email).unwrap(),
        )
        .add_header(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", api_key)).unwrap(),
        )
        .await;

    let body: AccessTokenResponse = response.json();
    body.access_token
}

/// Full API user setup: create user + device + generate JWT directly
///
/// ### Arguments
/// - `pool`: The SQLite connection pool
/// - `jwt_secret`: The JWT signing secret used to generate the access token
///
/// ### Returns
/// - `(user_id, device_id, jwt_token)` — the user's ID, device UUID, and signed JWT
pub async fn setup_api_user(pool: &SqlitePool, jwt_secret: &str) -> (i32, String, String) {
    let email = "api_user@test.com";
    let password = "TestPassword1!";
    let user_id = super::auth_helpers::create_verified_user(pool, email, password).await;
    let (device_id, _api_key) = create_device_for_user(pool, user_id, "Test Device").await;

    // Generate JWT directly (faster than going through /api/token endpoint)
    let jwt = access_token::generate_access_token(
        user_id,
        device_id.clone(),
        "Test Device".to_string(),
        jwt_secret,
        900,
    )
    .unwrap();

    (user_id, device_id, jwt)
}
