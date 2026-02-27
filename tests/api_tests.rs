mod common;

use axum::http::StatusCode;
use axum::http::header::{AUTHORIZATION, HeaderName, HeaderValue};
use common::{
    api_helpers::{create_device_for_user, get_jwt_token, setup_api_user},
    auth_helpers::create_verified_user,
    test_app::TestApp,
};
use fulgur_common::api::{
    devices::DeviceResponse,
    shares::{ShareFilePayload, ShareFileResponse, SharedFileResponse},
    sync::{AccessTokenResponse, BeginResponse, ErrorResponse, PingResponse},
};
use fulgurant::access_token;

/// Helper to create a Bearer auth header value
fn bearer(jwt: &str) -> HeaderValue {
    HeaderValue::from_str(&format!("Bearer {}", jwt)).unwrap()
}

fn x_user_email(email: &str) -> (HeaderName, HeaderValue) {
    (
        HeaderName::from_static("x-user-email"),
        HeaderValue::from_str(email).unwrap(),
    )
}

// ─────────────────────────────────────────────
// GET /api/ping
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_ping_ok() {
    let app = TestApp::new().await;
    let (_user_id, _device_id, jwt) = setup_api_user(&app.pool, &app.jwt_secret).await;

    let response = app
        .server
        .get("/api/ping")
        .add_header(AUTHORIZATION, bearer(&jwt))
        .await;

    response.assert_status_ok();
    let body: PingResponse = response.json();
    assert!(body.ok);
}

#[tokio::test]
async fn test_ping_unauthorized_no_token() {
    let app = TestApp::new().await;

    let response = app.server.get("/api/ping").expect_failure().await;

    response.assert_status_unauthorized();
    let body: ErrorResponse = response.json();
    assert!(body.error.contains("Authorization"));
}

#[tokio::test]
async fn test_ping_expired_token() {
    let app = TestApp::new().await;
    let (user_id, device_id, _jwt) = setup_api_user(&app.pool, &app.jwt_secret).await;

    // Generate a token that expired 2 minutes ago (beyond default JWT leeway)
    let expired_jwt = access_token::generate_access_token(
        user_id,
        device_id,
        "Test Device".to_string(),
        &app.jwt_secret,
        -120,
    )
    .unwrap();

    let response = app
        .server
        .get("/api/ping")
        .add_header(AUTHORIZATION, bearer(&expired_jwt))
        .expect_failure()
        .await;

    response.assert_status_unauthorized();
    let body: ErrorResponse = response.json();
    assert!(body.error.contains("expired"));
}

// ─────────────────────────────────────────────
// POST /api/token
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_token_success() {
    let app = TestApp::new().await;
    let email = "token_user@test.com";
    let user_id = create_verified_user(&app.pool, email, "TestPassword1!").await;
    let (_device_id, api_key) = create_device_for_user(&app.pool, user_id, "My Device").await;

    let jwt = get_jwt_token(&app.server, email, &api_key).await;

    // Verify the token is valid by using it
    let response = app
        .server
        .get("/api/ping")
        .add_header(AUTHORIZATION, bearer(&jwt))
        .await;

    response.assert_status_ok();
}

#[tokio::test]
async fn test_token_response_format() {
    let app = TestApp::new().await;
    let email = "token_format@test.com";
    let user_id = create_verified_user(&app.pool, email, "TestPassword1!").await;
    let (_device_id, api_key) = create_device_for_user(&app.pool, user_id, "My Device").await;

    let (header_name, header_value) = x_user_email(email);
    let response = app
        .server
        .post("/api/token")
        .add_header(header_name, header_value)
        .add_header(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", api_key)).unwrap(),
        )
        .await;

    let body: AccessTokenResponse = response.json();
    assert!(!body.access_token.is_empty());
    assert_eq!(body.token_type, "Bearer");
    assert_eq!(body.expires_in, 900);
    assert!(!body.expires_at.is_empty());
}

#[tokio::test]
async fn test_token_missing_email_header() {
    let app = TestApp::new().await;

    let response = app
        .server
        .post("/api/token")
        .add_header(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer fulgur_fake_key"),
        )
        .expect_failure()
        .await;

    response.assert_status_unauthorized();
    let body: ErrorResponse = response.json();
    assert!(body.error.contains("X-User-Email"));
}

#[tokio::test]
async fn test_token_missing_auth_header() {
    let app = TestApp::new().await;
    let (header_name, header_value) = x_user_email("user@test.com");

    let response = app
        .server
        .post("/api/token")
        .add_header(header_name, header_value)
        .expect_failure()
        .await;

    response.assert_status_unauthorized();
    let body: ErrorResponse = response.json();
    assert!(body.error.contains("Authorization"));
}

#[tokio::test]
async fn test_token_invalid_device_key() {
    let app = TestApp::new().await;
    let email = "invalid_key@test.com";
    create_verified_user(&app.pool, email, "TestPassword1!").await;

    let (header_name, header_value) = x_user_email(email);
    let response = app
        .server
        .post("/api/token")
        .add_header(header_name, header_value)
        .add_header(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer fulgur_invalid_key_that_does_not_exist"),
        )
        .expect_failure()
        .await;

    response.assert_status_unauthorized();
    let body: ErrorResponse = response.json();
    assert!(body.error.contains("Invalid credentials"));
}

#[tokio::test]
async fn test_token_nonexistent_user() {
    let app = TestApp::new().await;

    let (header_name, header_value) = x_user_email("nobody@test.com");
    let response = app
        .server
        .post("/api/token")
        .add_header(header_name, header_value)
        .add_header(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer fulgur_some_key"),
        )
        .expect_failure()
        .await;

    response.assert_status_unauthorized();
}

#[tokio::test]
async fn test_token_unverified_email() {
    let app = TestApp::new().await;
    let email = "unverified@test.com";
    let password_hash = fulgurant::auth::handlers::hash_password("TestPassword1!").unwrap();
    let user_repo = fulgurant::users::UserRepository::new(app.pool.clone());
    let user_id = user_repo
        .create(
            email.to_string(),
            "Test".to_string(),
            "User".to_string(),
            password_hash,
            false, // NOT verified
            false,
        )
        .await
        .unwrap();
    let (_device_id, api_key) = create_device_for_user(&app.pool, user_id, "Device").await;

    let (header_name, header_value) = x_user_email(email);
    let response = app
        .server
        .post("/api/token")
        .add_header(header_name, header_value)
        .add_header(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", api_key)).unwrap(),
        )
        .expect_failure()
        .await;

    response.assert_status_unauthorized();
    let body: ErrorResponse = response.json();
    assert!(body.error.contains("not verified"));
}

// ─────────────────────────────────────────────
// GET /api/devices
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_get_devices_excludes_current() {
    let app = TestApp::new().await;
    let email = "devices_user@test.com";
    let user_id = create_verified_user(&app.pool, email, "TestPassword1!").await;
    let (auth_device_id, _api_key) =
        create_device_for_user(&app.pool, user_id, "Auth Device").await;
    let (other_device_id, _) = create_device_for_user(&app.pool, user_id, "Other Device").await;

    let jwt = access_token::generate_access_token(
        user_id,
        auth_device_id.clone(),
        "Auth Device".to_string(),
        &app.jwt_secret,
        900,
    )
    .unwrap();

    let response = app
        .server
        .get("/api/devices")
        .add_header(AUTHORIZATION, bearer(&jwt))
        .await;

    let devices: Vec<DeviceResponse> = response.json();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].id, other_device_id);
    assert_eq!(devices[0].name, "Other Device");
    // Verify the auth device is excluded
    assert!(devices.iter().all(|d| d.id != auth_device_id));
}

#[tokio::test]
async fn test_get_devices_empty_when_single_device() {
    let app = TestApp::new().await;
    let (_user_id, _device_id, jwt) = setup_api_user(&app.pool, &app.jwt_secret).await;

    let response = app
        .server
        .get("/api/devices")
        .add_header(AUTHORIZATION, bearer(&jwt))
        .await;

    let devices: Vec<DeviceResponse> = response.json();
    assert!(devices.is_empty());
}

// ─────────────────────────────────────────────
// POST /api/share
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_share_file_success() {
    let app = TestApp::new().await;
    let email = "share_user@test.com";
    let user_id = create_verified_user(&app.pool, email, "TestPassword1!").await;
    let (auth_device_id, _) = create_device_for_user(&app.pool, user_id, "Source").await;
    let (dest_device_id, _) = create_device_for_user(&app.pool, user_id, "Destination").await;

    let jwt = access_token::generate_access_token(
        user_id,
        auth_device_id,
        "Source".to_string(),
        &app.jwt_secret,
        900,
    )
    .unwrap();

    let payload = ShareFilePayload {
        content: "encrypted file content".to_string(),
        file_name: "test.txt".to_string(),
        device_id: dest_device_id,
        deduplication_hash: None,
    };

    let response = app
        .server
        .post("/api/share")
        .add_header(AUTHORIZATION, bearer(&jwt))
        .json(&payload)
        .await;

    response.assert_status_ok();
    let body: ShareFileResponse = response.json();
    assert!(body.message.contains("successfully"));
    assert!(!body.expiration_date.is_empty());
}

#[tokio::test]
async fn test_share_file_exceeds_max_size() {
    let app = TestApp::new().await;
    let email = "share_big@test.com";
    let user_id = create_verified_user(&app.pool, email, "TestPassword1!").await;
    let (auth_device_id, _) = create_device_for_user(&app.pool, user_id, "Source").await;
    let (dest_device_id, _) = create_device_for_user(&app.pool, user_id, "Destination").await;

    let jwt = access_token::generate_access_token(
        user_id,
        auth_device_id,
        "Source".to_string(),
        &app.jwt_secret,
        900,
    )
    .unwrap();

    // Create content larger than 1 MB
    let large_content = "x".repeat(1_048_577);
    let payload = ShareFilePayload {
        content: large_content,
        file_name: "big.txt".to_string(),
        device_id: dest_device_id,
        deduplication_hash: None,
    };

    let response = app
        .server
        .post("/api/share")
        .add_header(AUTHORIZATION, bearer(&jwt))
        .json(&payload)
        .expect_failure()
        .await;

    response.assert_status_bad_request();
    let body: ErrorResponse = response.json();
    assert!(body.error.contains("exceeds maximum"));
}

#[tokio::test]
async fn test_share_file_empty_file_name() {
    let app = TestApp::new().await;
    let (_user_id, _device_id, jwt) = setup_api_user(&app.pool, &app.jwt_secret).await;

    let payload = ShareFilePayload {
        content: "some content".to_string(),
        file_name: "".to_string(),
        device_id: "some-device-id".to_string(),
        deduplication_hash: None,
    };

    let response = app
        .server
        .post("/api/share")
        .add_header(AUTHORIZATION, bearer(&jwt))
        .json(&payload)
        .expect_failure()
        .await;

    response.assert_status_bad_request();
    let body: ErrorResponse = response.json();
    assert!(body.error.contains("File name"));
}

#[tokio::test]
async fn test_share_file_empty_device_id() {
    let app = TestApp::new().await;
    let (_user_id, _device_id, jwt) = setup_api_user(&app.pool, &app.jwt_secret).await;

    let payload = ShareFilePayload {
        content: "some content".to_string(),
        file_name: "test.txt".to_string(),
        device_id: "".to_string(),
        deduplication_hash: None,
    };

    let response = app
        .server
        .post("/api/share")
        .add_header(AUTHORIZATION, bearer(&jwt))
        .json(&payload)
        .expect_failure()
        .await;

    response.assert_status_bad_request();
    let body: ErrorResponse = response.json();
    assert!(body.error.contains("destination device"));
}

#[tokio::test]
async fn test_share_file_deduplication() {
    let app = TestApp::new().await;
    let email = "dedup_user@test.com";
    let user_id = create_verified_user(&app.pool, email, "TestPassword1!").await;
    let (auth_device_id, _) = create_device_for_user(&app.pool, user_id, "Source").await;
    let (dest_device_id, _) = create_device_for_user(&app.pool, user_id, "Dest").await;

    let jwt = access_token::generate_access_token(
        user_id,
        auth_device_id,
        "Source".to_string(),
        &app.jwt_secret,
        900,
    )
    .unwrap();

    let dedup_hash = "unique_hash_123".to_string();

    // First share
    let payload = ShareFilePayload {
        content: "version 1".to_string(),
        file_name: "test.txt".to_string(),
        device_id: dest_device_id.clone(),
        deduplication_hash: Some(dedup_hash.clone()),
    };
    app.server
        .post("/api/share")
        .add_header(AUTHORIZATION, bearer(&jwt))
        .json(&payload)
        .await;

    // Second share with same dedup hash (should replace)
    let payload2 = ShareFilePayload {
        content: "version 2".to_string(),
        file_name: "test.txt".to_string(),
        device_id: dest_device_id.clone(),
        deduplication_hash: Some(dedup_hash),
    };
    app.server
        .post("/api/share")
        .add_header(AUTHORIZATION, bearer(&jwt))
        .json(&payload2)
        .await;

    // Get shares - should only have the latest version
    let dest_jwt = access_token::generate_access_token(
        user_id,
        dest_device_id,
        "Dest".to_string(),
        &app.jwt_secret,
        900,
    )
    .unwrap();

    let response = app
        .server
        .get("/api/shares")
        .add_header(AUTHORIZATION, bearer(&dest_jwt))
        .await;

    let shares: Vec<SharedFileResponse> = response.json();
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].content, "version 2");
}

#[tokio::test]
async fn test_share_file_rejects_nonexistent_destination_device() {
    let app = TestApp::new().await;
    let email = "share_missing_dest@test.com";
    let user_id = create_verified_user(&app.pool, email, "TestPassword1!").await;
    let (auth_device_id, _) = create_device_for_user(&app.pool, user_id, "Source").await;

    let jwt = access_token::generate_access_token(
        user_id,
        auth_device_id,
        "Source".to_string(),
        &app.jwt_secret,
        900,
    )
    .unwrap();

    let payload = ShareFilePayload {
        content: "encrypted file content".to_string(),
        file_name: "test.txt".to_string(),
        device_id: "non-existent-device-id".to_string(),
        deduplication_hash: None,
    };

    let response = app
        .server
        .post("/api/share")
        .add_header(AUTHORIZATION, bearer(&jwt))
        .json(&payload)
        .expect_failure()
        .await;

    response.assert_status_bad_request();
    let body: ErrorResponse = response.json();
    assert!(body.error.contains("does not exist"));
}

#[tokio::test]
async fn test_share_file_rejects_other_users_destination_device() {
    let app = TestApp::new().await;
    let owner_email = "share_owner@test.com";
    let other_email = "share_other@test.com";
    let owner_user_id = create_verified_user(&app.pool, owner_email, "TestPassword1!").await;
    let other_user_id = create_verified_user(&app.pool, other_email, "TestPassword1!").await;
    let (auth_device_id, _) = create_device_for_user(&app.pool, owner_user_id, "Source").await;
    let (other_device_id, _) =
        create_device_for_user(&app.pool, other_user_id, "Other Device").await;

    let jwt = access_token::generate_access_token(
        owner_user_id,
        auth_device_id,
        "Source".to_string(),
        &app.jwt_secret,
        900,
    )
    .unwrap();

    let payload = ShareFilePayload {
        content: "encrypted file content".to_string(),
        file_name: "test.txt".to_string(),
        device_id: other_device_id,
        deduplication_hash: None,
    };

    let response = app
        .server
        .post("/api/share")
        .add_header(AUTHORIZATION, bearer(&jwt))
        .json(&payload)
        .expect_failure()
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
    let body: ErrorResponse = response.json();
    assert!(body.error.contains("does not belong"));
}

#[tokio::test]
async fn test_share_file_rejects_same_source_and_destination_device() {
    let app = TestApp::new().await;
    let email = "share_same_device@test.com";
    let user_id = create_verified_user(&app.pool, email, "TestPassword1!").await;
    let (auth_device_id, _) = create_device_for_user(&app.pool, user_id, "Source").await;

    let jwt = access_token::generate_access_token(
        user_id,
        auth_device_id.clone(),
        "Source".to_string(),
        &app.jwt_secret,
        900,
    )
    .unwrap();

    let payload = ShareFilePayload {
        content: "encrypted file content".to_string(),
        file_name: "test.txt".to_string(),
        device_id: auth_device_id,
        deduplication_hash: None,
    };

    let response = app
        .server
        .post("/api/share")
        .add_header(AUTHORIZATION, bearer(&jwt))
        .json(&payload)
        .expect_failure()
        .await;

    response.assert_status_bad_request();
    let body: ErrorResponse = response.json();
    assert!(body.error.contains("must be different"));
}

// ─────────────────────────────────────────────
// GET /api/shares
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_get_shares_returns_and_deletes() {
    let app = TestApp::new().await;
    let email = "get_shares@test.com";
    let user_id = create_verified_user(&app.pool, email, "TestPassword1!").await;
    let (source_id, _) = create_device_for_user(&app.pool, user_id, "Source").await;
    let (dest_id, _) = create_device_for_user(&app.pool, user_id, "Dest").await;

    // Create a share via the source device
    let source_jwt = access_token::generate_access_token(
        user_id,
        source_id,
        "Source".to_string(),
        &app.jwt_secret,
        900,
    )
    .unwrap();

    let payload = ShareFilePayload {
        content: "shared content".to_string(),
        file_name: "shared.txt".to_string(),
        device_id: dest_id.clone(),
        deduplication_hash: None,
    };
    app.server
        .post("/api/share")
        .add_header(AUTHORIZATION, bearer(&source_jwt))
        .json(&payload)
        .await;

    // Fetch shares as destination device
    let dest_jwt = access_token::generate_access_token(
        user_id,
        dest_id.clone(),
        "Dest".to_string(),
        &app.jwt_secret,
        900,
    )
    .unwrap();

    let response = app
        .server
        .get("/api/shares")
        .add_header(AUTHORIZATION, bearer(&dest_jwt))
        .await;

    let shares: Vec<SharedFileResponse> = response.json();
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].file_name, "shared.txt");
    assert_eq!(shares[0].content, "shared content");

    // Fetch again - should be empty (shares are deleted after retrieval)
    let response = app
        .server
        .get("/api/shares")
        .add_header(AUTHORIZATION, bearer(&dest_jwt))
        .await;

    let shares: Vec<SharedFileResponse> = response.json();
    assert!(shares.is_empty());
}

#[tokio::test]
async fn test_get_shares_empty() {
    let app = TestApp::new().await;
    let (_user_id, _device_id, jwt) = setup_api_user(&app.pool, &app.jwt_secret).await;

    let response = app
        .server
        .get("/api/shares")
        .add_header(AUTHORIZATION, bearer(&jwt))
        .await;

    let shares: Vec<SharedFileResponse> = response.json();
    assert!(shares.is_empty());
}

// ─────────────────────────────────────────────
// POST /api/begin
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_begin_returns_shares_and_updates_key() {
    let app = TestApp::new().await;
    let email = "begin_user@test.com";
    let user_id = create_verified_user(&app.pool, email, "TestPassword1!").await;
    let (source_id, _) = create_device_for_user(&app.pool, user_id, "Source").await;
    let (dest_id, _) = create_device_for_user(&app.pool, user_id, "Dest").await;

    // Create a share first
    let source_jwt = access_token::generate_access_token(
        user_id,
        source_id,
        "Source".to_string(),
        &app.jwt_secret,
        900,
    )
    .unwrap();

    let payload = ShareFilePayload {
        content: "begin test content".to_string(),
        file_name: "begin.txt".to_string(),
        device_id: dest_id.clone(),
        deduplication_hash: None,
    };
    app.server
        .post("/api/share")
        .add_header(AUTHORIZATION, bearer(&source_jwt))
        .json(&payload)
        .await;

    // Call begin as dest device with a public key
    let dest_jwt = access_token::generate_access_token(
        user_id,
        dest_id.clone(),
        "Dest".to_string(),
        &app.jwt_secret,
        900,
    )
    .unwrap();

    let begin_payload = serde_json::json!({
        "public_key": "base64_encoded_aes_key_for_testing"
    });

    let response = app
        .server
        .post("/api/begin")
        .add_header(AUTHORIZATION, bearer(&dest_jwt))
        .json(&begin_payload)
        .await;

    let body: BeginResponse = response.json();
    assert_eq!(body.device_name, "Dest");
    assert_eq!(body.shares.len(), 1);
    assert_eq!(body.shares[0].file_name, "begin.txt");

    // Verify encryption key was updated
    let device_repo = fulgurant::devices::DeviceRepository::new(app.pool.clone());
    let device = device_repo.get_by_device_id(&dest_id).await.unwrap();
    assert_eq!(
        device.encryption_key.as_deref(),
        Some("base64_encoded_aes_key_for_testing")
    );
}

#[tokio::test]
async fn test_begin_updates_last_activity() {
    let app = TestApp::new().await;
    let (_user_id, _device_id, jwt) = setup_api_user(&app.pool, &app.jwt_secret).await;

    let begin_payload = serde_json::json!({ "public_key": "" });

    app.server
        .post("/api/begin")
        .add_header(AUTHORIZATION, bearer(&jwt))
        .json(&begin_payload)
        .await;

    // Verify last_activity was updated (it should be very recent)
    let user_repo = fulgurant::users::UserRepository::new(app.pool.clone());
    let user = user_repo
        .get_by_email("api_user@test.com".to_string())
        .await
        .unwrap()
        .unwrap();
    let now = time::OffsetDateTime::now_utc();
    let diff = now - user.last_activity;
    assert!(
        diff.whole_seconds() < 5,
        "last_activity should be updated to within 5 seconds"
    );
}

#[tokio::test]
async fn test_begin_empty_public_key_skips_update() {
    let app = TestApp::new().await;
    let email = "begin_nokey@test.com";
    let user_id = create_verified_user(&app.pool, email, "TestPassword1!").await;
    let (device_id, _) = create_device_for_user(&app.pool, user_id, "Device").await;

    let jwt = access_token::generate_access_token(
        user_id,
        device_id.clone(),
        "Device".to_string(),
        &app.jwt_secret,
        900,
    )
    .unwrap();

    // Call begin with empty public key
    let begin_payload = serde_json::json!({ "public_key": "" });

    app.server
        .post("/api/begin")
        .add_header(AUTHORIZATION, bearer(&jwt))
        .json(&begin_payload)
        .await;

    // Verify encryption key was NOT set (still None)
    let device_repo = fulgurant::devices::DeviceRepository::new(app.pool.clone());
    let device = device_repo.get_by_device_id(&device_id).await.unwrap();
    assert!(device.encryption_key.is_none());
}
