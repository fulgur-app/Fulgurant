mod common;

use axum::http::StatusCode;
use axum::http::header::{AUTHORIZATION, HeaderName, HeaderValue};
use common::{
    api_helpers::{create_device_for_user, get_jwt_token, setup_api_user},
    auth_helpers::create_verified_user,
    test_app::TestApp,
};
use fulgur_common::api::{
    devices::DevicesResponse,
    shares::{ShareFilePayload, ShareFileResponse, SharedFileResponse},
    sync::{AccessTokenResponse, BeginResponse, BeginV2Response, ErrorResponse, PingResponse},
};
use fulgurant::access_token;
use fulgurant::api::sse::MAX_SSE_CONNECTIONS_PER_DEVICE;
use std::time::Duration as StdDuration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Helper to create a Bearer auth header value
fn bearer(jwt: &str) -> HeaderValue {
    HeaderValue::from_str(&format!("Bearer {jwt}")).unwrap()
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

#[tokio::test]
async fn test_ping_malformed_token() {
    let app = TestApp::new().await;

    let response = app
        .server
        .get("/api/ping")
        .add_header(AUTHORIZATION, bearer("not-a-jwt"))
        .expect_failure()
        .await;

    response.assert_status_unauthorized();
    let body: ErrorResponse = response.json();
    assert!(body.error.contains("Invalid access token"));
}

#[tokio::test]
async fn test_ping_wrong_secret_token() {
    let app = TestApp::new().await;
    let (user_id, device_id, _jwt) = setup_api_user(&app.pool, &app.jwt_secret).await;

    // Generate a structurally valid, unexpired token signed with a different secret.
    let foreign_jwt = access_token::generate_access_token(
        user_id,
        device_id,
        "Test Device".to_string(),
        "a-different-secret-that-is-at-least-32-bytes-long",
        900,
    )
    .unwrap();

    let response = app
        .server
        .get("/api/ping")
        .add_header(AUTHORIZATION, bearer(&foreign_jwt))
        .expect_failure()
        .await;

    response.assert_status_unauthorized();
    let body: ErrorResponse = response.json();
    assert!(body.error.contains("Invalid access token"));
}

#[tokio::test]
async fn test_ping_deleted_device_rejected() {
    let app = TestApp::new().await;
    let (_user_id, device_id, jwt) = setup_api_user(&app.pool, &app.jwt_secret).await;

    let device_repo = fulgurant::devices::DeviceRepository::new(app.db_pool.clone());
    let device = device_repo.get_by_device_id(&device_id).await.unwrap();
    device_repo.delete(device.id).await.unwrap();

    let response = app
        .server
        .get("/api/ping")
        .add_header(AUTHORIZATION, bearer(&jwt))
        .expect_failure()
        .await;

    response.assert_status_unauthorized();
    let body: ErrorResponse = response.json();
    assert!(body.error.contains("Device not found"));
}

#[tokio::test]
async fn test_ping_expired_device_rejected() {
    let app = TestApp::new().await;
    let (_user_id, device_id, jwt) = setup_api_user(&app.pool, &app.jwt_secret).await;

    sqlx::query("UPDATE devices SET expires_at = unixepoch('now') - 60 WHERE device_id = ?")
        .bind(&device_id)
        .execute(&app.pool)
        .await
        .unwrap();

    let response = app
        .server
        .get("/api/ping")
        .add_header(AUTHORIZATION, bearer(&jwt))
        .expect_failure()
        .await;

    response.assert_status_unauthorized();
    let body: ErrorResponse = response.json();
    assert!(body.error.contains("Device has expired"));
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
            HeaderValue::from_str(&format!("Bearer {api_key}")).unwrap(),
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
    let user_repo = fulgurant::users::UserRepository::new(app.db_pool.clone());
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
            HeaderValue::from_str(&format!("Bearer {api_key}")).unwrap(),
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

    let body: DevicesResponse = response.json();
    let devices = body.devices;
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].id, other_device_id);
    assert_eq!(devices[0].name, "Other Device");
    // Verify the auth device is excluded
    assert!(devices.iter().all(|d| d.id != auth_device_id));
    assert_eq!(body.max_file_size_bytes, Some(1_048_576));
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

    let body: DevicesResponse = response.json();
    assert!(body.devices.is_empty());
    assert_eq!(body.max_file_size_bytes, Some(1_048_576));
}

#[tokio::test]
async fn test_get_devices_returns_deterministic_newest_first_order() {
    let app = TestApp::new().await;
    let email = "devices_order@test.com";
    let user_id = create_verified_user(&app.pool, email, "TestPassword1!").await;

    let (auth_device_id, _) = create_device_for_user(&app.pool, user_id, "Auth Device").await;
    let (_older_device_id, _) = create_device_for_user(&app.pool, user_id, "Older Device").await;
    let (_newer_device_id, _) = create_device_for_user(&app.pool, user_id, "Newer Device").await;

    let jwt = access_token::generate_access_token(
        user_id,
        auth_device_id,
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

    let devices = response.json::<DevicesResponse>().devices;
    assert_eq!(devices.len(), 2);
    assert_eq!(devices[0].name, "Newer Device");
    assert_eq!(devices[1].name, "Older Device");
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

    response.assert_status(StatusCode::PAYLOAD_TOO_LARGE);
    let body: ErrorResponse = response.json();
    assert!(body.error.contains("exceeds maximum"));
}

#[tokio::test]
async fn test_share_file_empty_file_name() {
    let app = TestApp::new().await;
    let (_user_id, _device_id, jwt) = setup_api_user(&app.pool, &app.jwt_secret).await;

    let payload = ShareFilePayload {
        content: "some content".to_string(),
        file_name: String::new(),
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
async fn test_share_file_rejects_traversal_file_name() {
    let app = TestApp::new().await;
    let (_user_id, _device_id, jwt) = setup_api_user(&app.pool, &app.jwt_secret).await;

    let payload = ShareFilePayload {
        content: "some content".to_string(),
        file_name: "../../.bashrc".to_string(),
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
async fn test_share_file_rejects_invalid_deduplication_hash() {
    let app = TestApp::new().await;
    let (_user_id, _device_id, jwt) = setup_api_user(&app.pool, &app.jwt_secret).await;

    let payload = ShareFilePayload {
        content: "some content".to_string(),
        file_name: "test.txt".to_string(),
        device_id: "some-device-id".to_string(),
        deduplication_hash: Some("not a hex hash".to_string()),
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
    assert!(body.error.contains("Deduplication hash"));
}

#[tokio::test]
async fn test_share_file_empty_device_id() {
    let app = TestApp::new().await;
    let (_user_id, _device_id, jwt) = setup_api_user(&app.pool, &app.jwt_secret).await;

    let payload = ShareFilePayload {
        content: "some content".to_string(),
        file_name: "test.txt".to_string(),
        device_id: String::new(),
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

    // Mirrors the client: SHA256 of the file path, hex-encoded
    let dedup_hash = "a".repeat(64);

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
async fn test_download_keeps_share_as_historic_downloaded_record() {
    let app = TestApp::new().await;
    let email = "download_history@test.com";
    let user_id = create_verified_user(&app.pool, email, "TestPassword1!").await;
    let (source_device_id, _) = create_device_for_user(&app.pool, user_id, "Source").await;
    let (dest_device_id, _) = create_device_for_user(&app.pool, user_id, "Dest").await;

    let source_jwt = access_token::generate_access_token(
        user_id,
        source_device_id,
        "Source".to_string(),
        &app.jwt_secret,
        900,
    )
    .unwrap();

    let payload = ShareFilePayload {
        content: "secret payload".to_string(),
        file_name: "note.txt".to_string(),
        device_id: dest_device_id.clone(),
        deduplication_hash: None,
    };
    app.server
        .post("/api/share")
        .add_header(AUTHORIZATION, bearer(&source_jwt))
        .json(&payload)
        .await;

    let dest_jwt = access_token::generate_access_token(
        user_id,
        dest_device_id,
        "Dest".to_string(),
        &app.jwt_secret,
        900,
    )
    .unwrap();

    // First download returns the content.
    let first = app
        .server
        .get("/api/shares")
        .add_header(AUTHORIZATION, bearer(&dest_jwt))
        .await;
    let first_shares: Vec<SharedFileResponse> = first.json();
    assert_eq!(first_shares.len(), 1);
    assert_eq!(first_shares[0].content, "secret payload");
    let share_id = first_shares[0].id.clone();

    // Second download no longer returns the already-downloaded share.
    let second = app
        .server
        .get("/api/shares")
        .add_header(AUTHORIZATION, bearer(&dest_jwt))
        .await;
    let second_shares: Vec<SharedFileResponse> = second.json();
    assert!(second_shares.is_empty());

    // The row is kept as a historic record: status "downloaded", content cleared.
    let share_repo = fulgurant::shares::ShareRepository::new(app.db_pool.clone());
    let stored = share_repo.get_by_id(&share_id).await.unwrap();
    assert_eq!(stored.status, "downloaded");
    assert!(stored.content.is_empty());
}

#[tokio::test]
async fn test_get_share_v2_returns_content_without_consuming() {
    let app = TestApp::new().await;
    let email = "get_share_v2@test.com";
    let user_id = create_verified_user(&app.pool, email, "TestPassword1!").await;
    let (source_device_id, _) = create_device_for_user(&app.pool, user_id, "Source").await;
    let (dest_device_id, _) = create_device_for_user(&app.pool, user_id, "Dest").await;

    let source_jwt = access_token::generate_access_token(
        user_id,
        source_device_id,
        "Source".to_string(),
        &app.jwt_secret,
        900,
    )
    .unwrap();

    let payload = ShareFilePayload {
        content: "secret payload".to_string(),
        file_name: "note.txt".to_string(),
        device_id: dest_device_id.clone(),
        deduplication_hash: None,
    };
    app.server
        .post("/api/share")
        .add_header(AUTHORIZATION, bearer(&source_jwt))
        .json(&payload)
        .await;

    let dest_jwt = access_token::generate_access_token(
        user_id,
        dest_device_id,
        "Dest".to_string(),
        &app.jwt_secret,
        900,
    )
    .unwrap();

    // Discover the pending share id without consuming it.
    let share_repo = fulgurant::shares::ShareRepository::new(app.db_pool.clone());
    let pending = share_repo.get_available_for_user(user_id).await.unwrap();
    assert_eq!(pending.len(), 1);
    let share_id = pending[0].id.clone();

    // Two consecutive reads both return the content: the share is never consumed.
    for _ in 0..2 {
        let response = app
            .server
            .get(&format!("/api/v2/shares/{share_id}"))
            .add_header(AUTHORIZATION, bearer(&dest_jwt))
            .await;
        response.assert_status_ok();
        let share: SharedFileResponse = response.json();
        assert_eq!(share.content, "secret payload");
    }

    // The row is still available with its content intact.
    let stored = share_repo.get_by_id(&share_id).await.unwrap();
    assert_eq!(stored.status, "available");
    assert_eq!(stored.content, "secret payload");
}

#[tokio::test]
async fn test_get_share_v2_unknown_id_returns_not_found() {
    let app = TestApp::new().await;
    let email = "get_share_v2_unknown@test.com";
    let user_id = create_verified_user(&app.pool, email, "TestPassword1!").await;
    let (device_id, _) = create_device_for_user(&app.pool, user_id, "Device").await;

    let jwt = access_token::generate_access_token(
        user_id,
        device_id,
        "Device".to_string(),
        &app.jwt_secret,
        900,
    )
    .unwrap();

    // A syntactically valid but unknown share id hits the not-found branch (404, not 500).
    let unknown_id = uuid::Uuid::new_v4().to_string();
    let response = app
        .server
        .get(&format!("/api/v2/shares/{unknown_id}"))
        .add_header(AUTHORIZATION, bearer(&jwt))
        .expect_failure()
        .await;
    response.assert_status_not_found();
}

#[tokio::test]
async fn test_share_successful_consumes_share() {
    let app = TestApp::new().await;
    let email = "share_successful@test.com";
    let user_id = create_verified_user(&app.pool, email, "TestPassword1!").await;
    let (source_device_id, _) = create_device_for_user(&app.pool, user_id, "Source").await;
    let (dest_device_id, _) = create_device_for_user(&app.pool, user_id, "Dest").await;

    let source_jwt = access_token::generate_access_token(
        user_id,
        source_device_id,
        "Source".to_string(),
        &app.jwt_secret,
        900,
    )
    .unwrap();

    let payload = ShareFilePayload {
        content: "secret payload".to_string(),
        file_name: "note.txt".to_string(),
        device_id: dest_device_id.clone(),
        deduplication_hash: None,
    };
    app.server
        .post("/api/share")
        .add_header(AUTHORIZATION, bearer(&source_jwt))
        .json(&payload)
        .await;

    let dest_jwt = access_token::generate_access_token(
        user_id,
        dest_device_id,
        "Dest".to_string(),
        &app.jwt_secret,
        900,
    )
    .unwrap();

    let share_repo = fulgurant::shares::ShareRepository::new(app.db_pool.clone());
    let share_id = share_repo.get_available_for_user(user_id).await.unwrap()[0]
        .id
        .clone();

    // Acknowledging the download consumes the share.
    let ack = app
        .server
        .post(&format!("/api/v2/shares/{share_id}/successful"))
        .add_header(AUTHORIZATION, bearer(&dest_jwt))
        .await;
    ack.assert_status(StatusCode::NO_CONTENT);

    // The row is kept as a historic record: status "downloaded", content cleared.
    let stored = share_repo.get_by_id(&share_id).await.unwrap();
    assert_eq!(stored.status, "downloaded");
    assert!(stored.content.is_empty());

    // The consumed share is no longer readable via the v2 endpoint.
    let read = app
        .server
        .get(&format!("/api/v2/shares/{share_id}"))
        .add_header(AUTHORIZATION, bearer(&dest_jwt))
        .expect_failure()
        .await;
    read.assert_status_not_found();

    // A duplicate acknowledgement is a harmless no-op returning 404.
    let second_ack = app
        .server
        .post(&format!("/api/v2/shares/{share_id}/successful"))
        .add_header(AUTHORIZATION, bearer(&dest_jwt))
        .expect_failure()
        .await;
    second_ack.assert_status_not_found();
}

#[tokio::test]
async fn test_share_successful_rejects_other_devices_share() {
    let app = TestApp::new().await;
    let email = "share_successful_other@test.com";
    let user_id = create_verified_user(&app.pool, email, "TestPassword1!").await;
    let (source_device_id, _) = create_device_for_user(&app.pool, user_id, "Source").await;
    let (dest_device_id, _) = create_device_for_user(&app.pool, user_id, "Dest").await;
    let (other_device_id, _) = create_device_for_user(&app.pool, user_id, "Other").await;

    let source_jwt = access_token::generate_access_token(
        user_id,
        source_device_id,
        "Source".to_string(),
        &app.jwt_secret,
        900,
    )
    .unwrap();

    let payload = ShareFilePayload {
        content: "secret payload".to_string(),
        file_name: "note.txt".to_string(),
        device_id: dest_device_id.clone(),
        deduplication_hash: None,
    };
    app.server
        .post("/api/share")
        .add_header(AUTHORIZATION, bearer(&source_jwt))
        .json(&payload)
        .await;

    let share_repo = fulgurant::shares::ShareRepository::new(app.db_pool.clone());
    let share_id = share_repo.get_available_for_user(user_id).await.unwrap()[0]
        .id
        .clone();

    // A device that is not the destination cannot acknowledge the share.
    let other_jwt = access_token::generate_access_token(
        user_id,
        other_device_id,
        "Other".to_string(),
        &app.jwt_secret,
        900,
    )
    .unwrap();
    let response = app
        .server
        .post(&format!("/api/v2/shares/{share_id}/successful"))
        .add_header(AUTHORIZATION, bearer(&other_jwt))
        .expect_failure()
        .await;
    response.assert_status_not_found();

    // The share remains available for the legitimate destination device.
    let stored = share_repo.get_by_id(&share_id).await.unwrap();
    assert_eq!(stored.status, "available");
    assert_eq!(stored.content, "secret payload");
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

    let share_repo = fulgurant::shares::ShareRepository::new(app.db_pool.clone());
    let owner_shares = share_repo.get_all_for_user(owner_user_id).await.unwrap();
    assert!(owner_shares.is_empty());
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
        "public_key": "age1testpublickeyfortesting"
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

    // Verify public key was updated
    let device_repo = fulgurant::devices::DeviceRepository::new(app.db_pool.clone());
    let device = device_repo.get_by_device_id(&dest_id).await.unwrap();
    assert_eq!(
        device.public_key.as_deref(),
        Some("age1testpublickeyfortesting")
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
    let user_repo = fulgurant::users::UserRepository::new(app.db_pool.clone());
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

    // Verify public key was NOT set (still None)
    let device_repo = fulgurant::devices::DeviceRepository::new(app.db_pool.clone());
    let device = device_repo.get_by_device_id(&device_id).await.unwrap();
    assert!(device.public_key.is_none());
}

// ─────────────────────────────────────────────
// POST /api/v2/begin
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_begin_v2_advertises_min_fulgur_version() {
    let app = TestApp::new().await;
    let (_user_id, _device_id, jwt) = setup_api_user(&app.pool, &app.jwt_secret).await;

    let begin_payload = serde_json::json!({ "public_key": "" });

    let response = app
        .server
        .post("/api/v2/begin")
        .add_header(AUTHORIZATION, bearer(&jwt))
        .json(&begin_payload)
        .await;

    let body: BeginV2Response = response.json();
    assert_eq!(
        body.min_fulgur_version.as_deref(),
        Some(fulgurant::MIN_FULGUR_VERSION),
        "begin v2 must advertise the server's minimum Fulgur version"
    );
}

#[tokio::test]
async fn test_begin_v2_lists_pending_shares_without_consuming() {
    let app = TestApp::new().await;
    let email = "begin_v2_pending@test.com";
    let user_id = create_verified_user(&app.pool, email, "TestPassword1!").await;
    let (source_id, _) = create_device_for_user(&app.pool, user_id, "Source").await;
    let (dest_id, _) = create_device_for_user(&app.pool, user_id, "Dest").await;

    let source_jwt = access_token::generate_access_token(
        user_id,
        source_id,
        "Source".to_string(),
        &app.jwt_secret,
        900,
    )
    .unwrap();

    let payload = ShareFilePayload {
        content: "v2 begin content".to_string(),
        file_name: "v2begin.txt".to_string(),
        device_id: dest_id.clone(),
        deduplication_hash: None,
    };
    app.server
        .post("/api/share")
        .add_header(AUTHORIZATION, bearer(&source_jwt))
        .json(&payload)
        .await;

    let dest_jwt = access_token::generate_access_token(
        user_id,
        dest_id.clone(),
        "Dest".to_string(),
        &app.jwt_secret,
        900,
    )
    .unwrap();

    let begin_payload = serde_json::json!({ "public_key": "" });
    let response = app
        .server
        .post("/api/v2/begin")
        .add_header(AUTHORIZATION, bearer(&dest_jwt))
        .json(&begin_payload)
        .await;

    let body: BeginV2Response = response.json();
    assert_eq!(body.device_name, "Dest");
    assert_eq!(
        body.share_ids.len(),
        1,
        "should advertise the pending share"
    );

    // The v2 contract is non-destructive: the share must stay available with intact content.
    let share_repo = fulgurant::shares::ShareRepository::new(app.db_pool.clone());
    let stored = share_repo.get_by_id(&body.share_ids[0]).await.unwrap();
    assert_eq!(stored.status, "available");
    assert_eq!(stored.content, "v2 begin content");
}

#[tokio::test]
async fn test_begin_v2_persists_public_key() {
    let app = TestApp::new().await;
    let email = "begin_v2_key@test.com";
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

    let begin_payload = serde_json::json!({ "public_key": "age1testpublickeyfortesting" });
    app.server
        .post("/api/v2/begin")
        .add_header(AUTHORIZATION, bearer(&jwt))
        .json(&begin_payload)
        .await;

    let device_repo = fulgurant::devices::DeviceRepository::new(app.db_pool.clone());
    let device = device_repo.get_by_device_id(&device_id).await.unwrap();
    assert_eq!(
        device.public_key.as_deref(),
        Some("age1testpublickeyfortesting")
    );
}

#[tokio::test]
async fn test_begin_v2_updates_last_activity() {
    let app = TestApp::new().await;
    let (_user_id, _device_id, jwt) = setup_api_user(&app.pool, &app.jwt_secret).await;

    let begin_payload = serde_json::json!({ "public_key": "" });
    app.server
        .post("/api/v2/begin")
        .add_header(AUTHORIZATION, bearer(&jwt))
        .json(&begin_payload)
        .await;

    let user_repo = fulgurant::users::UserRepository::new(app.db_pool.clone());
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
async fn test_begin_v2_empty_public_key_skips_update() {
    let app = TestApp::new().await;
    let email = "begin_v2_nokey@test.com";
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

    let begin_payload = serde_json::json!({ "public_key": "" });
    app.server
        .post("/api/v2/begin")
        .add_header(AUTHORIZATION, bearer(&jwt))
        .json(&begin_payload)
        .await;

    let device_repo = fulgurant::devices::DeviceRepository::new(app.db_pool.clone());
    let device = device_repo.get_by_device_id(&device_id).await.unwrap();
    assert!(device.public_key.is_none());
}

#[tokio::test]
async fn test_begin_v2_empty_when_nothing_pending() {
    let app = TestApp::new().await;
    let (_user_id, _device_id, jwt) = setup_api_user(&app.pool, &app.jwt_secret).await;

    let begin_payload = serde_json::json!({ "public_key": "" });
    let response = app
        .server
        .post("/api/v2/begin")
        .add_header(AUTHORIZATION, bearer(&jwt))
        .json(&begin_payload)
        .await;

    let body: BeginV2Response = response.json();
    assert!(
        body.share_ids.is_empty(),
        "no shares pending should yield an empty list"
    );
    assert_eq!(body.max_file_size_bytes, Some(1_048_576));
}

#[tokio::test]
async fn test_get_share_legacy_consumes_and_keeps_historic_record() {
    let app = TestApp::new().await;
    let email = "get_share_legacy@test.com";
    let user_id = create_verified_user(&app.pool, email, "TestPassword1!").await;
    let (source_device_id, _) = create_device_for_user(&app.pool, user_id, "Source").await;
    let (dest_device_id, _) = create_device_for_user(&app.pool, user_id, "Dest").await;

    let source_jwt = access_token::generate_access_token(
        user_id,
        source_device_id,
        "Source".to_string(),
        &app.jwt_secret,
        900,
    )
    .unwrap();

    let payload = ShareFilePayload {
        content: "secret payload".to_string(),
        file_name: "note.txt".to_string(),
        device_id: dest_device_id.clone(),
        deduplication_hash: None,
    };
    app.server
        .post("/api/share")
        .add_header(AUTHORIZATION, bearer(&source_jwt))
        .json(&payload)
        .await;

    let dest_jwt = access_token::generate_access_token(
        user_id,
        dest_device_id,
        "Dest".to_string(),
        &app.jwt_secret,
        900,
    )
    .unwrap();

    let share_repo = fulgurant::shares::ShareRepository::new(app.db_pool.clone());
    let share_id = share_repo.get_available_for_user(user_id).await.unwrap()[0]
        .id
        .clone();

    // First claim returns the intact content to the caller.
    let first = app
        .server
        .get(&format!("/api/shares/{share_id}"))
        .add_header(AUTHORIZATION, bearer(&dest_jwt))
        .await;
    first.assert_status_ok();
    let share: SharedFileResponse = first.json();
    assert_eq!(share.content, "secret payload");

    // The row is kept as a historic record: status "downloaded", content cleared.
    let stored = share_repo.get_by_id(&share_id).await.unwrap();
    assert_eq!(stored.status, "downloaded");
    assert!(stored.content.is_empty());

    // A second claim returns 404: the once-only download guarantee holds.
    let second = app
        .server
        .get(&format!("/api/shares/{share_id}"))
        .add_header(AUTHORIZATION, bearer(&dest_jwt))
        .expect_failure()
        .await;
    second.assert_status_not_found();
}

#[tokio::test]
async fn test_get_share_legacy_rejects_other_devices_share() {
    let app = TestApp::new().await;
    let email = "get_share_legacy_other@test.com";
    let user_id = create_verified_user(&app.pool, email, "TestPassword1!").await;
    let (source_device_id, _) = create_device_for_user(&app.pool, user_id, "Source").await;
    let (dest_device_id, _) = create_device_for_user(&app.pool, user_id, "Dest").await;
    let (other_device_id, _) = create_device_for_user(&app.pool, user_id, "Other").await;

    let source_jwt = access_token::generate_access_token(
        user_id,
        source_device_id,
        "Source".to_string(),
        &app.jwt_secret,
        900,
    )
    .unwrap();

    let payload = ShareFilePayload {
        content: "secret payload".to_string(),
        file_name: "note.txt".to_string(),
        device_id: dest_device_id.clone(),
        deduplication_hash: None,
    };
    app.server
        .post("/api/share")
        .add_header(AUTHORIZATION, bearer(&source_jwt))
        .json(&payload)
        .await;

    let share_repo = fulgurant::shares::ShareRepository::new(app.db_pool.clone());
    let share_id = share_repo.get_available_for_user(user_id).await.unwrap()[0]
        .id
        .clone();

    // A device that is not the destination cannot claim the share.
    let other_jwt = access_token::generate_access_token(
        user_id,
        other_device_id,
        "Other".to_string(),
        &app.jwt_secret,
        900,
    )
    .unwrap();
    let response = app
        .server
        .get(&format!("/api/shares/{share_id}"))
        .add_header(AUTHORIZATION, bearer(&other_jwt))
        .expect_failure()
        .await;
    response.assert_status_not_found();

    // The share remains available for the legitimate destination device.
    let stored = share_repo.get_by_id(&share_id).await.unwrap();
    assert_eq!(stored.status, "available");
    assert_eq!(stored.content, "secret payload");
}

#[tokio::test]
async fn test_get_share_legacy_returns_not_found_for_expired_share() {
    let app = TestApp::new().await;
    let email = "get_share_legacy_expired@test.com";
    let user_id = create_verified_user(&app.pool, email, "TestPassword1!").await;
    let (source_device_id, _) = create_device_for_user(&app.pool, user_id, "Source").await;
    let (dest_device_id, _) = create_device_for_user(&app.pool, user_id, "Dest").await;

    let source_jwt = access_token::generate_access_token(
        user_id,
        source_device_id,
        "Source".to_string(),
        &app.jwt_secret,
        900,
    )
    .unwrap();

    let payload = ShareFilePayload {
        content: "secret payload".to_string(),
        file_name: "note.txt".to_string(),
        device_id: dest_device_id.clone(),
        deduplication_hash: None,
    };
    app.server
        .post("/api/share")
        .add_header(AUTHORIZATION, bearer(&source_jwt))
        .json(&payload)
        .await;

    let share_repo = fulgurant::shares::ShareRepository::new(app.db_pool.clone());
    let share_id = share_repo.get_available_for_user(user_id).await.unwrap()[0]
        .id
        .clone();

    // Force the share past its expiration while still in the "available" state.
    sqlx::query("UPDATE shares SET expires_at = unixepoch('now') - 60 WHERE id = ?")
        .bind(&share_id)
        .execute(&app.pool)
        .await
        .unwrap();

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
        .get(&format!("/api/shares/{share_id}"))
        .add_header(AUTHORIZATION, bearer(&dest_jwt))
        .expect_failure()
        .await;
    response.assert_status_not_found();
}

// ─────────────────────────────────────────────
// GET /api/sse
// ─────────────────────────────────────────────

/// Open a raw TCP connection to the running test server and issue an SSE GET request.
///
/// A raw socket is required rather than `axum_test`'s buffering client: the SSE response never
/// completes, so a normally awaited request would block forever. The request is written but no
/// response bytes are read here.
///
/// ### Arguments
/// - `app`: the running test application exposing the bound HTTP address
/// - `jwt`: the bearer access token authenticating the device
///
/// ### Returns
/// - `TcpStream`: the connected socket with the SSE request already written
async fn open_sse_connection(app: &TestApp, jwt: &str) -> TcpStream {
    let address = app
        .server
        .server_address()
        .expect("HTTP transport must expose a bound address");
    let authority = address.authority();
    let socket_addr = address
        .socket_addrs(|| None)
        .expect("server address must resolve")[0];
    let mut stream = TcpStream::connect(socket_addr)
        .await
        .expect("connecting to the test server must succeed");
    let request = format!(
        "GET /api/sse HTTP/1.1\r\nHost: {authority}\r\nAuthorization: Bearer {jwt}\r\nAccept: text/event-stream\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("writing the SSE request must succeed");
    stream
}

/// Read from an SSE socket until `needle` appears in the response or the timeout elapses.
///
/// ### Arguments
/// - `stream`: the connected SSE socket to read from
/// - `needle`: the substring to wait for in the accumulated response bytes
/// - `timeout`: the maximum time to wait before giving up
///
/// ### Returns
/// - `String`: the bytes read from the socket, decoded lossily
async fn read_sse_until(stream: &mut TcpStream, needle: &str, timeout: StdDuration) -> String {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    let _ = tokio::time::timeout(timeout, async {
        loop {
            let read = stream
                .read(&mut chunk)
                .await
                .expect("reading from the SSE socket must succeed");
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if String::from_utf8_lossy(&buffer).contains(needle) {
                break;
            }
        }
    })
    .await;
    String::from_utf8_lossy(&buffer).into_owned()
}

#[tokio::test]
async fn test_sse_emits_pending_shares_snapshot_on_connect() {
    let app = TestApp::new().await;
    let email = "sse_snapshot@test.com";
    let user_id = create_verified_user(&app.pool, email, "TestPassword1!").await;
    let (source_device_id, _) = create_device_for_user(&app.pool, user_id, "Source").await;
    let (dest_device_id, _) = create_device_for_user(&app.pool, user_id, "Dest").await;

    let source_jwt = access_token::generate_access_token(
        user_id,
        source_device_id,
        "Source".to_string(),
        &app.jwt_secret,
        900,
    )
    .unwrap();

    // Create a pending share addressed to the device that will open the SSE stream.
    let payload = ShareFilePayload {
        content: "secret payload".to_string(),
        file_name: "note.txt".to_string(),
        device_id: dest_device_id.clone(),
        deduplication_hash: None,
    };
    app.server
        .post("/api/share")
        .add_header(AUTHORIZATION, bearer(&source_jwt))
        .json(&payload)
        .await;

    let share_repo = fulgurant::shares::ShareRepository::new(app.db_pool.clone());
    let share_id = share_repo.get_available_for_user(user_id).await.unwrap()[0]
        .id
        .clone();

    let dest_jwt = access_token::generate_access_token(
        user_id,
        dest_device_id,
        "Dest".to_string(),
        &app.jwt_secret,
        900,
    )
    .unwrap();

    // On connect, the device immediately receives a pending_shares snapshot listing the share id.
    let mut stream = open_sse_connection(&app, &dest_jwt).await;
    let received = read_sse_until(&mut stream, "pending_shares", StdDuration::from_secs(5)).await;

    assert!(
        received.contains("200 OK"),
        "the SSE connection must succeed, got: {received}"
    );
    assert!(
        received.contains("pending_shares"),
        "expected a pending_shares snapshot event, got: {received}"
    );
    assert!(
        received.contains(&share_id),
        "snapshot must list the pending share id {share_id}, got: {received}"
    );
}

#[tokio::test]
async fn test_sse_rejects_connections_over_per_device_cap() {
    let app = TestApp::new().await;
    let (_user_id, _device_id, jwt) = setup_api_user(&app.pool, &app.jwt_secret).await;

    // Saturate the per-device connection cap, keeping every stream open so its guard stays held.
    let mut held_connections = Vec::new();
    for _ in 0..MAX_SSE_CONNECTIONS_PER_DEVICE {
        let mut stream = open_sse_connection(&app, &jwt).await;
        // Reading the initial snapshot proves the handler passed the limiter and holds a slot.
        let received =
            read_sse_until(&mut stream, "pending_shares", StdDuration::from_secs(5)).await;
        assert!(
            received.contains("200 OK"),
            "an in-cap SSE connection must succeed, got: {received}"
        );
        held_connections.push(stream);
    }

    // One more connection for the same device must be rejected with 429.
    let mut overflow = open_sse_connection(&app, &jwt).await;
    let rejected = read_sse_until(&mut overflow, "429", StdDuration::from_secs(5)).await;
    assert!(
        rejected.contains("429"),
        "the over-cap SSE connection must be rejected with 429, got: {rejected}"
    );

    // Keep the saturating connections alive until after the over-cap assertion has run.
    drop(held_connections);
}
