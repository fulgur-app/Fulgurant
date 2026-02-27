mod common;

use axum::http::StatusCode;
use axum::http::header::{HeaderName, HeaderValue};
use common::{
    api_helpers::create_device_for_user,
    auth_helpers::{create_verified_user, extract_csrf_token, login},
    test_app::{TestApp, TestAppOptions},
};
use fulgurant::{
    devices::DeviceRepository,
    shares::{CreateShare, ShareRepository},
};
use serde::Serialize;

#[derive(Serialize)]
struct CreateDeviceFormData<'a> {
    name: &'a str,
    device_type: &'a str,
    api_key_lifetime: i64,
}

#[derive(Serialize)]
struct UpdateDeviceFormData<'a> {
    name: &'a str,
    device_type: &'a str,
}

#[derive(Serialize)]
struct UpdateNameFormData<'a> {
    first_name: &'a str,
    last_name: &'a str,
}

/// Build the `x-csrf-token` header from a token string
fn csrf_header(token: &str) -> (HeaderName, HeaderValue) {
    (
        HeaderName::from_static("x-csrf-token"),
        HeaderValue::from_str(token).unwrap(),
    )
}

// ─────────────────────────────────────────────
// Fallback 404
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_404_on_unknown_path() {
    let app = TestApp::new().await;

    let response = app.server.get("/nonexistent-path").expect_failure().await;

    response.assert_status(StatusCode::NOT_FOUND);
}

// ─────────────────────────────────────────────
// GET /
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_index_authenticated() {
    let app = TestApp::new().await;
    create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    login(&app.server, "user@test.com", "Password123!").await;

    let response = app.server.get("/").await;

    response.assert_status_ok();
    assert!(response.text().contains("csrf-token"));
}

#[tokio::test]
async fn test_index_unauthenticated_redirects() {
    let app = TestApp::new().await;

    let response = app.server.get("/").expect_failure().await;

    response.assert_status(StatusCode::SEE_OTHER);
}

// ─────────────────────────────────────────────
// POST /device/{user_id}/create
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_create_device_success() {
    let app = TestApp::new().await;
    let user_id = create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    login(&app.server, "user@test.com", "Password123!").await;

    let page = app.server.get("/").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .post(&format!("/device/{}/create", user_id))
        .add_header(name, value)
        .form(&CreateDeviceFormData {
            name: "My Laptop",
            device_type: "Desktop",
            api_key_lifetime: 365,
        })
        .await;

    response.assert_status_ok();
    assert!(response.text().contains("Your API key is:"));
}

#[tokio::test]
async fn test_create_device_empty_name() {
    let app = TestApp::new().await;
    let user_id = create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    login(&app.server, "user@test.com", "Password123!").await;

    let page = app.server.get("/").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .post(&format!("/device/{}/create", user_id))
        .add_header(name, value)
        .form(&CreateDeviceFormData {
            name: "",
            device_type: "Desktop",
            api_key_lifetime: 365,
        })
        .expect_failure()
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    assert!(response.text().contains("cannot be empty"));
}

#[tokio::test]
async fn test_create_device_max_reached() {
    let app = TestApp::with_options(TestAppOptions {
        max_devices_per_user: 0,
        ..TestAppOptions::default()
    })
    .await;
    let user_id = create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    login(&app.server, "user@test.com", "Password123!").await;

    let page = app.server.get("/").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .post(&format!("/device/{}/create", user_id))
        .add_header(name, value)
        .form(&CreateDeviceFormData {
            name: "My Laptop",
            device_type: "Desktop",
            api_key_lifetime: 365,
        })
        .expect_failure()
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

// ─────────────────────────────────────────────
// PUT /device/{id}
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_update_device_success() {
    let app = TestApp::new().await;
    let user_id = create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    login(&app.server, "user@test.com", "Password123!").await;

    let (device_uuid, _) = create_device_for_user(&app.pool, user_id, "Old Name").await;
    let device_repo = DeviceRepository::new(app.pool.clone());
    let device = device_repo.get_by_device_id(&device_uuid).await.unwrap();

    let page = app.server.get("/").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .put(&format!("/device/{}", device.id))
        .add_header(name, value)
        .form(&UpdateDeviceFormData {
            name: "Updated Device",
            device_type: "Mobile",
        })
        .await;

    response.assert_status_ok();
    assert!(response.text().contains("Updated Device"));
}

#[tokio::test]
async fn test_update_device_empty_name() {
    let app = TestApp::new().await;
    let user_id = create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    login(&app.server, "user@test.com", "Password123!").await;

    let (device_uuid, _) = create_device_for_user(&app.pool, user_id, "My Device").await;
    let device_repo = DeviceRepository::new(app.pool.clone());
    let device = device_repo.get_by_device_id(&device_uuid).await.unwrap();

    let page = app.server.get("/").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .put(&format!("/device/{}", device.id))
        .add_header(name, value)
        .form(&UpdateDeviceFormData {
            name: "",
            device_type: "Desktop",
        })
        .expect_failure()
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    assert!(response.text().contains("cannot be empty"));
}

// ─────────────────────────────────────────────
// DELETE /device/{id}
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_delete_device_success() {
    let app = TestApp::new().await;
    let user_id = create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    login(&app.server, "user@test.com", "Password123!").await;

    let (device_uuid, _) = create_device_for_user(&app.pool, user_id, "My Device").await;
    let device_repo = DeviceRepository::new(app.pool.clone());
    let device = device_repo.get_by_device_id(&device_uuid).await.unwrap();

    let page = app.server.get("/").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .delete(&format!("/device/{}", device.id))
        .add_header(name, value)
        .await;

    response.assert_status_ok();
}

// ─────────────────────────────────────────────
// DELETE /share/{id}
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_delete_share_success() {
    let app = TestApp::new().await;
    let user_id = create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    login(&app.server, "user@test.com", "Password123!").await;

    // Shares require real devices due to the FK constraint on source_device_id
    let (source_uuid, _) = create_device_for_user(&app.pool, user_id, "Source Device").await;
    let share_repo = ShareRepository::new(app.pool.clone());
    let share = share_repo
        .create(
            user_id,
            CreateShare {
                source_device_id: source_uuid.clone(),
                destination_device_id: source_uuid,
                file_name: "test.txt".to_string(),
                content: "test content".to_string(),
                deduplication_hash: None,
            },
        )
        .await
        .unwrap();

    let page = app.server.get("/").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .delete(&format!("/share/{}", share.id))
        .add_header(name, value)
        .await;

    response.assert_status_ok();
}

// ─────────────────────────────────────────────
// GET /settings
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_settings_page_renders() {
    let app = TestApp::new().await;
    create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    login(&app.server, "user@test.com", "Password123!").await;

    let response = app.server.get("/settings").await;

    response.assert_status_ok();
    assert!(response.text().contains("Account Settings"));
}

// ─────────────────────────────────────────────
// POST /settings/update-name
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_update_name_success() {
    let app = TestApp::new().await;
    create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    login(&app.server, "user@test.com", "Password123!").await;

    let page = app.server.get("/settings").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .post("/settings/update-name")
        .add_header(name, value)
        .form(&UpdateNameFormData {
            first_name: "Alice",
            last_name: "Smith",
        })
        .await;

    response.assert_status_ok();
    assert!(response.text().contains("Name successfully updated"));
}

#[tokio::test]
async fn test_update_name_empty() {
    let app = TestApp::new().await;
    create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    login(&app.server, "user@test.com", "Password123!").await;

    let page = app.server.get("/settings").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .post("/settings/update-name")
        .add_header(name, value)
        .form(&UpdateNameFormData {
            first_name: "",
            last_name: "Smith",
        })
        .expect_failure()
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    assert!(response.text().contains("cannot be empty"));
}

#[tokio::test]
async fn test_update_name_too_long() {
    let app = TestApp::new().await;
    create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    login(&app.server, "user@test.com", "Password123!").await;

    let page = app.server.get("/settings").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    // MAX_NAME_LEN is 50, so 51 chars triggers the error
    let long_name = "A".repeat(51);

    let response = app
        .server
        .post("/settings/update-name")
        .add_header(name, value)
        .form(&UpdateNameFormData {
            first_name: &long_name,
            last_name: "Smith",
        })
        .expect_failure()
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    assert!(response.text().contains("cannot exceed"));
}
