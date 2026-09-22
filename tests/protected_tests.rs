mod common;

use axum::http::StatusCode;
use axum::http::header::{HeaderName, HeaderValue};
use common::{
    api_helpers::create_device_for_user,
    auth_helpers::{create_verified_user, extract_csrf_token, login},
    test_app::{TestApp, TestAppOptions},
};
use fulgur_common::api::{shares::ShareFileResponse, sync::ErrorResponse};
use fulgurant::{
    db::DbPool,
    devices::{DeviceRepository, WEB_DEVICE_NAME, WEB_DEVICE_TYPE},
    shares::{CreateShare, SHARE_VALIDITY_DAYS, ShareRepository},
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
struct WebShareRequestData<'a> {
    destination_device_id: &'a str,
    file_name: &'a str,
    content: &'a str,
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
        .post(&format!("/device/{user_id}/create"))
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
        .post(&format!("/device/{user_id}/create"))
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
        .post(&format!("/device/{user_id}/create"))
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

#[tokio::test]
async fn test_create_device_limit_enforced_at_boundary() {
    let app = TestApp::with_options(TestAppOptions {
        max_devices_per_user: 1,
        ..TestAppOptions::default()
    })
    .await;
    let user_id = create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    login(&app.server, "user@test.com", "Password123!").await;

    // Seed the single allowed device directly.
    create_device_for_user(&app.pool, user_id, "Existing Device").await;

    let page = app.server.get("/").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .post(&format!("/device/{user_id}/create"))
        .add_header(name, value)
        .form(&CreateDeviceFormData {
            name: "Second Device",
            device_type: "Desktop",
            api_key_lifetime: 365,
        })
        .expect_failure()
        .await;

    response.assert_status(StatusCode::FORBIDDEN);

    // The transactional check must not have inserted the extra device.
    let device_repo = DeviceRepository::new(app.db_pool.clone());
    let count = device_repo.count_devices_for_user(user_id).await.unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn test_create_device_for_another_user_forbidden() {
    let app = TestApp::new().await;
    let attacker_id = create_verified_user(&app.pool, "attacker@test.com", "Password123!").await;
    let victim_id = create_verified_user(&app.pool, "victim@test.com", "Password123!").await;
    assert_ne!(attacker_id, victim_id);

    login(&app.server, "attacker@test.com", "Password123!").await;
    let page = app.server.get("/").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .post(&format!("/device/{victim_id}/create"))
        .add_header(name, value)
        .form(&CreateDeviceFormData {
            name: "Stolen Device",
            device_type: "Desktop",
            api_key_lifetime: 365,
        })
        .expect_failure()
        .await;

    response.assert_status(StatusCode::FORBIDDEN);

    let device_repo = DeviceRepository::new(app.db_pool.clone());
    let victim_devices = device_repo.get_all_for_user(victim_id).await.unwrap();
    assert!(victim_devices.is_empty());
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
    let device_repo = DeviceRepository::new(app.db_pool.clone());
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
    let device_repo = DeviceRepository::new(app.db_pool.clone());
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

#[tokio::test]
async fn test_update_other_users_device_forbidden() {
    let app = TestApp::new().await;
    let attacker_id = create_verified_user(&app.pool, "attacker@test.com", "Password123!").await;
    let victim_id = create_verified_user(&app.pool, "victim@test.com", "Password123!").await;
    let (victim_device_uuid, _) =
        create_device_for_user(&app.pool, victim_id, "Victim Device").await;

    login(&app.server, "attacker@test.com", "Password123!").await;

    let device_repo = DeviceRepository::new(app.db_pool.clone());
    let victim_device = device_repo
        .get_by_device_id(&victim_device_uuid)
        .await
        .unwrap();

    let page = app.server.get("/").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .put(&format!("/device/{}", victim_device.id))
        .add_header(name, value)
        .form(&UpdateDeviceFormData {
            name: "Compromised Device",
            device_type: "Mobile",
        })
        .expect_failure()
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
    assert_ne!(attacker_id, victim_id);

    let unchanged_device = device_repo
        .get_by_device_id(&victim_device_uuid)
        .await
        .unwrap();
    assert_eq!(unchanged_device.name, "Victim Device");
    assert_eq!(unchanged_device.device_type, "Desktop");
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
    let device_repo = DeviceRepository::new(app.db_pool.clone());
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

#[tokio::test]
async fn test_delete_other_users_device_forbidden() {
    let app = TestApp::new().await;
    create_verified_user(&app.pool, "attacker@test.com", "Password123!").await;
    let victim_id = create_verified_user(&app.pool, "victim@test.com", "Password123!").await;
    let (victim_device_uuid, _) =
        create_device_for_user(&app.pool, victim_id, "Victim Device").await;

    login(&app.server, "attacker@test.com", "Password123!").await;

    let device_repo = DeviceRepository::new(app.db_pool.clone());
    let victim_device = device_repo
        .get_by_device_id(&victim_device_uuid)
        .await
        .unwrap();

    let page = app.server.get("/").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .delete(&format!("/device/{}", victim_device.id))
        .add_header(name, value)
        .expect_failure()
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
    let still_exists = device_repo
        .get_by_device_id(&victim_device_uuid)
        .await
        .unwrap();
    assert_eq!(still_exists.id, victim_device.id);
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
    let share_repo = ShareRepository::new(app.db_pool.clone());
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
            SHARE_VALIDITY_DAYS,
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

    // The row is kept as a historic record: status becomes "deleted" and content is cleared.
    let deleted = share_repo.get_by_id(&share.id).await.unwrap();
    assert_eq!(deleted.status, "deleted");
    assert!(deleted.content.is_empty());
}

#[tokio::test]
async fn test_delete_other_users_share_forbidden() {
    let app = TestApp::new().await;
    create_verified_user(&app.pool, "attacker@test.com", "Password123!").await;
    let victim_id = create_verified_user(&app.pool, "victim@test.com", "Password123!").await;
    login(&app.server, "attacker@test.com", "Password123!").await;

    // Shares require existing source/destination devices due to FK constraints.
    let (victim_device_uuid, _) =
        create_device_for_user(&app.pool, victim_id, "Victim Device").await;
    let share_repo = ShareRepository::new(app.db_pool.clone());
    let share = share_repo
        .create(
            victim_id,
            CreateShare {
                source_device_id: victim_device_uuid.clone(),
                destination_device_id: victim_device_uuid,
                file_name: "secret.txt".to_string(),
                content: "confidential".to_string(),
                deduplication_hash: None,
            },
            SHARE_VALIDITY_DAYS,
        )
        .await
        .unwrap();

    let page = app.server.get("/").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .delete(&format!("/share/{}", share.id))
        .add_header(name, value)
        .expect_failure()
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
    let remaining_share = share_repo.get_by_id(&share.id).await.unwrap();
    assert_eq!(remaining_share.id, share.id);
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

// ─────────────────────────────────────────────
// GET /share/new
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_new_share_page_requires_auth() {
    let app = TestApp::new().await;

    let response = app.server.get("/share/new").expect_failure().await;

    response.assert_status(StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn test_new_share_page_lists_devices_and_limit() {
    let app = TestApp::new().await;
    let user_id = create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    login(&app.server, "user@test.com", "Password123!").await;
    let (synced_id, _) = create_device_for_user(&app.pool, user_id, "Synced laptop").await;
    create_device_for_user(&app.pool, user_id, "Fresh tower").await;
    let device_repo = DeviceRepository::new(DbPool::Sqlite(app.pool.clone()));
    device_repo
        .update_public_key(&synced_id, "age1testpublickey".to_string())
        .await
        .unwrap();

    let response = app.server.get("/share/new").await;

    response.assert_status_ok();
    let html = response.text();
    assert!(html.contains("Send a file to your devices"));
    assert!(html.contains("data-max-bytes=\"1048576\""));
    assert!(html.contains("up to 1 MB"));
    assert!(html.contains("Synced laptop"));
    assert!(html.contains("data-public-key=\"age1testpublickey\""));
    assert!(html.contains("Fresh tower"));
    assert!(html.contains("Sync from Fulgur first"));
}

#[tokio::test]
async fn test_dashboard_has_new_share_button() {
    let app = TestApp::new().await;
    create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    login(&app.server, "user@test.com", "Password123!").await;

    let response = app.server.get("/").await;

    response.assert_status_ok();
    assert!(response.text().contains("href=\"/share/new\""));
}

// ─────────────────────────────────────────────
// POST /share
// ─────────────────────────────────────────────

/// Create a user with a synced device and log in, returning the ids and CSRF header
async fn setup_web_share_user(app: &TestApp) -> (i32, String, (HeaderName, HeaderValue)) {
    let user_id = create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    login(&app.server, "user@test.com", "Password123!").await;
    let (device_id, _) = create_device_for_user(&app.pool, user_id, "Laptop").await;
    DeviceRepository::new(DbPool::Sqlite(app.pool.clone()))
        .update_public_key(&device_id, "age1testpublickey".to_string())
        .await
        .unwrap();
    let page = app.server.get("/share/new").await;
    let csrf = csrf_header(&extract_csrf_token(&page.text()));
    (user_id, device_id, csrf)
}

#[tokio::test]
async fn test_create_web_share_success() {
    let app = TestApp::new().await;
    let (user_id, device_id, (name, value)) = setup_web_share_user(&app).await;

    let response = app
        .server
        .post("/share")
        .add_header(name.clone(), value.clone())
        .json(&WebShareRequestData {
            destination_device_id: &device_id,
            file_name: "notes.md",
            content: "ciphertext-base64",
        })
        .await;

    response.assert_status_ok();
    let body: ShareFileResponse = response.json();
    assert!(body.message.contains("successfully"));
    assert!(!body.expiration_date.is_empty());

    let device_repo = DeviceRepository::new(DbPool::Sqlite(app.pool.clone()));
    let web_device = device_repo.get_web_device(user_id).await.unwrap().unwrap();
    assert_eq!(web_device.device_type, WEB_DEVICE_TYPE);
    assert_eq!(web_device.name, WEB_DEVICE_NAME);
    assert!(web_device.is_expired());
    assert!(web_device.public_key.is_none());

    let shares = ShareRepository::new(app.db_pool.clone())
        .get_available_for_user(user_id)
        .await
        .unwrap();
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].source_device_id, web_device.device_id);
    assert_eq!(shares[0].destination_device_id, device_id);
    assert_eq!(shares[0].file_name, "notes.md");
    assert_eq!(shares[0].content, "ciphertext-base64");

    // A second share reuses the same web device instead of creating another one
    app.server
        .post("/share")
        .add_header(name, value)
        .json(&WebShareRequestData {
            destination_device_id: &device_id,
            file_name: "second.txt",
            content: "more-ciphertext",
        })
        .await
        .assert_status_ok();
    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM devices WHERE user_id = ? AND device_type = ?")
            .bind(user_id)
            .bind(WEB_DEVICE_TYPE)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(count.0, 1);
}

#[tokio::test]
async fn test_web_device_hidden_from_dashboard_but_named_in_shares() {
    let app = TestApp::new().await;
    let (user_id, device_id, (name, value)) = setup_web_share_user(&app).await;
    app.server
        .post("/share")
        .add_header(name, value)
        .json(&WebShareRequestData {
            destination_device_id: &device_id,
            file_name: "notes.md",
            content: "ciphertext-base64",
        })
        .await
        .assert_status_ok();

    let html = app.server.get("/").await.text();

    let device_repo = DeviceRepository::new(DbPool::Sqlite(app.pool.clone()));
    let web_device = device_repo.get_web_device(user_id).await.unwrap().unwrap();
    assert!(!html.contains(&format!("id=\"device-{}\"", web_device.id)));
    assert_eq!(
        device_repo.get_all_for_user(user_id).await.unwrap().len(),
        1
    );
    assert_eq!(
        device_repo.count_devices_for_user(user_id).await.unwrap(),
        1
    );
    // The share row shows the web device as its source instead of "Unknown"
    assert!(html.contains("<td>Web</td>"));
    assert!(!html.contains("<td>Unknown</td>"));
}

#[tokio::test]
async fn test_create_web_share_rejects_unsynced_device() {
    let app = TestApp::new().await;
    let (user_id, _, (name, value)) = setup_web_share_user(&app).await;
    let (unsynced_id, _) = create_device_for_user(&app.pool, user_id, "Fresh tower").await;

    let response = app
        .server
        .post("/share")
        .add_header(name, value)
        .json(&WebShareRequestData {
            destination_device_id: &unsynced_id,
            file_name: "notes.md",
            content: "ciphertext-base64",
        })
        .expect_failure()
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    let body: ErrorResponse = response.json();
    assert!(body.error.contains("never synced"));
}

#[tokio::test]
async fn test_create_web_share_rejects_other_users_device() {
    let app = TestApp::new().await;
    let (_, _, (name, value)) = setup_web_share_user(&app).await;
    let victim_id = create_verified_user(&app.pool, "victim@test.com", "Password123!").await;
    let (victim_device, _) = create_device_for_user(&app.pool, victim_id, "Victim").await;
    DeviceRepository::new(DbPool::Sqlite(app.pool.clone()))
        .update_public_key(&victim_device, "age1victimkey".to_string())
        .await
        .unwrap();

    let response = app
        .server
        .post("/share")
        .add_header(name, value)
        .json(&WebShareRequestData {
            destination_device_id: &victim_device,
            file_name: "notes.md",
            content: "ciphertext-base64",
        })
        .expect_failure()
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_create_web_share_rejects_oversized_content() {
    let app = TestApp::new().await;
    let (_, device_id, (name, value)) = setup_web_share_user(&app).await;
    let content = "A".repeat(1_048_577);

    let response = app
        .server
        .post("/share")
        .add_header(name, value)
        .json(&WebShareRequestData {
            destination_device_id: &device_id,
            file_name: "big.txt",
            content: &content,
        })
        .expect_failure()
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    let body: ErrorResponse = response.json();
    assert!(body.error.contains("exceeds the server limit"));
}

#[tokio::test]
async fn test_create_web_share_rejects_invalid_file_name() {
    let app = TestApp::new().await;
    let (_, device_id, (name, value)) = setup_web_share_user(&app).await;

    let response = app
        .server
        .post("/share")
        .add_header(name, value)
        .json(&WebShareRequestData {
            destination_device_id: &device_id,
            file_name: "../etc/passwd",
            content: "ciphertext-base64",
        })
        .expect_failure()
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    let body: ErrorResponse = response.json();
    assert!(body.error.contains("File name"));
}

#[tokio::test]
async fn test_create_web_share_requires_csrf() {
    let app = TestApp::new().await;
    let (_, device_id, _) = setup_web_share_user(&app).await;

    let response = app
        .server
        .post("/share")
        .json(&WebShareRequestData {
            destination_device_id: &device_id,
            file_name: "notes.md",
            content: "ciphertext-base64",
        })
        .expect_failure()
        .await;

    assert!(response.status_code().is_client_error());
}

// ─────────────────────────────────────────────
// Reserved device type
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_create_device_rejects_reserved_type() {
    let app = TestApp::new().await;
    let user_id = create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    login(&app.server, "user@test.com", "Password123!").await;
    let page = app.server.get("/").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .post(&format!("/device/{user_id}/create"))
        .add_header(name, value)
        .form(&CreateDeviceFormData {
            name: "Sneaky",
            device_type: "Web",
            api_key_lifetime: 30,
        })
        .expect_failure()
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    assert!(response.text().contains("reserved"));
}

#[tokio::test]
async fn test_create_device_rejects_reserved_name() {
    let app = TestApp::new().await;
    let user_id = create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    login(&app.server, "user@test.com", "Password123!").await;
    let page = app.server.get("/").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .post(&format!("/device/{user_id}/create"))
        .add_header(name, value)
        .form(&CreateDeviceFormData {
            name: "web",
            device_type: "Laptop",
            api_key_lifetime: 30,
        })
        .expect_failure()
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    assert!(response.text().contains("name is reserved"));
}

#[tokio::test]
async fn test_update_device_rejects_reserved_name() {
    let app = TestApp::new().await;
    let user_id = create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    login(&app.server, "user@test.com", "Password123!").await;
    create_device_for_user(&app.pool, user_id, "Laptop").await;
    let device = DeviceRepository::new(DbPool::Sqlite(app.pool.clone()))
        .get_all_for_user(user_id)
        .await
        .unwrap()
        .remove(0);
    let page = app.server.get("/").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .put(&format!("/device/{}", device.id))
        .add_header(name, value)
        .form(&UpdateDeviceFormData {
            name: "WEB",
            device_type: "Laptop",
        })
        .expect_failure()
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    assert!(response.text().contains("name is reserved"));
}

#[tokio::test]
async fn test_web_device_cannot_be_managed() {
    let app = TestApp::new().await;
    let (user_id, device_id, (name, value)) = setup_web_share_user(&app).await;
    app.server
        .post("/share")
        .add_header(name.clone(), value.clone())
        .json(&WebShareRequestData {
            destination_device_id: &device_id,
            file_name: "notes.md",
            content: "ciphertext-base64",
        })
        .await
        .assert_status_ok();
    let web_device = DeviceRepository::new(DbPool::Sqlite(app.pool.clone()))
        .get_web_device(user_id)
        .await
        .unwrap()
        .unwrap();

    let response = app
        .server
        .delete(&format!("/device/{}", web_device.id))
        .add_header(name, value)
        .expect_failure()
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}
