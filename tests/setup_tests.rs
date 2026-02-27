mod common;

use axum::http::StatusCode;
use axum::http::header::{HeaderName, HeaderValue};
use common::{
    auth_helpers::{create_admin_user, extract_csrf_token},
    test_app::TestApp,
};
use serde::Serialize;
use sqlx::SqlitePool;

#[derive(Serialize)]
struct SetupFormData<'a> {
    email: &'a str,
    first_name: &'a str,
    last_name: &'a str,
    password: &'a str,
}

/// Build the `x-csrf-token` header from a token string
fn csrf_header(token: &str) -> (HeaderName, HeaderValue) {
    (
        HeaderName::from_static("x-csrf-token"),
        HeaderValue::from_str(token).unwrap(),
    )
}

/// Remove all admin users and their associated devices from the database
///
/// The seed migration inserts an admin user with devices. Setup tests require
/// no admin to exist, so this helper clears that state respecting FK constraints.
async fn remove_all_admins(pool: &SqlitePool) {
    sqlx::query("DELETE FROM devices WHERE user_id IN (SELECT id FROM users WHERE role = 'Admin')")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE role = 'Admin'")
        .execute(pool)
        .await
        .unwrap();
}

// ─────────────────────────────────────────────
// GET /setup
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_setup_page_when_needed() {
    let app = TestApp::with_setup_needed().await;
    remove_all_admins(&app.pool).await;

    let response = app.server.get("/setup").await;

    response.assert_status_ok();
    assert!(response.text().contains("Initial Setup"));
    assert!(response.text().contains("csrf-token"));
}

#[tokio::test]
async fn test_setup_redirects_when_admin_exists() {
    let app = TestApp::new().await;
    create_admin_user(&app.pool).await;

    let response = app.server.get("/setup").expect_failure().await;

    response.assert_status(StatusCode::SEE_OTHER);
}

// ─────────────────────────────────────────────
// POST /setup
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_create_admin_success() {
    let app = TestApp::with_setup_needed().await;
    remove_all_admins(&app.pool).await;

    let page = app.server.get("/setup").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .post("/setup")
        .add_header(name, value)
        .form(&SetupFormData {
            email: "admin@example.com",
            first_name: "Alice",
            last_name: "Admin",
            password: "SecurePass1!",
        })
        .await;

    response.assert_status_ok();
    assert_eq!(response.header("HX-Redirect"), "/");
}

#[tokio::test]
async fn test_create_admin_weak_password() {
    let app = TestApp::with_setup_needed().await;
    remove_all_admins(&app.pool).await;

    let page = app.server.get("/setup").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .post("/setup")
        .add_header(name, value)
        .form(&SetupFormData {
            email: "admin@example.com",
            first_name: "Alice",
            last_name: "Admin",
            password: "weak",
        })
        .await;

    response.assert_status_ok();
    assert!(response.text().contains("Password must be"));
}

#[tokio::test]
async fn test_create_admin_sets_setup_needed_false() {
    let app = TestApp::with_setup_needed().await;
    remove_all_admins(&app.pool).await;

    let page = app.server.get("/setup").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    // Perform setup: creates admin and clears the setup_needed flag
    app.server
        .post("/setup")
        .add_header(name, value)
        .form(&SetupFormData {
            email: "admin@example.com",
            first_name: "Alice",
            last_name: "Admin",
            password: "SecurePass1!",
        })
        .await
        .assert_status_ok();

    // GET /setup must now redirect because has_admin() returns true
    let response = app.server.get("/setup").expect_failure().await;
    response.assert_status(StatusCode::SEE_OTHER);
}
