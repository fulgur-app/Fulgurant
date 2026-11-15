mod common;

use axum::http::StatusCode;
use axum::http::header::{HeaderName, HeaderValue};
use common::{
    auth_helpers::{create_admin_user, extract_csrf_token},
    test_app::TestApp,
};
use fulgurant::db::DbPool;
use fulgurant::{db_execute, db_fetch_one};
use serde::Serialize;

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
async fn remove_all_admins(pool: &DbPool) {
    db_execute!(
        pool,
        "DELETE FROM devices WHERE user_id IN (SELECT id FROM users WHERE role = 'Admin')"
    )
    .unwrap();
    db_execute!(pool, "DELETE FROM users WHERE role = 'Admin'").unwrap();
}

/// Count the users holding the `Admin` role
///
/// ### Arguments
/// - `pool`: The test database pool
///
/// ### Returns
/// - `i64`: The number of admin users
async fn count_admins(pool: &DbPool) -> i64 {
    let (count,) = db_fetch_one!(
        pool,
        "SELECT COUNT(*) FROM users WHERE role = 'Admin'",
        (i64,)
    )
    .unwrap();
    count
}

/// Count the users registered with the given email
///
/// ### Arguments
/// - `pool`: The test database pool
/// - `email`: The email to look up
///
/// ### Returns
/// - `i64`: The number of users with that email
async fn count_users_with_email(pool: &DbPool, email: &str) -> i64 {
    let (count,) = db_fetch_one!(
        pool,
        "SELECT COUNT(*) FROM users WHERE email = ?",
        (i64,),
        email
    )
    .unwrap();
    count
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

#[tokio::test]
async fn test_create_admin_rejected_when_admin_exists() {
    let app = TestApp::new().await;
    create_admin_user(&app.pool).await;

    let login_page = app.server.get("/login").await;
    let (name, value) = csrf_header(&extract_csrf_token(&login_page.text()));

    let response = app
        .server
        .post("/setup")
        .add_header(name, value)
        .form(&SetupFormData {
            email: "intruder@example.com",
            first_name: "Eve",
            last_name: "Intruder",
            password: "SecurePass1!",
        })
        .await;

    response.assert_status_ok();
    assert_eq!(response.header("HX-Redirect"), "/login");
    assert_eq!(count_admins(&app.pool).await, 1);
    assert_eq!(
        count_users_with_email(&app.pool, "intruder@example.com").await,
        0
    );
}

#[tokio::test]
async fn test_create_admin_invalid_email() {
    let app = TestApp::with_setup_needed().await;
    remove_all_admins(&app.pool).await;

    let page = app.server.get("/setup").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .post("/setup")
        .add_header(name, value)
        .form(&SetupFormData {
            email: "not-an-email",
            first_name: "Alice",
            last_name: "Admin",
            password: "SecurePass1!",
        })
        .await;

    response.assert_status_ok();
    assert!(response.text().contains("Invalid email address"));
    assert_eq!(count_admins(&app.pool).await, 0);
}

#[tokio::test]
async fn test_create_admin_empty_name() {
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
            first_name: "   ",
            last_name: "Admin",
            password: "SecurePass1!",
        })
        .await;

    response.assert_status_ok();
    assert!(
        response
            .text()
            .contains("First name and last name are required")
    );
    assert_eq!(count_admins(&app.pool).await, 0);
}

// ─────────────────────────────────────────────
// require_setup_complete
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_unauthenticated_request_redirects_to_setup_when_needed() {
    let app = TestApp::with_setup_needed().await;
    remove_all_admins(&app.pool).await;

    let dashboard = app.server.get("/").expect_failure().await;
    dashboard.assert_status(StatusCode::SEE_OTHER);
    assert_eq!(dashboard.header("location"), "/login");

    let login_page = app.server.get("/login").expect_failure().await;
    login_page.assert_status(StatusCode::SEE_OTHER);
    assert_eq!(login_page.header("location"), "/setup");
}
