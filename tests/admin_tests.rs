mod common;

use axum::http::StatusCode;
use axum::http::header::{HeaderName, HeaderValue};
use common::{
    auth_helpers::{create_verified_user, extract_csrf_token, login, login_as_admin},
    test_app::TestApp,
};
use serde::Serialize;

#[derive(Serialize)]
struct CreateUserFormData<'a> {
    email: &'a str,
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
// GET /admin
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_admin_page_for_admin() {
    let app = TestApp::new().await;
    login_as_admin(&app.server, &app.pool).await;

    let response = app.server.get("/admin").await;

    response.assert_status_ok();
    assert!(response.text().contains("Admin"));
}

#[tokio::test]
async fn test_admin_page_forbidden_for_user() {
    let app = TestApp::new().await;
    create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    login(&app.server, "user@test.com", "Password123!").await;

    let response = app.server.get("/admin").expect_failure().await;

    // require_admin uses AppError::InternalError for non-admin users → 500
    response.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
}

// ─────────────────────────────────────────────
// GET /admin/users/search
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_search_by_email() {
    let app = TestApp::new().await;
    login_as_admin(&app.server, &app.pool).await;
    create_verified_user(&app.pool, "alice@example.com", "Password123!").await;
    create_verified_user(&app.pool, "bob@example.com", "Password123!").await;

    let response = app
        .server
        .get("/admin/users/search")
        .add_query_param("email", "alice")
        .await;

    response.assert_status_ok();
    assert!(response.text().contains("alice@example.com"));
    assert!(!response.text().contains("bob@example.com"));
}

#[tokio::test]
async fn test_search_pagination() {
    let app = TestApp::new().await;
    login_as_admin(&app.server, &app.pool).await;
    create_verified_user(&app.pool, "user1@test.com", "Password123!").await;
    create_verified_user(&app.pool, "user2@test.com", "Password123!").await;
    create_verified_user(&app.pool, "user3@test.com", "Password123!").await;

    // 4 total (admin + 3 users), page_size=2 → page 2 has 2 remaining
    let response = app
        .server
        .get("/admin/users/search")
        .add_query_param("page", "2")
        .add_query_param("page_size", "2")
        .await;

    response.assert_status_ok();
}

// ─────────────────────────────────────────────
// POST /user/{id}/change-role
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_toggle_role() {
    let app = TestApp::new().await;
    login_as_admin(&app.server, &app.pool).await;
    let user_id = create_verified_user(&app.pool, "user@test.com", "Password123!").await;

    let page = app.server.get("/admin").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .post(&format!("/user/{}/change-role", user_id))
        .add_header(name, value)
        .await;

    response.assert_status_ok();
    assert!(response.text().contains("Role successfully changed"));
}

// ─────────────────────────────────────────────
// DELETE /user/{id}
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_delete_user_success() {
    let app = TestApp::new().await;
    login_as_admin(&app.server, &app.pool).await;
    let user_id = create_verified_user(&app.pool, "user@test.com", "Password123!").await;

    let page = app.server.get("/admin").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .delete(&format!("/user/{}", user_id))
        .add_header(name, value)
        .await;

    response.assert_status_ok();
    assert!(response.text().contains("has been deleted"));
}

// ─────────────────────────────────────────────
// POST /user/create
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_create_user_success() {
    let app = TestApp::new().await;
    login_as_admin(&app.server, &app.pool).await;

    let page = app.server.get("/admin").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .post("/user/create")
        .add_header(name, value)
        .form(&CreateUserFormData {
            email: "newuser@example.com",
            first_name: "Alice",
            last_name: "Smith",
        })
        .await;

    response.assert_status_ok();
    assert!(response.text().contains("User successfully created"));
}

#[tokio::test]
async fn test_create_user_invalid_email() {
    let app = TestApp::new().await;
    login_as_admin(&app.server, &app.pool).await;

    let page = app.server.get("/admin").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .post("/user/create")
        .add_header(name, value)
        .form(&CreateUserFormData {
            email: "not-an-email",
            first_name: "Alice",
            last_name: "Smith",
        })
        .expect_failure()
        .await;

    // create_user_from_admin uses AppError::InternalError for invalid email → 500
    response.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
}
