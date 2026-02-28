mod common;

use axum::http::StatusCode;
use axum::http::header::{HeaderName, HeaderValue};
use common::{
    auth_helpers::{
        create_user_with_force_update, create_verified_user, extract_csrf_token, login,
    },
    test_app::{TestApp, TestAppOptions},
};
use serde::Serialize;

#[derive(Serialize)]
struct LoginFormData<'a> {
    email: &'a str,
    password: &'a str,
}

#[derive(Serialize)]
struct RegisterFormData<'a> {
    email: &'a str,
    first_name: &'a str,
    last_name: &'a str,
    password: &'a str,
}

#[derive(Serialize)]
struct RegisterStep2FormData<'a> {
    email: &'a str,
    code: &'a str,
}

#[derive(Serialize)]
struct PasswordFormData<'a> {
    password: &'a str,
}

#[derive(Serialize)]
struct EmailFormData<'a> {
    email: &'a str,
}

#[derive(Serialize)]
struct ResetPasswordFormData<'a> {
    email: &'a str,
    password: &'a str,
}

/// Build the `x-csrf-token` header from a token string
fn csrf_header(token: &str) -> (HeaderName, HeaderValue) {
    (
        HeaderName::from_static("x-csrf-token"),
        HeaderValue::from_str(token).unwrap(),
    )
}

// ─────────────────────────────────────────────
// GET /login
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_login_page_renders() {
    let app = TestApp::new().await;

    let response = app.server.get("/login").await;

    response.assert_status_ok();
    assert!(response.text().contains("csrf-token"));
}

// ─────────────────────────────────────────────
// POST /login
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_login_success() {
    let app = TestApp::new().await;
    create_verified_user(&app.pool, "user@test.com", "Password123!").await;

    let page = app.server.get("/login").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .post("/login")
        .add_header(name, value)
        .form(&LoginFormData {
            email: "user@test.com",
            password: "Password123!",
        })
        .await;

    response.assert_status_ok();
    assert_eq!(response.header("HX-Redirect"), "/");
}

#[tokio::test]
async fn test_login_wrong_password() {
    let app = TestApp::new().await;
    create_verified_user(&app.pool, "user@test.com", "Password123!").await;

    let page = app.server.get("/login").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .post("/login")
        .add_header(name, value)
        .form(&LoginFormData {
            email: "user@test.com",
            password: "WrongPass1!",
        })
        .await;

    response.assert_status_ok();
    assert!(response.text().contains("Invalid email or password"));
}

#[tokio::test]
async fn test_login_nonexistent_user() {
    let app = TestApp::new().await;

    let page = app.server.get("/login").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .post("/login")
        .add_header(name, value)
        .form(&LoginFormData {
            email: "nobody@test.com",
            password: "Password123!",
        })
        .await;

    response.assert_status_ok();
    assert!(response.text().contains("Invalid email or password"));
}

// ─────────────────────────────────────────────
// GET /register
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_register_page_when_enabled() {
    let app = TestApp::new().await;

    let response = app.server.get("/register").await;

    response.assert_status_ok();
    assert!(response.text().contains("csrf-token"));
}

#[tokio::test]
async fn test_register_page_when_disabled() {
    let app = TestApp::with_options(TestAppOptions {
        can_register: false,
        ..TestAppOptions::default()
    })
    .await;

    let response = app.server.get("/register").await;

    response.assert_status_ok();
    assert!(response.text().contains("not allowed"));
}

// ─────────────────────────────────────────────
// POST /auth/register
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_register_success() {
    let app = TestApp::new().await;

    let page = app.server.get("/register").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .post("/auth/register")
        .add_header(name, value)
        .form(&RegisterFormData {
            email: "new@test.com",
            first_name: "Test",
            last_name: "User",
            password: "Password123!",
        })
        .await;

    response.assert_status_ok();
    // Step 2 form: email verification code input shown with the submitted address
    assert!(response.text().contains("new@test.com"));
}

#[tokio::test]
async fn test_register_weak_password() {
    let app = TestApp::new().await;

    let page = app.server.get("/register").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .post("/auth/register")
        .add_header(name, value)
        .form(&RegisterFormData {
            email: "new@test.com",
            first_name: "Test",
            last_name: "User",
            password: "weak",
        })
        .await;

    response.assert_status_ok();
    assert!(response.text().contains("Invalid password"));
}

#[tokio::test]
async fn test_register_duplicate_email() {
    let app = TestApp::new().await;
    create_verified_user(&app.pool, "existing@test.com", "Password123!").await;

    let page = app.server.get("/register").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .post("/auth/register")
        .add_header(name, value)
        .form(&RegisterFormData {
            email: "existing@test.com",
            first_name: "Test",
            last_name: "User",
            password: "Password123!",
        })
        .await;

    response.assert_status_ok();
    assert!(response.text().contains("already registered"));
}

#[tokio::test]
async fn test_register_empty_name() {
    let app = TestApp::new().await;

    let page = app.server.get("/register").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .post("/auth/register")
        .add_header(name, value)
        .form(&RegisterFormData {
            email: "new@test.com",
            first_name: "",
            last_name: "User",
            password: "Password123!",
        })
        .await;

    response.assert_status_ok();
    assert!(response.text().contains("First name cannot be empty"));
}

#[tokio::test]
async fn test_register_step2_invalid_code_shows_error_step2() {
    let app = TestApp::new().await;

    let page = app.server.get("/register").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let step1_response = app
        .server
        .post("/auth/register")
        .add_header(name.clone(), value.clone())
        .form(&RegisterFormData {
            email: "verify@test.com",
            first_name: "Verify",
            last_name: "User",
            password: "Password123!",
        })
        .await;

    step1_response.assert_status_ok();
    assert!(step1_response.text().contains("Check your email!"));

    let step2_response = app
        .server
        .post("/auth/register/step2")
        .add_header(name, value)
        .form(&RegisterStep2FormData {
            email: "verify@test.com",
            code: "000000",
        })
        .await;

    step2_response.assert_status_ok();
    assert!(step2_response.text().contains("Invalid verification code"));
    assert!(step2_response.text().contains("Check your email!"));
    assert!(!step2_response.text().contains("Congratulations"));
}

// ─────────────────────────────────────────────
// POST /logout
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_logout_clears_session() {
    let app = TestApp::new().await;
    create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    login(&app.server, "user@test.com", "Password123!").await;

    // Confirm the session is active
    let dashboard = app.server.get("/").await;
    dashboard.assert_status_ok();
    let (name, value) = csrf_header(&extract_csrf_token(&dashboard.text()));

    let logout_response = app.server.post("/logout").add_header(name, value).await;
    logout_response.assert_status_ok();
    assert_eq!(logout_response.header("HX-Redirect"), "/logout");

    // After logout, / must redirect to login
    let response = app.server.get("/").expect_failure().await;
    response.assert_status(StatusCode::SEE_OTHER);
}

// ─────────────────────────────────────────────
// POST /force-password-update
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_force_password_success() {
    let app = TestApp::new().await;
    create_user_with_force_update(&app.pool, "forced@test.com", "OldPassword1!").await;
    login(&app.server, "forced@test.com", "OldPassword1!").await;

    let page = app.server.get("/force-password-update").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .post("/force-password-update")
        .add_header(name, value)
        .form(&PasswordFormData {
            password: "NewPassword2!",
        })
        .await;

    response.assert_status_ok();
    assert_eq!(response.header("HX-Redirect"), "/");
}

#[tokio::test]
async fn test_force_password_weak() {
    let app = TestApp::new().await;
    create_user_with_force_update(&app.pool, "forced@test.com", "OldPassword1!").await;
    login(&app.server, "forced@test.com", "OldPassword1!").await;

    let page = app.server.get("/force-password-update").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .post("/force-password-update")
        .add_header(name, value)
        .form(&PasswordFormData { password: "weak" })
        .await;

    response.assert_status_ok();
    assert!(response.text().contains("Password must be"));
}

// ─────────────────────────────────────────────
// POST /auth/forgot-password
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_forgot_password_sends_code() {
    let app = TestApp::new().await;
    create_verified_user(&app.pool, "user@test.com", "Password123!").await;

    let page = app.server.get("/auth/forgot-password").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .post("/auth/forgot-password")
        .add_header(name, value)
        .form(&EmailFormData {
            email: "user@test.com",
        })
        .await;

    response.assert_status_ok();
    // Step 2 form shown: verification code input for the given email
    assert!(response.text().contains("user@test.com"));
}

// ─────────────────────────────────────────────
// POST /auth/forgot-password/reset
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_reset_password_success() {
    let app = TestApp::new().await;
    create_verified_user(&app.pool, "user@test.com", "Password123!").await;

    let page = app.server.get("/auth/forgot-password").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .post("/auth/forgot-password/reset")
        .add_header(name, value)
        .form(&ResetPasswordFormData {
            email: "user@test.com",
            password: "NewPassword2!",
        })
        .await;

    response.assert_status_ok();
    // Verify the new password now works
    login(&app.server, "user@test.com", "NewPassword2!").await;
}
