mod common;

use axum::http::StatusCode;
use axum::http::header::{HeaderName, HeaderValue};
use common::{
    auth_helpers::{
        create_unverified_user, create_user_with_force_update, create_verified_user,
        extract_csrf_token, login, try_login,
    },
    test_app::{TestApp, TestAppOptions},
};
use fulgurant::db::DbPool;
use fulgurant::session::{FulgurSessionStore, SESSION_USER_ID, SessionRepository};
use fulgurant::users::UserRepository;
use fulgurant::verification_code::VerificationCodeRepository;
use fulgurant::{db_execute_dual, db_fetch_one, db_fetch_one_dual};
use serde::Serialize;

#[derive(Serialize)]
struct LoginFormData<'a> {
    email: &'a str,
    password: &'a str,
}

#[derive(Serialize)]
struct RememberMeLoginFormData<'a> {
    email: &'a str,
    password: &'a str,
    remember_me: &'a str,
}

#[derive(Serialize)]
struct VerifyCodeFormData<'a> {
    email: &'a str,
    code: &'a str,
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

/// Read the `expires_at` unix timestamp of the only session owned by `user_id`
async fn session_expires_at(pool: &DbPool, user_id: i32) -> i64 {
    let (expires_at,) = db_fetch_one_dual!(
        pool,
        sqlite: "SELECT expires_at FROM sessions WHERE user_id = ?",
        postgres: "SELECT EXTRACT(EPOCH FROM expires_at)::BIGINT FROM sessions WHERE user_id = $1",
        (i64,),
        user_id
    )
    .unwrap();
    expires_at
}

#[tokio::test]
async fn test_remember_me_keeps_30_day_expiry_after_first_page_load() {
    let app = TestApp::new().await;
    let user_id = create_verified_user(&app.pool, "user@test.com", "Password123!").await;

    let page = app.server.get("/login").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));
    app.server
        .post("/login")
        .add_header(name, value)
        .form(&RememberMeLoginFormData {
            email: "user@test.com",
            password: "Password123!",
            remember_me: "on",
        })
        .await
        .assert_status_ok();

    let dashboard = app.server.get("/").await;
    dashboard.assert_status_ok();

    let thirty_days = time::Duration::days(30);
    let max_age = dashboard
        .cookie("id")
        .max_age()
        .expect("session cookie should carry a Max-Age");
    assert!(max_age > thirty_days - time::Duration::minutes(1));
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let expires_at = session_expires_at(&app.pool, user_id).await;
    assert!(expires_at > now + thirty_days.whole_seconds() - 60);
}

#[tokio::test]
async fn test_session_idle_timeout_slides_on_activity() {
    let app = TestApp::new().await;
    let user_id = create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    login(&app.server, "user@test.com", "Password123!").await;
    app.server.get("/").await.assert_status_ok();

    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    db_execute_dual!(
        app.pool,
        sqlite: "UPDATE sessions \
                 SET expires_at = ?, \
                     data = CAST(json_set(CAST(data AS TEXT), '$.data.last_seen', ?) AS BLOB) \
                 WHERE user_id = ?",
        postgres: "UPDATE sessions \
                   SET expires_at = to_timestamp($1), \
                       data = convert_to(jsonb_set(convert_from(data, 'UTF8')::jsonb, \
                                                   '{data,last_seen}', to_jsonb($2::BIGINT))::TEXT, 'UTF8') \
                   WHERE user_id = $3",
        now + 600,
        now - 120,
        user_id
    )
    .unwrap();

    let dashboard = app.server.get("/").await;
    dashboard.assert_status_ok();

    let one_hour = time::Duration::hours(1);
    let max_age = dashboard
        .cookie("id")
        .max_age()
        .expect("session cookie should carry a Max-Age");
    assert!(max_age > one_hour - time::Duration::minutes(1));
    assert!(max_age <= one_hour);
    let expires_at = session_expires_at(&app.pool, user_id).await;
    assert!(expires_at > now + one_hour.whole_seconds() - 60);
}

#[tokio::test]
async fn test_session_not_rewritten_within_activity_refresh_interval() {
    let app = TestApp::new().await;
    create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    login(&app.server, "user@test.com", "Password123!").await;
    app.server.get("/").await.assert_status_ok();

    let dashboard = app.server.get("/").await;

    dashboard.assert_status_ok();
    assert!(dashboard.maybe_cookie("id").is_none());
}

#[tokio::test]
async fn test_login_rate_limit_ignores_spoofed_forwarded_for() {
    let app = TestApp::new().await;
    let forwarded_for = HeaderName::from_static("x-forwarded-for");

    let mut last_status = StatusCode::OK;
    for i in 0..6 {
        let spoofed_ip = HeaderValue::from_str(&format!("198.51.100.{i}")).unwrap();
        last_status = app
            .server
            .post("/login")
            .add_header(forwarded_for.clone(), spoofed_ip)
            .form(&LoginFormData {
                email: "user@test.com",
                password: "WrongPass1!",
            })
            .expect_failure()
            .await
            .status_code();
    }

    assert_eq!(last_status, StatusCode::TOO_MANY_REQUESTS);
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

#[tokio::test]
async fn test_login_unverified_user_rejected() {
    let app = TestApp::new().await;
    create_unverified_user(&app.pool, "unverified@test.com", "Password123!").await;

    let page = app.server.get("/login").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .post("/login")
        .add_header(name, value)
        .form(&LoginFormData {
            email: "unverified@test.com",
            password: "Password123!",
        })
        .await;

    response.assert_status_ok();
    // Correct credentials but unverified email: same generic error as a bad
    // password, and no authenticated redirect (no enumeration oracle).
    assert!(response.text().contains("Invalid email or password"));
    assert!(response.headers().get("HX-Redirect").is_none());
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

#[tokio::test]
async fn test_register_full_flow_verifies_user_and_allows_login() {
    let app = TestApp::new().await;

    let page = app.server.get("/register").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    app.server
        .post("/auth/register")
        .add_header(name.clone(), value.clone())
        .form(&RegisterFormData {
            email: "complete@test.com",
            first_name: "Complete",
            last_name: "User",
            password: "Password123!",
        })
        .await
        .assert_status_ok();

    // created_at has 1-second resolution, so replace the random step 1 code instead of
    // relying on ordering to pick this known one.
    let verification_codes = VerificationCodeRepository::new(app.pool.clone());
    verification_codes
        .delete_for("complete@test.com".to_string(), "registration".to_string())
        .await
        .unwrap();
    verification_codes
        .create(
            "complete@test.com".to_string(),
            "123456".to_string(),
            "registration".to_string(),
        )
        .await
        .unwrap();

    let step2_response = app
        .server
        .post("/auth/register/step2")
        .add_header(name.clone(), value.clone())
        .form(&RegisterStep2FormData {
            email: "complete@test.com",
            code: "123456",
        })
        .await;

    step2_response.assert_status_ok();
    assert!(
        step2_response
            .text()
            .contains("Congratulations, Complete! You're registered!")
    );

    let user = UserRepository::new(app.pool.clone())
        .get_by_email("complete@test.com".to_string())
        .await
        .unwrap()
        .expect("registered user should exist");
    assert!(user.email_verified);

    let login_response = app
        .server
        .post("/login")
        .add_header(name, value)
        .form(&LoginFormData {
            email: "complete@test.com",
            password: "Password123!",
        })
        .await;

    login_response.assert_status_ok();
    assert_eq!(login_response.header("HX-Redirect"), "/");
}

#[tokio::test]
async fn test_register_step2_unknown_email_is_unauthorized() {
    let app = TestApp::new().await;

    let page = app.server.get("/register").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .post("/auth/register/step2")
        .add_header(name, value)
        .form(&RegisterStep2FormData {
            email: "nobody@test.com",
            code: "123456",
        })
        .expect_failure()
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

/// Submit registration step 1 with the given names and email and return the response body
async fn register_step1_body(
    app: &TestApp,
    email: &str,
    first_name: &str,
    last_name: &str,
) -> String {
    let page = app.server.get("/register").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .post("/auth/register")
        .add_header(name, value)
        .form(&RegisterFormData {
            email,
            first_name,
            last_name,
            password: "Password123!",
        })
        .await;

    response.assert_status_ok();
    response.text()
}

#[tokio::test]
async fn test_register_empty_last_name() {
    let app = TestApp::new().await;

    let body = register_step1_body(&app, "new@test.com", "Test", "").await;

    assert!(body.contains("Last name cannot be empty"));
}

#[tokio::test]
async fn test_register_last_name_too_long() {
    let app = TestApp::new().await;
    let long_last_name = "a".repeat(51);

    let body = register_step1_body(&app, "new@test.com", "Test", &long_last_name).await;

    assert!(body.contains("Names cannot exceed 50 characters"));
}

#[tokio::test]
async fn test_register_invalid_email() {
    let app = TestApp::new().await;

    let body = register_step1_body(&app, "not-an-email", "Test", "User").await;

    assert!(body.contains("Invalid email"));
}

#[tokio::test]
async fn test_register_verification_code_limit_creates_no_user() {
    let app = TestApp::new().await;
    let code_repository = VerificationCodeRepository::new(app.pool.clone());
    for code in ["111111", "222222", "333333"] {
        code_repository
            .create(
                "limited@test.com".to_string(),
                code.to_string(),
                "registration".to_string(),
            )
            .await
            .unwrap();
    }

    let body = register_step1_body(&app, "limited@test.com", "Test", "User").await;

    assert!(body.contains("maximum number of verification codes"));
    let user = UserRepository::new(app.pool.clone())
        .get_by_email("limited@test.com".to_string())
        .await
        .unwrap();
    assert!(user.is_none());
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

#[tokio::test]
async fn test_force_password_page_redirects_without_pending_update() {
    let app = TestApp::new().await;
    create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    login(&app.server, "user@test.com", "Password123!").await;

    let response = app
        .server
        .get("/force-password-update")
        .expect_failure()
        .await;

    response.assert_status(StatusCode::SEE_OTHER);
    assert_eq!(response.header("location"), "/");
}

#[tokio::test]
async fn test_force_password_rejected_without_pending_update() {
    let app = TestApp::new().await;
    let user_id = create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    login(&app.server, "user@test.com", "Password123!").await;
    let original_hash = password_hash_for(&app.pool, user_id).await;

    let page = app.server.get("/settings").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .post("/force-password-update")
        .add_header(name, value)
        .form(&PasswordFormData {
            password: "NewPassword2!",
        })
        .expect_failure()
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(
        password_hash_for(&app.pool, user_id).await,
        original_hash,
        "password must not change without a pending forced update"
    );
}

/// Read the stored password hash of a user
///
/// ### Arguments
/// - `pool`: The test database pool
/// - `user_id`: The user's ID
///
/// ### Returns
/// - `String`: The stored Argon2 password hash
async fn password_hash_for(pool: &DbPool, user_id: i32) -> String {
    let (password_hash,) = db_fetch_one!(
        pool,
        "SELECT password_hash FROM users WHERE id = ?",
        (String,),
        user_id
    )
    .unwrap();
    password_hash
}

#[tokio::test]
async fn test_force_password_same_password_rejected() {
    let app = TestApp::new().await;
    let user_id =
        create_user_with_force_update(&app.pool, "forced@test.com", "OldPassword1!").await;
    login(&app.server, "forced@test.com", "OldPassword1!").await;

    let page = app.server.get("/force-password-update").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));

    let response = app
        .server
        .post("/force-password-update")
        .add_header(name, value)
        .form(&PasswordFormData {
            password: "OldPassword1!",
        })
        .await;

    response.assert_status_ok();
    assert!(
        response
            .text()
            .contains("New password must be different from your current password.")
    );
    let user = UserRepository::new(app.pool.clone())
        .get_by_id(user_id)
        .await
        .unwrap()
        .unwrap();
    assert!(user.force_password_update);
    let gated = app.server.get("/").expect_failure().await;
    gated.assert_status(StatusCode::SEE_OTHER);
    assert_eq!(gated.header("location"), "/force-password-update");
}

// ─────────────────────────────────────────────
// require_auth force-password-update gate
// ─────────────────────────────────────────────

#[tokio::test]
async fn test_force_password_gate_redirects_protected_pages() {
    let app = TestApp::new().await;
    create_user_with_force_update(&app.pool, "forced@test.com", "OldPassword1!").await;
    login(&app.server, "forced@test.com", "OldPassword1!").await;

    for path in ["/", "/settings", "/admin"] {
        let response = app.server.get(path).expect_failure().await;
        response.assert_status(StatusCode::SEE_OTHER);
        assert_eq!(
            response.header("location"),
            "/force-password-update",
            "{path} should redirect to the forced password update"
        );
    }
}

#[tokio::test]
async fn test_force_password_gate_allows_update_page_logout_and_assets() {
    let app = TestApp::new().await;
    create_user_with_force_update(&app.pool, "forced@test.com", "OldPassword1!").await;
    login(&app.server, "forced@test.com", "OldPassword1!").await;

    app.server
        .get("/force-password-update")
        .await
        .assert_status_ok();
    app.server
        .get("/assets/favicon.svg")
        .await
        .assert_status_ok();
    app.server.get("/logout").await.assert_status_ok();
}

#[tokio::test]
async fn test_force_password_gate_lifted_after_update() {
    let app = TestApp::new().await;
    create_user_with_force_update(&app.pool, "forced@test.com", "OldPassword1!").await;
    login(&app.server, "forced@test.com", "OldPassword1!").await;

    let page = app.server.get("/force-password-update").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));
    app.server
        .post("/force-password-update")
        .add_header(name, value)
        .form(&PasswordFormData {
            password: "NewPassword2!",
        })
        .await
        .assert_status_ok();

    app.server.get("/").await.assert_status_ok();
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

    // Step 1: load the page to obtain a CSRF token and start a session.
    let page = app.server.get("/auth/forgot-password").await;
    let csrf = extract_csrf_token(&page.text());

    // Seed a known verification code so step 2 can succeed deterministically.
    VerificationCodeRepository::new(app.pool.clone())
        .create(
            "user@test.com".to_string(),
            "123456".to_string(),
            "password_reset".to_string(),
        )
        .await
        .unwrap();

    // Step 2: verify the code, which authorizes the reset for this session.
    let (name, value) = csrf_header(&csrf);
    let step2 = app
        .server
        .post("/auth/forgot-password/verify")
        .add_header(name, value)
        .form(&VerifyCodeFormData {
            email: "user@test.com",
            code: "123456",
        })
        .await;
    step2.assert_status_ok();

    // Step 3: reset succeeds because the session now carries the authorization.
    let (name, value) = csrf_header(&csrf);
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
    assert_eq!(
        try_login(&app.server, "user@test.com", "Password123!").await,
        None,
        "the old password must no longer log in"
    );
    assert_eq!(
        login(&app.server, "user@test.com", "NewPassword2!").await,
        "/"
    );
}

#[tokio::test]
async fn test_reset_password_without_step2_is_rejected() {
    let app = TestApp::new().await;
    create_verified_user(&app.pool, "user@test.com", "Password123!").await;

    // Attacker calls step 3 directly with a valid CSRF token but never passed step 2.
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
    assert!(
        response.text().contains("expired or is invalid"),
        "reset without step 2 should be refused"
    );

    // The new password must not have taken effect: logging in with it fails.
    let page = app.server.get("/login").await;
    let (name, value) = csrf_header(&extract_csrf_token(&page.text()));
    let login_attempt = app
        .server
        .post("/login")
        .add_header(name, value)
        .form(&LoginFormData {
            email: "user@test.com",
            password: "NewPassword2!",
        })
        .await;
    assert!(
        login_attempt.text().contains("Invalid email or password"),
        "the password must not have been changed"
    );
}

// ─────────────────────────────────────────────
// Forgot-password failure modes
// ─────────────────────────────────────────────

/// Marker rendered only by the step-3 (new password) form
const RESET_FORM_MARKER: &str = "/auth/forgot-password/reset";

/// Marker rendered only by the reset success partial
const RESET_SUCCESS_MARKER: &str = "Password Reset Successful!";

/// Load the forgot-password page and return its CSRF token (also starts the session)
async fn forgot_password_csrf(app: &TestApp) -> String {
    let page = app.server.get("/auth/forgot-password").await;
    extract_csrf_token(&page.text())
}

/// Seed a known `password_reset` verification code for `email`
async fn seed_reset_code(pool: &DbPool, email: &str, code: &str) {
    VerificationCodeRepository::new(pool.clone())
        .create(
            email.to_string(),
            code.to_string(),
            "password_reset".to_string(),
        )
        .await
        .unwrap();
}

/// Count the active `password_reset` verification codes for `email`
async fn active_reset_codes(pool: &DbPool, email: &str) -> i32 {
    VerificationCodeRepository::new(pool.clone())
        .count_active_codes(email.to_string(), "password_reset".to_string())
        .await
        .unwrap()
}

/// Check whether the stored password hash of `email` matches `password`
async fn password_matches(pool: &DbPool, email: &str, password: &str) -> bool {
    use argon2::{Argon2, PasswordHash, PasswordVerifier};

    let user = UserRepository::new(pool.clone())
        .get_by_email(email.to_string())
        .await
        .unwrap()
        .expect("user should exist");
    let parsed = PasswordHash::new(&user.password_hash).unwrap();
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Submit forgot-password step 1 and return the response body
async fn post_forgot_step1(app: &TestApp, csrf: &str, email: &str) -> String {
    let (name, value) = csrf_header(csrf);
    let response = app
        .server
        .post("/auth/forgot-password")
        .add_header(name, value)
        .form(&EmailFormData { email })
        .await;
    response.assert_status_ok();
    response.text()
}

/// Submit forgot-password step 2 (code verification) and return the response body
async fn post_forgot_verify(app: &TestApp, csrf: &str, email: &str, code: &str) -> String {
    let (name, value) = csrf_header(csrf);
    let response = app
        .server
        .post("/auth/forgot-password/verify")
        .add_header(name, value)
        .form(&VerifyCodeFormData { email, code })
        .await;
    response.assert_status_ok();
    response.text()
}

/// Submit forgot-password step 3 (new password) and return the response body
async fn post_forgot_reset(app: &TestApp, csrf: &str, email: &str, password: &str) -> String {
    let (name, value) = csrf_header(csrf);
    let response = app
        .server
        .post("/auth/forgot-password/reset")
        .add_header(name, value)
        .form(&ResetPasswordFormData { email, password })
        .await;
    response.assert_status_ok();
    response.text()
}

/// Call the resend route for `email` and return the response body
async fn get_forgot_resend(app: &TestApp, email: &str) -> String {
    let response = app
        .server
        .get("/auth/forgot-password/resend")
        .add_query_param("email", email)
        .await;
    response.assert_status_ok();
    response.text()
}

#[tokio::test]
async fn test_forgot_password_unknown_email_looks_like_known_email() {
    let app = TestApp::new().await;
    create_verified_user(&app.pool, "known@test.com", "Password123!").await;
    let csrf = forgot_password_csrf(&app).await;

    let known_body = post_forgot_step1(&app, &csrf, "known@test.com").await;
    let unknown_body = post_forgot_step1(&app, &csrf, "unknown@test.com").await;

    assert_eq!(
        known_body.replace("known@test.com", "EMAIL"),
        unknown_body.replace("unknown@test.com", "EMAIL"),
        "step 1 must not reveal whether an account exists"
    );
    assert_eq!(active_reset_codes(&app.pool, "known@test.com").await, 1);
    assert_eq!(active_reset_codes(&app.pool, "unknown@test.com").await, 0);
}

#[tokio::test]
async fn test_forgot_password_step1_respects_code_limit() {
    let app = TestApp::new().await;
    create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    for code in ["111111", "222222", "333333"] {
        seed_reset_code(&app.pool, "user@test.com", code).await;
    }
    let csrf = forgot_password_csrf(&app).await;

    let body = post_forgot_step1(&app, &csrf, "user@test.com").await;

    assert!(body.contains("/auth/forgot-password/verify"));
    assert_eq!(active_reset_codes(&app.pool, "user@test.com").await, 3);
}

#[tokio::test]
async fn test_forgot_password_wrong_code_counts_down_then_locks() {
    let app = TestApp::new().await;
    create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    seed_reset_code(&app.pool, "user@test.com", "123456").await;
    let csrf = forgot_password_csrf(&app).await;

    let first = post_forgot_verify(&app, &csrf, "user@test.com", "000000").await;
    assert!(first.contains("2 attempt(s) remaining"));
    let second = post_forgot_verify(&app, &csrf, "user@test.com", "000000").await;
    assert!(second.contains("1 attempt(s) remaining"));
    let third = post_forgot_verify(&app, &csrf, "user@test.com", "000000").await;
    assert!(third.contains("Too many failed attempts"));

    let correct_after_lock = post_forgot_verify(&app, &csrf, "user@test.com", "123456").await;
    assert!(correct_after_lock.contains("Too many failed attempts"));
    assert!(
        !correct_after_lock.contains(RESET_FORM_MARKER),
        "a locked code must not unlock step 3"
    );
}

#[tokio::test]
async fn test_forgot_password_expired_code_is_refused() {
    let app = TestApp::new().await;
    create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    seed_reset_code(&app.pool, "user@test.com", "123456").await;
    let past = time::OffsetDateTime::now_utc().unix_timestamp() - 60;
    db_execute_dual!(
        app.pool,
        sqlite: "UPDATE verification_codes SET expires_at = ? WHERE email = ?",
        postgres: "UPDATE verification_codes SET expires_at = to_timestamp($1) WHERE email = $2",
        past,
        "user@test.com"
    )
    .unwrap();
    let csrf = forgot_password_csrf(&app).await;

    let body = post_forgot_verify(&app, &csrf, "user@test.com", "123456").await;

    assert!(body.contains("Verification code has expired"));
    assert!(!body.contains(RESET_FORM_MARKER));
}

#[tokio::test]
async fn test_forgot_password_missing_code_is_refused() {
    let app = TestApp::new().await;
    create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    let csrf = forgot_password_csrf(&app).await;

    let body = post_forgot_verify(&app, &csrf, "user@test.com", "123456").await;

    assert!(body.contains("No verification code found"));
    assert!(!body.contains(RESET_FORM_MARKER));
}

#[tokio::test]
async fn test_reset_password_weak_password_is_rejected() {
    let app = TestApp::new().await;
    create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    seed_reset_code(&app.pool, "user@test.com", "123456").await;
    let csrf = forgot_password_csrf(&app).await;
    post_forgot_verify(&app, &csrf, "user@test.com", "123456").await;

    let body = post_forgot_reset(&app, &csrf, "user@test.com", "weak").await;

    assert!(body.contains("Password must be 8-64 characters long"));
    assert!(password_matches(&app.pool, "user@test.com", "Password123!").await);
}

#[tokio::test]
async fn test_forgot_password_resend_creates_code_for_known_email_only() {
    let app = TestApp::new().await;
    create_verified_user(&app.pool, "known@test.com", "Password123!").await;

    let known_body = get_forgot_resend(&app, "known@test.com").await;
    let unknown_body = get_forgot_resend(&app, "unknown@test.com").await;

    assert!(known_body.contains("A new verification code has been sent"));
    assert_eq!(
        known_body.replace("known@test.com", "EMAIL"),
        unknown_body.replace("unknown@test.com", "EMAIL"),
        "resend must not reveal whether an account exists"
    );
    assert_eq!(active_reset_codes(&app.pool, "known@test.com").await, 1);
    assert_eq!(active_reset_codes(&app.pool, "unknown@test.com").await, 0);
}

#[tokio::test]
async fn test_forgot_password_resend_stops_at_code_limit() {
    let app = TestApp::new().await;
    create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    for code in ["111111", "222222", "333333"] {
        seed_reset_code(&app.pool, "user@test.com", code).await;
    }

    let body = get_forgot_resend(&app, "user@test.com").await;

    assert!(body.contains("A new verification code has been sent"));
    assert_eq!(active_reset_codes(&app.pool, "user@test.com").await, 3);
}

#[tokio::test]
async fn test_reset_authorization_is_bound_to_verified_email() {
    let app = TestApp::new().await;
    create_verified_user(&app.pool, "a@test.com", "PasswordA1!").await;
    create_verified_user(&app.pool, "b@test.com", "PasswordB1!").await;
    seed_reset_code(&app.pool, "a@test.com", "123456").await;
    let csrf = forgot_password_csrf(&app).await;

    let verified = post_forgot_verify(&app, &csrf, "a@test.com", "123456").await;
    assert!(verified.contains(RESET_FORM_MARKER));

    let other_account = post_forgot_reset(&app, &csrf, "b@test.com", "Hijacked1!").await;
    assert!(other_account.contains("expired or is invalid"));
    assert!(password_matches(&app.pool, "b@test.com", "PasswordB1!").await);

    let original_account = post_forgot_reset(&app, &csrf, "a@test.com", "NewPassword2!").await;
    assert!(
        original_account.contains("expired or is invalid"),
        "a mismatched attempt must burn the authorization"
    );
    assert!(password_matches(&app.pool, "a@test.com", "PasswordA1!").await);
}

#[tokio::test]
async fn test_reset_password_cannot_be_replayed() {
    let app = TestApp::new().await;
    create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    seed_reset_code(&app.pool, "user@test.com", "123456").await;
    let csrf = forgot_password_csrf(&app).await;
    post_forgot_verify(&app, &csrf, "user@test.com", "123456").await;

    let first = post_forgot_reset(&app, &csrf, "user@test.com", "NewPassword2!").await;
    assert!(first.contains(RESET_SUCCESS_MARKER));

    let replay = post_forgot_reset(&app, &csrf, "user@test.com", "OtherPassword3!").await;
    assert!(replay.contains("expired or is invalid"));
    assert!(password_matches(&app.pool, "user@test.com", "NewPassword2!").await);
    assert!(!password_matches(&app.pool, "user@test.com", "Password123!").await);
}

#[tokio::test]
async fn test_reset_password_revokes_existing_sessions() {
    use tower_sessions::SessionStore;
    use tower_sessions::session::{Id, Record};

    let app = TestApp::new().await;
    let user_id = create_verified_user(&app.pool, "user@test.com", "Password123!").await;
    let session_repository = SessionRepository::new(app.pool.clone());
    let mut other_device_session = Record {
        id: Id::default(),
        data: std::collections::HashMap::from([(
            SESSION_USER_ID.to_string(),
            serde_json::json!(user_id),
        )]),
        expiry_date: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
    };
    FulgurSessionStore::new(session_repository.clone())
        .create(&mut other_device_session)
        .await
        .unwrap();
    assert_eq!(session_repository.count_for_user(user_id).await.unwrap(), 1);

    seed_reset_code(&app.pool, "user@test.com", "123456").await;
    let csrf = forgot_password_csrf(&app).await;
    post_forgot_verify(&app, &csrf, "user@test.com", "123456").await;
    let body = post_forgot_reset(&app, &csrf, "user@test.com", "NewPassword2!").await;

    assert!(body.contains(RESET_SUCCESS_MARKER));
    assert_eq!(
        session_repository.count_for_user(user_id).await.unwrap(),
        0,
        "a password reset must log out every existing session"
    );
}
