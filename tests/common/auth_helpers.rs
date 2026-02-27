use axum::http::header::{HeaderName, HeaderValue};
use axum_test::TestServer;
use fulgurant::auth::handlers::hash_password;
use fulgurant::users::{UserRepository, generate_encryption_key};
use serde::Serialize;
use sqlx::SqlitePool;

#[derive(Serialize)]
struct LoginFormData<'a> {
    email: &'a str,
    password: &'a str,
}

/// Create a verified user directly in the database
///
/// ### Arguments
/// - `pool`: The SQLite connection pool
/// - `email`: The user's email address
/// - `password`: The user's plaintext password (will be hashed)
///
/// ### Returns
/// - `i32`: The created user's ID
pub async fn create_verified_user(pool: &SqlitePool, email: &str, password: &str) -> i32 {
    let password_hash = hash_password(password).unwrap();
    let user_repo = UserRepository::new(pool.clone());
    user_repo
        .create(
            email.to_string(),
            "Test".to_string(),
            "User".to_string(),
            password_hash,
            true,
            false,
        )
        .await
        .unwrap()
}

/// Create an admin user directly in the database
///
/// Bypasses the production guard in `UserRepository::create_admin()` that prevents
/// creating a second admin. This is necessary because seed migrations may already
/// insert an admin user into the test database.
///
/// ### Arguments
/// - `pool`: The SQLite connection pool
///
/// ### Returns
/// - `(user_id, email, password)` — the created admin's ID and fixed credentials
#[allow(dead_code)]
pub async fn create_admin_user(pool: &SqlitePool) -> (i32, String, String) {
    let email = "admin2@test.com".to_string();
    let password = "TestAdmin1!".to_string();
    let password_hash = hash_password(&password).unwrap();
    let encryption_key = generate_encryption_key();
    let result = sqlx::query(
        "INSERT INTO users (email, first_name, last_name, password_hash, role, email_verified, encryption_key) VALUES (?, 'Admin', 'User', ?, 'Admin', TRUE, ?)",
    )
    .bind(&email)
    .bind(&password_hash)
    .bind(&encryption_key)
    .execute(pool)
    .await
    .unwrap();
    let id = result.last_insert_rowid() as i32;
    (id, email, password)
}

/// Create a verified user with `force_password_update = true` directly in the database
///
/// ### Arguments
/// - `pool`: The SQLite connection pool
/// - `email`: The user's email address
/// - `password`: The user's plaintext password (will be hashed)
///
/// ### Returns
/// - `i32`: The created user's ID
#[allow(dead_code)]
pub async fn create_user_with_force_update(pool: &SqlitePool, email: &str, password: &str) -> i32 {
    let password_hash = hash_password(password).unwrap();
    let user_repo = UserRepository::new(pool.clone());
    user_repo
        .create(
            email.to_string(),
            "Test".to_string(),
            "User".to_string(),
            password_hash,
            true,
            true,
        )
        .await
        .unwrap()
}

/// Log in as a user via the web UI (GET /login for CSRF, then POST /login)
///
/// Persists the session cookie on the `TestServer` for subsequent authenticated requests.
///
/// ### Arguments
/// - `server`: The test server instance (must have `save_cookies` enabled)
/// - `email`: The user's email address
/// - `password`: The user's plaintext password
#[allow(dead_code)]
pub async fn login(server: &TestServer, email: &str, password: &str) {
    let page = server.get("/login").await;
    let csrf = extract_csrf_token(&page.text());
    server
        .post("/login")
        .add_header(
            HeaderName::from_static("x-csrf-token"),
            HeaderValue::from_str(&csrf).unwrap(),
        )
        .form(&LoginFormData { email, password })
        .await;
}

/// Create an admin user and immediately log in as that admin
///
/// ### Arguments
/// - `server`: The test server instance (must have `save_cookies` enabled)
/// - `pool`: The SQLite connection pool
///
/// ### Returns
/// - `(user_id, email, password)` — the admin's ID and fixed credentials
#[allow(dead_code)]
pub async fn login_as_admin(server: &TestServer, pool: &SqlitePool) -> (i32, String, String) {
    let (id, email, password) = create_admin_user(pool).await;
    login(server, &email, &password).await;
    (id, email, password)
}

/// Extract CSRF token from an HTML response body
///
/// Parses the `<meta name="csrf-token" content="...">` tag rendered by the layout template.
/// The CSRF middleware validates this token via the `x-csrf-token` request header.
/// Panics if the tag is not found (test infrastructure error, not a test failure).
///
/// ### Arguments
/// - `html`: The full HTML response body to search
///
/// ### Returns
/// - `String`: The CSRF token value string
#[allow(dead_code)]
pub fn extract_csrf_token(html: &str) -> String {
    // Match: <meta name="csrf-token" content="<TOKEN>">
    let start_marker = "name=\"csrf-token\" content=\"";
    let start = html
        .find(start_marker)
        .unwrap_or_else(|| panic!("CSRF meta tag not found in HTML"));
    let after_marker = &html[start + start_marker.len()..];
    let end = after_marker
        .find('"')
        .unwrap_or_else(|| panic!("CSRF token end quote not found"));
    after_marker[..end].to_string()
}
