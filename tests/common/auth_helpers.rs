use fulgurant::auth::handlers::hash_password;
use fulgurant::users::UserRepository;
use sqlx::SqlitePool;

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
/// ### Arguments
/// - `pool`: The SQLite connection pool
///
/// ### Returns
/// - `(user_id, email, password)` — the created admin's ID and fixed credentials
pub async fn create_admin_user(pool: &SqlitePool) -> (i32, String, String) {
    let email = "admin@test.com".to_string();
    let password = "TestAdmin1!".to_string();
    let password_hash = hash_password(&password).unwrap();
    let user_repo = UserRepository::new(pool.clone());
    let id = user_repo
        .create_admin(
            email.clone(),
            "Admin".to_string(),
            "User".to_string(),
            password_hash,
        )
        .await
        .unwrap();
    (id, email, password)
}

/// Extract CSRF token from an HTML response body
///
/// Parses the hidden input with `name="csrf_token"` and returns its value.
/// Panics if the token is not found (test infrastructure error, not a test failure).
///
/// ### Arguments
/// - `html`: The full HTML response body to search
///
/// ### Returns
/// - `String`: The CSRF token value string
pub fn extract_csrf_token(html: &str) -> String {
    // Match: name="csrf_token" value="<TOKEN>" (with possible whitespace variations)
    let start_marker = "name=\"csrf_token\"";
    let start = html
        .find(start_marker)
        .unwrap_or_else(|| panic!("CSRF token not found in HTML"));
    let after_name = &html[start + start_marker.len()..];
    let value_marker = "value=\"";
    let value_start = after_name
        .find(value_marker)
        .unwrap_or_else(|| panic!("CSRF token value attribute not found"));
    let after_value = &after_name[value_start + value_marker.len()..];
    let value_end = after_value
        .find('"')
        .unwrap_or_else(|| panic!("CSRF token value end quote not found"));
    after_value[..value_end].to_string()
}
