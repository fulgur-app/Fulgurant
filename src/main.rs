use axum::{
    Router,
    http::{HeaderValue, header},
    middleware,
    routing::{delete, get, post, put},
};
use dotenvy::dotenv;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::{
    net::SocketAddr,
    str::FromStr,
    sync::{Arc, atomic::AtomicBool},
};
use tower_http::{services::ServeDir, set_header::SetResponseHeaderLayer, trace::TraceLayer};
use tower_sessions::{
    Expiry, MemoryStore, SessionManagerLayer, cookie::time::Duration as CookieDuration,
};

use crate::shares::ShareRepository;
use crate::verification_code::VerificationCodeRepository;

mod access_token;
pub mod api_key;
mod database_backup;
mod errors;
mod auth {
    pub(crate) mod handlers;
    pub(crate) mod middleware;
}
mod api {
    pub(crate) mod handlers;
    pub(crate) mod middleware;
    pub(crate) mod sse;
}
mod setup {
    pub(crate) mod handlers;
    pub(crate) mod middleware;
}
mod admin {
    pub(crate) mod handlers;
    pub(crate) mod middleware;
}
pub mod devices;
mod handlers;
mod logging;
mod mail;
pub mod shares;
mod templates;
pub mod users;
mod utils;
mod verification_code;

// #[cfg(not(target_env = "msvc"))]
// use tikv_jemallocator::Jemalloc;

// #[cfg(not(target_env = "msvc"))]
// #[global_allocator]
// static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();
    let is_prod = std::env::var("IS_PROD").unwrap_or("false".to_string()) == "true";
    let log_folder = logging::get_log_folder();
    let _log_guard = logging::init_logging(log_folder.clone(), is_prod)?;
    tracing::info!("========================================");
    tracing::info!("Starting Fulgur server v{}", env!("CARGO_PKG_VERSION"));
    tracing::info!(
        "Running in {} environment",
        if is_prod { "PRODUCTION" } else { "DEVELOPMENT" }
    );
    tracing::info!("Log folder: {}", log_folder.display());
    tracing::info!("========================================");
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let options = SqliteConnectOptions::from_str(database_url.as_str())?
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .busy_timeout(std::time::Duration::from_secs(30));
    let connection = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await?;
    tracing::info!("Database connection established");
    tracing::info!("Running migrations...");
    sqlx::migrate!("./data/migrations").run(&connection).await?;
    tracing::info!("Migrations completed successfully");
    let device_repository = devices::DeviceRepository::new(connection.clone());
    let user_repository = users::UserRepository::new(connection.clone());
    let verification_code_repository =
        verification_code::VerificationCodeRepository::new(connection.clone());
    let share_repository = shares::ShareRepository::new(connection.clone());
    let has_admin = user_repository.has_admin().await?;
    let setup_needed = !has_admin;
    if setup_needed {
        tracing::warn!("No admin user found - initial setup required at /setup");
    }
    let sse_heartbeat_seconds = std::env::var("SSE_HEARTBEAT_SECONDS")
        .unwrap_or_else(|_| "30".to_string())
        .parse::<u64>()
        .expect("SSE_HEARTBEAT_SECONDS must be a valid number");
    tracing::info!("SSE heartbeat interval: {} seconds", sse_heartbeat_seconds);
    let sse_manager = Arc::new(api::sse::SseChannelManager::new());
    tracing::info!("SSE channel manager initialized");
    let jwt_secret = std::env::var("JWT_SECRET")
        .expect("JWT_SECRET must be set. Generate with: openssl rand -base64 32");
    if jwt_secret.len() < 32 {
        panic!("JWT_SECRET must be at least 32 characters for security");
    }
    tracing::info!(
        "JWT secret loaded (length: {} characters)",
        jwt_secret.len()
    );
    let jwt_expiry_seconds = std::env::var("JWT_EXPIRY_SECONDS")
        .unwrap_or_else(|_| "900".to_string())
        .parse::<i64>()
        .expect("JWT_EXPIRY_SECONDS must be a valid number");
    tracing::info!(
        "JWT access token expiry: {} seconds (~{} minutes)",
        jwt_expiry_seconds,
        jwt_expiry_seconds / 60
    );
    let app_state = handlers::AppState {
        device_repository,
        user_repository,
        verification_code_repository,
        share_repository,
        mailer: mail::Mailer::new(),
        is_prod,
        can_register: auth::handlers::can_register(),
        setup_needed: Arc::new(AtomicBool::new(setup_needed)),
        share_validity_days: shares::get_share_validity_days(),
        max_devices_per_user: devices::get_max_devices_per_user(),
        sse_manager,
        sse_heartbeat_seconds,
        jwt_secret,
        jwt_expiry_seconds,
    };
    tracing::info!("Max devices per user: {}", app_state.max_devices_per_user);
    tracing::info!("API rate limiter: 100 requests per minute per IP");
    tracing::info!("Auth rate limiter: 10 requests per minute per IP");
    let tls_cert_path = std::env::var("TLS_CERT_PATH").ok();
    let tls_key_path = std::env::var("TLS_KEY_PATH").ok();
    let tls_enabled = tls_cert_path.is_some() && tls_key_path.is_some();
    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(tls_enabled)
        .with_expiry(Expiry::OnInactivity(CookieDuration::hours(1)));
    if tls_enabled {
        tracing::info!("Session cookies configured with secure flag (HTTPS only)");
    } else {
        tracing::warn!("Session cookies configured without secure flag (HTTP mode)");
    }
    let auth_routes = make_auth_routes(&app_state, session_layer.clone());
    let api_routes = make_api_routes(&app_state);
    let web_routes = make_web_routes(&app_state, session_layer.clone());
    let assets_service = ServeDir::new("assets");
    let app = Router::new()
        .merge(auth_routes)
        .merge(web_routes)
        .merge(api_routes)
        .nest_service("/assets", assets_service);
    let cleanup_share_repo = app_state.share_repository.clone();
    make_share_cleanup_task(cleanup_share_repo);
    let cleanup_verification_repo = app_state.verification_code_repository.clone();
    make_verification_code_cleanup_task(cleanup_verification_repo);
    let backup_pool = connection.clone();
    database_backup::make_daily_backup_task(backup_pool);
    let bind_host = std::env::var("BIND_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()); // default to localhost only for safety
    let bind_port = std::env::var("BIND_PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse::<u16>()
        .expect("BIND_PORT must be a valid port number");
    let addr = format!("{}:{}", bind_host, bind_port)
        .parse::<SocketAddr>()
        .expect("Failed to parse bind address");
    if bind_host == "0.0.0.0" {
        tracing::warn!("Server is listening on all interfaces (0.0.0.0)");
    } else if bind_host == "127.0.0.1" {
        tracing::info!("Server is listening on localhost only");
    }
    match (tls_cert_path, tls_key_path) {
        (Some(cert_path), Some(key_path)) => {
            tracing::info!("TLS enabled - loading certificate and key");
            tracing::info!("Certificate: {}", cert_path);
            tracing::info!("Private key: {}", key_path);
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
            let tls_config =
                axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path)
                    .await
                    .expect("Failed to load TLS certificate and key");
            tracing::info!("Server starting on https://{}", addr);
            axum_server::bind_rustls(addr, tls_config)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await?;
        }
        _ => {
            tracing::info!("TLS disabled - running HTTP only");
            tracing::warn!(
                "For production, configure TLS_CERT_PATH and TLS_KEY_PATH environment variables"
            );
            tracing::info!("Server starting on http://{}", addr);
            let listener = tokio::net::TcpListener::bind(addr).await?;
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await?;
        }
    }
    Ok(())
}

/// Make the auth routes
///
/// ### Arguments
/// - `app_state`: The state of the application
/// - `session_layer`: The session layer
///
/// ### Returns
/// - `Router`: The router that handles the auth routes
fn make_auth_routes(
    app_state: &handlers::AppState,
    session_layer: SessionManagerLayer<MemoryStore>,
) -> Router {
    let auth_governor_conf = Arc::new(
        tower_governor::governor::GovernorConfigBuilder::default()
            .period(std::time::Duration::from_secs(6)) // 10 requests/min = 1 per 6s
            .burst_size(5)
            .use_headers()
            .finish()
            .expect("Failed to build auth governor config"),
    );
    Router::new()
        .route("/auth/register", post(auth::handlers::register_step_1))
        .route(
            "/auth/register/step2",
            post(auth::handlers::register_step_2),
        )
        .route("/login", post(auth::handlers::login))
        .route(
            "/auth/forgot-password",
            post(auth::handlers::forgot_password_step_1),
        )
        .route(
            "/auth/forgot-password/verify",
            post(auth::handlers::forgot_password_step_2),
        )
        .route(
            "/auth/forgot-password/reset",
            post(auth::handlers::forgot_password_step_3),
        )
        .route(
            "/auth/forgot-password/resend",
            get(auth::handlers::resend_forgot_password_code),
        )
        .route("/setup", post(setup::handlers::create_admin))
        .with_state(app_state.clone())
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            setup::middleware::require_setup_complete,
        ))
        .layer(axum::middleware::from_fn(
            axum_tower_sessions_csrf::CsrfMiddleware::middleware,
        ))
        .layer(session_layer)
        .layer(tower_governor::GovernorLayer::new(auth_governor_conf))
}

/// Make the public routes
fn make_public_routes(app_state: &handlers::AppState) -> Router {
    Router::new()
        .route("/login", get(auth::handlers::get_login_page))
        .route("/logout", get(auth::handlers::logout))
        .route("/register", get(auth::handlers::get_register_page))
        .route(
            "/auth/forgot-password",
            get(auth::handlers::get_forgot_password_page),
        )
        .route("/setup", get(setup::handlers::get_setup_page))
        .with_state(app_state.clone())
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            setup::middleware::require_setup_complete,
        ))
}

/// Make the admin routes
///
/// ### Arguments
/// - `app_state`: The state of the application
///
/// ### Returns
/// - `Router`: The router that handles the admin routes
fn make_admin_routes(app_state: &handlers::AppState) -> Router<handlers::AppState> {
    Router::new()
        .route("/admin", get(admin::handlers::get_admin))
        .route("/admin/users/search", get(admin::handlers::search_users))
        .route(
            "/user/{id}/change-role",
            post(admin::handlers::change_user_role),
        )
        .route("/user/{id}", delete(admin::handlers::delete_user))
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            admin::middleware::require_admin,
        ))
}

/// Make the api routes
///
/// ### Arguments
/// - `app_state`: The state of the application
///
/// ### Returns
/// - `Router`: The router that handles the api routes
fn make_api_routes(app_state: &handlers::AppState) -> Router {
    let governor_conf = Arc::new(
        tower_governor::governor::GovernorConfigBuilder::default()
            .period(std::time::Duration::from_millis(600)) // 100 requests/min = 1 per 600ms
            .burst_size(20)
            .use_headers()
            .finish()
            .expect("Failed to build governor config"),
    );
    let token_route = Router::new()
        .route("/api/token", post(api::handlers::obtain_access_token))
        .layer(tower_governor::GovernorLayer::new(governor_conf.clone()))
        .with_state(app_state.clone());
    let authenticated_routes = Router::new()
        .route("/api/ping", get(api::handlers::ping))
        .route("/api/begin", post(api::handlers::begin))
        .route("/api/devices", get(api::handlers::get_devices))
        .route(
            "/api/encryption-key",
            get(api::handlers::get_encryption_key),
        )
        .route("/api/share", post(api::handlers::share_file))
        .route("/api/shares", get(api::handlers::get_shares))
        .route("/api/sse", get(api::sse::handle_sse_connection))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            api::middleware::require_api_auth,
        ))
        .layer(tower_governor::GovernorLayer::new(governor_conf))
        .with_state(app_state.clone());
    token_route.merge(authenticated_routes)
}

/// Make the web routes
///
/// ### Arguments
/// - `app_state`: The state of the application
/// - `session_layer`: The session layer
///
/// ### Returns
/// - `Router`: The router that handles the web routes
fn make_web_routes(
    app_state: &handlers::AppState,
    session_layer: SessionManagerLayer<MemoryStore>,
) -> Router {
    Router::new()
        .merge(make_public_routes(app_state))
        .merge(make_protected_routes(app_state))
        .layer(axum::middleware::from_fn(
            axum_tower_sessions_csrf::CsrfMiddleware::middleware,
        ))
        .layer(session_layer)
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::HeaderName::from_static("x-xss-protection"),
            HeaderValue::from_static("1; mode=block"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self' 'unsafe-inline' https://unpkg.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;"
            ),
        ))
}

/// Make the protected routes
///
/// ### Arguments
/// - `app_state`: The state of the application
///
/// ### Returns
/// - `Router`: The router that handles the protected routes
fn make_protected_routes(app_state: &handlers::AppState) -> Router {
    Router::new()
        .route("/", get(handlers::index))
        .route("/device/{user_id}/create", post(handlers::create_device))
        .route("/device/{id}/edit", get(handlers::get_device_edit_form))
        .route("/device/{id}", put(handlers::update_device))
        .route("/device/{id}", delete(handlers::delete_device))
        .route("/device/{id}/cancel", get(handlers::cancel_edit_device))
        .route("/device/{id}/renew", get(handlers::get_device_renew_form))
        .route("/device/{id}/renew", post(handlers::renew_device))
        .route("/share/{id}", delete(handlers::delete_share))
        .route("/settings", get(handlers::get_settings))
        .route("/settings/update-name", post(handlers::update_name))
        .route(
            "/settings/update-email",
            post(handlers::update_email_step_1),
        )
        .route(
            "/settings/verify-email-change",
            post(handlers::update_email_step_2),
        )
        .merge(make_admin_routes(app_state))
        .with_state(app_state.clone())
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            auth::middleware::require_auth,
        ))
}

/// Make the share cleanup task. Runs every hour.
///
/// ### Arguments
/// - `share_repository`: The share repository
fn make_share_cleanup_task(share_repository: ShareRepository) {
    tracing::info!("Starting share cleanup task (runs every 1 hour)");
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600)); // 1 hour
        loop {
            interval.tick().await;
            match share_repository.delete_expired().await {
                Ok(count) => {
                    if count > 0 {
                        tracing::info!("Cleaned up {} expired share(s)", count);
                    } else {
                        tracing::debug!("Share cleanup check complete - no expired shares found");
                    }
                }
                Err(e) => {
                    tracing::error!("Error cleaning up expired shares: {:?}", e);
                }
            }
        }
    });
}

/// Make the verification code cleanup task. Runs every minute.
///
/// ### Arguments
/// - `verification_code_repository`: The verification code repository
fn make_verification_code_cleanup_task(verification_code_repository: VerificationCodeRepository) {
    tracing::info!("Starting verification code cleanup task (runs every 1 minute)");
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60)); // 1 minutes
        loop {
            interval.tick().await;
            match verification_code_repository.delete_expired().await {
                Ok(count) => {
                    if count > 0 {
                        tracing::info!("Cleaned up {} expired verification code(s)", count);
                    } else {
                        tracing::debug!(
                            "Verification code cleanup check complete - no expired codes found"
                        );
                    }
                }
                Err(e) => {
                    tracing::error!("Error cleaning up expired verification codes: {:?}", e);
                }
            }
        }
    });
}
