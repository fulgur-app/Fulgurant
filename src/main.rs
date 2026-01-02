use axum::{
    middleware,
    routing::{delete, get, post, put},
    Router,
};
use dotenvy::dotenv;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::{
    net::SocketAddr,
    str::FromStr,
    sync::{atomic::AtomicBool, Arc},
};
use tower_http::trace::TraceLayer;
use tower_sessions::{MemoryStore, SessionManagerLayer};

use crate::shares::ShareRepository;
use crate::verification_code::VerificationCodeRepository;

mod api_key;
mod errors;
mod auth {
    pub(crate) mod handlers;
    pub(crate) mod middleware;
}
mod api {
    pub(crate) mod handlers;
    pub(crate) mod middleware;
    pub(crate) mod rate_limit;
}
mod setup {
    pub(crate) mod handlers;
    pub(crate) mod middleware;
}
pub mod devices;
mod handlers;
mod logging;
mod mail;
pub mod shares;
mod templates;
mod users;
mod verification_code;

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
    };
    tracing::info!("Max devices per user: {}", app_state.max_devices_per_user);
    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store).with_secure(true);
    let public_routes = Router::new()
        .route("/auth/register", post(auth::handlers::register_step_1))
        .route(
            "/auth/register/step2",
            post(auth::handlers::register_step_2),
        )
        .route("/login", get(auth::handlers::get_login_page))
        .route("/login", post(auth::handlers::login))
        .route("/logout", get(auth::handlers::logout))
        .route("/register", get(auth::handlers::get_register_page))
        .route(
            "/auth/forgot-password",
            get(auth::handlers::get_forgot_password_page),
        )
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
        .route("/setup", get(setup::handlers::get_setup_page))
        .route("/setup", post(setup::handlers::create_admin))
        .with_state(app_state.clone())
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            setup::middleware::require_setup_complete,
        ));

    let protected_routes = Router::new()
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
        .with_state(app_state.clone())
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            auth::middleware::require_auth,
        ));
    let api_routes = Router::new()
        .route("/api/ping", get(api::handlers::ping))
        .route("/api/begin", get(api::handlers::begin))
        .route("/api/devices", get(api::handlers::get_devices))
        .route(
            "/api/encryption-key",
            get(api::handlers::get_encryption_key),
        )
        .route("/api/share", post(api::handlers::share_file))
        .route("/api/shares", get(api::handlers::get_shares))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            api::middleware::require_api_auth,
        ))
        .layer(middleware::from_fn(api::rate_limit::rate_limit_middleware))
        .with_state(app_state.clone());
    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .merge(api_routes)
        .layer(session_layer);
    let cleanup_share_repo = app_state.share_repository.clone();
    make_share_cleanup_task(cleanup_share_repo);
    let cleanup_verification_repo = app_state.verification_code_repository.clone();
    make_verification_code_cleanup_task(cleanup_verification_repo);
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::info!("Server starting on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

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
