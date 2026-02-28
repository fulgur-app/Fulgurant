use dotenvy::dotenv;
use fulgurant::{
    api, database_backup, devices, handlers, logging, mail, shares, users, users::UserRepository,
    verification_code,
};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::{
    net::SocketAddr,
    str::FromStr,
    sync::{Arc, atomic::AtomicBool},
};
use tokio_util::sync::CancellationToken;
use tower_http::services::ServeDir;
use tower_sessions::{
    Expiry, MemoryStore, SessionManagerLayer, cookie::time::Duration as CookieDuration,
};

use shares::ShareRepository;
use verification_code::VerificationCodeRepository;

const DEFAULT_DATABASE_URL: &str = "sqlite:data/database.db";
const DEFAULT_BIND_HOST: &str = "127.0.0.1";
const DEFAULT_BIND_PORT: u16 = 3000;
const DEFAULT_SSE_HEARTBEAT_SECONDS: u64 = 30;
const MIN_SSE_HEARTBEAT_SECONDS: u64 = 5;
const MAX_SSE_HEARTBEAT_SECONDS: u64 = 300;
const DEFAULT_JWT_EXPIRY_SECONDS: i64 = 900;
const MIN_JWT_EXPIRY_SECONDS: i64 = 60;
const MAX_JWT_EXPIRY_SECONDS: i64 = 86_400;
const DEFAULT_SHARE_VALIDITY_DAYS: i64 = 3;
const MIN_SHARE_VALIDITY_DAYS: i64 = 1;
const MAX_SHARE_VALIDITY_DAYS: i64 = 30;
const DEFAULT_MAX_DEVICES_PER_USER: i32 = 99;
const MIN_MAX_DEVICES_PER_USER: i32 = 0;
const MAX_MAX_DEVICES_PER_USER: i32 = 10_000;

/// Runtime configuration loaded from environment variables with validation.
struct RuntimeConfig {
    is_prod: bool,
    database_url: String,
    sse_heartbeat_seconds: u64,
    jwt_secret: String,
    jwt_expiry_seconds: i64,
    can_register: bool,
    share_validity_days: i64,
    max_devices_per_user: i32,
    tls_cert_path: Option<String>,
    tls_key_path: Option<String>,
    bind_host: String,
    bind_port: u16,
}

/// Parse an optional boolean environment variable.
///
/// ### Arguments
/// - `name`: Environment variable name
/// - `default`: Default value if variable is absent
///
/// ### Returns
/// - `Ok(bool)`: Parsed boolean value
/// - `Err(anyhow::Error)`: Invalid boolean value
fn parse_env_bool(name: &str, default: bool) -> anyhow::Result<bool> {
    let raw = match std::env::var(name) {
        Ok(v) => v.trim().to_ascii_lowercase(),
        Err(_) => return Ok(default),
    };
    match raw.as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(anyhow::anyhow!(
            "{} must be a boolean value (true/false, 1/0, yes/no, on/off)",
            name
        )),
    }
}

/// Parse an optional i64 environment variable with bounds.
///
/// ### Arguments
/// - `name`: Environment variable name
/// - `default`: Default value if variable is absent
/// - `min`: Inclusive lower bound
/// - `max`: Inclusive upper bound
///
/// ### Returns
/// - `Ok(i64)`: Parsed bounded value
/// - `Err(anyhow::Error)`: Invalid or out-of-range value
fn parse_env_i64_bounded(name: &str, default: i64, min: i64, max: i64) -> anyhow::Result<i64> {
    let value = match std::env::var(name) {
        Ok(raw) => raw.parse::<i64>().map_err(|_| {
            anyhow::anyhow!(
                "{} must be a valid integer between {} and {}",
                name,
                min,
                max
            )
        })?,
        Err(_) => default,
    };
    if value < min || value > max {
        return Err(anyhow::anyhow!(
            "{} must be between {} and {} (got {})",
            name,
            min,
            max,
            value
        ));
    }
    Ok(value)
}

/// Parse an optional i32 environment variable with bounds.
///
/// ### Arguments
/// - `name`: Environment variable name
/// - `default`: Default value if variable is absent
/// - `min`: Inclusive lower bound
/// - `max`: Inclusive upper bound
///
/// ### Returns
/// - `Ok(i32)`: Parsed bounded value
/// - `Err(anyhow::Error)`: Invalid or out-of-range value
fn parse_env_i32_bounded(name: &str, default: i32, min: i32, max: i32) -> anyhow::Result<i32> {
    let value = match std::env::var(name) {
        Ok(raw) => raw.parse::<i32>().map_err(|_| {
            anyhow::anyhow!(
                "{} must be a valid integer between {} and {}",
                name,
                min,
                max
            )
        })?,
        Err(_) => default,
    };
    if value < min || value > max {
        return Err(anyhow::anyhow!(
            "{} must be between {} and {} (got {})",
            name,
            min,
            max,
            value
        ));
    }
    Ok(value)
}

/// Parse an optional u64 environment variable with bounds.
///
/// ### Arguments
/// - `name`: Environment variable name
/// - `default`: Default value if variable is absent
/// - `min`: Inclusive lower bound
/// - `max`: Inclusive upper bound
///
/// ### Returns
/// - `Ok(u64)`: Parsed bounded value
/// - `Err(anyhow::Error)`: Invalid or out-of-range value
fn parse_env_u64_bounded(name: &str, default: u64, min: u64, max: u64) -> anyhow::Result<u64> {
    let value = match std::env::var(name) {
        Ok(raw) => raw.parse::<u64>().map_err(|_| {
            anyhow::anyhow!(
                "{} must be a valid integer between {} and {}",
                name,
                min,
                max
            )
        })?,
        Err(_) => default,
    };
    if value < min || value > max {
        return Err(anyhow::anyhow!(
            "{} must be between {} and {} (got {})",
            name,
            min,
            max,
            value
        ));
    }
    Ok(value)
}

/// Load and validate runtime configuration from environment variables.
///
/// ### Returns
/// - `Ok(RuntimeConfig)`: Validated runtime configuration
/// - `Err(anyhow::Error)`: Invalid or unsafe configuration
fn load_runtime_config() -> anyhow::Result<RuntimeConfig> {
    let is_prod = parse_env_bool("IS_PROD", false)?;
    let can_register = parse_env_bool("CAN_REGISTER", false)?;
    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| DEFAULT_DATABASE_URL.to_string());
    if database_url.trim().is_empty() {
        return Err(anyhow::anyhow!("DATABASE_URL cannot be empty"));
    }
    let sse_heartbeat_seconds = parse_env_u64_bounded(
        "SSE_HEARTBEAT_SECONDS",
        DEFAULT_SSE_HEARTBEAT_SECONDS,
        MIN_SSE_HEARTBEAT_SECONDS,
        MAX_SSE_HEARTBEAT_SECONDS,
    )?;
    let jwt_secret = std::env::var("JWT_SECRET")
        .map_err(|_| anyhow::anyhow!("JWT_SECRET must be set (minimum 32 characters)"))?;
    if jwt_secret.len() < 32 {
        return Err(anyhow::anyhow!(
            "JWT_SECRET must be at least 32 characters for security"
        ));
    }
    let jwt_expiry_seconds = parse_env_i64_bounded(
        "JWT_EXPIRY_SECONDS",
        DEFAULT_JWT_EXPIRY_SECONDS,
        MIN_JWT_EXPIRY_SECONDS,
        MAX_JWT_EXPIRY_SECONDS,
    )?;
    let share_validity_days = parse_env_i64_bounded(
        "SHARE_VALIDITY_DAYS",
        DEFAULT_SHARE_VALIDITY_DAYS,
        MIN_SHARE_VALIDITY_DAYS,
        MAX_SHARE_VALIDITY_DAYS,
    )?;
    let max_devices_per_user = parse_env_i32_bounded(
        "MAX_DEVICES_PER_USER",
        DEFAULT_MAX_DEVICES_PER_USER,
        MIN_MAX_DEVICES_PER_USER,
        MAX_MAX_DEVICES_PER_USER,
    )?;
    let bind_host = std::env::var("BIND_HOST").unwrap_or_else(|_| DEFAULT_BIND_HOST.to_string());
    if bind_host.trim().is_empty() {
        return Err(anyhow::anyhow!("BIND_HOST cannot be empty"));
    }
    let bind_port = parse_env_i64_bounded("BIND_PORT", DEFAULT_BIND_PORT as i64, 1, 65_535)? as u16;
    let tls_cert_path = std::env::var("TLS_CERT_PATH").ok();
    let tls_key_path = std::env::var("TLS_KEY_PATH").ok();
    if tls_cert_path.is_some() ^ tls_key_path.is_some() {
        return Err(anyhow::anyhow!(
            "TLS_CERT_PATH and TLS_KEY_PATH must be set together"
        ));
    }
    Ok(RuntimeConfig {
        is_prod,
        database_url,
        sse_heartbeat_seconds,
        jwt_secret,
        jwt_expiry_seconds,
        can_register,
        share_validity_days,
        max_devices_per_user,
        tls_cert_path,
        tls_key_path,
        bind_host,
        bind_port,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();
    let config = load_runtime_config()?;
    let is_prod = config.is_prod;
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
    let options = SqliteConnectOptions::from_str(config.database_url.as_str())?
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
    let sse_heartbeat_seconds = config.sse_heartbeat_seconds;
    tracing::info!("SSE heartbeat interval: {} seconds", sse_heartbeat_seconds);
    let sse_manager = Arc::new(api::sse::SseChannelManager::new());
    tracing::info!("SSE channel manager initialized");
    let jwt_secret = config.jwt_secret.clone();
    tracing::info!(
        "JWT secret loaded (length: {} characters)",
        jwt_secret.len()
    );
    let jwt_expiry_seconds = config.jwt_expiry_seconds;
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
        mailer: Arc::new(mail::Mailer::new(is_prod)?),
        is_prod,
        can_register: config.can_register,
        setup_needed: Arc::new(AtomicBool::new(setup_needed)),
        share_validity_days: config.share_validity_days,
        max_devices_per_user: config.max_devices_per_user,
        sse_manager,
        sse_heartbeat_seconds,
        jwt_secret,
        jwt_expiry_seconds,
    };
    tracing::info!("Max devices per user: {}", app_state.max_devices_per_user);
    tracing::info!("API rate limiter: 100 requests per minute per IP");
    tracing::info!("Auth rate limiter: 10 requests per minute per IP");
    let tls_cert_path = config.tls_cert_path.clone();
    let tls_key_path = config.tls_key_path.clone();
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
    let app = fulgurant::build_app(&app_state, session_layer);
    let assets_service = ServeDir::new("assets");
    let app = app.nest_service("/assets", assets_service);
    let shutdown_token = CancellationToken::new();
    let cleanup_share_repo = app_state.share_repository.clone();
    make_share_cleanup_task(cleanup_share_repo, shutdown_token.clone());
    let cleanup_verification_repo = app_state.verification_code_repository.clone();
    make_verification_code_cleanup_task(cleanup_verification_repo, shutdown_token.clone());
    let cleanup_user_repo = app_state.user_repository.clone();
    make_unverified_user_cleanup_task(cleanup_user_repo, shutdown_token.clone());
    let backup_pool = connection.clone();
    database_backup::make_daily_backup_task(backup_pool, shutdown_token.clone(), is_prod);
    let bind_host = config.bind_host.clone();
    let bind_port = config.bind_port;
    let addr = format!("{}:{}", bind_host, bind_port).parse::<SocketAddr>()?;
    if bind_host == "0.0.0.0" {
        tracing::warn!("Server is listening on all interfaces (0.0.0.0)");
    } else if bind_host == "127.0.0.1" {
        tracing::info!("Server is listening on localhost only");
    }
    let sse_manager_shutdown = app_state.sse_manager.clone();
    let shutdown_token_handler = shutdown_token.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        shutdown_token_handler.cancel();
        tracing::info!("Closing all SSE connections");
        drop(sse_manager_shutdown);
        tracing::info!("Graceful shutdown complete");
    });

    match (tls_cert_path, tls_key_path) {
        (Some(cert_path), Some(key_path)) => {
            tracing::info!("TLS enabled - loading certificate and key");
            tracing::info!("Certificate: {}", cert_path);
            tracing::info!("Private key: {}", key_path);
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
            let tls_config =
                axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path)
                    .await
                    .map_err(|e| {
                        anyhow::anyhow!("Failed to load TLS certificate and key: {}", e)
                    })?;
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
            .with_graceful_shutdown(shutdown_signal())
            .await?;
        }
    }
    Ok(())
}

/// Create a shutdown signal handler that listens for SIGTERM/SIGINT
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C signal");
        },
        _ = terminate => {
            tracing::info!("Received SIGTERM signal");
        },
    }

    tracing::info!("Starting graceful shutdown...");
}

/// Make the share cleanup task. Runs every hour.
///
/// ### Arguments
/// - `share_repository`: The share repository
/// - `shutdown_token`: Token to signal graceful shutdown
fn make_share_cleanup_task(share_repository: ShareRepository, shutdown_token: CancellationToken) {
    tracing::info!("Starting share cleanup task (runs every 1 hour)");
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600)); // 1 hour
        loop {
            tokio::select! {
                _ = interval.tick() => {
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
                },
                _ = shutdown_token.cancelled() => {
                    tracing::info!("Share cleanup task shutting down gracefully");
                    break;
                }
            }
        }
    });
}

/// Make the unverified user cleanup task. Runs every hour. Deletes users who registered but never completed email verification within 24 hours.
///
/// ### Arguments
/// - `user_repository`: The user repository
/// - `shutdown_token`: Token to signal graceful shutdown
fn make_unverified_user_cleanup_task(
    user_repository: UserRepository,
    shutdown_token: CancellationToken,
) {
    tracing::info!("Starting unverified user cleanup task (runs every 1 hour, 24h retention)");
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600)); // 1 hour
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match user_repository.delete_unverified_older_than(24).await {
                        Ok(count) => {
                            if count > 0 {
                                tracing::info!("Cleaned up {} unverified user(s)", count);
                            } else {
                                tracing::debug!(
                                    "Unverified user cleanup check complete - no stale unverified users found"
                                );
                            }
                        }
                        Err(e) => {
                            tracing::error!("Error cleaning up unverified users: {:?}", e);
                        }
                    }
                },
                _ = shutdown_token.cancelled() => {
                    tracing::info!("Unverified user cleanup task shutting down gracefully");
                    break;
                }
            }
        }
    });
}

/// Make the verification code cleanup task. Runs every minute.
///
/// ### Arguments
/// - `verification_code_repository`: The verification code repository
/// - `shutdown_token`: Token to signal graceful shutdown
fn make_verification_code_cleanup_task(
    verification_code_repository: VerificationCodeRepository,
    shutdown_token: CancellationToken,
) {
    tracing::info!("Starting verification code cleanup task (runs every 1 minute)");
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60)); // 1 minute
        loop {
            tokio::select! {
                _ = interval.tick() => {
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
                },
                _ = shutdown_token.cancelled() => {
                    tracing::info!("Verification code cleanup task shutting down gracefully");
                    break;
                }
            }
        }
    });
}
