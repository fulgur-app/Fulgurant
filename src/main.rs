use dotenvy::dotenv;
use fulgurant::{
    api, auth, database_backup, devices, handlers, logging, mail, shares, users,
    users::UserRepository, verification_code,
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
        mailer: Arc::new(mail::Mailer::new(is_prod)),
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
