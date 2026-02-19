use axum_test::TestServer;
use fulgurant::{
    api::sse::SseChannelManager, devices::DeviceRepository, handlers::AppState, mail::Mailer,
    shares::ShareRepository, users::UserRepository, verification_code::VerificationCodeRepository,
};
use sqlx::SqlitePool;
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::{Arc, atomic::AtomicBool};
use tower_sessions::{
    Expiry, MemoryStore, SessionManagerLayer, cookie::time::Duration as CookieDuration,
};

/// Test application wrapper providing a configured test server with an in-memory database
pub struct TestApp {
    pub server: TestServer,
    pub pool: SqlitePool,
    #[allow(dead_code)]
    pub jwt_secret: String,
}

/// Configuration options for test application setup
pub struct TestAppOptions {
    pub can_register: bool,
    pub setup_needed: bool,
    pub max_devices_per_user: i32,
}

impl Default for TestAppOptions {
    fn default() -> Self {
        Self {
            can_register: true,
            setup_needed: false,
            max_devices_per_user: 99,
        }
    }
}

impl TestApp {
    /// Create a test app with default options (registration enabled, setup done)
    ///
    /// ### Returns
    /// - `TestApp` with an in-memory SQLite database and all migrations applied
    pub async fn new() -> Self {
        Self::with_options(TestAppOptions::default()).await
    }

    /// Create a test app where setup is still needed (no admin exists)
    ///
    /// ### Returns
    /// - `TestApp` configured with `setup_needed = true`
    #[allow(dead_code)]
    pub async fn with_setup_needed() -> Self {
        Self::with_options(TestAppOptions {
            setup_needed: true,
            ..TestAppOptions::default()
        })
        .await
    }

    /// Create a test app with custom options
    ///
    /// ### Arguments
    /// - `opts`: Configuration options controlling registration, setup state, and device limits
    ///
    /// ### Returns
    /// - `TestApp` with an in-memory SQLite database, all migrations applied, and the given options
    pub async fn with_options(opts: TestAppOptions) -> Self {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./data/migrations")
            .run(&pool)
            .await
            .unwrap();

        let jwt_secret =
            "test_jwt_secret_key_minimum_32_bytes_long_for_testing_purposes".to_string();

        let app_state = AppState {
            device_repository: DeviceRepository::new(pool.clone()),
            user_repository: UserRepository::new(pool.clone()),
            verification_code_repository: VerificationCodeRepository::new(pool.clone()),
            share_repository: ShareRepository::new(pool.clone()),
            mailer: Arc::new(Mailer::new(false)),
            is_prod: false,
            can_register: opts.can_register,
            setup_needed: Arc::new(AtomicBool::new(opts.setup_needed)),
            share_validity_days: 3,
            max_devices_per_user: opts.max_devices_per_user,
            sse_manager: Arc::new(SseChannelManager::new()),
            sse_heartbeat_seconds: 30,
            jwt_secret: jwt_secret.clone(),
            jwt_expiry_seconds: 900,
        };

        let session_store = MemoryStore::default();
        let session_layer = SessionManagerLayer::new(session_store)
            .with_secure(false)
            .with_expiry(Expiry::OnInactivity(CookieDuration::hours(1)));

        let app = fulgurant::build_app(&app_state, session_layer);

        let server = TestServer::builder()
            .save_cookies()
            .expect_success_by_default()
            .http_transport()
            .build(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .unwrap();

        TestApp {
            server,
            pool,
            jwt_secret,
        }
    }
}
