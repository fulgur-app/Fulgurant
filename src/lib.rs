pub mod access_token;
pub mod api_key;
pub mod csp;
pub mod database_backup;
pub mod errors;
pub mod auth {
    pub mod handlers;
    pub mod middleware;
}
pub mod api {
    pub mod handlers;
    pub mod middleware;
    pub mod sse;
}
pub mod setup {
    pub mod handlers;
    pub mod middleware;
}
pub mod admin {
    pub mod handlers;
    pub mod middleware;
}
pub mod devices;
pub mod handlers;
pub mod logging;
pub mod mail;
pub mod session;
pub mod shares;
pub mod templates;
pub mod users;
pub mod utils;
pub mod verification_code;

use axum::{
    Router,
    http::{HeaderValue, header},
    middleware as axum_mw,
    routing::{delete, get, post, put},
};
use std::sync::Arc;
use tower_http::{set_header::SetResponseHeaderLayer, trace::TraceLayer};
use tower_sessions::{MemoryStore, SessionManagerLayer};

/// Build the complete application router
///
/// ### Arguments
/// - `app_state`: The application state containing repositories and configuration
/// - `session_layer`: The session management layer
///
/// ### Returns
/// - `Router`: The fully assembled router with all routes and middleware
pub fn build_app(
    app_state: &handlers::AppState,
    session_layer: SessionManagerLayer<MemoryStore>,
) -> Router {
    let auth_routes = make_auth_routes(app_state, session_layer.clone());
    let api_routes = make_api_routes(app_state);
    let web_routes = make_web_routes(app_state, session_layer);

    Router::new()
        .merge(auth_routes)
        .merge(web_routes)
        .merge(api_routes)
        .fallback(handlers::not_found)
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
        .route(
            "/force-password-update",
            post(auth::handlers::force_password_update),
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
///
/// ### Arguments
/// - `app_state`: The state of the application
///
/// ### Returns
/// - `Router`: The router that handles the public (unauthenticated) routes
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
        .route(
            "/user/{id}/toggle-force-password-update",
            post(admin::handlers::toggle_force_password_update),
        )
        .route("/user/{id}", delete(admin::handlers::delete_user))
        .route(
            "/user/create",
            post(admin::handlers::create_user_from_admin),
        )
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
        .route("/api/share", post(api::handlers::share_file))
        .route("/api/shares", get(api::handlers::get_shares))
        .route("/api/sse", get(api::sse::handle_sse_connection))
        .layer(axum_mw::from_fn_with_state(
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
        .layer(axum::middleware::from_fn(csp::add_csp_nonce_and_header))
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
        .route(
            "/force-password-update",
            get(auth::handlers::get_force_password_update_page),
        )
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
