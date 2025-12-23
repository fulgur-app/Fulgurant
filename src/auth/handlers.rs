use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use askama::Template;
use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Form,
};
use serde::Deserialize;
use tower_sessions::Session;

use crate::{
    handlers::AppState,
    templates::{self, LoginTemplate},
    verification_code::{generate_code, VerificationResult},
};

const SESSION_USER_ID: &str = "user_id";

/// Checks if the registration is allowed
///
/// ### Returns
/// - `true` if the registration is allowed, `false` otherwise (default is false)
pub fn can_register() -> bool {
    std::env::var("CAN_REGISTER").unwrap_or_else(|_| "false".to_string()) == "true"
}

#[derive(Deserialize)]
pub struct LoginRequest {
    email: String,
    password: String,
}

/// GET /login - Returns the login page
///
/// ### Arguments
/// - `state`: The state of the application
///
/// ### Returns
/// - `Ok(Html<String>)`: The login page
/// - `Err(AppError)`: An error occurred while rendering the template
pub async fn get_login_page(State(state): State<AppState>) -> Result<Html<String>, AppError> {
    let template = LoginTemplate {
        can_register: state.can_register,
    };
    Ok(Html(template.render().map_err(|e| {
        AppError::Internal(format!("Template error: {}", e))
    })?))
}

/// POST /login - Logs in a user
///
/// ### Arguments
/// - `state`: The state of the application
/// - `session`: The session
/// - `request`: The login request
///
/// ### Returns
/// - `Ok(Response)`: The response
/// - `Err(AppError)`: An error occurred while logging in the user
pub async fn login(
    State(state): State<AppState>,
    session: Session,
    Form(request): Form<LoginRequest>,
) -> Result<Response, AppError> {
    let email = request.email.trim().to_lowercase();
    let password = request.password.trim();
    let user = match state.user_repository.get_by_email(email.clone()).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            tracing::warn!("Login attempt for non-existent user: {}", email);
            let template = templates::ErrorMessageTemplate {
                message: "Invalid email or code. Please try again.".to_string(),
            };
            let rendered = template
                .render()
                .map_err(|e| AppError::Internal(format!("Template error: {}", e)))?;
            return Ok(Html(rendered).into_response());
        }
        Err(e) => {
            return Err(AppError::Database(format!(
                "Failed to get user by email: {:?}",
                e.to_string()
            )));
        }
    };
    let password_verified = verify_password(password, user.password_hash.clone());
    tracing::info!("Password verified: {}", password_verified);
    if !password_verified {
        let template = templates::ErrorMessageTemplate {
            message: "Invalid password. Please try again.".to_string(),
        };
        return Ok(Html(
            template
                .render()
                .map_err(|e| AppError::Internal(format!("Template error: {}", e)))?,
        )
        .into_response());
    }
    session
        .insert(SESSION_USER_ID, user.id)
        .await
        .map_err(|_| AppError::Internal("Session error".into()))?;
    let mut response = Html("").into_response();
    response
        .headers_mut()
        .insert("HX-Redirect", "/".parse().unwrap());
    Ok(response)
}

/// GET /register - Returns the register page
///
/// ### Arguments
/// - `state`: The state of the application
///
/// ### Returns
/// - `Ok(Html<String>)`: The register page
/// - `Err(AppError)`: An error occurred while rendering the template
pub async fn get_register_page(State(state): State<AppState>) -> Result<Html<String>, AppError> {
    if !state.can_register {
        let template = templates::ErrorTemplate {
            title: "Registration not allowed".to_string(),
            message: "Registration is not allowed on this server. Contact the administrator if you need to register.".to_string(),
            link: Some("/login".to_string()),
            link_text: Some("Login".to_string()),
        };
        return Ok(Html(template.render().map_err(|e| {
            AppError::Internal(format!("Template error: {}", e))
        })?));
    }
    let template = templates::RegisterTemplate {
        error_message: "".to_string(),
        email: "".to_string(),
        first_name: "".to_string(),
        last_name: "".to_string(),
    };
    Ok(Html(template.render().map_err(|e| {
        AppError::Internal(format!("Template error: {}", e))
    })?))
}

/// POST /logout - Logs out a user
///
/// ### Arguments
/// - `state`: The state of the application
/// - `session`: The session
///
/// ### Returns
/// - `Ok(Html<String>)`: The response
/// - `Err(AppError)`: An error occurred while logging out the user
pub async fn logout(
    State(state): State<AppState>,
    session: Session,
) -> Result<Html<String>, AppError> {
    session
        .delete()
        .await
        .map_err(|_| AppError::Internal("Session error".into()))?;
    let template = templates::LoginTemplate {
        can_register: state.can_register,
    };
    Ok(Html(template.render().map_err(|e| {
        AppError::Internal(format!("Template error: {}", e))
    })?))
}

#[derive(Deserialize)]
pub struct RegisterStep1Request {
    email: String,
    first_name: String,
    last_name: String,
    password: String,
}

#[derive(Deserialize)]
pub struct RegisterStep2Request {
    email: String,
    code: String,
}

/// Checks if the password is valid
///
/// ### Arguments
/// - `password`: The password to check
///
/// ### Returns
/// - `true` if the password is valid, `false` otherwise
fn is_password_valid(password: &str) -> bool {
    let right_length = password.len() >= 8 && password.len() <= 64;
    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_digit(10));
    let has_special = password.chars().any(|c| !c.is_alphanumeric());
    if !right_length || !has_uppercase || !has_lowercase || !has_digit || !has_special {
        return false;
    }
    true
}

/// POST /register/step-1 - Registers a user
///
/// ### Arguments
/// - `state`: The state of the application
/// - `session`: The session
/// - `request`: The register step 1 request
///
/// ### Returns
/// - `Ok(Html<String>)`: The response
/// - `Err(AppError)`: An error occurred while registering the user
pub async fn register_step_1(
    State(state): State<AppState>,
    _session: Session,
    Form(request): Form<RegisterStep1Request>,
) -> Result<Html<String>, AppError> {
    let first_name = request.first_name.trim();
    let last_name = request.last_name.trim();
    let password = request.password.trim();
    let email = request.email.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') {
        let template = templates::RegisterStep1Template {
            error_message: "Invalid email".to_string(),
            email: email.clone(),
            first_name: first_name.to_string(),
            last_name: last_name.to_string(),
        };
        return Ok(Html(template.render().map_err(|e| {
            AppError::Internal(format!("Template error: {}", e))
        })?));
    }
    match state.user_repository.get_by_email(email.clone()).await {
        Ok(Some(_)) => {
            let template = templates::RegisterStep1Template {
                error_message: "Email already registered".to_string(),
                email: email.clone(),
                first_name: first_name.to_string(),
                last_name: last_name.to_string(),
            };
            return Ok(Html(template.render().map_err(|e| {
                AppError::Internal(format!("Template error: {}", e))
            })?));
        }
        Ok(None) => (),
        Err(e) => {
            return Err(AppError::Database(format!(
                "Failed to get user by email: {:?}",
                e.to_string()
            )))
        }
    };
    if !is_password_valid(password) {
        let template = templates::RegisterStep1Template {
            error_message: "Invalid password".to_string(),
            email: email.clone(),
            first_name: first_name.to_string(),
            last_name: last_name.to_string(),
        };
        return Ok(Html(template.render().map_err(|e| {
            AppError::Internal(format!("Template error: {}", e))
        })?));
    }
    let code = generate_code();
    let _verification_code = match state
        .verification_code_repository
        .create(email.clone(), code.clone(), "registration".to_string())
        .await
    {
        Ok(verification_code) => verification_code,
        Err(e) => {
            tracing::error!("Failed to create verification code: {}", e);
            return Err(AppError::Internal(format!(
                "Failed to create verification code: {}",
                e
            )));
        }
    };
    let password_hash = hash_password(password)
        .map_err(|e| AppError::Internal(format!("Failed to hash password: {}", e)))?;
    let _user_id = match state
        .user_repository
        .create(
            email.clone(),
            first_name.to_string(),
            last_name.to_string(),
            password_hash,
        )
        .await
    {
        Ok(user_id) => user_id,
        Err(e) => {
            tracing::error!("Failed to create user: {}", e);
            return Err(AppError::Internal(format!("Failed to create user: {}", e)));
        }
    };
    if state.is_prod {
        match state
            .mailer
            .send_verification_email(email.clone(), code)
            .await
        {
            Ok(_) => (),
            Err(e) => {
                return Err(AppError::Internal(format!(
                    "Failed to send verification email: {}",
                    e
                )))
            }
        }
    } else {
        tracing::info!("Development mode - verification email not sent");
        tracing::info!("Verification code for {}: {}", email, code.clone());
    }

    let template = templates::RegisterStep2Template {
        email: email.clone(),
        error_message: "".to_string(),
    };
    Ok(Html(template.render().map_err(|e| {
        AppError::Internal(format!("Template error: {}", e))
    })?))
}

/// POST /register/step-2 - Registers a user
///
/// ### Arguments
/// - `state`: The state of the application
/// - `session`: The session
/// - `request`: The register step 2 request
///
/// ### Returns
/// - `Ok(Html<String>)`: The response
/// - `Err(AppError)`: An error occurred while registering the user
pub async fn register_step_2(
    State(state): State<AppState>,
    _session: Session,
    Form(request): Form<RegisterStep2Request>,
) -> Result<Html<String>, AppError> {
    let email = request.email.trim().to_lowercase();
    let code = request.code.trim().to_string();
    let user = match state.user_repository.get_by_email(email.clone()).await {
        Ok(Some(user)) => user,
        Ok(None) => return Err(AppError::Unauthorized),
        Err(e) => {
            return Err(AppError::Database(format!(
                "Failed to get user by email: {:?}",
                e.to_string()
            )))
        }
    };
    let verification_result = match state
        .verification_code_repository
        .verify_code(code.clone(), email.clone(), "registration".to_string())
        .await
    {
        Ok(verification_result) => verification_result,
        Err(e) => {
            tracing::error!("Failed to verify verification code: {}", e);
            return Err(AppError::Internal(format!(
                "Failed to verify verification code: {}",
                e
            )));
        }
    };
    let error_message = match verification_result {
        VerificationResult::Verified => {
            state
                .user_repository
                .mark_as_verified(user.id)
                .await
                .map_err(|e| {
                    AppError::Database(format!(
                        "Failed to mark user as verified: {:?}",
                        e.to_string()
                    ))
                })?;
            "Yeah! You're registered!".to_string()
        }
        VerificationResult::NotFound => "Verification code not found".to_string(),
        VerificationResult::Expired => "Verification code expired".to_string(),
        VerificationResult::Invalid { attempts_remaining } => format!(
            "Invalid verification code. {} attempts remaining.",
            attempts_remaining
        ),
        VerificationResult::TooManyAttempts => {
            "Too many failed attempts. Please request a new code.".to_string()
        }
    };
    let template = templates::RegisterStep3Template {
        first_name: user.first_name,
    };
    Ok(Html(template.render().map_err(|e| {
        AppError::Internal(format!("Template error: {}", e))
    })?))
}

/// Error handling
///
/// ### Arguments
/// - `self`: The AppError
///
/// ### Returns
/// - `Response`: The response
#[derive(Debug)]
pub enum AppError {
    Unauthorized,
    Internal(String),
    Database(String),
}

impl IntoResponse for AppError {
    /// Converts an AppError to a response
    ///
    /// ### Arguments
    /// - `self`: The AppError
    ///
    /// ### Returns
    /// - `Response`: The response
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized".into()),
            AppError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            AppError::Database(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        (status, message).into_response()
    }
}

/// Hashes a password
///
/// ### Arguments
/// - `password`: The password to hash
///
/// ### Returns
/// - `Result<String, argon2::password_hash::Error>`: The hashed password
fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

/// Verifies a password
///
/// ### Arguments
/// - `password`: The password to verify
/// - `password_hash`: The hashed password
///
/// ### Returns
/// - `true`: True if the password is valid, `false` otherwise
fn verify_password(password: &str, password_hash: String) -> bool {
    let password_hash = PasswordHash::new(&password_hash).unwrap();
    let argon2 = Argon2::default();
    argon2
        .verify_password(password.as_bytes(), &password_hash)
        .is_ok()
}
