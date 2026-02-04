use crate::utils::{is_password_valid, is_valid_email};
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use askama::Template;
use axum::{
    Form,
    extract::{Query, State},
    response::{Html, IntoResponse, Response},
};
use serde::Deserialize;
use tower_sessions::Session;

use crate::{
    errors::AppError,
    handlers::AppState,
    logging::sanitize_for_log,
    templates::{self, LoginTemplate},
    verification_code::{self, VerificationResult, generate_code},
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
pub async fn get_login_page(
    State(state): State<AppState>,
    session: Session,
) -> Result<Html<String>, AppError> {
    let csrf_token = axum_tower_sessions_csrf::get_or_create_token(&session)
        .await
        .map_err(|e| {
            AppError::InternalError(anyhow::anyhow!("Failed to generate CSRF token: {}", e))
        })?;
    let template = LoginTemplate {
        can_register: state.can_register,
        csrf_token,
    };
    Ok(Html(template.render()?))
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
            tracing::warn!(
                "Login attempt for non-existent user: {}",
                sanitize_for_log(&email)
            );
            let template = templates::ErrorMessageTemplate {
                message: "Invalid email or password. Please try again.".to_string(),
            };
            let rendered = template
                .render()
                .map_err(|e| AppError::InternalError(anyhow::anyhow!("Template error: {}", e)))?;
            return Ok(Html(rendered).into_response());
        }
        Err(e) => {
            return Err(AppError::InternalError(anyhow::anyhow!(
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
                .map_err(|e| AppError::InternalError(anyhow::anyhow!("Template error: {}", e)))?,
        )
        .into_response());
    }
    state
        .user_repository
        .update_last_activity(user.id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update last_activity: {}", e);
            AppError::InternalError(anyhow::anyhow!("Failed to update last_activity"))
        })?;
    session
        .insert(SESSION_USER_ID, user.id)
        .await
        .map_err(|_| AppError::InternalError(anyhow::anyhow!("Session error")))?;
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
/// - `session`: The session
///
/// ### Returns
/// - `Ok(Html<String>)`: The register page
/// - `Err(AppError)`: An error occurred while rendering the template
pub async fn get_register_page(
    State(state): State<AppState>,
    session: Session,
) -> Result<Html<String>, AppError> {
    if !state.can_register {
        let template = templates::ErrorTemplate {
            title: "Registration not allowed".to_string(),
            message: "Registration is not allowed on this server. Contact the administrator if you need to register.".to_string(),
            link: Some("/login".to_string()),
            link_text: Some("Login".to_string()),
        };
        return Ok(Html(template.render().map_err(|e| {
            AppError::InternalError(anyhow::anyhow!("Template error: {}", e))
        })?));
    }
    let csrf_token = axum_tower_sessions_csrf::get_or_create_token(&session)
        .await
        .map_err(|e| {
            AppError::InternalError(anyhow::anyhow!("Failed to generate CSRF token: {}", e))
        })?;
    let template = templates::RegisterTemplate {
        error_message: "".to_string(),
        email: "".to_string(),
        first_name: "".to_string(),
        last_name: "".to_string(),
        csrf_token,
    };
    Ok(Html(template.render()?))
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
        .map_err(|_| AppError::InternalError(anyhow::anyhow!("Session error")))?;
    let csrf_token = axum_tower_sessions_csrf::get_or_create_token(&session)
        .await
        .map_err(|e| {
            AppError::InternalError(anyhow::anyhow!("Failed to generate CSRF token: {}", e))
        })?;
    let template = templates::LoginTemplate {
        can_register: state.can_register,
        csrf_token,
    };
    Ok(Html(template.render()?))
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

/// POST /register/step-1 - Registers a user, sends a verification code to the email address and shows the form for the second step of the registration process
///
/// ### Arguments
/// - `state`: The state of the application
/// - `session`: The session
/// - `request`: The register step 1 request
///
/// ### Returns
/// - `Ok(Html<String>)`: The form for the second step of the registration process as formatted HTML
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
    if !is_valid_email(&email) {
        let template = templates::RegisterStep1Template {
            error_message: "Invalid email".to_string(),
            email: email.clone(),
            first_name: first_name.to_string(),
            last_name: last_name.to_string(),
        };
        return Ok(Html(template.render().map_err(|e| {
            AppError::InternalError(anyhow::anyhow!("Template error: {}", e))
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
                AppError::InternalError(anyhow::anyhow!("Template error: {}", e))
            })?));
        }
        Ok(None) => (),
        Err(e) => {
            return Err(AppError::InternalError(anyhow::anyhow!(
                "Failed to get user by email: {:?}",
                e.to_string()
            )));
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
            AppError::InternalError(anyhow::anyhow!("Template error: {}", e))
        })?));
    }
    if let Err(e) = check_verification_code_rate_limit(&state, &email, "registration").await {
        let template = templates::RegisterStep1Template {
            error_message: e.to_string(),
            email: email.clone(),
            first_name: first_name.to_string(),
            last_name: last_name.to_string(),
        };
        return Ok(Html(template.render().map_err(|e| {
            AppError::InternalError(anyhow::anyhow!("Template error: {}", e))
        })?));
    }
    let _code = create_and_send_verification_code(&state, &email, "registration").await?;
    let password_hash = hash_password(password)
        .map_err(|e| AppError::InternalError(anyhow::anyhow!("Failed to hash password: {}", e)))?;
    let _user_id = state
        .user_repository
        .create(
            email.clone(),
            first_name.to_string(),
            last_name.to_string(),
            password_hash,
            false,
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to create user: {}", e);
            AppError::InternalError(anyhow::anyhow!("Failed to create user: {}", e))
        })?;
    let template = templates::RegisterStep2Template {
        email: email.clone(),
        error_message: "".to_string(),
    };
    Ok(Html(template.render()?))
}

/// POST /register/step-2 - Verifies the verification code and marks the user as verified
///
/// ### Arguments
/// - `state`: The state of the application
/// - `session`: The session
/// - `request`: The register step 2 request
///
/// ### Returns
/// - `Ok(Html<String>)`: The registration success message as formatted HTML
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
            return Err(AppError::InternalError(anyhow::anyhow!(
                "Failed to get user by email: {:?}",
                e.to_string()
            )));
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
            return Err(AppError::InternalError(anyhow::anyhow!(
                "Failed to verify verification code: {}",
                e
            )));
        }
    };
    let _error_message = match verification_result {
        VerificationResult::Verified => {
            state
                .user_repository
                .mark_as_verified(user.id)
                .await
                .map_err(|e| {
                    AppError::InternalError(anyhow::anyhow!(
                        "Failed to mark user as verified: {:?}",
                        e.to_string()
                    ))
                })?;
            "Yeah! You're registered!".to_string()
        }
        _ => format_verification_error(&verification_result),
    };
    let template = templates::RegisterStep3Template {
        first_name: user.first_name,
    };
    Ok(Html(template.render()?))
}

/// GET /auth/forgot-password - Returns the forgot password page
///
/// ### Arguments
/// - `session`: The session
///
/// ### Returns
/// - `Ok(Html<String>)`: The forgot password page as formatted HTML
/// - `Err(AppError)`: Error that occurred while rendering the template
pub async fn get_forgot_password_page(session: Session) -> Result<Html<String>, AppError> {
    let csrf_token = axum_tower_sessions_csrf::get_or_create_token(&session)
        .await
        .map_err(|e| {
            AppError::InternalError(anyhow::anyhow!("Failed to generate CSRF token: {}", e))
        })?;
    let template = templates::ForgotPasswordStep1Template {
        error_message: String::new(),
        email: String::new(),
        csrf_token,
    };
    Ok(Html(template.render()?))
}

#[derive(Deserialize)]
pub struct ForgotPasswordStep1Request {
    email: String,
}

/// POST /auth/forgot-password - Step 1: Send verification code to email and shows the verification code form
///
/// ### Arguments
/// - `state`: The state of the application
/// - `request`: The forgot password step 1 request
///
/// ### Returns
/// - `Ok(Html<String>)`: The verification code form as formatted HTML
/// - `Err(AppError)`: Error that occurred while processing the request
pub async fn forgot_password_step_1(
    State(state): State<AppState>,
    Form(request): Form<ForgotPasswordStep1Request>,
) -> Result<Html<String>, AppError> {
    let user = match state
        .user_repository
        .get_by_email(request.email.clone())
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => {
            let template = templates::ForgotPasswordStep2Template {
                email: request.email,
                error_message: String::new(),
                success_message: String::new(),
            };
            return Ok(Html(template.render().map_err(|e| {
                AppError::InternalError(anyhow::anyhow!("Template error: {}", e))
            })?));
        }
        Err(e) => {
            tracing::error!("Database error: {}", e);
            return Err(AppError::InternalError(anyhow::anyhow!("Database error")));
        }
    };
    if let Err(e) = check_verification_code_rate_limit(&state, &user.email, "password_reset").await
    {
        let template = templates::ForgotPasswordStep1PartialTemplate {
            email: request.email,
            error_message: e.to_string(),
        };
        return Ok(Html(template.render().map_err(|e| {
            AppError::InternalError(anyhow::anyhow!("Template error: {}", e))
        })?));
    }
    let _code = create_and_send_verification_code(&state, &user.email, "password_reset").await?;
    let template = templates::ForgotPasswordStep2Template {
        email: request.email,
        error_message: String::new(),
        success_message: String::new(),
    };
    Ok(Html(template.render()?))
}

#[derive(Deserialize)]
pub struct ForgotPasswordStep2Request {
    email: String,
    code: String,
}

/// POST /auth/forgot-password/verify - Step 2: Verify code and show the password form
///
/// ### Arguments
/// - `state`: The state of the application
/// - `request`: The verification request
///
/// ### Returns
/// - `Ok(Html<String>)`: The password reset form as formatted HTML
/// - `Err(AppError)`: Error that occurred while verifying the code
pub async fn forgot_password_step_2(
    State(state): State<AppState>,
    Form(request): Form<ForgotPasswordStep2Request>,
) -> Result<Html<String>, AppError> {
    let result = state
        .verification_code_repository
        .verify_code(
            request.code.clone(),
            request.email.clone(),
            "password_reset".to_string(),
        )
        .await
        .map_err(|e| AppError::InternalError(anyhow::anyhow!("Failed to verify code: {}", e)))?;
    match result {
        VerificationResult::Verified => {
            let _ = state
                .verification_code_repository
                .delete_for(request.email.clone(), "password_reset".to_string())
                .await;
            let template = templates::ForgotPasswordStep3Template {
                email: request.email,
                error_message: String::new(),
            };
            Ok(Html(template.render().map_err(|e| {
                AppError::InternalError(anyhow::anyhow!("Template error: {}", e))
            })?))
        }
        _ => {
            let template = templates::ForgotPasswordStep2Template {
                email: request.email,
                error_message: format_verification_error(&result),
                success_message: String::new(),
            };
            Ok(Html(template.render().map_err(|e| {
                AppError::InternalError(anyhow::anyhow!("Template error: {}", e))
            })?))
        }
    }
}

#[derive(Deserialize)]
pub struct ForgotPasswordStep3Request {
    email: String,
    password: String,
}

/// POST /auth/forgot-password/reset - Step 3: Reset the password and show the success message
///
/// ### Arguments
/// - `state`: The state of the application
/// - `request`: The password reset request
///
/// ### Returns
/// - `Ok(Html<String>)`: Success message as formatted HTML
/// - `Err(AppError)`: Error that occurred while resetting the password
pub async fn forgot_password_step_3(
    State(state): State<AppState>,
    Form(request): Form<ForgotPasswordStep3Request>,
) -> Result<Html<String>, AppError> {
    if !is_password_valid(&request.password) {
        let template = templates::ForgotPasswordStep3Template {
            email: request.email,
            error_message: "Password must be 8-64 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.".to_string(),
        };
        return Ok(Html(template.render().map_err(|e| {
            AppError::InternalError(anyhow::anyhow!("Template error: {}", e))
        })?));
    }
    let user = match state
        .user_repository
        .get_by_email(request.email.clone())
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => {
            return Err(AppError::InternalError(anyhow::anyhow!("User not found")));
        }
        Err(e) => {
            tracing::error!("Database error: {}", e);
            return Err(AppError::InternalError(anyhow::anyhow!("Database error")));
        }
    };
    let password_hash = hash_password(&request.password)
        .map_err(|e| AppError::InternalError(anyhow::anyhow!("Failed to hash password: {}", e)))?;
    match state
        .user_repository
        .update_password(user.id, password_hash)
        .await
    {
        Ok(_) => {
            tracing::info!("Password reset for user: {}", user.email);
        }
        Err(e) => {
            tracing::error!("Failed to update password: {}", e);
            return Err(AppError::InternalError(anyhow::anyhow!(
                "Failed to update password"
            )));
        }
    }
    let template = templates::ForgotPasswordSuccessTemplate {};
    Ok(Html(template.render()?))
}

#[derive(Deserialize)]
pub struct ResendCodeQuery {
    email: String,
}

/// GET /auth/forgot-password/resend - Resend the verification code for password reset
///
/// ### Arguments
/// - `state`: The state of the application
/// - `query`: The resend code query containing the email
///
/// ### Returns
/// - `Ok(Html<String>)`: The verification code form with success message as formatted HTML
/// - `Err(AppError)`: Error that occurred while resending the code
pub async fn resend_forgot_password_code(
    State(state): State<AppState>,
    Query(query): Query<ResendCodeQuery>,
) -> Result<Html<String>, AppError> {
    let email = query.email.trim().to_lowercase();
    if let Err(e) = check_verification_code_rate_limit(&state, &email, "password_reset").await {
        let template = templates::ForgotPasswordStep2Template {
            email,
            error_message: e.to_string(),
            success_message: String::new(),
        };
        return Ok(Html(template.render().map_err(|e| {
            AppError::InternalError(anyhow::anyhow!("Template error: {}", e))
        })?));
    }
    let user_exists = match state.user_repository.get_by_email(email.clone()).await {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(e) => {
            tracing::error!("Database error: {}", e);
            return Err(AppError::InternalError(anyhow::anyhow!("Database error")));
        }
    };
    if user_exists {
        let _code = create_and_send_verification_code(&state, &email, "password_reset").await?;
    }
    let template = templates::ForgotPasswordStep2Template {
        email,
        error_message: String::new(),
        success_message: "A new verification code has been sent to your email.".to_string(),
    };
    Ok(Html(template.render()?))
}

/// Check if verification code rate limit has been exceeded
///
/// ### Arguments
/// - `state`: The application state
/// - `email`: The user's email
/// - `purpose`: The verification code purpose
///
/// ### Returns
/// - `Ok(())`: Rate limit not exceeded
/// - `Err(AppError)`: Rate limit exceeded
async fn check_verification_code_rate_limit(
    state: &AppState,
    email: &str,
    purpose: &str,
) -> Result<(), AppError> {
    let active_count = state
        .verification_code_repository
        .count_active_codes(email.to_string(), purpose.to_string())
        .await
        .map_err(|e| {
            AppError::InternalError(anyhow::anyhow!("Failed to count verification codes: {}", e))
        })?;
    if active_count >= verification_code::VERIFICATION_CODE_MAX_ATTEMPTS {
        return Err(AppError::InternalError(anyhow::anyhow!(
            "You've reached the maximum number of verification codes. Please wait 5 minutes before requesting a new code."
        )));
    }
    Ok(())
}

/// Create verification code and send email
///
/// ### Arguments
/// - `state`: The application state
/// - `email`: The user's email
/// - `purpose`: The verification code purpose
///
/// ### Returns
/// - `Ok(String)`: The generated verification code
/// - `Err(AppError)`: Error occurred during creation or sending
async fn create_and_send_verification_code(
    state: &AppState,
    email: &str,
    purpose: &str,
) -> Result<String, AppError> {
    let code = generate_code();
    state
        .verification_code_repository
        .create(email.to_string(), code.clone(), purpose.to_string())
        .await
        .map_err(|e| {
            tracing::error!("Failed to create verification code: {}", e);
            AppError::InternalError(anyhow::anyhow!("Failed to create verification code: {}", e))
        })?;
    if state.is_prod {
        state
            .mailer
            .send_verification_email(email.to_string(), code.clone())
            .await
            .map_err(|e| {
                tracing::error!("Failed to send email: {}", e);
                AppError::InternalError(anyhow::anyhow!("Failed to send email: {}", e))
            })?;
        tracing::info!("Verification email sent to {}", sanitize_for_log(&email));
    } else {
        tracing::info!(
            "Development mode - verification email not sent\nVerification code for {}: {}",
            sanitize_for_log(&email),
            &code
        );
    }
    Ok(code)
}

/// Format verification result into user-friendly error message
///
/// ### Arguments
/// - `result`: The verification result
///
/// ### Returns
/// - `String`: User-friendly error message
fn format_verification_error(result: &VerificationResult) -> String {
    match result {
        VerificationResult::Invalid { attempts_remaining } => {
            if *attempts_remaining > 0 {
                format!(
                    "Invalid verification code. {} attempt(s) remaining.",
                    attempts_remaining
                )
            } else {
                "Too many failed attempts. Please request a new code.".to_string()
            }
        }
        VerificationResult::TooManyAttempts => {
            "Too many failed attempts. Please request a new code.".to_string()
        }
        VerificationResult::Expired => {
            "Verification code has expired. Please request a new code.".to_string()
        }
        VerificationResult::NotFound => {
            "No verification code found. Please request a new code.".to_string()
        }
        _ => "Verification failed".to_string(),
    }
}

/// Hashes a password
///
/// ### Arguments
/// - `password`: The password to hash
///
/// ### Returns
/// - `Ok(String)`: The hashed password
/// - `Err(argon2::password_hash::Error)`: The error if the password cannot be hashed
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
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
/// - `true` if the password is valid, `false` otherwise
fn verify_password(password: &str, password_hash: String) -> bool {
    let password_hash = PasswordHash::new(&password_hash).unwrap();
    let argon2 = Argon2::default();
    argon2
        .verify_password(password.as_bytes(), &password_hash)
        .is_ok()
}
