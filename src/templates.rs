use crate::{devices::Device, shares::DisplayShare};
use askama::Template;

/// Main page template
#[derive(Template)]
#[template(path = "index.html")]
pub struct IndexTemplate {
    pub devices: Vec<Device>,
    pub max_devices_per_user: Option<i32>,
    pub shares: Vec<DisplayShare>,
    pub user_id: i32,
    pub first_name: String,
}

/// Individual device row template (for HTMX updates)
#[derive(Template)]
#[template(path = "partials/devices/device_row.html")]
pub struct DeviceRowTemplate {
    pub device: Device,
}

/// Error message template
#[derive(Template)]
#[template(path = "error.html")]
pub struct ErrorTemplate {
    pub title: String,
    pub message: String,
    pub link: Option<String>,
    pub link_text: Option<String>,
}

/// Edit form template (for HTMX inline editing)
#[derive(Template)]
#[template(path = "partials/devices/device_edit_form.html")]
pub struct DeviceEditFormTemplate {
    pub device: Device,
}

/// Inline edit form template (for HTMX inline editing)
#[derive(Template)]
#[template(path = "partials/devices/inline_edit_form.html")]
pub struct InlineEditFormTemplate {
    pub device: Device,
}

/// Inline renew form template (for HTMX inline renewing)
#[derive(Template)]
#[template(path = "partials/devices/inline_renew_form.html")]
pub struct InlineRenewFormTemplate {
    pub device: Device,
}

/// Empty state template
#[derive(Template)]
#[template(path = "partials/devices/empty_state.html")]
pub struct DeviceEmptyStateTemplate;

/// Error message template
#[derive(Template)]
#[template(path = "partials/error_message.html")]
pub struct ErrorMessageTemplate {
    pub message: String,
}

/// Device creation response template (includes device row and API key panel)
#[derive(Template)]
#[template(path = "partials/devices/device_creation_response.html")]
pub struct DeviceCreationResponseTemplate {
    pub device: Device,
    pub api_key: String,
}

/// Empty state template
#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub can_register: bool,
}

/// Register template
#[derive(Template)]
#[template(path = "register.html")]
pub struct RegisterTemplate {
    pub error_message: String,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
}

/// Register step 2 template
#[derive(Template)]
#[template(path = "partials/auth/registration_step_1.html")]
pub struct RegisterStep1Template {
    pub error_message: String,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
}

/// Register step 2 template
#[derive(Template)]
#[template(path = "partials/auth/registration_step_2.html")]
pub struct RegisterStep2Template {
    pub email: String,
    pub error_message: String,
}

/// Registration step 3 template
#[derive(Template)]
#[template(path = "partials/auth/registration_step_3.html")]
pub struct RegisterStep3Template {
    pub first_name: String,
}

/// Settings page template
#[derive(Template)]
#[template(path = "settings.html")]
pub struct SettingsTemplate {
    pub email: String,
    pub first_name: String,
    pub last_name: String,
}

/// Update name success message template
#[derive(Template)]
#[template(path = "partials/settings/update_name_success.html")]
pub struct UpdateNameSuccessTemplate {
    pub first_name: String,
    pub last_name: String,
}

/// Email change step 2 template (verification code entry)
#[derive(Template)]
#[template(path = "partials/settings/email_change_step_2.html")]
pub struct EmailChangeStep2Template {
    pub new_email: String,
    pub error_message: String,
}

/// Email change success template
#[derive(Template)]
#[template(path = "partials/settings/email_change_success.html")]
pub struct EmailChangeSuccessTemplate {
    pub email: String,
}

/// Forgot password step 1 template (full page)
#[derive(Template)]
#[template(path = "forgot_password.html")]
pub struct ForgotPasswordStep1Template {
    pub error_message: String,
    pub email: String,
}

/// Forgot password step 1 partial template (form only, for HTMX responses)
#[derive(Template)]
#[template(path = "partials/auth/forgot_password_step_1.html")]
pub struct ForgotPasswordStep1PartialTemplate {
    pub error_message: String,
    pub email: String,
}

/// Forgot password step 2 template (verification code)
#[derive(Template)]
#[template(path = "partials/auth/forgot_password_step_2.html")]
pub struct ForgotPasswordStep2Template {
    pub email: String,
    pub error_message: String,
    pub success_message: String,
}

/// Forgot password step 3 template (new password)
#[derive(Template)]
#[template(path = "partials/auth/forgot_password_step_3.html")]
pub struct ForgotPasswordStep3Template {
    pub email: String,
    pub error_message: String,
}

/// Forgot password success template
#[derive(Template)]
#[template(path = "partials/auth/forgot_password_success.html")]
pub struct ForgotPasswordSuccessTemplate {}

/// Initial setup template (create first admin user)
#[derive(Template)]
#[template(path = "setup.html")]
pub struct SetupTemplate {
    pub error_message: String,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
}
