use lazy_static::lazy_static;
use regex::Regex;
use time::OffsetDateTime;

lazy_static! {
    static ref EMAIL_REGEX: Regex = Regex::new(
        r"^[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+)*@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
    ).unwrap();
}

/// Checks if the email is valid
///
/// ### Arguments
/// - `email`: The email to check
///
/// ### Returns
/// - `true` if the email is valid, `false` otherwise
pub fn is_valid_email(email: &str) -> bool {
    EMAIL_REGEX.is_match(email)
}

/// Checks if the password is valid
///
/// ### Arguments
/// - `password`: The password to check
///
/// ### Returns
/// - `true` if the password is valid, `false` otherwise
pub fn is_password_valid(password: &str) -> bool {
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

/// Format timestamp as YYYY-MM-DD HH:MM:SS UTC
///
/// ### Arguments
/// - `dt`: The OffsetDateTime to format
///
/// ### Returns
/// - Formatted string in the format "YYYY-MM-DD HH:MM:SS"
pub fn format_datetime_utc(dt: &OffsetDateTime) -> String {
    let dt_utc = dt.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        dt_utc.year(),
        dt_utc.month() as u8,
        dt_utc.day(),
        dt_utc.hour(),
        dt_utc.minute(),
        dt_utc.second()
    )
}

/// Format timestamp as YYYY-MM-DD UTC
///
/// ### Arguments
/// - `dt`: The OffsetDateTime to format
///
/// ### Returns
/// - Formatted string in the format "YYYY-MM-DD"
pub fn format_date_utc(dt: &OffsetDateTime) -> String {
    let dt_utc = dt.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}",
        dt_utc.year(),
        dt_utc.month() as u8,
        dt_utc.day()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_email_with_valid_emails() {
        // Standard emails
        assert!(is_valid_email("user@example.com"));
        assert!(is_valid_email("test.user@example.com"));
        assert!(is_valid_email("user+tag@example.co.uk"));
        
        // Edge cases that should be valid
        assert!(is_valid_email("a@b.c"));
        assert!(is_valid_email("user123@test-domain.com"));
        assert!(is_valid_email("first.last@subdomain.example.com"));
        
        // Special characters allowed in local part
        assert!(is_valid_email("user!#$%&'*+/=?^_`{|}~@example.com"));
        
        // Numbers in domain
        assert!(is_valid_email("user@123.456.com"));
    }

    #[test]
    fn test_is_valid_email_with_invalid_emails() {
        // Missing @
        assert!(!is_valid_email("userexample.com"));
        assert!(!is_valid_email("user"));
        
        // Multiple @
        assert!(!is_valid_email("user@@example.com"));
        assert!(!is_valid_email("user@domain@example.com"));
        
        // Empty or whitespace
        assert!(!is_valid_email(""));
        assert!(!is_valid_email(" "));
        assert!(!is_valid_email("   "));
        
        // Missing local part
        assert!(!is_valid_email("@example.com"));
        
        // Missing domain
        assert!(!is_valid_email("user@"));
        
        // Invalid characters
        assert!(!is_valid_email("user name@example.com")); // space
        assert!(!is_valid_email("user@exam ple.com")); // space in domain

        // No TLD
        assert!(!is_valid_email("user@domain"));

        // Starts/ends with special chars
        assert!(!is_valid_email(".user@example.com"));
        assert!(!is_valid_email("user.@example.com"));
    }

    #[test]
    fn test_is_password_valid_with_valid_passwords() {
        // Minimum valid password (8 chars with all requirements)
        assert!(is_password_valid("Pass123!"));
        assert!(is_password_valid("Abcdef1!"));
        
        // Common valid passwords
        assert!(is_password_valid("MyPassword1!"));
        assert!(is_password_valid("Secure@Pass123"));
        assert!(is_password_valid("ComplexP@ssw0rd"));
        
        // Various special characters
        assert!(is_password_valid("Password1#"));
        assert!(is_password_valid("Password1$"));
        assert!(is_password_valid("Password1%"));
        assert!(is_password_valid("Password1&"));
        assert!(is_password_valid("Password1*"));
        
        // Maximum length (64 chars)
        assert!(is_password_valid(&format!("{}1!Aa", "a".repeat(59))));
    }

    #[test]
    fn test_is_password_valid_too_short() {
        assert!(!is_password_valid("Pass1!")); 
        assert!(!is_password_valid("Abc123!")); 
        assert!(!is_password_valid(""));
    }

    #[test]
    fn test_is_password_valid_too_long() {
        let password = format!("Aa1!{}", "a".repeat(61));
        assert!(!is_password_valid(&password));
        let password = format!("Aa1!{}", "a".repeat(96));
        assert!(!is_password_valid(&password));
    }

    #[test]
    fn test_is_password_valid_missing_uppercase() {
        assert!(!is_password_valid("password123!"));
        assert!(!is_password_valid("mypass1!"));
        assert!(!is_password_valid("lowercaseonly123!"));
    }

    #[test]
    fn test_is_password_valid_missing_lowercase() {
        assert!(!is_password_valid("PASSWORD123!"));
        assert!(!is_password_valid("MYPASS1!"));
        assert!(!is_password_valid("UPPERCASEONLY123!"));
    }

    #[test]
    fn test_is_password_valid_missing_digit() {
        assert!(!is_password_valid("Password!"));
        assert!(!is_password_valid("MyPass!@#"));
        assert!(!is_password_valid("NoDigitsHere!"));
    }

    #[test]
    fn test_is_password_valid_missing_special_character() {
        assert!(!is_password_valid("Password123"));
        assert!(!is_password_valid("MyPass123"));
        assert!(!is_password_valid("NoSpecialChar1"));
    }

    #[test]
    fn test_is_password_valid_multiple_missing_requirements() {
        // Missing multiple requirements
        assert!(!is_password_valid("password"));    
        assert!(!is_password_valid("PASSWORD"));
        assert!(!is_password_valid("12345678"));
        assert!(!is_password_valid("Pass"));
    }
}