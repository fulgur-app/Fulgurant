use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

/// JWT claims structure for access tokens
///
/// ### Fields
/// - `sub`: Subject (user_id as string)
/// - `device_id`: UUID of the authenticated device
/// - `device_name`: Human-readable device name
/// - `exp`: Expiration timestamp (Unix epoch)
/// - `iat`: Issued at timestamp (Unix epoch)
/// - `iss`: Issuer (always "fulgurant")
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub sub: String,
    pub device_id: String,
    pub device_name: String,
    pub exp: i64,
    pub iat: i64,
    pub iss: String,
}

/// Generate a JWT access token
///
/// ### Arguments
/// - `user_id`: The user ID
/// - `device_id`: The device UUID
/// - `device_name`: The device name
/// - `jwt_secret`: The JWT signing secret
/// - `expiry_seconds`: Token expiry duration in seconds (default: 900 = 15 minutes)
///
/// ### Returns
/// - `Ok(String)`: The signed JWT token
/// - `Err(anyhow::Error)`: Error if token generation fails
pub fn generate_access_token(
    user_id: i32,
    device_id: String,
    device_name: String,
    jwt_secret: &str,
    expiry_seconds: i64,
) -> anyhow::Result<String> {
    let now = OffsetDateTime::now_utc();
    let expiration = now + Duration::seconds(expiry_seconds);
    let claims = AccessTokenClaims {
        sub: user_id.to_string(),
        device_id,
        device_name,
        exp: expiration.unix_timestamp(),
        iat: now.unix_timestamp(),
        iss: "fulgurant".to_string(),
    };
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .map_err(|e| anyhow::anyhow!("Failed to generate JWT: {}", e))?;
    Ok(token)
}

/// Validate a JWT access token and extract claims
///
/// ### Arguments
/// - `token`: The JWT token to validate
/// - `jwt_secret`: The JWT signing secret
///
/// ### Returns
/// - `Ok(AccessTokenClaims)`: The validated claims
/// - `Err(anyhow::Error)`: Error if validation fails (invalid signature, expired, etc.)
pub fn validate_access_token(token: &str, jwt_secret: &str) -> anyhow::Result<AccessTokenClaims> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&["fulgurant"]);
    let token_data = decode::<AccessTokenClaims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|e| anyhow::anyhow!("JWT validation failed: {}", e))?;
    Ok(token_data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_validate_token() {
        let secret = "test_secret_key_minimum_32_bytes_long!!";
        let token = generate_access_token(
            123,
            "device-uuid-123".to_string(),
            "Test Device".to_string(),
            secret,
            900,
        )
        .unwrap();
        let claims = validate_access_token(&token, secret).unwrap();
        assert_eq!(claims.sub, "123");
        assert_eq!(claims.device_id, "device-uuid-123");
        assert_eq!(claims.device_name, "Test Device");
        assert_eq!(claims.iss, "fulgurant");
    }

    #[test]
    fn test_validate_with_wrong_secret() {
        let secret = "test_secret_key_minimum_32_bytes_long!!";
        let token = generate_access_token(
            123,
            "device-uuid-123".to_string(),
            "Test Device".to_string(),
            secret,
            900,
        )
        .unwrap();

        let wrong_secret = "wrong_secret_key_minimum_32_bytes_long!!";
        let result = validate_access_token(&token, wrong_secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_expired_token() {
        let secret = "test_secret_key_minimum_32_bytes_long!!";
        let token = generate_access_token(
            123,
            "device-uuid-123".to_string(),
            "Test Device".to_string(),
            secret,
            -120,
        )
        .unwrap();

        std::thread::sleep(std::time::Duration::from_millis(100));
        let result = validate_access_token(&token, secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_claims_integrity() {
        let secret = "test_secret_key_minimum_32_bytes_long!!";
        let token = generate_access_token(
            456,
            "device-xyz".to_string(),
            "Test Device 2".to_string(),
            secret,
            900,
        )
        .unwrap();
        let claims = validate_access_token(&token, secret).unwrap();
        assert_eq!(claims.sub, "456");
        assert_eq!(claims.device_id, "device-xyz");
        assert_eq!(claims.device_name, "Test Device 2");
        assert_eq!(claims.iss, "fulgurant");
        let now = OffsetDateTime::now_utc().unix_timestamp();
        assert!(claims.iat <= now);
        assert!(claims.exp > now);
        assert_eq!(claims.exp - claims.iat, 900);
    }

    #[test]
    fn test_token_reuse_different_issuer() {
        let secret1 = "secret_for_instance_1_minimum_32_chars!!";
        let secret2 = "secret_for_instance_2_minimum_32_chars!!";
        let token = generate_access_token(
            789,
            "device-def".to_string(),
            "Instance 1 Device".to_string(),
            secret1,
            900,
        )
        .unwrap();
        let result = validate_access_token(&token, secret2);
        assert!(result.is_err());
    }
}
