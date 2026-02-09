use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use base64::{Engine as _, engine::general_purpose};
use rand::Rng;

/// Generate a new API key
///
/// ### Returns
/// - `String`: The new API key
pub fn generate_api_key() -> String {
    let mut rng = rand::rng();
    let mut key_bytes = [0u8; 32];
    rng.fill(&mut key_bytes);
    let encoded = general_purpose::URL_SAFE_NO_PAD.encode(key_bytes);
    format!("fulgur_{}", encoded)
}

/// Hash an API key
///
/// ### Arguments
/// - `api_key`: The API key to hash
///
/// ### Returns
/// - `Ok(String)`: The hashed API key
/// - `Err(anyhow::Error)`: The error if the API key cannot be hashed
pub fn hash_api_key(api_key: &str) -> anyhow::Result<String> {
    let mut rng = rand::rng();
    let mut salt_bytes = [0u8; 16];
    rng.fill(&mut salt_bytes);

    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to encode salt: {}", e))?;
    let hash = match Argon2::default().hash_password(api_key.as_bytes(), &salt) {
        Ok(hash) => hash,
        Err(e) => return Err(anyhow::anyhow!("Failed to hash API key: {}", e)),
    };
    Ok(hash.to_string())
}

/// Verify an API key
///
/// ### Arguments
/// - `api_key`: The API key to verify
/// - `hash`: The hashed API key
///
/// ### Returns
/// - `Ok(bool)`: True if the API key is valid, false otherwise
/// - `Err(anyhow::Error)`: The error if the API key cannot be verified
pub fn verify_api_key(api_key: &str, hash: &str) -> anyhow::Result<bool> {
    let hash = match PasswordHash::new(hash) {
        Ok(hash) => hash,
        Err(e) => return Err(anyhow::anyhow!("Invalid hash: {}", e)),
    };
    Ok(Argon2::default()
        .verify_password(api_key.as_bytes(), &hash)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_api_key_format() {
        let key = generate_api_key();

        // Should start with "fulgur_"
        assert!(
            key.starts_with("fulgur_"),
            "API key should start with 'fulgur_'"
        );

        // Should be longer than just the prefix
        assert!(key.len() > 7, "API key should be longer than prefix");

        // Extract the encoded part (after "fulgur_")
        let encoded_part = &key[7..];

        // Should be valid base64 URL-safe encoding (no padding)
        // Base64 URL-safe without padding is 43 characters for 32 bytes
        assert_eq!(
            encoded_part.len(),
            43,
            "Encoded part should be 43 characters for 32 bytes"
        );
    }

    #[test]
    fn test_generate_api_key_uniqueness() {
        // Generate multiple keys and verify they're different
        let key1 = generate_api_key();
        let key2 = generate_api_key();
        let key3 = generate_api_key();

        assert_ne!(key1, key2, "Generated keys should be unique");
        assert_ne!(key1, key3, "Generated keys should be unique");
        assert_ne!(key2, key3, "Generated keys should be unique");
    }

    #[test]
    fn test_hash_api_key_success() {
        let api_key = "test_api_key_123";

        let result = hash_api_key(api_key);

        assert!(
            result.is_ok(),
            "hash_api_key should succeed for valid input"
        );
        let hash = result.unwrap();

        // Hash should not be empty
        assert!(!hash.is_empty(), "Hash should not be empty");

        // Hash should start with $argon2 (Argon2 hash format)
        assert!(
            hash.starts_with("$argon2"),
            "Hash should be in Argon2 format"
        );
    }

    #[test]
    fn test_hash_api_key_different_salts() {
        let api_key = "same_api_key";

        // Hash the same key twice - should produce different hashes due to different salts
        let hash1 = hash_api_key(api_key).unwrap();
        let hash2 = hash_api_key(api_key).unwrap();

        assert_ne!(
            hash1, hash2,
            "Same key with different salts should produce different hashes"
        );
    }

    #[test]
    fn test_hash_api_key_empty_string() {
        let result = hash_api_key("");

        // Empty string should still hash successfully
        assert!(result.is_ok(), "hash_api_key should handle empty string");
        let hash = result.unwrap();
        assert!(
            !hash.is_empty(),
            "Hash should not be empty even for empty input"
        );
    }

    #[test]
    fn test_verify_api_key_correct() {
        let api_key = "test_api_key_456";

        // Hash the key
        let hash = hash_api_key(api_key).unwrap();

        // Verify with the same key
        let result = verify_api_key(api_key, &hash);

        assert!(
            result.is_ok(),
            "verify_api_key should succeed for valid hash"
        );
        assert!(
            result.unwrap(),
            "Correct API key should verify successfully"
        );
    }

    #[test]
    fn test_verify_api_key_incorrect() {
        let api_key = "test_api_key_456";
        let wrong_key = "wrong_api_key";

        // Hash the correct key
        let hash = hash_api_key(api_key).unwrap();

        // Verify with wrong key
        let result = verify_api_key(wrong_key, &hash);

        assert!(
            result.is_ok(),
            "verify_api_key should succeed even for incorrect key"
        );
        assert!(
            !result.unwrap(),
            "Incorrect API key should not verify successfully"
        );
    }

    #[test]
    fn test_verify_api_key_invalid_hash() {
        let api_key = "test_api_key_789";
        let invalid_hash = "not_a_valid_hash";

        let result = verify_api_key(api_key, invalid_hash);

        assert!(
            result.is_err(),
            "verify_api_key should fail for invalid hash format"
        );
    }

    #[test]
    fn test_verify_api_key_empty_hash() {
        let api_key = "test_api_key";

        let result = verify_api_key(api_key, "");

        assert!(result.is_err(), "verify_api_key should fail for empty hash");
    }

    #[test]
    fn test_hash_and_verify_roundtrip() {
        let api_key = generate_api_key();

        // Hash the generated key
        let hash = hash_api_key(&api_key).unwrap();

        // Verify it can be verified
        let verified = verify_api_key(&api_key, &hash).unwrap();
        assert!(verified, "Generated and hashed key should verify correctly");
    }

    #[test]
    fn test_hash_and_verify_special_characters() {
        let api_key = "fulgur_!@#$%^&*()_+-=[]{}|;:,.<>?";

        let hash = hash_api_key(api_key).unwrap();
        let verified = verify_api_key(api_key, &hash).unwrap();

        assert!(
            verified,
            "API key with special characters should verify correctly"
        );
    }

    #[test]
    fn test_hash_and_verify_unicode() {
        let api_key = "fulgur_测试_key_🎉";

        let hash = hash_api_key(api_key).unwrap();
        let verified = verify_api_key(api_key, &hash).unwrap();

        assert!(
            verified,
            "API key with unicode characters should verify correctly"
        );
    }

    #[test]
    fn test_hash_and_verify_long_key() {
        // Generate a very long API key
        let long_key = "fulgur_".to_string() + &"a".repeat(200);

        let hash = hash_api_key(&long_key).unwrap();
        let verified = verify_api_key(&long_key, &hash).unwrap();

        assert!(verified, "Long API key should verify correctly");
    }
}
