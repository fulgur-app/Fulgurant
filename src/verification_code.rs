use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Row, Sqlite, SqlitePool};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

const VERIFICATION_CODE_EXPIRATION_MINUTES: i64 = 5;
pub const VERIFICATION_CODE_MAX_ATTEMPTS: i32 = 3;

/// Generate a random 6-digit code
///
/// ### Returns
/// - `String`: The generated code
pub fn generate_code() -> String {
    let code: u32 = rand::rng().random_range(100000..=999999);
    code.to_string()
}

/// Hash a code
///
/// ### Arguments
/// - `code`: The code to hash
///
/// ### Returns
/// - `String`: The hashed code
pub fn hash_code(code: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(code.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

/// Verify a code
///
/// ### Arguments
/// - `code`: The code to verify
/// - `hash`: The hashed code
///
/// ### Returns
/// - `true` if the code is valid, `false` otherwise
pub fn verify_code(code: &str, hash: &str) -> bool {
    let parsed = PasswordHash::new(hash).unwrap();
    Argon2::default()
        .verify_password(code.as_bytes(), &parsed)
        .is_ok()
}

pub enum VerificationResult {
    NotFound,
    Invalid { attempts_remaining: i32 },
    Expired,
    Verified,
    TooManyAttempts,
}

#[allow(dead_code)]
impl VerificationResult {
    /// Convert a VerificationResult to an error message
    ///
    /// ### Arguments
    /// - `self`: The VerificationResult
    ///
    /// ### Returns
    /// - `String`: The error message
    pub fn to_error_message(&self) -> String {
        match self {
            VerificationResult::Verified => "Code verified successfully".to_string(),
            VerificationResult::NotFound => {
                "No verification code found. Please request a new one.".to_string()
            }
            VerificationResult::Expired => {
                "Code has expired. Please request a new one.".to_string()
            }
            VerificationResult::Invalid { attempts_remaining } => {
                format!("Invalid code. {} attempt(s) remaining.", attempts_remaining)
            }
            VerificationResult::TooManyAttempts => {
                "Too many failed attempts. Please request a new code.".to_string()
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, Clone)]
pub struct VerificationCode {
    pub id: String,
    pub email: String,
    pub code_hash: String,
    pub attempts: i32,
    pub max_attempts: i32,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub verified_at: Option<OffsetDateTime>,
    pub purpose: String,
}

#[derive(Clone)]
pub struct VerificationCodeRepository {
    pool: SqlitePool,
}

impl VerificationCodeRepository {
    /// Create a new verification code repository
    ///
    /// ### Arguments
    /// - `pool`: The SQLite pool
    ///
    /// ### Returns
    /// - `VerificationCodeRepository`: The verification code repository
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }

    /// Create a new verification code
    ///
    /// ### Arguments
    /// - `email`: The email of the user
    /// - `code`: The code to create
    /// - `purpose`: The purpose of the code
    ///
    /// ### Returns
    /// - `Ok(VerificationCode)`: The created verification code
    /// - `Err(anyhow::Error)`: The error if the operation fails
    pub async fn create(
        &self,
        email: String,
        code: String,
        purpose: String,
    ) -> anyhow::Result<VerificationCode> {
        let code_hash = hash_code(&code);
        let id = Uuid::new_v4().to_string();
        let expires_at =
            OffsetDateTime::now_utc() + Duration::minutes(VERIFICATION_CODE_EXPIRATION_MINUTES);
        sqlx::query(
            "INSERT INTO verification_codes (id, email, code_hash, expires_at, purpose) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(id.clone())
        .bind(email.clone())
        .bind(code_hash)
        .bind(expires_at.unix_timestamp())
        .bind(purpose.clone())
        .execute(&self.pool)
        .await?;
        let verification_code = self.get_for(email, purpose).await?;
        let verification_code = match verification_code {
            Some(code) => code,
            None => return Err(anyhow::anyhow!("Failed to create verification code")),
        };
        Ok(verification_code)
    }

    /// Delete a verification code for an email and purpose
    ///
    /// ### Arguments
    /// - `email`: The email of the user
    /// - `purpose`: The purpose of the code
    ///
    /// ### Returns
    /// - `Ok(())`: The result of the operation if the verification code was deleted successfully
    /// - `Err(anyhow::Error)`: The error if the operation fails
    pub async fn delete_for(&self, email: String, purpose: String) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM verification_codes WHERE email = ? AND purpose = ?")
            .bind(email)
            .bind(purpose)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Get a verification code for an email and purpose
    ///
    /// ### Arguments
    /// - `email`: The email of the user
    /// - `purpose`: The purpose of the code
    ///
    /// ### Returns
    /// - `Ok(Option<VerificationCode>)`: The verification code if found, otherwise None
    /// - `Err(anyhow::Error)`: The error if the operation fails
    pub async fn get_for(
        &self,
        email: String,
        purpose: String,
    ) -> anyhow::Result<Option<VerificationCode>> {
        let verification_code = sqlx::query_as::<_, VerificationCode>(
            "SELECT * FROM verification_codes WHERE email = ? AND purpose = ? AND verified_at IS NULL",
        )
        .bind(email)
        .bind(purpose)
        .fetch_optional(&self.pool)
        .await?;
        Ok(verification_code)
    }

    /// Update the attempts for a verification code
    ///
    /// ### Arguments
    /// - `id`: The ID of the verification code
    ///
    /// ### Returns
    /// - `Ok(())`: The result of the operation if the attempts were updated successfully
    /// - `Err(anyhow::Error)`: The error if the operation fails
    pub async fn update_attempts(&self, id: String) -> anyhow::Result<()> {
        sqlx::query("UPDATE verification_codes SET attempts = attempts + 1 WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Mark a verification code as verified
    ///
    /// ### Arguments
    /// - `id`: The ID of the verification code
    ///
    /// ### Returns
    /// - `Ok(())`: The result of the operation if the verification code was marked as verified successfully
    /// - `Err(anyhow::Error)`: The error if the operation fails
    pub async fn mark_as_verified(&self, id: String) -> anyhow::Result<()> {
        let now = OffsetDateTime::now_utc();
        sqlx::query("UPDATE verification_codes SET verified_at = ? WHERE id = ?")
            .bind(now.unix_timestamp())
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Verify a validationcode
    ///
    /// ### Arguments
    /// - `code`: The code to verify
    /// - `email`: The email of the user
    /// - `purpose`: The purpose of the code
    ///
    /// ### Returns
    /// - `Ok(VerificationResult)`: The result of the verification
    /// - `Err(anyhow::Error)`: The error if the operation fails
    pub async fn verify_code(
        &self,
        code: String,
        email: String,
        purpose: String,
    ) -> anyhow::Result<VerificationResult> {
        let verification_code = self.get_for(email, purpose).await?;
        let verification_code = match verification_code {
            Some(code) => code,
            None => return Ok(VerificationResult::NotFound),
        };

        if OffsetDateTime::now_utc() > verification_code.expires_at {
            return Ok(VerificationResult::Expired);
        }

        if verification_code.attempts >= verification_code.max_attempts {
            return Ok(VerificationResult::TooManyAttempts);
        }

        let is_valid = verify_code(&code, &verification_code.code_hash);
        if !is_valid {
            let remaining = verification_code.max_attempts - verification_code.attempts - 1;
            self.update_attempts(verification_code.id).await?;
            return Ok(VerificationResult::Invalid {
                attempts_remaining: remaining,
            });
        }

        self.mark_as_verified(verification_code.id).await?;
        Ok(VerificationResult::Verified)
    }

    /// Count active (non-expired) verification codes for an email and purpose
    ///
    /// ### Arguments
    /// - `email`: The email of the user
    /// - `purpose`: The purpose of the code
    ///
    /// ### Returns
    /// - `Ok(i32)`: The number of active verification codes
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn count_active_codes(
        &self,
        email: String,
        purpose: String,
    ) -> Result<i32, sqlx::Error> {
        let now = OffsetDateTime::now_utc();
        let result = sqlx::query(
            "SELECT COUNT(*) FROM verification_codes WHERE email = ? AND purpose = ? AND expires_at > ?"
        )
        .bind(email)
        .bind(purpose)
        .bind(now.unix_timestamp())
        .fetch_one(&self.pool)
        .await?;
        Ok(result.get::<i32, _>(0))
    }

    /// Delete all expired verification codes (for cleanup job)
    ///
    /// ### Returns
    /// - `Ok(u64)`: The number of deleted verification codes
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn delete_expired(&self) -> Result<u64, sqlx::Error> {
        let now = OffsetDateTime::now_utc();
        let result = sqlx::query("DELETE FROM verification_codes WHERE expires_at < ?")
            .bind(now.unix_timestamp())
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}
