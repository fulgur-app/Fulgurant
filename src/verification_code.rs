use crate::db::DbPool;
use crate::{db_execute, db_execute_dual, db_fetch_one_dual, db_fetch_optional};
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use rand::RngExt;
use serde::{Deserialize, Serialize};
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
/// - `Ok(String)`: The hashed code
/// - `Err(anyhow::Error)`: If hashing fails
pub fn hash_code(code: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(code.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Failed to hash verification code: {e}"))?
        .to_string();
    Ok(hash)
}

/// Verify a code
///
/// ### Arguments
/// - `code`: The code to verify
/// - `hash`: The hashed code
///
/// ### Returns
/// - `true` if the code is valid, `false` otherwise (including on malformed hash)
pub fn verify_code(code: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        tracing::warn!("Failed to parse verification code hash - treating as invalid");
        return false;
    };
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
    pool: DbPool,
}

impl VerificationCodeRepository {
    /// Create a new verification code repository
    ///
    /// ### Arguments
    /// - `pool`: The database pool (`SQLite` or `PostgreSQL`)
    ///
    /// ### Returns
    /// - `VerificationCodeRepository`: The verification code repository
    pub fn new(pool: DbPool) -> Self {
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
        let code_hash = hash_code(&code)?;
        let id = Uuid::new_v4().to_string();
        let expires_at =
            OffsetDateTime::now_utc() + Duration::minutes(VERIFICATION_CODE_EXPIRATION_MINUTES);
        db_execute_dual!(
            self.pool,
            sqlite: "INSERT INTO verification_codes (id, email, code_hash, expires_at, purpose) VALUES (?, ?, ?, ?, ?)",
            postgres: "INSERT INTO verification_codes (id, email, code_hash, expires_at, purpose) VALUES ($1, $2, $3, to_timestamp($4), $5)",
            id.clone(),
            email.clone(),
            code_hash,
            expires_at.unix_timestamp(),
            purpose.clone()
        )?;
        let verification_code = self.get_for(email, purpose).await?;
        let Some(verification_code) = verification_code else {
            return Err(anyhow::anyhow!("Failed to create verification code"));
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
        db_execute!(
            self.pool,
            "DELETE FROM verification_codes WHERE email = ? AND purpose = ?",
            email,
            purpose
        )?;
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
        let verification_code = db_fetch_optional!(
            self.pool,
            "SELECT * FROM verification_codes WHERE email = ? AND purpose = ? AND verified_at IS NULL",
            VerificationCode,
            email,
            purpose
        )?;
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
        db_execute!(
            self.pool,
            "UPDATE verification_codes SET attempts = attempts + 1 WHERE id = ?",
            id
        )?;
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
        db_execute_dual!(
            self.pool,
            sqlite: "UPDATE verification_codes SET verified_at = ? WHERE id = ?",
            postgres: "UPDATE verification_codes SET verified_at = to_timestamp($1) WHERE id = $2",
            now.unix_timestamp(),
            id
        )?;
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
        let Some(verification_code) = verification_code else {
            return Ok(VerificationResult::NotFound);
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
        let count: (i64,) = db_fetch_one_dual!(
            self.pool,
            sqlite: "SELECT COUNT(*) FROM verification_codes WHERE email = ? AND purpose = ? AND expires_at > ?",
            postgres: "SELECT COUNT(*) FROM verification_codes WHERE email = $1 AND purpose = $2 AND expires_at > to_timestamp($3)",
            (i64,),
            email,
            purpose,
            now.unix_timestamp()
        )?;
        Ok(count.0 as i32)
    }

    /// Delete all expired verification codes (for cleanup job)
    ///
    /// ### Returns
    /// - `Ok(u64)`: The number of deleted verification codes
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn delete_expired(&self) -> Result<u64, sqlx::Error> {
        let now = OffsetDateTime::now_utc();
        db_execute_dual!(
            self.pool,
            sqlite: "DELETE FROM verification_codes WHERE expires_at < ?",
            postgres: "DELETE FROM verification_codes WHERE expires_at < to_timestamp($1)",
            now.unix_timestamp()
        )
    }
}
