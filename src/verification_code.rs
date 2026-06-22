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
    let code: u32 = rand::rng().random_range(100_000..=999_999);
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

#[derive(Debug)]
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

    /// Atomically claim a verification attempt for a code
    ///
    /// ### Arguments
    /// - `id`: The ID of the verification code
    ///
    /// ### Returns
    /// - `Ok(true)`: An attempt was claimed; the caller may run the comparison
    /// - `Ok(false)`: The attempt cap was already reached; no attempt claimed
    /// - `Err(anyhow::Error)`: The error if the operation fails
    pub async fn claim_attempt(&self, id: String) -> anyhow::Result<bool> {
        let rows_affected = db_execute!(
            self.pool,
            "UPDATE verification_codes SET attempts = attempts + 1 WHERE id = ? AND attempts < max_attempts",
            id
        )?;
        Ok(rows_affected == 1)
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

        if !self.claim_attempt(verification_code.id.clone()).await? {
            return Ok(VerificationResult::TooManyAttempts);
        }

        let is_valid = verify_code(&code, &verification_code.code_hash);
        if !is_valid {
            let remaining =
                (verification_code.max_attempts - verification_code.attempts - 1).max(0);
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

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    /// Build an in-memory `SQLite`-backed verification code repository.
    ///
    /// ### Returns
    /// - `VerificationCodeRepository`: A repository over a fresh, migrated database
    async fn setup_test_repository() -> VerificationCodeRepository {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("failed to open in-memory SQLite");
        sqlx::migrate!("./data/migrations")
            .run(&pool)
            .await
            .expect("failed to run migrations");
        VerificationCodeRepository::new(DbPool::Sqlite(pool))
    }

    /// Insert a verification code with an explicit expiry offset, bypassing the
    /// public `create` helper which always sets a five-minute future expiry.
    ///
    /// ### Arguments
    /// - `repository`: The repository whose pool receives the row
    /// - `email`: The owning email
    /// - `purpose`: The code purpose
    /// - `code`: The plaintext code to hash and store
    /// - `expires_in_minutes`: Minutes from now until expiry (negative for already-expired)
    async fn insert_code_with_expiry(
        repository: &VerificationCodeRepository,
        email: &str,
        purpose: &str,
        code: &str,
        expires_in_minutes: i64,
    ) {
        let code_hash = hash_code(code).expect("hashing the code should succeed");
        let id = Uuid::new_v4().to_string();
        let expires_at = OffsetDateTime::now_utc() + Duration::minutes(expires_in_minutes);
        db_execute_dual!(
            repository.pool,
            sqlite: "INSERT INTO verification_codes (id, email, code_hash, expires_at, purpose) VALUES (?, ?, ?, ?, ?)",
            postgres: "INSERT INTO verification_codes (id, email, code_hash, expires_at, purpose) VALUES ($1, $2, $3, to_timestamp($4), $5)",
            id,
            email.to_string(),
            code_hash,
            expires_at.unix_timestamp(),
            purpose.to_string()
        )
        .expect("inserting a verification code should succeed");
    }

    #[test]
    fn test_hash_and_verify_code_round_trip() {
        let code = "123456";
        let hash = hash_code(code).expect("hashing the code should succeed");
        assert!(
            verify_code(code, &hash),
            "the matching code must verify successfully"
        );
        assert!(
            !verify_code("654321", &hash),
            "a non-matching code must fail verification"
        );
    }

    #[test]
    fn test_verify_code_rejects_malformed_hash_without_panicking() {
        assert!(
            !verify_code("123456", "not-a-valid-argon2-hash"),
            "a malformed hash must be treated as invalid rather than panicking"
        );
        assert!(
            !verify_code("123456", ""),
            "an empty hash must be treated as invalid"
        );
    }

    #[tokio::test]
    async fn test_verify_code_rejects_expired_code() {
        let repository = setup_test_repository().await;
        insert_code_with_expiry(
            &repository,
            "user@example.com",
            "registration",
            "123456",
            -1,
        )
        .await;

        let result = repository
            .verify_code(
                "123456".to_string(),
                "user@example.com".to_string(),
                "registration".to_string(),
            )
            .await
            .expect("verification should not error");

        assert!(
            matches!(result, VerificationResult::Expired),
            "a code past its expiry must be rejected as Expired"
        );
    }

    #[tokio::test]
    async fn test_verify_code_round_trip_marks_verified() {
        let repository = setup_test_repository().await;
        let created = repository
            .create(
                "user@example.com".to_string(),
                "123456".to_string(),
                "registration".to_string(),
            )
            .await
            .expect("creating a verification code should succeed");
        assert!(
            created.verified_at.is_none(),
            "a freshly created code must not be marked verified"
        );

        let result = repository
            .verify_code(
                "123456".to_string(),
                "user@example.com".to_string(),
                "registration".to_string(),
            )
            .await
            .expect("verification should not error");
        assert!(
            matches!(result, VerificationResult::Verified),
            "the correct code must verify successfully"
        );

        let still_pending = repository
            .get_for("user@example.com".to_string(), "registration".to_string())
            .await
            .expect("lookup should not error");
        assert!(
            still_pending.is_none(),
            "a verified code must no longer be returned as pending"
        );
    }

    #[tokio::test]
    async fn test_verify_code_tracks_remaining_attempts_then_blocks() {
        let repository = setup_test_repository().await;
        insert_code_with_expiry(&repository, "user@example.com", "registration", "123456", 5).await;

        for expected_remaining in (0..VERIFICATION_CODE_MAX_ATTEMPTS).rev() {
            let result = repository
                .verify_code(
                    "000000".to_string(),
                    "user@example.com".to_string(),
                    "registration".to_string(),
                )
                .await
                .expect("verification should not error");
            match result {
                VerificationResult::Invalid { attempts_remaining } => {
                    assert_eq!(
                        attempts_remaining, expected_remaining,
                        "remaining attempts must count down on each wrong guess"
                    );
                }
                other => panic!("expected Invalid, got a different result variant: {other:?}"),
            }
        }

        let result = repository
            .verify_code(
                "000000".to_string(),
                "user@example.com".to_string(),
                "registration".to_string(),
            )
            .await
            .expect("verification should not error");
        assert!(
            matches!(result, VerificationResult::TooManyAttempts),
            "once the attempt limit is reached the code must be locked out"
        );
    }

    #[tokio::test]
    async fn test_claim_attempt_enforces_cap_atomically() {
        let repository = setup_test_repository().await;
        insert_code_with_expiry(&repository, "user@example.com", "registration", "123456", 5).await;
        let code = repository
            .get_for("user@example.com".to_string(), "registration".to_string())
            .await
            .expect("lookup should not error")
            .expect("the inserted code must be present");

        for _ in 0..code.max_attempts {
            assert!(
                repository
                    .claim_attempt(code.id.clone())
                    .await
                    .expect("claiming an attempt should not error"),
                "each attempt under the cap must be claimable"
            );
        }

        assert!(
            !repository
                .claim_attempt(code.id.clone())
                .await
                .expect("claiming an attempt should not error"),
            "the guarded UPDATE must refuse the claim once the cap is reached"
        );

        let after = repository
            .get_for("user@example.com".to_string(), "registration".to_string())
            .await
            .expect("lookup should not error")
            .expect("the code must still be present");
        assert_eq!(
            after.attempts, after.max_attempts,
            "the attempt counter must never exceed max_attempts"
        );
    }

    #[tokio::test]
    async fn test_count_active_codes_excludes_expired() {
        let repository = setup_test_repository().await;
        insert_code_with_expiry(&repository, "user@example.com", "registration", "111111", 5).await;
        insert_code_with_expiry(&repository, "user@example.com", "registration", "222222", 5).await;
        insert_code_with_expiry(
            &repository,
            "user@example.com",
            "registration",
            "333333",
            -1,
        )
        .await;
        insert_code_with_expiry(
            &repository,
            "other@example.com",
            "registration",
            "444444",
            5,
        )
        .await;
        insert_code_with_expiry(
            &repository,
            "user@example.com",
            "password_reset",
            "555555",
            5,
        )
        .await;

        let active = repository
            .count_active_codes("user@example.com".to_string(), "registration".to_string())
            .await
            .expect("counting active codes should succeed");

        assert_eq!(
            active, 2,
            "only non-expired codes for the matching email and purpose must be counted"
        );
    }

    #[tokio::test]
    async fn test_count_active_codes_reaches_rate_limit_threshold() {
        let repository = setup_test_repository().await;
        for index in 0..VERIFICATION_CODE_MAX_ATTEMPTS {
            insert_code_with_expiry(
                &repository,
                "user@example.com",
                "registration",
                &format!("10000{index}"),
                5,
            )
            .await;
        }

        let active = repository
            .count_active_codes("user@example.com".to_string(), "registration".to_string())
            .await
            .expect("counting active codes should succeed");

        assert!(
            active >= VERIFICATION_CODE_MAX_ATTEMPTS,
            "the active-code count must reach the rate-limit threshold once the cap is filled"
        );
    }

    #[tokio::test]
    async fn test_delete_expired_only_removes_expired_codes() {
        let repository = setup_test_repository().await;
        insert_code_with_expiry(&repository, "user@example.com", "registration", "111111", 5).await;
        insert_code_with_expiry(
            &repository,
            "user@example.com",
            "registration",
            "222222",
            -1,
        )
        .await;

        let deleted = repository
            .delete_expired()
            .await
            .expect("deleting expired codes should succeed");
        assert_eq!(deleted, 1, "only the expired code must be deleted");

        let remaining = repository
            .get_for("user@example.com".to_string(), "registration".to_string())
            .await
            .expect("lookup should not error");
        assert!(
            remaining.is_some(),
            "the still-valid code must survive the cleanup"
        );
    }
}
