use std::str::FromStr;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tower_sessions::Session;
use tower_sessions::session::{Id, Record};
use tower_sessions::session_store::{self, SessionStore};

use crate::db::DbPool;
use crate::errors::AppError;
use crate::{
    db_execute, db_execute_dual, db_fetch_all_dual, db_fetch_one_dual, db_fetch_optional_dual,
};

/// Session key for storing user ID
pub const SESSION_USER_ID: &str = "user_id";

/// Session key for storing force password update flag
pub const SESSION_FORCE_PASSWORD_UPDATE: &str = "force_password_update";

/// Session key for storing the remember-me flag chosen at login
pub const SESSION_REMEMBER_ME: &str = "remember_me";

/// Session key for the short-lived forgot-password authorization set after step 2
pub const SESSION_PASSWORD_RESET_AUTHORIZED: &str = "password_reset_authorized";

/// Lifetime of a forgot-password authorization marker, in seconds (5 minutes)
const PASSWORD_RESET_AUTHORIZATION_TTL_SECONDS: i64 = 300;

/// Server-side proof that a user completed step 2 of the forgot-password flow.
///
/// Stored in the session after a verification code is accepted and consumed in
/// step 3, so the password reset cannot be triggered without proving step 2.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PasswordResetAuthorization {
    email: String,
    expires_at: i64,
}

/// Record that the given email passed forgot-password step 2.
///
/// ### Arguments
/// - `session`: The session to store the authorization in
/// - `email`: The email that successfully verified its reset code
///
/// ### Returns
/// - `Ok(())`: The authorization marker was stored
/// - `Err(AppError::InternalError)`: If session access fails
pub async fn authorize_password_reset(session: &Session, email: &str) -> Result<(), AppError> {
    let authorization = PasswordResetAuthorization {
        email: email.to_string(),
        expires_at: OffsetDateTime::now_utc().unix_timestamp()
            + PASSWORD_RESET_AUTHORIZATION_TTL_SECONDS,
    };
    session
        .insert(SESSION_PASSWORD_RESET_AUTHORIZED, authorization)
        .await
        .map_err(|e| {
            AppError::InternalError(anyhow::anyhow!(
                "Failed to store password reset authorization: {e}"
            ))
        })?;
    Ok(())
}

/// Consume a forgot-password authorization, verifying it matches the email and is fresh.
///
/// The marker is always removed from the session, whether or not it was valid,
/// so it cannot be replayed for a second reset.
///
/// ### Arguments
/// - `session`: The session holding the authorization
/// - `email`: The email submitted in step 3
///
/// ### Returns
/// - `Ok(true)`: A fresh authorization for `email` existed and was consumed
/// - `Ok(false)`: No authorization, the email did not match, or it had expired
/// - `Err(AppError::InternalError)`: If session access fails
pub async fn consume_password_reset_authorization(
    session: &Session,
    email: &str,
) -> Result<bool, AppError> {
    let authorization: Option<PasswordResetAuthorization> = session
        .remove(SESSION_PASSWORD_RESET_AUTHORIZED)
        .await
        .map_err(|e| {
            AppError::InternalError(anyhow::anyhow!(
                "Failed to read password reset authorization: {e}"
            ))
        })?;
    let Some(authorization) = authorization else {
        return Ok(false);
    };
    let now = OffsetDateTime::now_utc().unix_timestamp();
    Ok(authorization.email.eq_ignore_ascii_case(email) && authorization.expires_at > now)
}

/// Extracts the authenticated user ID from the session
///
/// ### Arguments
/// - `session`: The session to extract the user ID from
///
/// ### Returns
/// - `Ok(i32)`: The user ID if authenticated
/// - `Err(AppError::Unauthorized)`: If user is not authenticated
/// - `Err(AppError::InternalError)`: If session access fails
pub async fn get_session_user_id(session: &Session) -> Result<i32, AppError> {
    let user_id: Option<i32> = session.get(SESSION_USER_ID).await.map_err(|e| {
        AppError::InternalError(anyhow::anyhow!("Failed to get user id from session: {e}"))
    })?;

    user_id.ok_or(AppError::Unauthorized)
}

/// Rotate the session ID and discard the anonymous CSRF token at a privilege boundary.
///
/// ### Arguments
/// - `session`: The session to rotate
///
/// ### Returns
/// - `Ok(())`: The session ID was rotated and the CSRF token cleared
/// - `Err(AppError::InternalError)`: If session access fails
pub async fn rotate_session(session: &Session) -> Result<(), AppError> {
    session
        .cycle_id()
        .await
        .map_err(|e| AppError::InternalError(anyhow::anyhow!("Failed to rotate session: {e}")))?;
    session
        .remove::<String>(axum_tower_sessions_csrf::TOKEN_KEY)
        .await
        .map_err(|e| AppError::InternalError(anyhow::anyhow!("Failed to clear CSRF token: {e}")))?;
    Ok(())
}

/// Persisted session row backing the custom tower-sessions store.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SessionRecord {
    pub id: String,
    pub user_id: Option<i32>,
    pub data: Vec<u8>, // holds the serialized tower-sessions record (`serde_json` bytes)
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
    pub user_agent: Option<String>,
    pub remember_me: bool,
}

#[derive(Clone)]
pub struct SessionRepository {
    pool: DbPool,
}

impl SessionRepository {
    /// Create a new session repository
    ///
    /// ### Arguments
    /// - `pool`: The database pool (`SQLite` or `PostgreSQL`)
    ///
    /// ### Returns
    /// - `SessionRepository`: The session repository
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Insert or update a session row.
    ///
    /// ### Arguments
    /// - `record`: The session record to persist
    ///
    /// ### Returns
    /// - `Ok(())`: The row was written
    /// - `Err(anyhow::Error)`: The error if the operation fails
    pub async fn upsert(&self, record: &SessionRecord) -> anyhow::Result<()> {
        db_execute_dual!(
            self.pool,
            sqlite: "INSERT INTO sessions (id, user_id, data, expires_at, user_agent, remember_me) \
                     VALUES (?, ?, ?, ?, ?, ?) \
                     ON CONFLICT(id) DO UPDATE SET \
                         user_id = excluded.user_id, \
                         data = excluded.data, \
                         expires_at = excluded.expires_at, \
                         user_agent = excluded.user_agent, \
                         remember_me = excluded.remember_me",
            postgres: "INSERT INTO sessions (id, user_id, data, expires_at, user_agent, remember_me) \
                       VALUES ($1, $2, $3, to_timestamp($4), $5, $6) \
                       ON CONFLICT(id) DO UPDATE SET \
                           user_id = EXCLUDED.user_id, \
                           data = EXCLUDED.data, \
                           expires_at = EXCLUDED.expires_at, \
                           user_agent = EXCLUDED.user_agent, \
                           remember_me = EXCLUDED.remember_me",
            record.id.clone(),
            record.user_id,
            record.data.clone(),
            record.expires_at.unix_timestamp(),
            record.user_agent.clone(),
            record.remember_me
        )?;
        Ok(())
    }

    /// Load a session row by id.
    ///
    /// ### Arguments
    /// - `id`: The session id
    ///
    /// ### Returns
    /// - `Ok(Some(SessionRecord))`: The session exists and is not expired
    /// - `Ok(None)`: No matching session, or it has expired
    /// - `Err(anyhow::Error)`: The error if the operation fails
    pub async fn load(&self, id: &str) -> anyhow::Result<Option<SessionRecord>> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let record = db_fetch_optional_dual!(
            self.pool,
            sqlite: "SELECT id, user_id, data, expires_at, created_at, user_agent, remember_me \
                     FROM sessions WHERE id = ? AND expires_at > ?",
            postgres: "SELECT id, user_id, data, expires_at, created_at, user_agent, remember_me \
                       FROM sessions WHERE id = $1 AND expires_at > to_timestamp($2)",
            SessionRecord,
            id.to_string(),
            now
        )?;
        Ok(record)
    }

    /// Delete a single session row by id.
    ///
    /// ### Arguments
    /// - `id`: The session id
    ///
    /// ### Returns
    /// - `Ok(())`: Always returns Ok, even if no row matched
    /// - `Err(anyhow::Error)`: The error if the operation fails
    pub async fn delete(&self, id: &str) -> anyhow::Result<()> {
        db_execute!(
            self.pool,
            "DELETE FROM sessions WHERE id = ?",
            id.to_string()
        )?;
        Ok(())
    }

    /// Delete every session belonging to a user.
    ///
    /// ### Arguments
    /// - `user_id`: The user whose sessions should be revoked
    ///
    /// ### Returns
    /// - `Ok(u64)`: The number of deleted rows
    /// - `Err(anyhow::Error)`: The error if the operation fails
    pub async fn delete_all_for_user(&self, user_id: i32) -> anyhow::Result<u64> {
        let count = db_execute!(self.pool, "DELETE FROM sessions WHERE user_id = ?", user_id)?;
        Ok(count)
    }

    /// Delete every session belonging to a user except the one provided.
    ///
    /// ### Arguments
    /// - `user_id`: The user whose sessions should be revoked
    /// - `current_id`: The session id to preserve
    ///
    /// ### Returns
    /// - `Ok(u64)`: The number of deleted rows
    /// - `Err(anyhow::Error)`: The error if the operation fails
    pub async fn delete_all_for_user_except(
        &self,
        user_id: i32,
        current_id: &str,
    ) -> anyhow::Result<u64> {
        let count = db_execute!(
            self.pool,
            "DELETE FROM sessions WHERE user_id = ? AND id <> ?",
            user_id,
            current_id.to_string()
        )?;
        Ok(count)
    }

    /// List every active (non-expired) session belonging to a user.
    ///
    /// ### Arguments
    /// - `user_id`: The user whose sessions should be listed
    ///
    /// ### Returns
    /// - `Ok(Vec<SessionRecord>)`: All active sessions, newest first
    /// - `Err(anyhow::Error)`: The error if the operation fails
    pub async fn list_for_user(&self, user_id: i32) -> anyhow::Result<Vec<SessionRecord>> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let rows = db_fetch_all_dual!(
            self.pool,
            sqlite: "SELECT id, user_id, data, expires_at, created_at, user_agent, remember_me \
                     FROM sessions WHERE user_id = ? AND expires_at > ? \
                     ORDER BY created_at DESC",
            postgres: "SELECT id, user_id, data, expires_at, created_at, user_agent, remember_me \
                       FROM sessions WHERE user_id = $1 AND expires_at > to_timestamp($2) \
                       ORDER BY created_at DESC",
            SessionRecord,
            user_id,
            now
        )?;
        Ok(rows)
    }

    /// Count active (non-expired) sessions for a user.
    ///
    /// ### Arguments
    /// - `user_id`: The user whose sessions should be counted
    ///
    /// ### Returns
    /// - `Ok(i32)`: The number of active sessions
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn count_for_user(&self, user_id: i32) -> Result<i32, sqlx::Error> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let count: (i64,) = db_fetch_one_dual!(
            self.pool,
            sqlite: "SELECT COUNT(*) FROM sessions WHERE user_id = ? AND expires_at > ?",
            postgres: "SELECT COUNT(*) FROM sessions WHERE user_id = $1 AND expires_at > to_timestamp($2)",
            (i64,),
            user_id,
            now
        )?;
        Ok(count.0 as i32)
    }

    /// Delete every expired session row (for the cleanup task).
    ///
    /// ### Returns
    /// - `Ok(u64)`: The number of deleted rows
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn delete_expired(&self) -> Result<u64, sqlx::Error> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        db_execute_dual!(
            self.pool,
            sqlite: "DELETE FROM sessions WHERE expires_at < ?",
            postgres: "DELETE FROM sessions WHERE expires_at < to_timestamp($1)",
            now
        )
    }
}

/// Extract the authenticated user id from a tower-sessions record, if any.
///
/// ### Arguments
/// - `record`: The tower-sessions record to inspect
///
/// ### Returns
/// - `Some(i32)`: The authenticated user id stored under `SESSION_USER_ID`
/// - `None`: No user id is set or the stored value is not an integer
fn extract_user_id(record: &Record) -> Option<i32> {
    record
        .data
        .get(SESSION_USER_ID)
        .and_then(serde_json::Value::as_i64)
        .and_then(|n| i32::try_from(n).ok())
}

/// Extract the remember-me flag from a tower-sessions record.
///
/// ### Arguments
/// - `record`: The tower-sessions record to inspect
///
/// ### Returns
/// - `true`: The login form set `SESSION_REMEMBER_ME` to true
/// - `false`: The key is missing or its value is not a boolean
fn extract_remember_me(record: &Record) -> bool {
    record
        .data
        .get(SESSION_REMEMBER_ME)
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

/// Custom `tower_sessions::SessionStore` backed by `SessionRepository`.
///
/// Keeps the full session record as a JSON blob in the `data` column while
/// hoisting `user_id` and `remember_me` into dedicated indexed columns so
/// admin and user revocation queries do not need to deserialize every row.
#[derive(Clone)]
pub struct FulgurSessionStore {
    repository: SessionRepository,
}

impl std::fmt::Debug for FulgurSessionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FulgurSessionStore").finish()
    }
}

impl FulgurSessionStore {
    /// Create a new session store wrapping the given repository.
    ///
    /// ### Arguments
    /// - `repository`: The session repository to dispatch persistence through
    ///
    /// ### Returns
    /// - `FulgurSessionStore`: The configured store
    pub fn new(repository: SessionRepository) -> Self {
        Self { repository }
    }
}

/// Encode a tower-sessions `Record` into the bytes stored in the `data` column.
///
/// ### Arguments
/// - `record`: The record to encode
///
/// ### Returns
/// - `Ok(Vec<u8>)`: JSON-encoded record
/// - `Err(session_store::Error::Encode)`: If serialization fails
fn encode_record(record: &Record) -> session_store::Result<Vec<u8>> {
    serde_json::to_vec(record).map_err(|e| session_store::Error::Encode(e.to_string()))
}

/// Decode the `data` column back into a tower-sessions `Record`.
///
/// ### Arguments
/// - `bytes`: The JSON-encoded record bytes
///
/// ### Returns
/// - `Ok(Record)`: The decoded record
/// - `Err(session_store::Error::Decode)`: If deserialization fails
fn decode_record(bytes: &[u8]) -> session_store::Result<Record> {
    serde_json::from_slice(bytes).map_err(|e| session_store::Error::Decode(e.to_string()))
}

#[async_trait]
impl SessionStore for FulgurSessionStore {
    /// Create a new session row, regenerating the id on collision.
    ///
    /// ### Arguments
    /// - `record`: The tower-sessions record to persist; its `id` may be
    ///   replaced if a collision is detected
    ///
    /// ### Returns
    /// - `Ok(())`: The row was inserted under a unique id
    /// - `Err(session_store::Error::Backend)`: The backing repository failed
    async fn create(&self, record: &mut Record) -> session_store::Result<()> {
        loop {
            let id_str = record.id.to_string();
            let existing = self
                .repository
                .load(&id_str)
                .await
                .map_err(|e| session_store::Error::Backend(e.to_string()))?;
            if existing.is_some() {
                record.id = Id::default();
                continue;
            }
            return self.save(record).await;
        }
    }

    /// Persist a session record, hoisting `user_id` and `remember_me` into
    /// their dedicated columns alongside the JSON-encoded blob.
    ///
    /// ### Arguments
    /// - `record`: The tower-sessions record to persist
    ///
    /// ### Returns
    /// - `Ok(())`: The row was inserted or updated
    /// - `Err(session_store::Error::Encode)`: JSON serialization failed
    /// - `Err(session_store::Error::Backend)`: The backing repository failed
    async fn save(&self, record: &Record) -> session_store::Result<()> {
        let row = SessionRecord {
            id: record.id.to_string(),
            user_id: extract_user_id(record),
            data: encode_record(record)?,
            expires_at: record.expiry_date,
            created_at: OffsetDateTime::now_utc(),
            user_agent: None,
            remember_me: extract_remember_me(record),
        };
        self.repository
            .upsert(&row)
            .await
            .map_err(|e| session_store::Error::Backend(e.to_string()))
    }

    /// Load a session by id, re-applying the persisted `id` and
    /// `expires_at` over the decoded blob to prevent payload tampering.
    ///
    /// ### Arguments
    /// - `session_id`: The tower-sessions id to look up
    ///
    /// ### Returns
    /// - `Ok(Some(Record))`: The session exists and is not expired
    /// - `Ok(None)`: No matching session or it has expired
    /// - `Err(session_store::Error::Decode)`: The stored blob could not be deserialized
    /// - `Err(session_store::Error::Backend)`: The backing repository failed
    async fn load(&self, session_id: &Id) -> session_store::Result<Option<Record>> {
        let id_str = session_id.to_string();
        let Some(row) = self
            .repository
            .load(&id_str)
            .await
            .map_err(|e| session_store::Error::Backend(e.to_string()))?
        else {
            return Ok(None);
        };
        let mut record = decode_record(&row.data)?;
        // Defensive: trust the column over a stale id inside the blob, and
        // trust the column expiry so callers cannot extend a revoked session
        // by tampering with the serialized payload.
        record.id = Id::from_str(&row.id)
            .map_err(|e| session_store::Error::Decode(format!("invalid session id: {e}")))?;
        record.expiry_date = row.expires_at;
        Ok(Some(record))
    }

    /// Delete a session row by id.
    ///
    /// ### Arguments
    /// - `session_id`: The tower-sessions id to delete
    ///
    /// ### Returns
    /// - `Ok(())`: The row was removed or no matching row existed
    /// - `Err(session_store::Error::Backend)`: The backing repository failed
    async fn delete(&self, session_id: &Id) -> session_store::Result<()> {
        let id_str = session_id.to_string();
        self.repository
            .delete(&id_str)
            .await
            .map_err(|e| session_store::Error::Backend(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    fn make_record() -> Record {
        Record {
            id: Id::default(),
            data: std::collections::HashMap::new(),
            expiry_date: OffsetDateTime::now_utc() + Duration::hours(1),
        }
    }

    #[test]
    fn extract_user_id_missing_returns_none() {
        let record = make_record();
        assert_eq!(extract_user_id(&record), None);
    }

    #[test]
    fn extract_user_id_present_returns_value() {
        let mut record = make_record();
        record
            .data
            .insert(SESSION_USER_ID.to_string(), serde_json::json!(42));
        assert_eq!(extract_user_id(&record), Some(42));
    }

    #[test]
    fn extract_user_id_non_integer_returns_none() {
        let mut record = make_record();
        record
            .data
            .insert(SESSION_USER_ID.to_string(), serde_json::json!("oops"));
        assert_eq!(extract_user_id(&record), None);
    }

    #[test]
    fn extract_remember_me_defaults_false() {
        let record = make_record();
        assert!(!extract_remember_me(&record));
    }

    #[test]
    fn extract_remember_me_reads_bool() {
        let mut record = make_record();
        record
            .data
            .insert(SESSION_REMEMBER_ME.to_string(), serde_json::json!(true));
        assert!(extract_remember_me(&record));
    }

    #[test]
    fn encode_decode_record_roundtrip() {
        let mut record = make_record();
        record
            .data
            .insert(SESSION_USER_ID.to_string(), serde_json::json!(7));
        let bytes = encode_record(&record).expect("encode");
        let decoded = decode_record(&bytes).expect("decode");
        assert_eq!(decoded.id, record.id);
        assert_eq!(decoded.data, record.data);
    }
}
