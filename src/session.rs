use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tower_sessions::Session;

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
