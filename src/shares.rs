use std::collections::HashMap;

use crate::db::DbPool;
use crate::{
    db_execute, db_execute_dual, db_fetch_all, db_fetch_all_dual, db_fetch_one, db_fetch_one_dual,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::utils::format_datetime_utc;

// Default validity period for shares (3 days)
pub const SHARE_VALIDITY_DAYS: i64 = 3;

pub fn get_share_validity_days() -> i64 {
    std::env::var("SHARE_VALIDITY_DAYS")
        .unwrap_or(SHARE_VALIDITY_DAYS.to_string())
        .parse()
        .unwrap_or(SHARE_VALIDITY_DAYS)
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, Clone)]
pub struct Share {
    pub id: String,
    pub user_id: i32,
    pub source_device_id: String,
    pub destination_device_id: String,
    pub file_hash: String, // SHA256 hex
    pub file_name: String,
    pub file_size: i32,
    pub content: String,
    pub deduplication_hash: Option<String>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

impl Share {
    /// Check if the share has expired
    ///
    /// ### Returns
    /// - `true`: If the share has expired, `false` otherwise
    pub fn is_expired(&self) -> bool {
        self.expires_at < OffsetDateTime::now_utc()
    }

    /// Convert the share to a display share
    ///
    /// ### Arguments
    /// - `device_names`: Map of `device_id -> device_name`
    ///
    /// ### Returns
    /// - `DisplayShare`: The display share
    pub fn to_display_shares(&self, device_names: &HashMap<String, String>) -> DisplayShare {
        let from = device_names
            .get(&self.source_device_id)
            .cloned()
            .unwrap_or_else(|| "Unknown".to_string());
        let to = device_names
            .get(&self.destination_device_id)
            .cloned()
            .unwrap_or_else(|| "Unknown".to_string());
        let created_at = format_datetime_utc(&self.created_at);
        let expires_at = format_datetime_utc(&self.expires_at);
        DisplayShare {
            id: self.id.clone(),
            file_name: self.file_name.clone(),
            from,
            to,
            created_at,
            expires_at,
        }
    }
}

pub struct DisplayShare {
    pub id: String,
    pub file_name: String,
    pub from: String,
    pub to: String,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateShare {
    pub source_device_id: String,
    pub destination_device_id: String,
    pub file_name: String,
    pub content: String,
    pub deduplication_hash: Option<String>,
}

/// Calculate SHA256 hash of file content
///
/// ### Arguments
/// - `content`: The content to calculate the hash of a file
///
/// ### Returns
/// - `String`: The SHA256 hash of the content
pub fn calculate_file_hash(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    hex::encode(hasher.finalize())
}

#[derive(Clone)]
pub struct ShareRepository {
    pool: DbPool,
}

impl ShareRepository {
    /// Create a new share repository
    ///
    /// ### Arguments
    /// - `pool`: The database pool (`SQLite` or `PostgreSQL`)
    ///
    /// ### Returns
    /// - `ShareRepository`: The share repository
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Create a new share, or replace an existing one if `deduplication_hash` matches
    ///
    /// When `deduplication_hash` is `Some`, uses UPSERT to replace any existing share
    /// with the same (`source_device_id`, `destination_device_id`, `deduplication_hash`).
    /// When `None`, always inserts a new share (`SQLite` treats NULLs as distinct).
    ///
    /// ### Arguments
    /// - `user_id`: The ID of the user
    /// - `data`: The data for the share
    ///
    /// ### Returns
    /// - `Ok(Share)`: The created or updated share
    /// - `Err(sqlx::Error)`: The error that occurred while creating the share
    pub async fn create(&self, user_id: i32, data: CreateShare) -> Result<Share, sqlx::Error> {
        let id = Uuid::new_v4().to_string();
        let file_hash = calculate_file_hash(&data.content);
        let file_size = data.content.len() as i32;
        let now = OffsetDateTime::now_utc();
        let expires_at = now + Duration::days(SHARE_VALIDITY_DAYS);

        if data.deduplication_hash.is_some() {
            let share = db_fetch_one_dual!(
                self.pool,
                sqlite: r#"
                INSERT INTO shares (
                    id, user_id, source_device_id, destination_device_id,
                    file_hash, file_name, file_size, content, deduplication_hash,
                    created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_device_id, destination_device_id, deduplication_hash)
                DO UPDATE SET
                    file_hash = excluded.file_hash,
                    file_name = excluded.file_name,
                    file_size = excluded.file_size,
                    content = excluded.content,
                    created_at = excluded.created_at,
                    expires_at = excluded.expires_at
                RETURNING *
                "#,
                postgres: r#"
                INSERT INTO shares (
                    id, user_id, source_device_id, destination_device_id,
                    file_hash, file_name, file_size, content, deduplication_hash,
                    created_at, expires_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, to_timestamp($10), to_timestamp($11))
                ON CONFLICT(source_device_id, destination_device_id, deduplication_hash)
                DO UPDATE SET
                    file_hash = excluded.file_hash,
                    file_name = excluded.file_name,
                    file_size = excluded.file_size,
                    content = excluded.content,
                    created_at = excluded.created_at,
                    expires_at = excluded.expires_at
                RETURNING *
                "#,
                Share,
                &id,
                user_id,
                &data.source_device_id,
                &data.destination_device_id,
                &file_hash,
                &data.file_name,
                file_size,
                &data.content,
                &data.deduplication_hash,
                now.unix_timestamp(),
                expires_at.unix_timestamp()
            )?;
            Ok(share)
        } else {
            let share = db_fetch_one_dual!(
                self.pool,
                sqlite: r#"
                INSERT INTO shares (
                    id, user_id, source_device_id, destination_device_id,
                    file_hash, file_name, file_size, content, deduplication_hash,
                    created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
                RETURNING *
                "#,
                postgres: r#"
                INSERT INTO shares (
                    id, user_id, source_device_id, destination_device_id,
                    file_hash, file_name, file_size, content, deduplication_hash,
                    created_at, expires_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, to_timestamp($9), to_timestamp($10))
                RETURNING *
                "#,
                Share,
                &id,
                user_id,
                &data.source_device_id,
                &data.destination_device_id,
                &file_hash,
                &data.file_name,
                file_size,
                &data.content,
                now.unix_timestamp(),
                expires_at.unix_timestamp()
            )?;
            Ok(share)
        }
    }

    /// Get share by ID
    ///
    /// ### Arguments
    /// - `id`: The ID of the share
    ///
    /// ### Returns
    /// - `Ok(Share)`: The share
    /// - `Err(sqlx::Error)`: The error that occurred while getting the share
    pub async fn get_by_id(&self, id: &str) -> Result<Share, sqlx::Error> {
        db_fetch_one!(self.pool, "SELECT * FROM shares WHERE id = ?", Share, id)
    }

    /// Get all shares for a user
    ///
    /// ### Arguments
    /// - `user_id`: The ID of the user
    ///
    /// ### Returns
    /// - `Ok(Vec<Share>)`: The shares for the user
    /// - `Err(sqlx::Error)`: The error that occurred while getting the shares for the user
    pub async fn get_all_for_user(&self, user_id: i32) -> Result<Vec<Share>, sqlx::Error> {
        db_fetch_all!(
            self.pool,
            "SELECT * FROM shares WHERE user_id = ? ORDER BY created_at DESC",
            Share,
            user_id
        )
    }

    /// Delete a share by ID
    ///
    /// ### Arguments
    /// - `id`: The ID of the share to delete
    ///
    /// ### Returns
    /// - `Ok(())`: The result of the operation if the share was deleted successfully
    /// - `Err(sqlx::Error)`: The error that occurred while deleting the share
    pub async fn delete(&self, id: &str) -> Result<(), sqlx::Error> {
        db_execute!(self.pool, "DELETE FROM shares WHERE id = ?", id)?;
        Ok(())
    }

    /// Delete all expired shares (for cleanup job)
    ///
    /// ### Returns
    /// - `Ok(u64)`: The number of deleted shares
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn delete_expired(&self) -> Result<u64, sqlx::Error> {
        db_execute_dual!(
            self.pool,
            sqlite: "DELETE FROM shares WHERE expires_at < unixepoch('now')",
            postgres: "DELETE FROM shares WHERE expires_at < NOW()"
        )
    }

    /// Get all non-expired shares for a specific device
    /// Returns shares where the `device_id` matches the `destination_device_id`
    ///
    /// ### Arguments
    /// - `device_id`: The ID of the device
    ///
    /// ### Returns
    /// - `Ok(Vec<Share>)`: The shares for the device
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn get_shares_for_device(&self, device_id: &str) -> Result<Vec<Share>, sqlx::Error> {
        db_fetch_all_dual!(
            self.pool,
            sqlite: "SELECT * FROM shares WHERE destination_device_id = ? AND expires_at > unixepoch('now') ORDER BY created_at DESC",
            postgres: "SELECT * FROM shares WHERE destination_device_id = $1 AND expires_at > NOW() ORDER BY created_at DESC",
            Share,
            device_id
        )
    }

    /// Get all non-expired shares for a specific device and delete them
    ///
    /// ### Description
    /// This function gets all non-expired shares for a specific device and deletes them in a single atomic operation.
    /// Returns shares where the `device_id` matches the `destination_device_id`
    ///
    /// ### Arguments
    /// - `device_id`: The ID of the device
    ///
    /// ### Returns
    /// - `Ok(Vec<Share>)`: The shares for the device that were deleted
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn get_and_delete_shares_for_device(
        &self,
        device_id: &str,
    ) -> Result<Vec<Share>, sqlx::Error> {
        db_fetch_all_dual!(
            self.pool,
            sqlite: "DELETE FROM shares WHERE destination_device_id = ? AND expires_at > unixepoch('now') RETURNING *",
            postgres: "DELETE FROM shares WHERE destination_device_id = $1 AND expires_at > NOW() RETURNING *",
            Share,
            device_id
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_file_hash() {
        let content = "Hello, World!";
        let hash = calculate_file_hash(content);
        assert_eq!(hash.len(), 64);
        let hash2 = calculate_file_hash(content);
        assert_eq!(hash, hash2);
        let hash3 = calculate_file_hash("Different content");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_share_validity_days_constant() {
        assert_eq!(SHARE_VALIDITY_DAYS, 3);
    }
}
