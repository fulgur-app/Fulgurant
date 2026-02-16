use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Pool, Sqlite, SqlitePool};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::devices::Device;
use crate::utils::format_datetime_utc;

// Default validity period for shares (3 days)
pub const SHARE_VALIDITY_DAYS: i64 = 3;

// Max file size: 1 MB
pub const MAX_FILE_SIZE: usize = 1_048_576; // 1 MB in bytes

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
    /// - `devices`: The devices to convert the share to a display share
    ///
    /// ### Returns
    /// - `DisplayShare`: The display share
    pub fn to_display_shares(&self, devices: &[Device]) -> DisplayShare {
        let from = match devices
            .iter()
            .find(|d| d.device_id == self.source_device_id)
        {
            Some(d) => d.name.clone(),
            None => "Unknown".to_string(),
        };
        let to = match devices
            .iter()
            .find(|d| d.device_id == self.destination_device_id)
        {
            Some(d) => d.name.clone(),
            None => "Unknown".to_string(),
        };
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
    format!("{:x}", hasher.finalize())
}

#[derive(Clone)]
pub struct ShareRepository {
    pool: SqlitePool,
}

impl ShareRepository {
    /// Create a new share repository
    ///
    /// ### Arguments
    /// - `pool`: The SQLite pool
    ///
    /// ### Returns
    /// - `ShareRepository`: The share repository
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }

    /// Create a new share, or replace an existing one if deduplication_hash matches
    ///
    /// When `deduplication_hash` is `Some`, uses UPSERT to replace any existing share
    /// with the same (source_device_id, destination_device_id, deduplication_hash).
    /// When `None`, always inserts a new share (SQLite treats NULLs as distinct).
    ///
    /// ### Arguments
    /// - `user_id`: The ID of the user
    /// - `data`: The data for the share
    ///
    /// ### Returns
    /// - `Ok(Share)`: The created or updated share
    /// - `Err(anyhow::Error)`: The error that occurred while creating the share
    pub async fn create(&self, user_id: i32, data: CreateShare) -> Result<Share, anyhow::Error> {
        let id = Uuid::new_v4().to_string();
        let file_hash = calculate_file_hash(&data.content);
        let file_size = data.content.len() as i32;
        if file_size as usize > MAX_FILE_SIZE {
            return Err(anyhow::anyhow!(
                "File size exceeds maximum of {} bytes",
                MAX_FILE_SIZE
            ));
        }
        let now = OffsetDateTime::now_utc();
        let expires_at = now + Duration::days(SHARE_VALIDITY_DAYS);

        if data.deduplication_hash.is_some() {
            // UPSERT: replace existing share with same source/destination/hash
            let share = sqlx::query_as::<_, Share>(
                r#"
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
            )
            .bind(&id)
            .bind(user_id)
            .bind(&data.source_device_id)
            .bind(&data.destination_device_id)
            .bind(&file_hash)
            .bind(&data.file_name)
            .bind(file_size)
            .bind(&data.content)
            .bind(&data.deduplication_hash)
            .bind(now.unix_timestamp())
            .bind(expires_at.unix_timestamp())
            .fetch_one(&self.pool)
            .await?;
            Ok(share)
        } else {
            // Plain INSERT: no dedup, always creates a new share
            let share = sqlx::query_as::<_, Share>(
                r#"
                INSERT INTO shares (
                    id, user_id, source_device_id, destination_device_id,
                    file_hash, file_name, file_size, content, deduplication_hash,
                    created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
                RETURNING *
                "#,
            )
            .bind(&id)
            .bind(user_id)
            .bind(&data.source_device_id)
            .bind(&data.destination_device_id)
            .bind(&file_hash)
            .bind(&data.file_name)
            .bind(file_size)
            .bind(&data.content)
            .bind(now.unix_timestamp())
            .bind(expires_at.unix_timestamp())
            .fetch_one(&self.pool)
            .await?;
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
    /// - `Err(anyhow::Error)`: The error that occurred while getting the share
    pub async fn get_by_id(&self, id: &str) -> Result<Share, anyhow::Error> {
        let share = sqlx::query_as::<_, Share>("SELECT * FROM shares WHERE id = ?")
            .bind(id)
            .fetch_one(&self.pool)
            .await?;
        Ok(share)
    }

    /// Get all shares for a user       /
    /// - `user_id`: The ID of the user
    ///
    /// ### Returns
    /// - `Ok(Vec<Share>)`: The shares for the user
    /// - `Err(sqlx::Error)`: The error that occurred while getting the shares for the user
    pub async fn get_all_for_user(&self, user_id: i32) -> Result<Vec<Share>, sqlx::Error> {
        sqlx::query_as::<_, Share>(
            "SELECT * FROM shares WHERE user_id = ? ORDER BY created_at DESC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
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
        sqlx::query("DELETE FROM shares WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Delete all expired shares (for cleanup job)
    ///
    /// ### Arguments
    /// - `device_id`: The ID of the device
    ///
    /// ### Returns
    /// - `Ok(Vec<Share>)`: The shares for the device that were deleted
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn delete_expired(&self) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM shares WHERE expires_at < unixepoch('now')")
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Get all non-expired shares for a specific device
    /// Returns shares where the device_id matches the destination_device_id
    ///
    /// ### Arguments
    /// - `device_id`: The ID of the device
    ///
    /// ### Returns
    /// - `Ok(Vec<Share>)`: The shares for the device
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn get_shares_for_device(&self, device_id: &str) -> Result<Vec<Share>, sqlx::Error> {
        sqlx::query_as::<_, Share>(
            r#"
            SELECT * FROM shares
            WHERE destination_device_id = ?
            AND expires_at > unixepoch('now')
            ORDER BY created_at DESC
            "#,
        )
        .bind(device_id)
        .fetch_all(&self.pool)
        .await
    }

    /// Get all non-expired shares for a specific device and delete them
    ///
    /// ### Description
    /// This function gets all non-expired shares for a specific device and deletes them in a single atomic operation.
    /// Returns shares where the device_id matches the destination_device_id
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
        sqlx::query_as::<_, Share>(
            r#"
            DELETE FROM shares
            WHERE destination_device_id = ?
            AND expires_at > unixepoch('now')
            RETURNING *
            "#,
        )
        .bind(device_id)
        .fetch_all(&self.pool)
        .await
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
    fn test_file_size_constants() {
        assert_eq!(MAX_FILE_SIZE, 1_048_576);
        assert_eq!(SHARE_VALIDITY_DAYS, 3);
    }
}
