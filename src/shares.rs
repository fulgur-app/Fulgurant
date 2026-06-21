use std::collections::HashMap;

use crate::db::DbPool;
use crate::{
    db_execute, db_execute_dual, db_fetch_all, db_fetch_all_dual, db_fetch_one, db_fetch_one_dual,
    db_fetch_optional_dual,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::utils::format_datetime_utc;

// Default validity period for shares (3 days)
pub const SHARE_VALIDITY_DAYS: i64 = 3;

/// Lifecycle status of a share.
///
/// Shares are never hard-deleted: their content is cleared and their status
/// updated, keeping the row as a historic/stat record.
pub mod status {
    /// Shared by a device, not yet downloaded by the destination device.
    pub const AVAILABLE: &str = "available";
    /// Downloaded by the destination device.
    pub const DOWNLOADED: &str = "downloaded";
    /// Expired before the destination device downloaded it.
    pub const EXPIRED: &str = "expired";
    /// Manually deleted by the user.
    pub const DELETED: &str = "deleted";
}

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
    pub status: String,
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
                sqlite: r"
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
                    status = 'available',
                    created_at = excluded.created_at,
                    expires_at = excluded.expires_at
                RETURNING *
                ",
                postgres: r"
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
                    status = 'available',
                    created_at = excluded.created_at,
                    expires_at = excluded.expires_at
                RETURNING *
                ",
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
                sqlite: r"
                INSERT INTO shares (
                    id, user_id, source_device_id, destination_device_id,
                    file_hash, file_name, file_size, content, deduplication_hash,
                    created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
                RETURNING *
                ",
                postgres: r"
                INSERT INTO shares (
                    id, user_id, source_device_id, destination_device_id,
                    file_hash, file_name, file_size, content, deduplication_hash,
                    created_at, expires_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, to_timestamp($9), to_timestamp($10))
                RETURNING *
                ",
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

    /// Get all shares for a user, regardless of status (including historic rows)
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

    /// Get the available (not yet downloaded, expired, or deleted) shares for a user
    ///
    /// ### Arguments
    /// - `user_id`: The ID of the user
    ///
    /// ### Returns
    /// - `Ok(Vec<Share>)`: The available shares for the user
    /// - `Err(sqlx::Error)`: The error that occurred while getting the shares for the user
    pub async fn get_available_for_user(&self, user_id: i32) -> Result<Vec<Share>, sqlx::Error> {
        db_fetch_all!(
            self.pool,
            "SELECT * FROM shares WHERE user_id = ? AND status = 'available' ORDER BY created_at DESC",
            Share,
            user_id
        )
    }

    /// Mark a share as deleted and clear its content
    ///
    /// The row is kept as a historic record; only its `status` becomes `deleted` and its `content` is cleared.
    ///
    /// ### Arguments
    /// - `id`: The ID of the share to delete
    ///
    /// ### Returns
    /// - `Ok(())`: The result of the operation if the share was marked as deleted successfully
    /// - `Err(sqlx::Error)`: The error that occurred while marking the share as deleted
    pub async fn mark_deleted(&self, id: &str) -> Result<(), sqlx::Error> {
        db_execute!(
            self.pool,
            "UPDATE shares SET status = 'deleted', content = '' WHERE id = ?",
            id
        )?;
        Ok(())
    }

    /// Mark all expired available shares as expired and clear their content (for cleanup job)
    ///
    /// Only `available` shares past their expiration are affected; already downloaded
    /// or deleted shares are left untouched. Rows are kept as historic records.
    ///
    /// ### Returns
    /// - `Ok(u64)`: The number of shares marked as expired
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn mark_expired(&self) -> Result<u64, sqlx::Error> {
        db_execute_dual!(
            self.pool,
            sqlite: "UPDATE shares SET status = 'expired', content = '' WHERE status = 'available' AND expires_at < unixepoch('now')",
            postgres: "UPDATE shares SET status = 'expired', content = '' WHERE status = 'available' AND expires_at < NOW()"
        )
    }

    /// Get all available (not yet downloaded or expired) shares for a specific device
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
            sqlite: "SELECT * FROM shares WHERE destination_device_id = ? AND status = 'available' AND expires_at > unixepoch('now') ORDER BY created_at DESC",
            postgres: "SELECT * FROM shares WHERE destination_device_id = $1 AND status = 'available' AND expires_at > NOW() ORDER BY created_at DESC",
            Share,
            device_id
        )
    }

    /// List IDs of all available (not yet downloaded or expired) shares for a specific device without consuming them
    ///
    /// ### Arguments
    /// - `device_id`: The ID of the destination device
    ///
    /// ### Returns
    /// - `Ok(Vec<String>)`: The IDs of available shares for the device, oldest first
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn list_share_ids_for_device(
        &self,
        device_id: &str,
    ) -> Result<Vec<String>, sqlx::Error> {
        let rows: Vec<(String,)> = db_fetch_all_dual!(
            self.pool,
            sqlite: "SELECT id FROM shares WHERE destination_device_id = ? AND status = 'available' AND expires_at > unixepoch('now') ORDER BY created_at ASC",
            postgres: "SELECT id FROM shares WHERE destination_device_id = $1 AND status = 'available' AND expires_at > NOW() ORDER BY created_at ASC",
            (String,),
            device_id
        )?;
        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    /// Consume a single available share by ID for a specific destination device
    ///
    /// ### Description
    /// Atomically claims the share by flipping its status from `available` to
    /// `downloaded` (so a concurrent consumer cannot claim it twice), returns its
    /// content, then clears the stored content. The row is kept as a historic
    /// record. The whole operation runs in a transaction.
    ///
    /// ### Arguments
    /// - `id`: The ID of the share
    /// - `device_id`: The ID of the destination device that must own the share
    ///
    /// ### Returns
    /// - `Ok(Some(Share))`: The consumed share, with its content intact
    /// - `Ok(None)`: No matching available share for this device
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn consume_share_for_device(
        &self,
        id: &str,
        device_id: &str,
    ) -> Result<Option<Share>, sqlx::Error> {
        match &self.pool {
            DbPool::Sqlite(pool) => {
                let mut tx = pool.begin().await?;
                let claimed: Option<Share> = sqlx::query_as(
                    "UPDATE shares SET status = 'downloaded' WHERE id = ? AND destination_device_id = ? AND status = 'available' AND expires_at > unixepoch('now') RETURNING *",
                )
                .bind(id)
                .bind(device_id)
                .fetch_optional(&mut *tx)
                .await?;
                if claimed.is_some() {
                    sqlx::query("UPDATE shares SET content = '' WHERE id = ?")
                        .bind(id)
                        .execute(&mut *tx)
                        .await?;
                }
                tx.commit().await?;
                Ok(claimed)
            }
            DbPool::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                let claimed: Option<Share> = sqlx::query_as(
                    "UPDATE shares SET status = 'downloaded' WHERE id = $1 AND destination_device_id = $2 AND status = 'available' AND expires_at > NOW() RETURNING *",
                )
                .bind(id)
                .bind(device_id)
                .fetch_optional(&mut *tx)
                .await?;
                if claimed.is_some() {
                    sqlx::query("UPDATE shares SET content = '' WHERE id = $1")
                        .bind(id)
                        .execute(&mut *tx)
                        .await?;
                }
                tx.commit().await?;
                Ok(claimed)
            }
        }
    }

    /// Peek at a single available share by ID for a specific destination device
    ///
    /// ### Arguments
    /// - `id`: The ID of the share
    /// - `device_id`: The ID of the destination device that must own the share
    ///
    /// ### Returns
    /// - `Ok(Some(Share))`: The available share, with its content intact
    /// - `Ok(None)`: No matching available share for this device
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn peek_available_share_for_device(
        &self,
        id: &str,
        device_id: &str,
    ) -> Result<Option<Share>, sqlx::Error> {
        db_fetch_optional_dual!(
            self.pool,
            sqlite: "SELECT * FROM shares WHERE id = ? AND destination_device_id = ? AND status = 'available' AND expires_at > unixepoch('now')",
            postgres: "SELECT * FROM shares WHERE id = $1 AND destination_device_id = $2 AND status = 'available' AND expires_at > NOW()",
            Share,
            id,
            device_id
        )
    }

    /// Mark a single available share as downloaded and clear its content
    ///
    /// ### Arguments
    /// - `id`: The ID of the share
    /// - `device_id`: The ID of the destination device that must own the share
    ///
    /// ### Returns
    /// - `Ok(true)`: The share was marked as downloaded
    /// - `Ok(false)`: No matching available share for this device (already consumed, expired, or unknown)
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn mark_downloaded(&self, id: &str, device_id: &str) -> Result<bool, sqlx::Error> {
        let affected = db_execute_dual!(
            self.pool,
            sqlite: "UPDATE shares SET status = 'downloaded', content = '' WHERE id = ? AND destination_device_id = ? AND status = 'available' AND expires_at > unixepoch('now')",
            postgres: "UPDATE shares SET status = 'downloaded', content = '' WHERE id = $1 AND destination_device_id = $2 AND status = 'available' AND expires_at > NOW()",
            id,
            device_id
        )?;
        Ok(affected > 0)
    }

    /// Consume all available shares for a specific destination device
    ///
    /// ### Description
    /// Atomically claims every available share for the device by flipping their
    /// status from `available` to `downloaded`, returns them with their content
    /// intact, then clears the stored content. Rows are kept as historic records.
    /// The whole operation runs in a transaction.
    ///
    /// ### Arguments
    /// - `device_id`: The ID of the device
    ///
    /// ### Returns
    /// - `Ok(Vec<Share>)`: The consumed shares, with their content intact
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn consume_shares_for_device(
        &self,
        device_id: &str,
    ) -> Result<Vec<Share>, sqlx::Error> {
        match &self.pool {
            DbPool::Sqlite(pool) => {
                let mut tx = pool.begin().await?;
                let claimed: Vec<Share> = sqlx::query_as(
                    "UPDATE shares SET status = 'downloaded' WHERE destination_device_id = ? AND status = 'available' AND expires_at > unixepoch('now') RETURNING *",
                )
                .bind(device_id)
                .fetch_all(&mut *tx)
                .await?;
                if !claimed.is_empty() {
                    sqlx::query("UPDATE shares SET content = '' WHERE destination_device_id = ? AND status = 'downloaded' AND content <> ''")
                        .bind(device_id)
                        .execute(&mut *tx)
                        .await?;
                }
                tx.commit().await?;
                Ok(claimed)
            }
            DbPool::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                let claimed: Vec<Share> = sqlx::query_as(
                    "UPDATE shares SET status = 'downloaded' WHERE destination_device_id = $1 AND status = 'available' AND expires_at > NOW() RETURNING *",
                )
                .bind(device_id)
                .fetch_all(&mut *tx)
                .await?;
                if !claimed.is_empty() {
                    sqlx::query("UPDATE shares SET content = '' WHERE destination_device_id = $1 AND status = 'downloaded' AND content <> ''")
                        .bind(device_id)
                        .execute(&mut *tx)
                        .await?;
                }
                tx.commit().await?;
                Ok(claimed)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::{CreateDevice, DeviceRepository};
    use crate::users::UserRepository;
    use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};

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

    /// Build an in-memory `SQLite`-backed share repository with an owning user and a source device.
    ///
    /// ### Returns
    /// - `(ShareRepository, SqlitePool, i32, String)`: The repository, the raw pool (for direct
    ///   setup such as forcing rows past expiry), the owning user id, and the source device's
    ///   public `device_id`
    async fn setup_test_repository() -> (ShareRepository, SqlitePool, i32, String) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("failed to open in-memory SQLite");
        sqlx::migrate!("./data/migrations")
            .run(&pool)
            .await
            .expect("failed to run migrations");
        let db_pool = DbPool::Sqlite(pool.clone());
        let user_id = UserRepository::new(db_pool.clone())
            .create(
                "share-owner@example.com".to_string(),
                "Share".to_string(),
                "Owner".to_string(),
                "hash".to_string(),
                true,
                false,
            )
            .await
            .expect("failed to create owning user");
        let source_device = DeviceRepository::new(db_pool.clone())
            .create(
                user_id,
                "source-device-key".to_string(),
                CreateDevice {
                    name: "Source".to_string(),
                    device_type: "desktop".to_string(),
                    api_key_lifetime: 30,
                },
                10,
            )
            .await
            .expect("failed to create source device");
        (
            ShareRepository::new(db_pool),
            pool,
            user_id,
            source_device.device_id,
        )
    }

    /// Build a `CreateShare` payload from a source device to an arbitrary destination.
    ///
    /// ### Arguments
    /// - `source_device_id`: The public id of the source device (must exist for the FK)
    /// - `destination_device_id`: The recipient device id (no FK, any string works)
    /// - `deduplication_hash`: Optional dedup tuple component
    ///
    /// ### Returns
    /// - `CreateShare`: A small text share payload
    fn sample_share(
        source_device_id: &str,
        destination_device_id: &str,
        deduplication_hash: Option<&str>,
    ) -> CreateShare {
        CreateShare {
            source_device_id: source_device_id.to_string(),
            destination_device_id: destination_device_id.to_string(),
            file_name: "note.txt".to_string(),
            content: "secret content".to_string(),
            deduplication_hash: deduplication_hash.map(str::to_string),
        }
    }

    #[tokio::test]
    async fn test_mark_expired_only_touches_available_rows() {
        let (repository, pool, user_id, source_device_id) = setup_test_repository().await;

        let available = repository
            .create(
                user_id,
                sample_share(&source_device_id, "dest-available", None),
            )
            .await
            .expect("create available share");
        let downloaded = repository
            .create(
                user_id,
                sample_share(&source_device_id, "dest-downloaded", None),
            )
            .await
            .expect("create downloaded share");
        let deleted = repository
            .create(
                user_id,
                sample_share(&source_device_id, "dest-deleted", None),
            )
            .await
            .expect("create deleted share");

        // Force every row past its expiration, then move two of them out of the
        // `available` state so only one row is eligible for `mark_expired`.
        sqlx::query("UPDATE shares SET expires_at = unixepoch('now') - 1")
            .execute(&pool)
            .await
            .expect("age rows past expiry");
        sqlx::query("UPDATE shares SET status = 'downloaded' WHERE id = ?")
            .bind(&downloaded.id)
            .execute(&pool)
            .await
            .expect("set downloaded status");
        sqlx::query("UPDATE shares SET status = 'deleted' WHERE id = ?")
            .bind(&deleted.id)
            .execute(&pool)
            .await
            .expect("set deleted status");

        let affected = repository.mark_expired().await.expect("mark_expired runs");
        assert_eq!(
            affected, 1,
            "only the expired available share must be touched"
        );

        assert_eq!(
            repository.get_by_id(&available.id).await.unwrap().status,
            status::EXPIRED
        );
        assert_eq!(
            repository.get_by_id(&downloaded.id).await.unwrap().status,
            status::DOWNLOADED,
            "downloaded rows must not be re-expired"
        );
        assert_eq!(
            repository.get_by_id(&deleted.id).await.unwrap().status,
            status::DELETED,
            "deleted rows must not be re-expired"
        );
    }

    #[tokio::test]
    async fn test_recreate_with_dedup_resets_consumed_share_to_available() {
        let (repository, _pool, user_id, source_device_id) = setup_test_repository().await;
        let dedup = Some("dedup-tuple");

        let first = repository
            .create(user_id, sample_share(&source_device_id, "dest-1", dedup))
            .await
            .expect("create initial share");

        let consumed = repository
            .consume_share_for_device(&first.id, "dest-1")
            .await
            .expect("consume succeeds");
        assert!(
            consumed.is_some(),
            "the available share should be consumable"
        );
        let after_consume = repository.get_by_id(&first.id).await.unwrap();
        assert_eq!(after_consume.status, status::DOWNLOADED);
        assert_eq!(
            after_consume.content, "",
            "consumed content must be cleared"
        );

        // Re-share the same (source, destination, dedup) tuple.
        let mut reshare = sample_share(&source_device_id, "dest-1", dedup);
        reshare.content = "fresh content".to_string();
        let second = repository
            .create(user_id, reshare)
            .await
            .expect("re-create succeeds");

        assert_eq!(second.id, first.id, "UPSERT must reuse the same row");
        assert_eq!(
            second.status,
            status::AVAILABLE,
            "re-sharing a consumed row must reactivate it"
        );
        assert_eq!(second.content, "fresh content");
    }

    #[tokio::test]
    async fn test_peek_returns_content_without_mutating_status() {
        let (repository, _pool, user_id, source_device_id) = setup_test_repository().await;
        let share = repository
            .create(user_id, sample_share(&source_device_id, "dest-1", None))
            .await
            .expect("create share");

        let peeked = repository
            .peek_available_share_for_device(&share.id, "dest-1")
            .await
            .expect("peek runs")
            .expect("available share should be returned");
        assert_eq!(peeked.content, "secret content");
        assert_eq!(peeked.status, status::AVAILABLE);

        let stored = repository.get_by_id(&share.id).await.unwrap();
        assert_eq!(
            stored.status,
            status::AVAILABLE,
            "peek must not mutate status"
        );
        assert_eq!(
            stored.content, "secret content",
            "peek must not clear content"
        );

        assert!(
            repository
                .peek_available_share_for_device(&share.id, "dest-1")
                .await
                .unwrap()
                .is_some(),
            "peek must be idempotently retryable"
        );
    }
}
