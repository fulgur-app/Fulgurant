use crate::db::DbPool;
use crate::utils::{format_date_utc, format_datetime_utc};
use crate::{db_execute, db_execute_dual, db_fetch_all, db_fetch_one, db_fetch_optional};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

pub const MAX_DEVICES_PER_USER: i32 = 99;
pub const MAX_DEVICE_NAME_LEN: usize = 50;
pub const MAX_DEVICE_TYPE_LEN: usize = 20;

/// Get the maximum number of devices per user from the environment variable, defaults to 99
///
/// ### Returns
/// - `i32`: The maximum number of devices per user
pub fn get_max_devices_per_user() -> i32 {
    std::env::var("MAX_DEVICES_PER_USER")
        .unwrap_or(MAX_DEVICES_PER_USER.to_string())
        .parse()
        .unwrap_or(MAX_DEVICES_PER_USER)
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, Clone)]
pub struct Device {
    pub id: i32,
    pub user_id: i32,
    pub device_id: String,                    // UUID v4 (public identifier)
    pub device_key: String,                   // Hashed API key (private)
    pub device_key_fast_hash: Option<String>, // SHA256 for fast lookup
    pub name: String,
    pub device_type: String,
    pub encryption_key: Option<String>, // Base64-encoded 256-bit AES key for encrypting shared files (nullable)
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl Device {
    /// Check if the device has expired
    ///
    /// ### Returns
    /// - `true`: If the device has expired, `false` otherwise
    pub fn is_expired(&self) -> bool {
        self.expires_at < OffsetDateTime::now_utc()
    }

    /// Get the created at date formatted as YYYY-MM-DD
    ///
    /// ### Returns
    /// - `String`: The created at date formatted as YYYY-MM-DD
    pub fn get_created_at_formatted(&self) -> String {
        format_date_utc(&self.created_at)
    }

    /// Get the updated at date formatted as YYYY-MM-DD HH:MM:SS
    ///
    /// ### Returns
    /// - `String`: The updated at date formatted as YYYY-MM-DD HH:MM:SS
    pub fn get_updated_at_formatted(&self) -> String {
        if self.updated_at == OffsetDateTime::UNIX_EPOCH {
            "Never".to_string()
        } else {
            format_datetime_utc(&self.updated_at)
        }
    }

    /// Get the expires at date formatted as YYYY-MM-DD
    ///
    /// ### Returns
    /// - `String`: The expires at date formatted as YYYY-MM-DD
    pub fn get_expires_at_formatted(&self) -> String {
        let formatted = format_date_utc(&self.expires_at);
        if formatted.starts_with("21")
        // TODO: Remove this once we have a better way to handle expired devices
        {
            "Never".to_string()
        } else {
            formatted
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct CreateDevice {
    pub name: String,
    pub device_type: String,
    pub api_key_lifetime: i64,
}

#[derive(Debug, Deserialize)]
pub struct UpdateDevice {
    pub name: String,
    pub device_type: String,
}

#[derive(Debug, Deserialize)]
pub struct RenewDevice {
    pub api_key_lifetime: i64,
}

#[derive(Clone)]
pub struct DeviceRepository {
    pool: DbPool,
}

impl DeviceRepository {
    /// Create a new device repository
    ///
    /// ### Arguments
    /// - `pool`: The database pool (`SQLite` or `PostgreSQL`)
    ///
    /// ### Returns
    /// - `DeviceRepository`: The device repository
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Get all devices for a user
    ///
    /// ### Arguments
    /// - `user_id`: The ID of the user
    ///
    /// ### Returns
    /// - `Ok(Vec<Device>)`: The devices for the user, newest first
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn get_all_for_user(&self, user_id: i32) -> Result<Vec<Device>, sqlx::Error> {
        db_fetch_all!(
            self.pool,
            "SELECT * FROM devices WHERE user_id = ? ORDER BY created_at DESC, id DESC",
            Device,
            user_id
        )
    }

    /// Create a new device
    ///
    /// ### Arguments
    /// - `user_id`: The ID of the user
    /// - `device_key`: The device key
    /// - `data`: The data for the device
    ///
    /// ### Returns
    /// - `Ok(Device)`: The created device
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn create(
        &self,
        user_id: i32,
        device_key: String,
        data: CreateDevice,
    ) -> Result<Device, sqlx::Error> {
        let now = OffsetDateTime::now_utc();
        let device_id = Uuid::new_v4().to_string();
        let CreateDevice {
            name,
            device_type,
            api_key_lifetime,
        } = data;
        let expires_at = now + Duration::days(api_key_lifetime);
        let fast_hash = crate::api_key::hash_api_key_fast(&device_key);
        let id = match &self.pool {
            DbPool::Sqlite(pool) => {
                let result = sqlx::query(
                    "INSERT INTO devices (user_id, device_id, device_key, device_key_fast_hash, name, device_type, encryption_key, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(user_id)
                .bind(&device_id)
                .bind(&device_key)
                .bind(&fast_hash)
                .bind(&name)
                .bind(&device_type)
                .bind(None::<String>)
                .bind(expires_at.unix_timestamp())
                .bind(now.unix_timestamp())
                .execute(pool)
                .await?;
                result.last_insert_rowid() as i32
            }
            DbPool::Postgres(pool) => {
                let row: (i32,) = sqlx::query_as(
                    "INSERT INTO devices (user_id, device_id, device_key, device_key_fast_hash, name, device_type, encryption_key, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, to_timestamp($8)) RETURNING id",
                )
                .bind(user_id)
                .bind(&device_id)
                .bind(&device_key)
                .bind(&fast_hash)
                .bind(&name)
                .bind(&device_type)
                .bind(None::<String>)
                .bind(expires_at.unix_timestamp())
                .fetch_one(pool)
                .await?;
                row.0
            }
        };
        self.get_by_id(id).await
    }

    /// Update a device
    ///
    /// ### Arguments
    /// - `id`: The ID of the device
    /// - `data`: The data for the device
    ///
    /// ### Returns
    /// - `Ok(Device)`: The updated device
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn update(&self, id: i32, data: UpdateDevice) -> Result<Device, sqlx::Error> {
        let UpdateDevice { name, device_type } = data;
        db_execute_dual!(
            self.pool,
            sqlite: "UPDATE devices SET name = ?, device_type = ?, updated_at = unixepoch('now') WHERE id = ?",
            postgres: "UPDATE devices SET name = $1, device_type = $2, updated_at = NOW() WHERE id = $3",
            name,
            device_type,
            id
        )?;
        self.get_by_id(id).await
    }

    /// Update the encryption key for a device
    ///
    /// ### Arguments
    /// - `device_id`: The device ID (UUID)
    /// - `encryption_key`: The new encryption key
    ///
    /// ### Returns
    /// - `Ok(())`: The result of the operation
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn update_encryption_key(
        &self,
        device_id: &str,
        encryption_key: String,
    ) -> Result<(), sqlx::Error> {
        db_execute_dual!(
            self.pool,
            sqlite: "UPDATE devices SET encryption_key = ?, updated_at = unixepoch('now') WHERE device_id = ?",
            postgres: "UPDATE devices SET encryption_key = $1, updated_at = NOW() WHERE device_id = $2",
            encryption_key,
            device_id
        )?;
        Ok(())
    }

    /// Renew a device by extending its expiration date
    ///
    /// ### Arguments
    /// - `id`: The ID of the device
    /// - `data`: The renew data containing the new API key lifetime
    ///
    /// ### Returns
    /// - `Ok(Device)`: The renewed device
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn renew(&self, id: i32, data: RenewDevice) -> Result<Device, sqlx::Error> {
        let RenewDevice { api_key_lifetime } = data;
        db_execute_dual!(
            self.pool,
            sqlite: "UPDATE devices SET expires_at = expires_at + (? * 86400), updated_at = unixepoch('now') WHERE id = ?",
            postgres: "UPDATE devices SET expires_at = expires_at + ($1 * INTERVAL '1 day'), updated_at = NOW() WHERE id = $2",
            api_key_lifetime,
            id
        )?;
        self.get_by_id(id).await
    }

    /// Delete a device
    ///
    /// ### Arguments
    /// - `id`: The ID of the device
    ///
    /// ### Returns
    /// - `Ok(())`: The result of the operation
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn delete(&self, id: i32) -> Result<(), sqlx::Error> {
        let device = self.get_by_id(id).await?;
        tracing::info!("Deleting device: {} (ID: {})", device.name, device.id);
        db_execute!(self.pool, "DELETE FROM devices WHERE id = ?", id)?;
        Ok(())
    }

    /// Get a device by ID
    ///
    /// ### Arguments
    /// - `id`: The ID of the device
    ///
    /// ### Returns
    /// - `Ok(Device)`: The device
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn get_by_id(&self, id: i32) -> Result<Device, sqlx::Error> {
        db_fetch_one!(self.pool, "SELECT * FROM devices WHERE id = ?", Device, id)
    }

    /// Get a device by device ID
    ///
    /// ### Arguments
    /// - `device_id`: The device ID
    ///
    /// ### Returns
    /// - `Ok(Device)`: The device
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn get_by_device_id(&self, device_id: &str) -> Result<Device, sqlx::Error> {
        db_fetch_one!(
            self.pool,
            "SELECT * FROM devices WHERE device_id = ?",
            Device,
            device_id
        )
    }

    /// Get a device by device key
    ///
    /// ### Arguments
    /// - `device_key`: The device key
    ///
    /// ### Returns
    /// - `Ok(Device)`: The device
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn get_by_device_key(&self, device_key: &str) -> Result<Device, sqlx::Error> {
        db_fetch_one!(
            self.pool,
            "SELECT * FROM devices WHERE device_key = ?",
            Device,
            device_key
        )
    }

    /// Get device by fast hash (O(1) lookup for token endpoint)
    ///
    /// ### Arguments
    /// - `fast_hash`: The SHA256 fast hash
    ///
    /// ### Returns
    /// - `Ok(Some(Device))`: The device if found
    /// - `Ok(None)`: No device with this fast hash
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn get_by_fast_hash(&self, fast_hash: &str) -> Result<Option<Device>, sqlx::Error> {
        db_fetch_optional!(
            self.pool,
            "SELECT * FROM devices WHERE device_key_fast_hash = ?",
            Device,
            fast_hash
        )
    }

    /// Update fast hash for lazy migration
    ///
    /// ### Arguments
    /// - `id`: The device ID
    /// - `fast_hash`: The SHA256 fast hash
    ///
    /// ### Returns
    /// - `Ok(())`: Success
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn update_fast_hash(&self, id: i32, fast_hash: String) -> Result<(), sqlx::Error> {
        db_execute!(
            self.pool,
            "UPDATE devices SET device_key_fast_hash = ? WHERE id = ?",
            fast_hash,
            id
        )?;
        Ok(())
    }

    /// Count the number of devices for a user
    ///
    /// ### Arguments
    /// - `user_id`: The ID of the user
    ///
    /// ### Returns
    /// - `Ok(i32)`: The number of devices for the user
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn count_devices_for_user(&self, user_id: i32) -> Result<i32, sqlx::Error> {
        let count: (i64,) = db_fetch_one!(
            self.pool,
            "SELECT COUNT(*) FROM devices WHERE user_id = ?",
            (i64,),
            user_id
        )?;
        Ok(count.0 as i32)
    }
}
