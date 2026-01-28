use serde::{Deserialize, Serialize};
use sqlx::{Pool, Row, Sqlite, SqlitePool};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

pub const MAX_DEVICES_PER_USER: i32 = 99;

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
    pub device_id: String,  // UUID v4 (public identifier)
    pub device_key: String, // Hashed API key (private)
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
        let format = time::format_description::parse("[year]-[month]-[day]").unwrap();
        self.created_at.format(&format).unwrap_or_default()
    }

    /// Get the updated at date formatted as YYYY-MM-DD HH:MM:SS
    ///
    /// ### Returns
    /// - `String`: The updated at date formatted as YYYY-MM-DD HH:MM:SS
    pub fn get_updated_at_formatted(&self) -> String {
        let format =
            time::format_description::parse("[year]-[month]-[day] [hour]:[minute]:[second]")
                .unwrap();
        self.updated_at.format(&format).unwrap_or_default()
    }

    /// Get the expires at date formatted as YYYY-MM-DD
    ///
    /// ### Returns
    /// - `String`: The expires at date formatted as YYYY-MM-DD
    pub fn get_expires_at_formatted(&self) -> String {
        let format = time::format_description::parse("[year]-[month]-[day]").unwrap();
        let formatted = self.expires_at.format(&format).unwrap_or_default();
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
    pool: SqlitePool,
}

impl DeviceRepository {
    /// Create a new device repository
    ///
    /// ### Arguments
    /// - `pool`: The SQLite pool
    ///
    /// ### Returns
    /// - `DeviceRepository`: The device repository
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }

    /// Get all devices for a user
    ///
    /// ### Arguments
    /// - `user_id`: The ID of the user
    ///
    /// ### Returns
    /// - `Ok(Vec<Device>)`: The devices for the user
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn get_all_for_user(&self, user_id: i32) -> Result<Vec<Device>, sqlx::Error> {
        sqlx::query_as::<_, Device>("SELECT * FROM devices WHERE user_id = ?")
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
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
        let result = sqlx::query(
            "INSERT INTO devices (user_id, device_id, device_key, name, device_type, encryption_key, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(user_id)
        .bind(&device_id)
        .bind(&device_key)
        .bind(name)
        .bind(device_type)
        .bind(None::<String>) // encryption_key defaults to NULL
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        let id = result.last_insert_rowid() as i32;
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
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let UpdateDevice { name, device_type } = data;
        sqlx::query("UPDATE devices SET name = ?, device_type = ?, updated_at = ? WHERE id = ?")
            .bind(name)
            .bind(device_type)
            .bind(now)
            .bind(id)
            .execute(&self.pool)
            .await?;
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
        let now = OffsetDateTime::now_utc().unix_timestamp();
        sqlx::query("UPDATE devices SET encryption_key = ?, updated_at = ? WHERE device_id = ?")
            .bind(encryption_key)
            .bind(now)
            .bind(device_id)
            .execute(&self.pool)
            .await?;
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
        let now = OffsetDateTime::now_utc();
        let RenewDevice { api_key_lifetime } = data;
        let new_expires_at = now + Duration::days(api_key_lifetime);
        sqlx::query("UPDATE devices SET expires_at = ?, updated_at = ? WHERE id = ?")
            .bind(new_expires_at)
            .bind(now.unix_timestamp())
            .bind(id)
            .execute(&self.pool)
            .await?;
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
        sqlx::query("DELETE FROM devices WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
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
        sqlx::query_as::<_, Device>("SELECT * FROM devices WHERE id = ?")
            .bind(id)
            .fetch_one(&self.pool)
            .await
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
        sqlx::query_as::<_, Device>("SELECT * FROM devices WHERE device_id = ?")
            .bind(device_id)
            .fetch_one(&self.pool)
            .await
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
        sqlx::query_as::<_, Device>("SELECT * FROM devices WHERE device_key = ?")
            .bind(device_key)
            .fetch_one(&self.pool)
            .await
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
        sqlx::query("SELECT COUNT(*) FROM devices WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(&self.pool)
            .await
            .and_then(|row| row.try_get::<i32, _>(0))
    }
}
