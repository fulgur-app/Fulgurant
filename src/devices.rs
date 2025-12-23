use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Sqlite, SqlitePool};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, Clone)]
pub struct Device {
    pub id: i32,
    pub user_id: i32,
    pub device_id: String,  // UUID v4 (public identifier)
    pub device_key: String, // Hashed API key (private)
    pub name: String,
    pub device_type: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Device {
    /// Check if the device has expired
    ///
    /// ### Returns
    /// - `true`: If the device has expired, `false` otherwise
    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }

    /// Get the created at date formatted as YYYY-MM-DD
    ///
    /// ### Returns
    /// - `String`: The created at date formatted as YYYY-MM-DD
    pub fn get_created_at_formatted(&self) -> String {
        self.created_at.format("%Y-%m-%d").to_string()
    }

    /// Get the updated at date formatted as YYYY-MM-DD HH:MM:SS
    ///
    /// ### Returns
    /// - `String`: The updated at date formatted as YYYY-MM-DD HH:MM:SS
    pub fn get_updated_at_formatted(&self) -> String {
        self.updated_at.format("%Y-%m-%d %H:%M:%S").to_string()
    }

    /// Get the expires at date formatted as YYYY-MM-DD
    ///
    /// ### Returns
    /// - `String`: The expires at date formatted as YYYY-MM-DD
    pub fn get_expires_at_formatted(&self) -> String {
        if self
            .expires_at
            .format("%Y-%m-%d")
            .to_string()
            .starts_with("21")
        {
            "Never".to_string()
        } else {
            self.expires_at.format("%Y-%m-%d").to_string()
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
        let now = Utc::now();
        let device_id = Uuid::new_v4().to_string();
        let CreateDevice {
            name,
            device_type,
            api_key_lifetime,
        } = data;
        let expires_at = now
            .checked_add_signed(chrono::Duration::days(api_key_lifetime))
            .unwrap();
        let result = sqlx::query(
            "INSERT INTO devices (user_id, device_id, device_key, name, device_type, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(user_id)
        .bind(&device_id)
        .bind(&device_key)
        .bind(name)
        .bind(device_type)
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
        let now = Utc::now().timestamp();
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
}
