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
    pub public_key: Option<String>, // Age (X25519) public key uploaded by the client (format: "age1..."), nullable
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

/// Error returned when creating a device
#[derive(Debug)]
pub enum CreateDeviceError {
    /// The user already owns the maximum allowed number of devices
    LimitReached(i32),
    /// An underlying database error occurred
    Database(sqlx::Error),
}

impl From<sqlx::Error> for CreateDeviceError {
    /// Convert a `sqlx::Error` into a `CreateDeviceError`
    ///
    /// ### Arguments
    /// - `err`: The `sqlx::Error` to convert
    ///
    /// ### Returns
    /// - `CreateDeviceError`: The wrapped database error
    fn from(err: sqlx::Error) -> Self {
        CreateDeviceError::Database(err)
    }
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

    /// Create a new device, enforcing the per-user device limit atomically
    ///
    /// The count and the insert run inside a single transaction so two
    /// concurrent requests cannot both observe `count < max_devices` and exceed
    /// the limit (TOCTOU race). On `PostgreSQL` a per-user transaction-scoped
    /// advisory lock serializes concurrent creations for the same user; on
    /// `SQLite` (WAL mode) the read-then-write transaction surfaces a snapshot
    /// conflict instead of silently over-counting.
    ///
    /// ### Arguments
    /// - `user_id`: The ID of the user
    /// - `device_key`: The device key
    /// - `data`: The data for the device
    /// - `max_devices`: The maximum number of devices allowed per user
    ///
    /// ### Returns
    /// - `Ok(Device)`: The created device
    /// - `Err(CreateDeviceError::LimitReached)`: The user already owns `max_devices` devices
    /// - `Err(CreateDeviceError::Database)`: The error if the operation fails
    pub async fn create(
        &self,
        user_id: i32,
        device_key: String,
        data: CreateDevice,
        max_devices: i32,
    ) -> Result<Device, CreateDeviceError> {
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
                let mut tx = pool.begin().await?;
                let count: (i64,) =
                    sqlx::query_as("SELECT COUNT(*) FROM devices WHERE user_id = ?")
                        .bind(user_id)
                        .fetch_one(&mut *tx)
                        .await?;
                if count.0 as i32 >= max_devices {
                    tx.rollback().await?;
                    return Err(CreateDeviceError::LimitReached(max_devices));
                }
                let result = sqlx::query(
                    "INSERT INTO devices (user_id, device_id, device_key, device_key_fast_hash, name, device_type, public_key, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                .execute(&mut *tx)
                .await?;
                let id = result.last_insert_rowid() as i32;
                tx.commit().await?;
                id
            }
            DbPool::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query("SELECT pg_advisory_xact_lock($1)")
                    .bind(i64::from(user_id))
                    .execute(&mut *tx)
                    .await?;
                let count: (i64,) =
                    sqlx::query_as("SELECT COUNT(*) FROM devices WHERE user_id = $1")
                        .bind(user_id)
                        .fetch_one(&mut *tx)
                        .await?;
                if count.0 as i32 >= max_devices {
                    tx.rollback().await?;
                    return Err(CreateDeviceError::LimitReached(max_devices));
                }
                let row: (i32,) = sqlx::query_as(
                    "INSERT INTO devices (user_id, device_id, device_key, device_key_fast_hash, name, device_type, public_key, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, to_timestamp($8)) RETURNING id",
                )
                .bind(user_id)
                .bind(&device_id)
                .bind(&device_key)
                .bind(&fast_hash)
                .bind(&name)
                .bind(&device_type)
                .bind(None::<String>)
                .bind(expires_at.unix_timestamp())
                .fetch_one(&mut *tx)
                .await?;
                tx.commit().await?;
                row.0
            }
        };
        Ok(self.get_by_id(id).await?)
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

    /// Update the age public key for a device
    ///
    /// ### Arguments
    /// - `device_id`: The device ID (UUID)
    /// - `public_key`: The device's age (X25519) public key, format "age1..."
    ///
    /// ### Returns
    /// - `Ok(())`: The result of the operation
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn update_public_key(
        &self,
        device_id: &str,
        public_key: String,
    ) -> Result<(), sqlx::Error> {
        db_execute_dual!(
            self.pool,
            sqlite: "UPDATE devices SET public_key = ?, updated_at = unixepoch('now') WHERE device_id = ?",
            postgres: "UPDATE devices SET public_key = $1, updated_at = NOW() WHERE device_id = $2",
            public_key,
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
        tracing::info!("Deleting device with ID: {}", device.id);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::DbPool;
    use crate::users::UserRepository;
    use sqlx::sqlite::SqlitePoolOptions;

    /// Build an in-memory `SQLite`-backed device repository and seed one owning user.
    ///
    /// ### Returns
    /// - `(DeviceRepository, i32)`: The repository and the seeded user id (used as the device owner)
    async fn setup_test_repository() -> (DeviceRepository, i32) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("failed to open in-memory SQLite");
        sqlx::migrate!("./data/migrations")
            .run(&pool)
            .await
            .expect("failed to run migrations");
        let db_pool = DbPool::Sqlite(pool);
        let user_id = UserRepository::new(db_pool.clone())
            .create(
                "device-owner@example.com".to_string(),
                "Device".to_string(),
                "Owner".to_string(),
                "hash".to_string(),
                true,
                false,
            )
            .await
            .expect("failed to create owning user");
        (DeviceRepository::new(db_pool), user_id)
    }

    /// Build a `CreateDevice` payload with a 30-day key lifetime.
    ///
    /// ### Arguments
    /// - `name`: The device name
    ///
    /// ### Returns
    /// - `CreateDevice`: A desktop device payload
    fn sample_device(name: &str) -> CreateDevice {
        CreateDevice {
            name: name.to_string(),
            device_type: "desktop".to_string(),
            api_key_lifetime: 30,
        }
    }

    #[tokio::test]
    async fn test_create_enforces_device_limit() {
        let (repository, user_id) = setup_test_repository().await;
        let max_devices = 2;
        for index in 0..max_devices {
            repository
                .create(
                    user_id,
                    format!("device-key-{index}"),
                    sample_device(&format!("Device {index}")),
                    max_devices,
                )
                .await
                .expect("creating a device under the limit should succeed");
        }

        let result = repository
            .create(
                user_id,
                "device-key-overflow".to_string(),
                sample_device("Overflow"),
                max_devices,
            )
            .await;
        match result {
            Err(CreateDeviceError::LimitReached(limit)) => assert_eq!(limit, max_devices),
            other => panic!("expected LimitReached, got {other:?}"),
        }

        assert_eq!(
            repository
                .count_devices_for_user(user_id)
                .await
                .expect("count query should succeed"),
            max_devices,
            "the rejected device must not have been inserted"
        );
    }

    #[tokio::test]
    async fn test_get_by_device_id_round_trip_and_not_found() {
        let (repository, user_id) = setup_test_repository().await;
        let created = repository
            .create(
                user_id,
                "device-key".to_string(),
                sample_device("Laptop"),
                10,
            )
            .await
            .expect("create should succeed");

        let fetched = repository
            .get_by_device_id(&created.device_id)
            .await
            .expect("device should be found by its UUID");
        assert_eq!(fetched.id, created.id);
        assert_eq!(fetched.name, "Laptop");

        let missing = repository.get_by_device_id("non-existent-uuid").await;
        assert!(
            matches!(missing, Err(sqlx::Error::RowNotFound)),
            "an unknown device_id should yield RowNotFound"
        );
    }

    #[tokio::test]
    async fn test_update_public_key_persists() {
        let (repository, user_id) = setup_test_repository().await;
        let created = repository
            .create(
                user_id,
                "device-key".to_string(),
                sample_device("Phone"),
                10,
            )
            .await
            .expect("create should succeed");
        assert!(
            created.public_key.is_none(),
            "a new device starts without a public key"
        );

        let recipient = "age1examplerecipientstring".to_string();
        repository
            .update_public_key(&created.device_id, recipient.clone())
            .await
            .expect("updating the public key should succeed");

        let refreshed = repository
            .get_by_device_id(&created.device_id)
            .await
            .expect("device should still exist");
        assert_eq!(refreshed.public_key.as_deref(), Some(recipient.as_str()));
    }

    #[tokio::test]
    async fn test_fast_hash_lookup_matches_argon2_verification() {
        let (repository, user_id) = setup_test_repository().await;
        let raw_key = crate::api_key::generate_api_key();
        let stored_hash =
            crate::api_key::hash_api_key(&raw_key).expect("hashing the key should succeed");
        let created = repository
            .create(user_id, stored_hash, sample_device("Tablet"), 10)
            .await
            .expect("create should succeed");

        // Mirror the token endpoint lazy migration: the persisted fast hash is the
        // SHA256 of the raw key, not of the stored Argon2 hash written at create time.
        let fast_hash = crate::api_key::hash_api_key_fast(&raw_key);
        repository
            .update_fast_hash(created.id, fast_hash.clone())
            .await
            .expect("populating the fast hash should succeed");

        let found = repository
            .get_by_fast_hash(&fast_hash)
            .await
            .expect("fast hash query should succeed")
            .expect("device should be found via its fast hash");
        assert_eq!(found.id, created.id);
        assert!(
            crate::api_key::verify_api_key(&raw_key, &found.device_key)
                .expect("verification should not error"),
            "the raw key must verify against the stored Argon2 hash"
        );

        let none = repository
            .get_by_fast_hash("deadbeef")
            .await
            .expect("fast hash query should succeed");
        assert!(none.is_none(), "an unknown fast hash should return None");
    }

    #[tokio::test]
    async fn test_renew_extends_expiration() {
        let (repository, user_id) = setup_test_repository().await;
        let created = repository
            .create(
                user_id,
                "device-key".to_string(),
                sample_device("Desktop"),
                10,
            )
            .await
            .expect("create should succeed");

        let renewed = repository
            .renew(
                created.id,
                RenewDevice {
                    api_key_lifetime: 30,
                },
            )
            .await
            .expect("renew should succeed");
        assert!(
            renewed.expires_at > created.expires_at,
            "renewing should push the expiry further out"
        );
    }

    #[tokio::test]
    async fn test_is_expired_reflects_expiration_date() {
        let (repository, user_id) = setup_test_repository().await;
        let active = repository
            .create(
                user_id,
                "active-key".to_string(),
                sample_device("Active"),
                10,
            )
            .await
            .expect("create should succeed");
        assert!(
            !active.is_expired(),
            "a freshly created device is not expired"
        );

        let expired = repository
            .create(
                user_id,
                "expired-key".to_string(),
                CreateDevice {
                    name: "Expired".to_string(),
                    device_type: "desktop".to_string(),
                    api_key_lifetime: -1,
                },
                10,
            )
            .await
            .expect("create should succeed");
        assert!(
            expired.is_expired(),
            "a device with a past expiry date is expired"
        );
    }
}
