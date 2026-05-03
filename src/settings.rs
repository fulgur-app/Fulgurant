use crate::db::DbPool;

/// Repository for admin-configurable server settings stored in the `server_settings` table.
#[derive(Clone)]
pub struct SettingsRepository {
    pool: DbPool,
}

impl SettingsRepository {
    /// Create a new `SettingsRepository`
    ///
    /// ### Arguments
    /// - `pool`: The database connection pool
    ///
    /// ### Returns
    /// - `Self`: The new repository
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Retrieve the admin-configured maximum share file size.
    ///
    /// ### Returns
    /// - `Ok(None)`: No limit is configured
    /// - `Ok(Some(n))`: Files are limited to `n` bytes
    /// - `Err(sqlx::Error)`: Database error
    pub async fn get_max_file_size_bytes(&self) -> Result<Option<u64>, sqlx::Error> {
        let value: Option<i64> = match &self.pool {
            DbPool::Sqlite(pool) => {
                sqlx::query_scalar("SELECT max_file_size_bytes FROM server_settings WHERE id = 1")
                    .fetch_one(pool)
                    .await?
            }
            DbPool::Postgres(pool) => {
                sqlx::query_scalar("SELECT max_file_size_bytes FROM server_settings WHERE id = 1")
                    .fetch_one(pool)
                    .await?
            }
        };
        Ok(value.map(|v| v as u64))
    }

    /// Update the maximum share file size.
    ///
    /// ### Arguments
    /// - `value`: `None` for no limit, `Some(n)` for a limit of `n` bytes (minimum 1024)
    ///
    /// ### Returns
    /// - `Ok(())`: Success
    /// - `Err(sqlx::Error)`: Database error
    pub async fn update_max_file_size_bytes(&self, value: Option<u64>) -> Result<(), sqlx::Error> {
        let db_value: Option<i64> = value.map(|v| v as i64);
        match &self.pool {
            DbPool::Sqlite(pool) => {
                sqlx::query("UPDATE server_settings SET max_file_size_bytes = ? WHERE id = 1")
                    .bind(db_value)
                    .execute(pool)
                    .await?;
            }
            DbPool::Postgres(pool) => {
                sqlx::query("UPDATE server_settings SET max_file_size_bytes = $1 WHERE id = 1")
                    .bind(db_value)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(())
    }
}
