use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Sqlite, SqlitePool};

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, Clone)]
pub struct User {
    pub id: i32,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub email_verified: bool,
    pub password_hash: String,
    pub encryption_key: String, // Base64-encoded 256-bit AES key for encrypting shared files
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Generate a random 256-bit (32-byte) encryption key encoded as base64
///
/// ### Returns
/// - `String`: The generated encryption key
fn generate_encryption_key() -> String {
    let mut rng = rand::rng();
    let key_bytes: [u8; 32] = rng.random();
    BASE64.encode(key_bytes)
}

#[derive(Clone)]
pub struct UserRepository {
    pool: SqlitePool,
}

impl UserRepository {
    /// Create a new user repository
    ///
    /// ### Arguments
    /// - `pool`: The SQLite pool
    ///
    /// ### Returns
    /// - `UserRepository`: The user repository
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }

    /// Get user by email
    ///
    /// ### Arguments
    /// - `email`: The email of the user
    ///
    /// ### Returns
    /// - `Ok(Option<User>)`: The user if found, otherwise None
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn get_by_email(&self, email: String) -> Result<Option<User>, sqlx::Error> {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = ?")
            .bind(email)
            .fetch_optional(&self.pool)
            .await
    }

    /// Get user by ID
    ///
    /// ### Arguments
    /// - `id`: The ID of the user
    ///
    /// ### Returns
    /// - `Ok(Option<User>)`: The user if found, otherwise None
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn get_by_id(&self, id: i32) -> Result<Option<User>, sqlx::Error> {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
    }

    /// Create a new user
    ///
    /// ### Arguments
    /// - `email`: The email of the user
    /// - `first_name`: The first name of the user
    /// - `last_name`: The last name of the user
    /// - `password_hash`: The password hash of the user
    ///
    /// ### Returns
    /// - `Ok(i32)`: The ID of the created user
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn create(
        &self,
        email: String,
        first_name: String,
        last_name: String,
        password_hash: String,
    ) -> Result<i32, sqlx::Error> {
        let encryption_key = generate_encryption_key();
        let result = sqlx::query(
            "INSERT INTO users (email, first_name, last_name, password_hash, encryption_key) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(email)
        .bind(first_name)
        .bind(last_name)
        .bind(password_hash)
        .bind(encryption_key)
        .execute(&self.pool)
        .await?;
        let id = result.last_insert_rowid() as i32;
        Ok(id)
    }

    /// Update the password of a user
    ///
    /// ### Arguments
    /// - `id`: The ID of the user
    /// - `password_hash`: The password hash of the user
    ///
    /// ### Returns
    /// - `Ok(())`: The result of the operation if the password was updated successfully
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn update_password(&self, id: i32, password_hash: String) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
            .bind(password_hash)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Mark a user as verified
    ///
    /// ### Arguments
    /// - `id`: The ID of the user
    ///
    /// ### Returns
    /// - `Ok(())`: The result of the operation if the user was marked as verified successfully
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn mark_as_verified(&self, id: i32) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE users SET email_verified = TRUE WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Update user's first and last name
    ///
    /// ### Arguments
    /// - `id`: The ID of the user
    /// - `first_name`: The new first name
    /// - `last_name`: The new last name
    ///
    /// ### Returns
    /// - `Ok(())`: The result of the operation if the user's name was updated successfully
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn update_name(
        &self,
        id: i32,
        first_name: String,
        last_name: String,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE users SET first_name = ?, last_name = ? WHERE id = ?")
            .bind(first_name)
            .bind(last_name)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Update user's email after it's been verified
    ///
    /// ### Arguments
    /// - `id`: The ID of the user
    /// - `email`: The new email address
    ///
    /// ### Returns
    /// - `Ok(())`: The result of the operation if the user's email was updated successfully
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn update_email(&self, id: i32, email: String) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE users SET email = ?, email_verified = TRUE WHERE id = ?")
            .bind(email)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
