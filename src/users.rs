use crate::utils::format_date_utc;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Sqlite, SqlitePool};
use time::OffsetDateTime;

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, Clone)]
pub struct User {
    pub id: i32,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub email_verified: bool,
    pub password_hash: String,
    pub role: String,
    pub encryption_key: String, // Base64-encoded 256-bit AES key for encrypting shared files
    pub last_activity: OffsetDateTime,
    pub shares: i32,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// Public-facing User struct that excludes sensitive information (password_hash, encryption_key)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DisplayUser {
    pub id: i32,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub email_verified: bool,
    pub role: String,
    pub last_activity: OffsetDateTime,
    pub shares: i32,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl DisplayUser {
    /// Get the short creation date. Used in the templates to display the creation date in a short format.
    ///
    /// ### Returns
    /// - `String`: The short creation date
    pub fn get_short_creation_date(&self) -> String {
        format_date_utc(&self.created_at)
    }

    /// Get the short updated date. Used in the templates to display the updated date in a short format.
    ///
    /// ### Returns
    /// - `String`: The short updated date
    pub fn get_short_updated_date(&self) -> String {
        format_date_utc(&self.updated_at)
    }

    /// Get the short last activity date. Used in the templates to display the last activity date in a short format.
    ///
    /// ### Returns
    /// - `String`: The short last activity date
    pub fn get_short_last_activity_date(&self) -> String {
        format_date_utc(&self.last_activity)
    }

    /// Get the alternative role of the user. Used in the templates.
    ///
    /// ### Returns
    /// - `String`: The alternative role
    pub fn toggle_role(&self) -> String {
        if self.role == "Admin" {
            "User".to_string()
        } else {
            "Admin".to_string()
        }
    }

    /// Get the prettyn value of the email_verified field. Used in the templates.
    ///
    /// ### Returns
    /// - `String`: The pretty value of the email_verified field
    pub fn is_email_verified(&self) -> String {
        if self.email_verified {
            "Yes".to_string()
        } else {
            "No".to_string()
        }
    }
}
impl From<User> for DisplayUser {
    /// Convert a User to a DisplayUser
    ///
    /// ### Arguments
    /// - `user`: The User to convert
    ///
    /// ### Returns
    /// - `DisplayUser`: The DisplayUser
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            first_name: user.first_name,
            last_name: user.last_name,
            email_verified: user.email_verified,
            role: user.role,
            last_activity: user.last_activity,
            shares: user.shares,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

/// Paginated response for user list
#[derive(Debug, Serialize, Deserialize)]
pub struct PaginatedUsers {
    pub users: Vec<DisplayUser>,
    pub total_count: i32,
    pub page: i32,
    pub page_size: i32,
    pub total_pages: i32,
}

/// Generate a random 256-bit (32-byte) encryption key encoded as base64
///
/// ### Returns
/// - `String`: The generated encryption key
pub fn generate_encryption_key() -> String {
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
    /// - `is_email_verified`: Whether the email is verified
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
        is_email_verified: bool,
    ) -> Result<i32, sqlx::Error> {
        let encryption_key = generate_encryption_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let result = sqlx::query(
            "INSERT INTO users (email, first_name, last_name, password_hash, encryption_key, email_verified, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(email)
        .bind(first_name)
        .bind(last_name)
        .bind(password_hash)
        .bind(encryption_key)
        .bind(is_email_verified)
        .bind(now)
        .bind(now)
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

    /// Check if at least one admin user exists
    ///
    /// ### Returns
    /// - `Ok(bool)`: True if at least one admin exists, false otherwise
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn has_admin(&self) -> Result<bool, sqlx::Error> {
        let count: (i32,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE role = 'Admin'")
            .fetch_one(&self.pool)
            .await?;
        Ok(count.0 > 0)
    }

    /// Create a new admin user (for initial setup, no email verification required)
    ///
    /// ### Arguments
    /// - `email`: The email of the user
    /// - `first_name`: The first name of the user
    /// - `last_name`: The last name of the user
    /// - `password_hash`: The password hash of the user
    ///
    /// ### Returns
    /// - `Ok(i32)`: The ID of the created admin user
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn create_admin(
        &self,
        email: String,
        first_name: String,
        last_name: String,
        password_hash: String,
    ) -> Result<i32, sqlx::Error> {
        // Use transaction to prevent race condition
        let mut tx = self.pool.begin().await?;
        let count: (i32,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE role = 'Admin'")
            .fetch_one(&mut *tx)
            .await?;
        if count.0 > 0 {
            tx.rollback().await?;
            return Err(sqlx::Error::RowNotFound);
        }
        let encryption_key = generate_encryption_key();
        let result = sqlx::query(
            "INSERT INTO users (email, first_name, last_name, password_hash, role, encryption_key, email_verified) VALUES (?, ?, ?, ?, 'Admin', ?, TRUE)",
        )
        .bind(email)
        .bind(first_name)
        .bind(last_name)
        .bind(password_hash)
        .bind(encryption_key)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        let id = result.last_insert_rowid() as i32;
        Ok(id)
    }

    /// Get all users with pagination
    ///
    /// ### Arguments
    /// - `page`: The page number (1-indexed)
    /// - `page_size`: The number of users per page
    ///
    /// ### Returns
    /// - `Ok(PaginatedUsers)`: The paginated list of users (without sensitive information)
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn get_all(&self, page: i32, page_size: i32) -> Result<PaginatedUsers, sqlx::Error> {
        let page = page.max(1);
        let page_size = page_size.max(1);
        let offset = (page - 1) * page_size;
        let total_count = self.count_all().await?;
        let total_pages = (total_count + page_size - 1) / page_size;
        let users = sqlx::query_as::<_, User>(
            "SELECT * FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?",
        )
        .bind(page_size)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;
        let display_users: Vec<DisplayUser> = users.into_iter().map(|u| u.into()).collect();
        Ok(PaginatedUsers {
            users: display_users,
            total_count,
            page,
            page_size,
            total_pages,
        })
    }

    /// Count all users
    ///
    /// ### Returns
    /// - `Ok(i32)`: The total number of users
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn count_all(&self) -> Result<i32, sqlx::Error> {
        let count: (i32,) = sqlx::query_as("SELECT COUNT(*) FROM users")
            .fetch_one(&self.pool)
            .await?;
        Ok(count.0)
    }

    /// Search users with filters and pagination
    ///
    /// ### Arguments
    /// - `email`: Optional email filter (contains search, case-insensitive)
    /// - `first_name`: Optional first name filter (contains search, case-insensitive)
    /// - `last_name`: Optional last name filter (contains search, case-insensitive)
    /// - `role`: Optional role filter (exact match, or "All" for no filter)
    /// - `page`: The page number (1-indexed)
    /// - `page_size`: The number of users per page
    ///
    /// ### Returns
    /// - `Ok(PaginatedUsers)`: The paginated list of filtered users (without sensitive information)
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn search(
        &self,
        email: Option<String>,
        first_name: Option<String>,
        last_name: Option<String>,
        role: Option<String>,
        page: i32,
        page_size: i32,
    ) -> Result<PaginatedUsers, sqlx::Error> {
        let page = page.max(1);
        let page_size = page_size.max(1);
        let offset = (page - 1) * page_size;
        let mut where_clauses = Vec::new();
        let mut params = Vec::new();
        if let Some(e) = email.as_ref().filter(|s| !s.trim().is_empty()) {
            where_clauses.push("email LIKE ?");
            params.push(format!("%{}%", e.trim()));
        }
        if let Some(f) = first_name.as_ref().filter(|s| !s.trim().is_empty()) {
            where_clauses.push("first_name LIKE ?");
            params.push(format!("%{}%", f.trim()));
        }
        if let Some(l) = last_name.as_ref().filter(|s| !s.trim().is_empty()) {
            where_clauses.push("last_name LIKE ?");
            params.push(format!("%{}%", l.trim()));
        }
        if let Some(r) = role
            .as_ref()
            .filter(|s| !s.trim().is_empty() && *s != "All")
        {
            where_clauses.push("role = ?");
            params.push(r.trim().to_string());
        }
        let where_clause = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };
        let count_query = format!("SELECT COUNT(*) FROM users {}", where_clause);
        let mut count_query_builder = sqlx::query_as::<_, (i32,)>(&count_query);
        for param in &params {
            count_query_builder = count_query_builder.bind(param);
        }
        let total_count = count_query_builder.fetch_one(&self.pool).await?.0;

        let total_pages = (total_count + page_size - 1) / page_size;
        let query = format!(
            "SELECT * FROM users {} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            where_clause
        );
        let mut query_builder = sqlx::query_as::<_, User>(&query);
        for param in &params {
            query_builder = query_builder.bind(param);
        }
        query_builder = query_builder.bind(page_size).bind(offset);
        let users = query_builder.fetch_all(&self.pool).await?;
        let display_users: Vec<DisplayUser> = users.into_iter().map(|u| u.into()).collect();
        Ok(PaginatedUsers {
            users: display_users,
            total_count,
            page,
            page_size,
            total_pages,
        })
    }

    /// Toggle a user's role between Admin and User
    ///
    /// ### Arguments
    /// - `id`: The ID of the user
    ///
    /// ### Returns
    /// - `Ok(DisplayUser)`: The updated user with the new role
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn toggle_role(&self, id: i32) -> Result<DisplayUser, sqlx::Error> {
        let user = self.get_by_id(id).await?;
        let user = user.ok_or(sqlx::Error::RowNotFound)?;
        let new_role = if user.role == "Admin" {
            "User"
        } else {
            "Admin"
        };
        sqlx::query("UPDATE users SET role = ? WHERE id = ?")
            .bind(new_role)
            .bind(id)
            .execute(&self.pool)
            .await?;
        let updated_user = self.get_by_id(id).await?;
        let updated_user = updated_user.ok_or(sqlx::Error::RowNotFound)?;
        Ok(updated_user.into())
    }

    /// Delete a user by ID
    ///
    /// ### Arguments
    /// - `id`: The ID of the user to delete
    ///
    /// ### Returns
    /// - `Ok(DisplayUser)`: The deleted user information
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn delete(&self, id: i32) -> Result<DisplayUser, sqlx::Error> {
        let user = self.get_by_id(id).await?;
        let user = user.ok_or(sqlx::Error::RowNotFound)?;
        sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(user.into())
    }

    /// Update user's last_activity to current timestamp
    ///
    /// ### Arguments
    /// - `id`: The ID of the user
    ///
    /// ### Returns
    /// - `Ok(())`: The result of the operation if the last_activity was updated successfully
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn update_last_activity(&self, id: i32) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE users SET last_activity = unixepoch('now') WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Increment user's shares count and update last_activity
    ///
    /// ### Arguments
    /// - `id`: The ID of the user
    ///
    /// ### Returns
    /// - `Ok(())`: The result of the operation if the shares count was incremented successfully
    /// - `Err(sqlx::Error)`: The error if the operation fails
    pub async fn increment_shares(&self, id: i32) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE users SET shares = shares + 1, last_activity = unixepoch('now') WHERE id = ?",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
