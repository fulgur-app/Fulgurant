use sqlx::{Pool, Postgres, Sqlite};

/// Database connection pool supporting `SQLite` and `PostgreSQL` backends.
/// Auto-detected from `DATABASE_URL` scheme at startup.
#[derive(Clone)]
pub enum DbPool {
    Sqlite(Pool<Sqlite>),
    Postgres(Pool<Postgres>),
}

/// Database backend identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbBackend {
    Sqlite,
    Postgres,
}

impl DbPool {
    /// Get the backend type for this pool
    pub fn backend(&self) -> DbBackend {
        match self {
            DbPool::Sqlite(_) => DbBackend::Sqlite,
            DbPool::Postgres(_) => DbBackend::Postgres,
        }
    }
}

/// Convert `?` placeholders to `$1, $2, ...` for `PostgreSQL`.
/// Only operates on `?` characters outside of quoted strings.
pub fn pg_params(sql: &str) -> String {
    let mut result = String::with_capacity(sql.len() + 16);
    let mut n = 0u32;
    let mut in_single_quote = false;

    for ch in sql.chars() {
        if ch == '\'' {
            in_single_quote = !in_single_quote;
            result.push(ch);
        } else if ch == '?' && !in_single_quote {
            n += 1;
            result.push('$');
            result.push_str(&n.to_string());
        } else {
            result.push(ch);
        }
    }
    result
}

// ============================================================================
// Dispatch macros
//
// Single-SQL variants: auto-convert ? to $N for PostgreSQL
// Dual-SQL variants: use different SQL per backend (for timestamps, RETURNING, etc.)
// ============================================================================

/// Execute a query, returning `Result<u64, sqlx::Error>` (`rows_affected`)
#[macro_export]
macro_rules! db_execute {
    ($pool:expr, $sql:expr $(, $bind:expr)*) => {{
        match &$pool {
            $crate::db::DbPool::Sqlite(pool) => {
                sqlx::query($sql)
                    $(.bind($bind))*
                    .execute(pool).await
                    .map(|r| r.rows_affected())
            }
            $crate::db::DbPool::Postgres(pool) => {
                let __pg_sql = $crate::db::pg_params($sql);
                sqlx::query(&__pg_sql)
                    $(.bind($bind))*
                    .execute(pool).await
                    .map(|r| r.rows_affected())
            }
        }
    }};
}

/// Execute with different SQL per backend, returning `Result<u64, sqlx::Error>`
#[macro_export]
macro_rules! db_execute_dual {
    ($pool:expr, sqlite: $sql_s:expr, postgres: $sql_p:expr $(, $bind:expr)*) => {{
        match &$pool {
            $crate::db::DbPool::Sqlite(pool) => {
                sqlx::query($sql_s)
                    $(.bind($bind))*
                    .execute(pool).await
                    .map(|r| r.rows_affected())
            }
            $crate::db::DbPool::Postgres(pool) => {
                sqlx::query($sql_p)
                    $(.bind($bind))*
                    .execute(pool).await
                    .map(|r| r.rows_affected())
            }
        }
    }};
}

/// Fetch optional row with `query_as`, auto-converting placeholders
#[macro_export]
macro_rules! db_fetch_optional {
    ($pool:expr, $sql:expr, $type:ty $(, $bind:expr)*) => {{
        match &$pool {
            $crate::db::DbPool::Sqlite(pool) => {
                sqlx::query_as::<_, $type>($sql)
                    $(.bind($bind))*
                    .fetch_optional(pool).await
            }
            $crate::db::DbPool::Postgres(pool) => {
                let __pg_sql = $crate::db::pg_params($sql);
                sqlx::query_as::<_, $type>(&__pg_sql)
                    $(.bind($bind))*
                    .fetch_optional(pool).await
            }
        }
    }};
}

/// Fetch optional row with different SQL per backend
#[macro_export]
macro_rules! db_fetch_optional_dual {
    ($pool:expr, sqlite: $sql_s:expr, postgres: $sql_p:expr, $type:ty $(, $bind:expr)*) => {{
        match &$pool {
            $crate::db::DbPool::Sqlite(pool) => {
                sqlx::query_as::<_, $type>($sql_s)
                    $(.bind($bind))*
                    .fetch_optional(pool).await
            }
            $crate::db::DbPool::Postgres(pool) => {
                sqlx::query_as::<_, $type>($sql_p)
                    $(.bind($bind))*
                    .fetch_optional(pool).await
            }
        }
    }};
}

/// Fetch one row with `query_as`, auto-converting placeholders
#[macro_export]
macro_rules! db_fetch_one {
    ($pool:expr, $sql:expr, $type:ty $(, $bind:expr)*) => {{
        match &$pool {
            $crate::db::DbPool::Sqlite(pool) => {
                sqlx::query_as::<_, $type>($sql)
                    $(.bind($bind))*
                    .fetch_one(pool).await
            }
            $crate::db::DbPool::Postgres(pool) => {
                let __pg_sql = $crate::db::pg_params($sql);
                sqlx::query_as::<_, $type>(&__pg_sql)
                    $(.bind($bind))*
                    .fetch_one(pool).await
            }
        }
    }};
}

/// Fetch one row with different SQL per backend
#[macro_export]
macro_rules! db_fetch_one_dual {
    ($pool:expr, sqlite: $sql_s:expr, postgres: $sql_p:expr, $type:ty $(, $bind:expr)*) => {{
        match &$pool {
            $crate::db::DbPool::Sqlite(pool) => {
                sqlx::query_as::<_, $type>($sql_s)
                    $(.bind($bind))*
                    .fetch_one(pool).await
            }
            $crate::db::DbPool::Postgres(pool) => {
                sqlx::query_as::<_, $type>($sql_p)
                    $(.bind($bind))*
                    .fetch_one(pool).await
            }
        }
    }};
}

/// Fetch all rows with `query_as`, auto-converting placeholders
#[macro_export]
macro_rules! db_fetch_all {
    ($pool:expr, $sql:expr, $type:ty $(, $bind:expr)*) => {{
        match &$pool {
            $crate::db::DbPool::Sqlite(pool) => {
                sqlx::query_as::<_, $type>($sql)
                    $(.bind($bind))*
                    .fetch_all(pool).await
            }
            $crate::db::DbPool::Postgres(pool) => {
                let __pg_sql = $crate::db::pg_params($sql);
                sqlx::query_as::<_, $type>(&__pg_sql)
                    $(.bind($bind))*
                    .fetch_all(pool).await
            }
        }
    }};
}

/// Fetch all rows with different SQL per backend
#[macro_export]
macro_rules! db_fetch_all_dual {
    ($pool:expr, sqlite: $sql_s:expr, postgres: $sql_p:expr, $type:ty $(, $bind:expr)*) => {{
        match &$pool {
            $crate::db::DbPool::Sqlite(pool) => {
                sqlx::query_as::<_, $type>($sql_s)
                    $(.bind($bind))*
                    .fetch_all(pool).await
            }
            $crate::db::DbPool::Postgres(pool) => {
                sqlx::query_as::<_, $type>($sql_p)
                    $(.bind($bind))*
                    .fetch_all(pool).await
            }
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pg_params_basic() {
        assert_eq!(
            pg_params("SELECT * FROM users WHERE id = ?"),
            "SELECT * FROM users WHERE id = $1"
        );
    }

    #[test]
    fn test_pg_params_multiple() {
        assert_eq!(
            pg_params("INSERT INTO users (a, b, c) VALUES (?, ?, ?)"),
            "INSERT INTO users (a, b, c) VALUES ($1, $2, $3)"
        );
    }

    #[test]
    fn test_pg_params_no_placeholders() {
        assert_eq!(pg_params("SELECT * FROM users"), "SELECT * FROM users");
    }

    #[test]
    fn test_pg_params_ignores_quoted_question_marks() {
        assert_eq!(
            pg_params("SELECT * FROM users WHERE name LIKE ? ESCAPE '\\'"),
            "SELECT * FROM users WHERE name LIKE $1 ESCAPE '\\'"
        );
    }

    #[test]
    fn test_pg_params_mixed() {
        assert_eq!(
            pg_params("SELECT * FROM t WHERE a = ? AND b LIKE '%?%' AND c = ?"),
            "SELECT * FROM t WHERE a = $1 AND b LIKE '%?%' AND c = $2"
        );
    }
}
