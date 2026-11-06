use crate::db::{DbBackend, DbPool};
use sqlx::SqlitePool;
use std::path::{Path, PathBuf};
use std::time::Duration;
use time::OffsetDateTime;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Maximum time the shutdown sequence waits for an in-flight backup before exiting anyway
pub const SHUTDOWN_BACKUP_TIMEOUT: Duration = Duration::from_secs(60);

/// Get the backup folder path from environment or use default
///
/// ### Returns
/// - `PathBuf`: Path to the backup folder
pub fn get_backup_folder() -> PathBuf {
    let backup_folder = std::env::var("BACKUP_FOLDER").unwrap_or_else(|_| "backups".to_string());
    PathBuf::from(backup_folder)
}

/// Check if daily database backups are enabled
pub fn is_daily_backup_enabled() -> bool {
    std::env::var("DAILY_DATABASE_BACKUP")
        .unwrap_or_else(|_| "false".to_string())
        .to_lowercase()
        == "true"
}

/// Validate that a path contains only safe characters for SQL interpolation
///
/// Since `SQLite`'s VACUUM INTO doesn't support parameterized queries, we must
/// sanitize the path manually to prevent SQL injection.
///
/// ### Arguments
/// - `path`: The path string to validate
///
/// ### Returns
/// - `Ok(())`: If the path is safe
/// - `Err(anyhow::Error)`: If the path contains potentially dangerous characters
fn validate_backup_path(path: &str) -> anyhow::Result<()> {
    if path.contains('\'') {
        return Err(anyhow::anyhow!(
            "Backup path contains single quote character, which is not allowed for security reasons"
        ));
    }
    Ok(())
}

/// Remove the `.partial` file of a failed backup, which may not have been created
///
/// ### Arguments
/// - `partial_path`: Path to the `.partial` file
fn remove_partial_backup(partial_path: &Path) {
    if let Err(e) = std::fs::remove_file(partial_path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(
            "Failed to remove partial backup {}: {:?}",
            partial_path.display(),
            e
        );
    }
}

/// Write a snapshot of the database to `backup_path` through a `.partial` sibling file
///
/// The file only takes its final name once `VACUUM INTO` has completed, so an interrupted
/// backup can never be mistaken for a valid one. Both files share a folder, which keeps the
/// rename atomic.
///
/// ### Arguments
/// - `pool`: The `SQLite` connection pool
/// - `backup_path`: Final path of the backup file
///
/// ### Returns
/// - `Ok(())`: If the backup is complete and carries its final name
/// - `Err(anyhow::Error)`: If the path is unsafe, or the snapshot or rename fails
async fn vacuum_into_atomically(pool: &SqlitePool, backup_path: &Path) -> anyhow::Result<()> {
    let partial_path = backup_path.with_added_extension("partial");
    let partial_path_str = partial_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid backup path"))?;
    validate_backup_path(partial_path_str)?;
    let query = format!("VACUUM INTO '{partial_path_str}'");
    if let Err(e) = sqlx::query(sqlx::AssertSqlSafe(query)).execute(pool).await {
        remove_partial_backup(&partial_path);
        return Err(e.into());
    }
    std::fs::rename(&partial_path, backup_path)?;
    Ok(())
}

/// Perform a database backup using `SQLite`'s VACUUM INTO command
///
/// ### Arguments
/// - `pool`: The `SQLite` connection pool
/// - `backup_folder`: Folder receiving the backup, created if missing
///
/// ### Returns
/// - `Ok(PathBuf)`: Path to the created backup file
/// - `Err(anyhow::Error)`: If backup fails
pub async fn perform_backup(pool: &SqlitePool, backup_folder: &Path) -> anyhow::Result<PathBuf> {
    std::fs::create_dir_all(backup_folder)?;
    let now = OffsetDateTime::now_utc();
    let timestamp = now.format(&time::format_description::parse_borrowed::<2>(
        "[year]-[month]-[day]_[hour]-[minute]-[second]",
    )?)?;
    let backup_filename = format!("fulgurant_backup_{timestamp}.db");
    let backup_path = backup_folder.join(&backup_filename);
    tracing::info!("Starting database backup to {}", backup_path.display());
    vacuum_into_atomically(pool, &backup_path).await?;
    tracing::info!(
        "Database backup completed successfully: {}",
        backup_path.display()
    );
    Ok(backup_path)
}

/// Create a background task that performs daily database backups.
/// Only supported for `SQLite`. `PostgreSQL` users should use `pg_dump` instead.
///
/// ### Arguments
/// - `pool`: The database pool
/// - `shutdown_token`: Token to signal graceful shutdown
/// - `is_prod`: If true, performs final backup on shutdown (production). If false, skips final backup (development).
///
/// ### Returns
/// - `Some(JoinHandle)`: Handle to pass to `wait_for_backup_task` once the server has stopped
/// - `None`: If backups are disabled or the backend is `PostgreSQL`
pub fn make_daily_backup_task(
    pool: DbPool,
    shutdown_token: CancellationToken,
    is_prod: bool,
) -> Option<JoinHandle<()>> {
    if pool.backend() == DbBackend::Postgres {
        tracing::info!("PostgreSQL detected - built-in backup disabled (use pg_dump)");
        return None;
    }
    if !is_daily_backup_enabled() {
        tracing::info!("Daily database backups are disabled");
        return None;
    }
    let sqlite_pool = match pool {
        DbPool::Sqlite(p) => p,
        DbPool::Postgres(_) => unreachable!(),
    };
    let backup_folder = get_backup_folder();
    tracing::info!(
        "Starting daily database backup task (runs every 24 hours, backups stored in {})",
        backup_folder.display()
    );
    Some(tokio::spawn(run_backup_loop(
        sqlite_pool,
        backup_folder,
        shutdown_token,
        is_prod,
    )))
}

/// Run a backup every 24 hours until shutdown, then a final one in production
///
/// ### Arguments
/// - `pool`: The `SQLite` connection pool
/// - `backup_folder`: Folder receiving the backups
/// - `shutdown_token`: Token to signal graceful shutdown
/// - `is_prod`: If true, performs final backup on shutdown (production). If false, skips final backup (development).
async fn run_backup_loop(
    pool: SqlitePool,
    backup_folder: PathBuf,
    shutdown_token: CancellationToken,
    is_prod: bool,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(86400)); // 24 hours
    loop {
        tokio::select! {
            _ = interval.tick() => {
                match perform_backup(&pool, &backup_folder).await {
                    Ok(backup_path) => {
                        tracing::info!("Daily backup created: {}", backup_path.display());
                    }
                    Err(e) => {
                        tracing::error!("Failed to create daily backup: {:?}", e);
                    }
                }
            },
            () = shutdown_token.cancelled() => {
                if is_prod {
                    tracing::info!("Database backup task shutting down - performing final backup");
                    match perform_backup(&pool, &backup_folder).await {
                        Ok(backup_path) => {
                            tracing::info!("Final shutdown backup created: {}", backup_path.display());
                        }
                        Err(e) => {
                            tracing::error!("Failed to create final shutdown backup: {:?}", e);
                        }
                    }
                } else {
                    tracing::debug!("Database backup task shutting down (dev mode - skipping final backup)");
                }
                break;
            }
        }
    }
}

/// Wait for the backup task to finish, so the process does not exit in the middle of a backup
///
/// If the timeout expires the task is abandoned. Its `.partial` file may remain, but no
/// truncated file ever carries the final backup name.
///
/// ### Arguments
/// - `backup_task`: Handle returned by `make_daily_backup_task`
/// - `timeout`: Maximum time to wait
pub async fn wait_for_backup_task(backup_task: Option<JoinHandle<()>>, timeout: Duration) {
    let Some(backup_task) = backup_task else {
        return;
    };
    match tokio::time::timeout(timeout, backup_task).await {
        Ok(Ok(())) => tracing::debug!("Database backup task finished"),
        Ok(Err(e)) => tracing::error!("Database backup task failed: {:?}", e),
        Err(_) => tracing::warn!(
            "Database backup still running after {} seconds, exiting without waiting for it",
            timeout.as_secs()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Temporary folder removed on drop, including when a test panics
    struct TestFolder(PathBuf);

    impl TestFolder {
        /// Create a uniquely named folder under the system temp directory
        ///
        /// ### Arguments
        /// - `suffix`: Text appended to the folder name
        fn new(suffix: &str) -> Self {
            let name = format!("fulgurant_backup_test_{}{suffix}", uuid::Uuid::new_v4());
            let path = std::env::temp_dir().join(name);
            std::fs::create_dir_all(&path).expect("failed to create test folder");
            Self(path)
        }

        /// List the names of the files in the folder
        fn file_names(&self) -> Vec<String> {
            std::fs::read_dir(&self.0)
                .expect("failed to read test folder")
                .map(|entry| {
                    entry
                        .expect("failed to read folder entry")
                        .file_name()
                        .to_string_lossy()
                        .into_owned()
                })
                .collect()
        }
    }

    impl Drop for TestFolder {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Create a file-backed WAL database holding one known row, configured like production
    ///
    /// The source cannot be `sqlite::memory:`: `ATTACH` inherits `SQLITE_OPEN_MEMORY` from the
    /// connection, so `VACUUM INTO` would report success without writing any file.
    ///
    /// ### Returns
    /// - `(SqlitePool, TestFolder)`: The pool and the folder holding its database file
    async fn seeded_pool() -> (SqlitePool, TestFolder) {
        let database_folder = TestFolder::new("_source");
        let options = SqliteConnectOptions::new()
            .filename(database_folder.0.join("source.db"))
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .expect("failed to create pool");
        sqlx::query("CREATE TABLE sample (value TEXT NOT NULL)")
            .execute(&pool)
            .await
            .expect("failed to create table");
        sqlx::query("INSERT INTO sample (value) VALUES ('kept')")
            .execute(&pool)
            .await
            .expect("failed to insert row");
        (pool, database_folder)
    }

    /// Open a backup file and read back the row written by `seeded_pool`
    ///
    /// ### Arguments
    /// - `backup_path`: Path to the backup file
    ///
    /// ### Returns
    /// - `String`: The value stored in the backup
    async fn read_seeded_value(backup_path: &Path) -> String {
        let options = SqliteConnectOptions::new()
            .filename(backup_path)
            .read_only(true);
        let backup_pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .expect("failed to open backup");
        let (value,): (String,) = sqlx::query_as("SELECT value FROM sample")
            .fetch_one(&backup_pool)
            .await
            .expect("failed to read backup");
        backup_pool.close().await;
        value
    }

    #[tokio::test]
    async fn test_perform_backup_publishes_complete_file_without_partial() {
        let folder = TestFolder::new("");
        let (pool, _database_folder) = seeded_pool().await;

        let backup_path = perform_backup(&pool, &folder.0)
            .await
            .expect("backup should succeed");

        let file_name = backup_path
            .file_name()
            .expect("backup should have a file name")
            .to_string_lossy()
            .into_owned();
        assert_eq!(folder.file_names(), vec![file_name]);
        assert_eq!(read_seeded_value(&backup_path).await, "kept");
    }

    #[tokio::test]
    async fn test_failed_vacuum_never_publishes_final_file() {
        let folder = TestFolder::new("");
        let (pool, _database_folder) = seeded_pool().await;
        let backup_path = folder.0.join("fulgurant_backup_test.db");
        std::fs::write(
            backup_path.with_added_extension("partial"),
            "truncated leftover",
        )
        .expect("failed to write leftover");

        let result = vacuum_into_atomically(&pool, &backup_path).await;

        assert!(result.is_err(), "VACUUM INTO must reject a non-empty file");
        assert_eq!(folder.file_names(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn test_perform_backup_rejects_folder_with_single_quote() {
        let folder = TestFolder::new("'; DROP TABLE sample; --");
        let (pool, _database_folder) = seeded_pool().await;

        let result = perform_backup(&pool, &folder.0).await;

        assert!(result.is_err());
        assert_eq!(folder.file_names(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn test_backup_loop_finishes_final_backup_before_returning() {
        let folder = TestFolder::new("");
        let (pool, _database_folder) = seeded_pool().await;
        let shutdown_token = CancellationToken::new();
        shutdown_token.cancel();

        run_backup_loop(pool, folder.0.clone(), shutdown_token, true).await;

        let file_names = folder.file_names();
        assert!(!file_names.is_empty(), "final backup should exist");
        for file_name in file_names {
            let extension = Path::new(&file_name).extension();
            assert_eq!(extension, Some("db".as_ref()), "unexpected {file_name}");
            assert_eq!(read_seeded_value(&folder.0.join(file_name)).await, "kept");
        }
    }

    #[tokio::test]
    async fn test_wait_for_backup_task_waits_until_task_finishes() {
        let finished = Arc::new(AtomicBool::new(false));
        let finished_in_task = finished.clone();
        let backup_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            finished_in_task.store(true, Ordering::SeqCst);
        });

        wait_for_backup_task(Some(backup_task), Duration::from_secs(30)).await;

        assert!(finished.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_wait_for_backup_task_gives_up_after_timeout() {
        let backup_task = tokio::spawn(std::future::pending::<()>());

        tokio::time::timeout(
            Duration::from_secs(30),
            wait_for_backup_task(Some(backup_task), Duration::from_millis(10)),
        )
        .await
        .expect("wait should stop at its own timeout");
    }

    #[tokio::test]
    async fn test_wait_for_backup_task_returns_when_backups_are_disabled() {
        wait_for_backup_task(None, Duration::from_secs(30)).await;
    }

    #[test]
    fn test_validate_backup_path_rejects_single_quote() {
        let malicious_path = "backups'; DROP TABLE users; --/backup.db";
        let result = validate_backup_path(malicious_path);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("single quote character")
        );
    }

    #[test]
    fn test_validate_backup_path_allows_safe_paths() {
        let safe_paths = vec![
            "backups/fulgurant_backup_2026-02-15_12-00-00.db",
            "/var/backups/fulgurant.db",
            "./backups/test.db",
            "../backups/backup.db",
            "C:\\backups\\fulgurant.db",
        ];

        for path in safe_paths {
            let result = validate_backup_path(path);
            assert!(
                result.is_ok(),
                "Path '{path}' should be valid but was rejected"
            );
        }
    }

    #[test]
    fn test_validate_backup_path_rejects_sql_injection_attempts() {
        let injection_attempts = vec![
            "'; DELETE FROM users; --",
            "backup'; DROP TABLE devices; --",
            "test' OR '1'='1",
        ];

        for path in injection_attempts {
            let result = validate_backup_path(path);
            assert!(
                result.is_err(),
                "Injection attempt '{path}' should be rejected"
            );
        }
    }
}
