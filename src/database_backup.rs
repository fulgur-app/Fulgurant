use sqlx::SqlitePool;
use std::path::PathBuf;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

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
/// Since SQLite's VACUUM INTO doesn't support parameterized queries, we must
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

/// Perform a database backup using SQLite's VACUUM INTO command
///
/// ### Arguments
/// - `pool`: The SQLite connection pool
///
/// ### Returns
/// - `Ok(PathBuf)`: Path to the created backup file
/// - `Err(anyhow::Error)`: If backup fails
pub async fn perform_backup(pool: &SqlitePool) -> anyhow::Result<PathBuf> {
    let backup_folder = get_backup_folder();
    std::fs::create_dir_all(&backup_folder)?;
    let now = OffsetDateTime::now_utc();
    let timestamp = now.format(&time::format_description::parse(
        "[year]-[month]-[day]_[hour]-[minute]-[second]",
    )?)?;
    let backup_filename = format!("fulgurant_backup_{}.db", timestamp);
    let backup_path = backup_folder.join(&backup_filename);
    tracing::info!("Starting database backup to {}", backup_path.display());
    let backup_path_str = backup_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid backup path"))?;
    validate_backup_path(backup_path_str)?;
    let query = format!("VACUUM INTO '{}'", backup_path_str);
    sqlx::query(&query).execute(pool).await?;
    tracing::info!(
        "Database backup completed successfully: {}",
        backup_path.display()
    );
    Ok(backup_path)
}

/// Create a background task that performs daily database backups
///
/// ### Arguments
/// - `pool`: The SQLite connection pool
/// - `shutdown_token`: Token to signal graceful shutdown
/// - `is_prod`: If true, performs final backup on shutdown (production). If false, skips final backup (development).
pub fn make_daily_backup_task(pool: SqlitePool, shutdown_token: CancellationToken, is_prod: bool) {
    if !is_daily_backup_enabled() {
        tracing::info!("Daily database backups are disabled");
        return;
    }
    let backup_folder = get_backup_folder();
    tracing::info!(
        "Starting daily database backup task (runs every 24 hours, backups stored in {})",
        backup_folder.display()
    );
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(86400)); // 24 hours
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match perform_backup(&pool).await {
                        Ok(backup_path) => {
                            tracing::info!("Daily backup created: {}", backup_path.display());
                        }
                        Err(e) => {
                            tracing::error!("Failed to create daily backup: {:?}", e);
                        }
                    }
                },
                _ = shutdown_token.cancelled() => {
                    if is_prod {
                        tracing::info!("Database backup task shutting down - performing final backup");
                        match perform_backup(&pool).await {
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
    });
}

#[cfg(test)]
mod tests {
    use super::*;

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
                "Path '{}' should be valid but was rejected",
                path
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
                "Injection attempt '{}' should be rejected",
                path
            );
        }
    }
}
