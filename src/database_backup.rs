use sqlx::SqlitePool;
use std::path::PathBuf;
use time::OffsetDateTime;

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
pub fn make_daily_backup_task(pool: SqlitePool) {
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
            interval.tick().await;
            match perform_backup(&pool).await {
                Ok(backup_path) => {
                    tracing::info!("Daily backup created: {}", backup_path.display());
                }
                Err(e) => {
                    tracing::error!("Failed to create daily backup: {:?}", e);
                }
            }
        }
    });
}
