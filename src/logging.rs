use std::path::PathBuf;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Gets the log folder path from environment variable or uses default
///
/// ### Returns
/// * `PathBuf`: The path to the log folder.
pub fn get_log_folder() -> PathBuf {
    std::env::var("LOG_FOLDER")
        .unwrap_or_else(|_| "logs".to_string())
        .into()
}

/// Initializes the logging system with file and console output
///
/// ### Description
/// - Creates a new log file per day (format: fulgur.log.YYYY-MM-DD)
/// - Appends to existing file if restarting on the same day
/// - In development mode: logs to both file and stdout with pretty formatting
/// - In production mode: logs to file only with compact formatting
/// - Respects RUST_LOG environment variable for filtering
///
/// ### Arguments
/// * `log_folder`: Path to the folder where log files will be stored
/// * `is_prod`: If true, only logs to file. If false, logs to both file and console
///
/// ### Returns
/// * `Some(WorkerGuard)`: A guard  for a non blocking writerthat must be kept alive for the duration of the program. Dropping the guard will cause buffered logs to be flushed and the worker to stop.
/// * `None`: An error occurred while initializing the logging system.
pub fn init_logging(log_folder: PathBuf, is_prod: bool) -> anyhow::Result<WorkerGuard> {
    std::fs::create_dir_all(&log_folder)?;
    let file_appender = tracing_appender::rolling::daily(log_folder, "fulgur.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        if is_prod {
            EnvFilter::new("info")
        } else {
            EnvFilter::new("debug")
        }
    });
    let file_layer = fmt::layer()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_target(true);

    if is_prod {
        // Production: Only log to file
        tracing_subscriber::registry()
            .with(env_filter)
            .with(file_layer)
            .init();
    } else {
        // Development: Log to both file and console
        let console_layer = fmt::layer().with_writer(std::io::stdout).with_target(true);
        tracing_subscriber::registry()
            .with(env_filter)
            .with(file_layer)
            .with(console_layer)
            .init();
    }
    Ok(guard)
}
