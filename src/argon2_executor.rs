use std::num::NonZeroUsize;
use std::sync::{Arc, LazyLock};
use tokio::sync::Semaphore;

/// Limits concurrent Argon2 operations to the available CPU parallelism.
///
/// Each operation allocates 19 MiB and keeps a core busy for tens of milliseconds, so running
/// more of them at once than there are cores only adds memory pressure without finishing sooner.
static ARGON2_PERMITS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| {
    let permits = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
    Arc::new(Semaphore::new(permits))
});

/// Run a CPU-bound Argon2 operation on the blocking thread pool.
///
/// Keeps async worker threads free to serve other requests and SSE heartbeats while hashing.
/// The concurrency permit is moved into the blocking task, so it is only released once the
/// work actually finishes, even if the calling future is dropped (e.g. client disconnect).
///
/// ### Arguments
/// - `work`: The synchronous Argon2 operation to run
///
/// ### Returns
/// - `T`: The value returned by `work`. A panic inside `work` is propagated to the caller.
pub async fn run_argon2<F, T>(work: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let permit = Arc::clone(&ARGON2_PERMITS)
        .acquire_owned()
        .await
        .expect("the Argon2 semaphore is never closed");
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    });
    match task.await {
        Ok(output) => output,
        Err(join_error) if join_error.is_panic() => {
            std::panic::resume_unwind(join_error.into_panic())
        }
        Err(join_error) => panic!("Argon2 task was cancelled: {join_error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_run_argon2_returns_work_output() {
        assert_eq!(run_argon2(|| 21 * 2).await, 42);
    }

    #[tokio::test]
    #[should_panic(expected = "boom")]
    async fn test_run_argon2_propagates_panic() {
        run_argon2(|| panic!("boom")).await;
    }
}
