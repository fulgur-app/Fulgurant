//! Test database provisioning shared by the unit tests in `src/` and the integration tests in
//! `tests/`.
//!
//! The backend is selected by the `TEST_DATABASE_URL` environment variable:
//! - unset or not a `PostgreSQL` URL: a fresh in-memory `SQLite` database per call
//! - `postgres://...` or `postgresql://...`: a fresh schema (`test_<uuid>`) per call in that
//!   database, selected through `search_path`, so tests running in parallel never share tables
//!
//! `PostgreSQL` test schemas are not dropped afterwards. Point `TEST_DATABASE_URL` at a
//! throwaway database (CI uses an ephemeral service container), never at a real one.

use crate::db::{DbPool, POSTGRES_MIGRATOR, SQLITE_MIGRATOR, is_postgres_url};
use sqlx::postgres::{PgConnectOptions, PgConnection, PgPoolOptions};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{AssertSqlSafe, ConnectOptions, Connection};
use std::str::FromStr;

/// Environment variable selecting the database backend used by the tests
pub const TEST_DATABASE_URL_ENV: &str = "TEST_DATABASE_URL";

/// Upper bound of connections per `PostgreSQL` test pool, kept low because tests run in parallel
const POSTGRES_TEST_POOL_MAX_CONNECTIONS: u32 = 5;

/// Create an isolated, fully migrated database for one test
///
/// Panics on any failure: this is test infrastructure and a broken database must fail the test.
///
/// ### Returns
/// - `DbPool::Sqlite`: an in-memory database when `TEST_DATABASE_URL` is unset or not `PostgreSQL`
/// - `DbPool::Postgres`: a pool bound to a new private schema when `TEST_DATABASE_URL` is `PostgreSQL`
pub async fn connect_test_pool() -> DbPool {
    match std::env::var(TEST_DATABASE_URL_ENV) {
        Ok(url) if is_postgres_url(&url) => connect_postgres_test_schema(&url).await,
        _ => connect_sqlite_in_memory().await,
    }
}

/// Create a migrated in-memory `SQLite` database
///
/// A single connection is mandatory: every `sqlite::memory:` connection opens its own database.
///
/// ### Returns
/// - `DbPool::Sqlite`: the migrated in-memory database
async fn connect_sqlite_in_memory() -> DbPool {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("failed to open the in-memory SQLite test database");
    SQLITE_MIGRATOR
        .run(&pool)
        .await
        .expect("failed to run SQLite migrations on the test database");
    DbPool::Sqlite(pool)
}

/// Create a new schema in the `PostgreSQL` test database and a migrated pool bound to it
///
/// ### Arguments
/// - `url`: The `PostgreSQL` URL of the throwaway test database
///
/// ### Returns
/// - `DbPool::Postgres`: a pool whose connections all use the new schema as `search_path`
async fn connect_postgres_test_schema(url: &str) -> DbPool {
    let base_options = PgConnectOptions::from_str(url).expect("invalid TEST_DATABASE_URL");
    let schema = format!("test_{}", uuid::Uuid::new_v4().simple());

    let mut admin_connection = base_options
        .connect()
        .await
        .expect("failed to connect to the PostgreSQL test database");
    sqlx::query(AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
        .execute(&mut admin_connection)
        .await
        .expect("failed to create the PostgreSQL test schema");
    PgConnection::close(admin_connection)
        .await
        .expect("failed to close the PostgreSQL admin connection");

    let pool = PgPoolOptions::new()
        .max_connections(POSTGRES_TEST_POOL_MAX_CONNECTIONS)
        .connect_with(base_options.options([("search_path", schema.as_str())]))
        .await
        .expect("failed to connect to the PostgreSQL test schema");
    POSTGRES_MIGRATOR
        .run(&pool)
        .await
        .expect("failed to run PostgreSQL migrations on the test schema");
    DbPool::Postgres(pool)
}
