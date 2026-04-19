# Contributing to Fulgurant

Thank you for your interest in contributing to Fulgurant. This guide covers the essentials: how to build the project, what quality checks are required, and the conventions the codebase follows.

---

## Table of Contents

- [Prerequisites and Building](#prerequisites-and-building)
- [Required Checks Before Submitting](#required-checks-before-submitting)
- [Code Style](#code-style)
- [Documentation](#documentation)
- [Error Handling](#error-handling)
- [Logging](#logging)
- [Tests](#tests)
- [Database Migrations](#database-migrations)
- [Use of AI / LLM Tools](#use-of-ai--llm-tools)
- [Branch Naming](#branch-naming)
- [Commit Messages](#commit-messages)
- [Submitting a Pull Request](#submitting-a-pull-request)

---

## Prerequisites and Building

See the [Build and Run section in README.md](README.md#build-and-run) for prerequisites (Rust version, environment setup) and build commands. That document is the authoritative and up-to-date reference.

**Database**: Copy `.env.example` to `.env` before running. The server auto-detects SQLite or PostgreSQL from `DATABASE_URL`. For PostgreSQL development: `docker compose -f docker-compose.pg.yml up -d`.

---

## Required Checks Before Submitting

Every contribution must pass these three checks, **in order**. Fix each failure before moving to the next.

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

These are enforced by CI. A PR that fails any of them will not be reviewed.

---

## Code Style

- **Language**: All code, comments, variable names, commit messages, and documentation must be in English.
- **Formatting**: Enforced by `rustfmt`. Run `cargo fmt --all` to auto-format before checking.
- **No emojis**: In source code, documentation, or commit messages.
- **Self-documenting code**: Prefer clear, explicit naming over comments. A comment explaining *what* the code does is a sign the code should be renamed or restructured. Only add a comment when the *why* is non-obvious: a hidden constraint, a workaround for a known upstream bug, or a subtle invariant.
- **No over-engineering**: Implement what the task requires. Do not add abstractions, fallbacks, or features for hypothetical future needs.
- **Avoid `unsafe`**: Avoiding `unsafe` is preferred. If `unsafe` is unavoidable, minimize its scope and document why it is necessary.
- **Error handling**: Use `Result` and `Option` for error handling. No `unwrap`, `expect`, or `panic!` in production paths. Use the `AppError` enum in `errors.rs` for handler errors; use `anyhow` for background tasks and utilities.
- **Avoid duplicated code**: If you find yourself copying and pasting code, consider refactoring into a shared function or macro.

---

## Documentation

Every public function and non-trivial private function must have a documentation comment using Rust's `///` syntax with the following structure:

```rust
/// Short summary line
/// 
/// ### Description
/// Optional, only when the summary alone is not enough to understand the behavior.
///
/// ### Arguments
/// - `arg_name`: What it is and any constraints
///
/// ### Returns
/// - `Ok(T)`: What success looks like
/// - `Err(E)`: What can fail and why
pub async fn create_share(request: CreateShareRequest) -> Result<Share, AppError> {
    ...
}
```

Omit `### Description`, `### Arguments` or `### Returns` when they add no information (e.g. a function with no arguments, or one whose name and return type are self-explanatory). Do not describe the implementation, only describe the contract.

---

## Error Handling

Use the `AppError` enum (defined in `errors.rs`) for all Axum handler errors. It converts automatically to HTTP responses via `IntoResponse`.

For background tasks and utility functions, wrap errors with context using `anyhow`. Always include the underlying error to preserve diagnostic detail:

```rust
// Correct
serde_json::from_str(&raw).map_err(|e| anyhow!("failed to parse config: {}", e))?;

// Wrong — loses the underlying error message
serde_json::from_str(&raw).map_err(|_| anyhow!("failed to parse config"))?;
```

---

## Logging

Use `tracing` macros exclusively. Never use `println!` or `eprintln!` in application code.

```rust
tracing::info!("server started on {}", addr);
tracing::warn!("share expired before download: {}", share_id);
tracing::error!("failed to send email: {}", err);
```

The only exception is bootstrap code that runs before the logger is initialized (before `init_logging()` is called in `main.rs`), where `eprintln!` is acceptable.

---

## Tests

Unit tests live inline in their source file using `#[cfg(test)]` modules. Integration tests may be added in the `tests/` directory.

Guidelines:

- Use an in-memory SQLite database for unit tests requiring a database. Do not write test data to fixed paths.
- Do not mock the database in tests. Use real queries against an in-memory SQLite instance.
- Tests should be deterministic and side-effect free. Do not depend on external services (SMTP, network).
- Except for platform-specific features, tests should run on all platforms.
- For seeding a development database, use `cargo run --bin seed_users` (creates 10 users, password: `Password123!`).

---

## Branch Naming

All contribution branches must follow the pattern:

```
dev-<short-description>
```

Use lowercase kebab-case for the description. Keep it short but specific enough to identify the work.

```
dev-admin-user-creation
dev-share-expiry-config
dev-fix-sse-reconnect
dev-perf-token-endpoint
```

Do not use `feature/`, `fix/`, or other prefixes. The `dev-` prefix is the project convention.

---

## Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification. The format is:

```
<type>(<scope>): <description>
```

**Types:**

| Type | When to use |
|---|---|
| `feat` | New feature or behavior |
| `fix` | Bug fix |
| `perf` | Performance improvement |
| `refactor` | Code restructuring without behavior change |
| `test` | Adding or updating tests |
| `chore` | Build scripts, version bumps, config changes |
| `docs` | Documentation only |

**Scope** is optional but recommended. Use the module or area affected, in kebab-case:

```
feat(admin): add configurable maximum share file size
fix(auth): prevent session fixation on password reset
perf(api): add SHA256 fast hash index for device lookup
chore(docker): update docker-compose example
```

**Description rules:**
- Lowercase, no trailing period
- Imperative mood ("add", "fix", "remove") not past tense ("added", "fixed")
- Under 72 characters for the subject line
- For non-obvious changes, add a body after a blank line explaining the *why*, not the *what*

---

## Database Migrations

> **Any PR that modifies the database schema without the corresponding migration files will be automatically refused, without review.**

Fulgurant supports two database backends, SQLite and PostgreSQL,and both must remain in sync at all times. Schema changes must never be applied directly to the database structs or queries without a corresponding migration.

### Rules

- Every schema change (new table, new column, dropped column, new index, new trigger) requires a migration file.
- Migrations must be created for **both** backends:
  - SQLite: `data/migrations/`
  - PostgreSQL: `data/migrations_postgres/`
- Migration filenames follow the timestamp convention: `YYYYMMDDHHMMSS_short_description.sql`
- Migrations are applied automatically on server startup and must be **non-destructive** and **idempotent** where possible (use `IF NOT EXISTS`, `IF EXISTS`).
- Never edit an existing migration file. If a previous migration was wrong, write a new one that corrects it.

### SQL Dialect Differences

SQLite and PostgreSQL have different SQL syntax. Key differences to handle in both files:

| Feature | SQLite | PostgreSQL |
|---|---|---|
| Current timestamp | `unixepoch('now')` | `NOW()` |
| Timestamp column type | `INTEGER` | `TIMESTAMPTZ` |
| Binding a timestamp | bind `i64` directly | wrap with `to_timestamp($N)` |
| Auto-increment | `INTEGER PRIMARY KEY` | `SERIAL PRIMARY KEY` |
| Last inserted ID | `last_insert_rowid()` | `RETURNING id` |
| Boolean | `INTEGER` (0/1) | `BOOLEAN` |

When the SQL differs between backends, use the `_dual` macro variants in Rust (`db_execute_dual!`, `db_fetch_one_dual!`, etc.). When the SQL is identical, use the single-SQL variants (`db_execute!`, `db_fetch_one!`, etc.).

### Migration Checklist

Before opening a PR with a schema change:

- [ ] Migration file created in `data/migrations/` (SQLite)
- [ ] Migration file created in `data/migrations_postgres/` (PostgreSQL)
- [ ] Both files have the same timestamp prefix and description
- [ ] New queries use the appropriate `db_*` dispatch macro
- [ ] Server starts cleanly from a fresh database with the new migration
- [ ] Server starts cleanly from an existing database (migration applied incrementally)

---

## Use of AI / LLM Tools

You are welcome to use AI assistants (e.g. Claude, Copilot, ChatGPT) during development. However, all LLM-generated code must be reviewed, understood, and validated by the developer before being submitted. Submitting code you cannot explain or defend is not acceptable.

In practice this means:

- Run all [required checks](#required-checks-before-submitting) on the generated code, as you would for any other code.
- Verify that generated code follows the conventions in this document (naming, error handling, documentation, logging).
- Do not submit generated code verbatim if it introduces patterns inconsistent with the rest of the codebase.

You are the author of what you submit, regardless of how it was produced. Low effort slop will not be tolerated and may result in a ban.

---

## Submitting a Pull Request

1. Fork the repository and create a branch from `main`.
2. Make your changes following the conventions above.
3. Run the [required checks](#required-checks-before-submitting) and fix any failures.
4. Open a pull request with a clear title and a description of what changed and why.
5. Link any relevant issue in the PR description.

For significant changes, open an issue first to discuss the approach before investing time in an implementation.
