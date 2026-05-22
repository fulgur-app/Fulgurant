-- Persistent web sessions backed by the application database.
-- Replaces the in-memory tower-sessions store with a custom SessionStore
-- so sessions survive restarts and can be revoked per-user.
--
-- user_id is nullable because a session record may exist before the user
-- authenticates (e.g. CSRF token storage on the login page).
-- data holds the serialized tower-sessions record (serde_json) as BYTEA.
-- expires_at is TIMESTAMPTZ; Rust binds i64 unix epoch values via to_timestamp().
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    data BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_agent TEXT,
    remember_me BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
