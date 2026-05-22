-- Persistent web sessions backed by the application database.
-- Replaces the in-memory tower-sessions store with a custom SessionStore
-- so sessions survive restarts and can be revoked per-user.
--
-- user_id is nullable because a session record may exist before the user
-- authenticates (e.g. CSRF token storage on the login page).
-- data holds the serialized tower-sessions record (serde_json) as a BLOB.
-- remember_me is hoisted into its own column so admin/user revocation flows
-- can list "remember me" sessions without deserializing every row.
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    data BLOB NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch('now')),
    user_agent TEXT,
    remember_me INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
