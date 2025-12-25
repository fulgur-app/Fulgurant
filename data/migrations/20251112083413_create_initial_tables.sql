-- USERS table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    email_verified BOOLEAN DEFAULT FALSE,
    password_hash TEXT NOT NULL,
    encryption_key TEXT NOT NULL DEFAULT '', -- Base64-encoded 256-bit AES key for encrypting shared files
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- After update: automatically update updated_at unless it was explicitly changed
-- The WHEN clause prevents infinite loops by only firing when updated_at wasn't changed
-- Using INSERT OR REPLACE pattern to avoid recursive trigger issues
CREATE TRIGGER IF NOT EXISTS trg_users_set_updated_at_after_update
AFTER UPDATE OF first_name, last_name, email, email_verified, password_hash ON users
FOR EACH ROW
WHEN OLD.updated_at = NEW.updated_at
BEGIN
    UPDATE users
    SET updated_at = CURRENT_TIMESTAMP
    WHERE id = NEW.id;
END;


-- DEVICES table
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    device_id TEXT NOT NULL UNIQUE,  -- UUID v4 (public identifier)
    device_key TEXT NOT NULL UNIQUE,  -- Hashed API key (private)
    name TEXT NOT NULL,
    device_type TEXT NOT NULL,
    expires_at DATE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- After update: automatically update updated_at unless it was explicitly changed
-- The WHEN clause prevents infinite loops by only firing when updated_at wasn't changed
-- Using OF clause to only fire on specific column updates to avoid recursion
CREATE TRIGGER IF NOT EXISTS trg_devices_set_updated_at_after_update
AFTER UPDATE OF user_id, device_id, device_key, name, device_type, expires_at ON devices
FOR EACH ROW
WHEN OLD.updated_at = NEW.updated_at
BEGIN
    UPDATE devices
    SET updated_at = CURRENT_TIMESTAMP
    WHERE id = NEW.id;
END;

CREATE TABLE api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_name TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    expires_at DATETIME,
    last_used_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_api_keys_expires ON api_keys(expires_at) WHERE expires_at IS NOT NULL;

CREATE TABLE verification_codes (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    code_hash TEXT NOT NULL,  -- Hashed code for security!
    attempts INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    created_at TEXT DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    verified_at TEXT,
    purpose TEXT DEFAULT 'registration'
);