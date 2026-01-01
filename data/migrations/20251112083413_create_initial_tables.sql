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

-- Index for API keys expiration
CREATE INDEX idx_api_keys_expires ON devices(expires_at) WHERE expires_at IS NOT NULL;

-- Create verification codes table for email verification and password reset
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

-- Create shares table for file sharing between devices
CREATE TABLE IF NOT EXISTS shares (
    id TEXT PRIMARY KEY,  -- UUID v4
    user_id INTEGER NOT NULL,
    source_device_id TEXT NOT NULL,  -- UUID of source device
    destination_device_id TEXT NOT NULL,  -- UUID of destination device
    file_hash TEXT NOT NULL,  -- SHA256 hex (for deduplication)
    file_name TEXT NOT NULL,
    file_size INTEGER NOT NULL CHECK(file_size <= 1048576),  -- max 1 MB (1048576 bytes)
    content TEXT NOT NULL,  -- text file content
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,  -- created_at + validity days 
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (source_device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

-- Index for listing shares by user
CREATE INDEX IF NOT EXISTS idx_shares_user_id ON shares(user_id);

-- Index for cleanup expired shares
CREATE INDEX IF NOT EXISTS idx_shares_expires_at ON shares(expires_at);

-- Index for finding shares from a specific device
CREATE INDEX IF NOT EXISTS idx_shares_source_device ON shares(source_device_id);
