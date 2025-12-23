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
    expires_at DATETIME NOT NULL,  -- created_at + validity days (3 days default)
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (source_device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

-- Index for listing shares by user
CREATE INDEX IF NOT EXISTS idx_shares_user_id ON shares(user_id);

-- Index for deduplication (finding existing shares by hash)
CREATE INDEX IF NOT EXISTS idx_shares_file_hash ON shares(file_hash);

-- Index for cleanup expired shares
CREATE INDEX IF NOT EXISTS idx_shares_expires_at ON shares(expires_at);

-- Index for finding shares from a specific device
CREATE INDEX IF NOT EXISTS idx_shares_source_device ON shares(source_device_id);

-- Composite index for finding shares by user and hash (common query for deduplication)
CREATE INDEX IF NOT EXISTS idx_shares_user_hash ON shares(user_id, file_hash);
