-- Add server_settings singleton table for admin-configurable runtime settings.
-- id is constrained to 1 to enforce singleton semantics.
-- max_file_size_bytes = NULL means no limit on share file size.
CREATE TABLE IF NOT EXISTS server_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    max_file_size_bytes INTEGER
);

INSERT OR IGNORE INTO server_settings (id, max_file_size_bytes) VALUES (1, 1048576);
