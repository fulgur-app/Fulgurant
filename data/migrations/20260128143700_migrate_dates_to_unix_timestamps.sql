-- Migration: Convert all date columns from TEXT/DATETIME to INTEGER Unix timestamps
-- This migration converts 13 date columns across 4 tables to Unix timestamps (seconds since epoch)
-- Strategy: Drop triggers first, then add temporary columns, convert data, drop old columns, rename temporary columns, recreate triggers
-- Note: SQLx automatically wraps migrations in transactions, so no explicit BEGIN/COMMIT needed

-- ============================================================================
-- STEP 1: Drop triggers that reference the columns we're about to modify
-- ============================================================================

DROP TRIGGER IF EXISTS trg_users_set_updated_at_after_update;
DROP TRIGGER IF EXISTS trg_devices_set_updated_at_after_update;

-- ============================================================================
-- TABLE: users (3 columns: created_at, updated_at, last_activity)
-- ============================================================================

-- Add temporary timestamp columns (no default, will be populated immediately)
ALTER TABLE users ADD COLUMN created_at_ts INTEGER;
ALTER TABLE users ADD COLUMN updated_at_ts INTEGER;
ALTER TABLE users ADD COLUMN last_activity_ts INTEGER;

-- Convert existing data
UPDATE users SET created_at_ts = unixepoch(created_at);
UPDATE users SET updated_at_ts = unixepoch(updated_at);
UPDATE users SET last_activity_ts = unixepoch(last_activity);

-- Drop old columns
ALTER TABLE users DROP COLUMN created_at;
ALTER TABLE users DROP COLUMN updated_at;
ALTER TABLE users DROP COLUMN last_activity;

-- Rename temporary columns to original names
ALTER TABLE users RENAME COLUMN created_at_ts TO created_at;
ALTER TABLE users RENAME COLUMN updated_at_ts TO updated_at;
ALTER TABLE users RENAME COLUMN last_activity_ts TO last_activity;

-- ============================================================================
-- TABLE: devices (3 columns: created_at, updated_at, expires_at)
-- ============================================================================

-- Drop index before modifying column
DROP INDEX IF EXISTS idx_api_keys_expires;

-- Add temporary timestamp columns
ALTER TABLE devices ADD COLUMN created_at_ts INTEGER;
ALTER TABLE devices ADD COLUMN updated_at_ts INTEGER;
ALTER TABLE devices ADD COLUMN expires_at_ts INTEGER;

-- Convert existing data (expires_at is nullable)
UPDATE devices SET created_at_ts = unixepoch(created_at);
UPDATE devices SET updated_at_ts = unixepoch(updated_at);
UPDATE devices SET expires_at_ts = unixepoch(expires_at) WHERE expires_at IS NOT NULL;

-- Drop old columns
ALTER TABLE devices DROP COLUMN created_at;
ALTER TABLE devices DROP COLUMN updated_at;
ALTER TABLE devices DROP COLUMN expires_at;

-- Rename temporary columns to original names
ALTER TABLE devices RENAME COLUMN created_at_ts TO created_at;
ALTER TABLE devices RENAME COLUMN updated_at_ts TO updated_at;
ALTER TABLE devices RENAME COLUMN expires_at_ts TO expires_at;

-- Recreate index on expires_at
CREATE INDEX idx_api_keys_expires ON devices(expires_at);

-- ============================================================================
-- TABLE: verification_codes (3 columns: created_at, expires_at, verified_at)
-- ============================================================================

-- Add temporary timestamp columns
ALTER TABLE verification_codes ADD COLUMN created_at_ts INTEGER;
ALTER TABLE verification_codes ADD COLUMN expires_at_ts INTEGER;
ALTER TABLE verification_codes ADD COLUMN verified_at_ts INTEGER;

-- Convert existing data (verified_at is nullable)
UPDATE verification_codes SET created_at_ts = unixepoch(created_at);
UPDATE verification_codes SET expires_at_ts = unixepoch(expires_at);
UPDATE verification_codes SET verified_at_ts = unixepoch(verified_at) WHERE verified_at IS NOT NULL;

-- Drop old columns
ALTER TABLE verification_codes DROP COLUMN created_at;
ALTER TABLE verification_codes DROP COLUMN expires_at;
ALTER TABLE verification_codes DROP COLUMN verified_at;

-- Rename temporary columns to original names
ALTER TABLE verification_codes RENAME COLUMN created_at_ts TO created_at;
ALTER TABLE verification_codes RENAME COLUMN expires_at_ts TO expires_at;
ALTER TABLE verification_codes RENAME COLUMN verified_at_ts TO verified_at;

-- ============================================================================
-- TABLE: shares (2 columns: created_at, expires_at)
-- ============================================================================

-- Drop index before modifying column
DROP INDEX IF EXISTS idx_shares_expires_at;

-- Add temporary timestamp columns
ALTER TABLE shares ADD COLUMN created_at_ts INTEGER;
ALTER TABLE shares ADD COLUMN expires_at_ts INTEGER;

-- Convert existing data
UPDATE shares SET created_at_ts = unixepoch(created_at);
UPDATE shares SET expires_at_ts = unixepoch(expires_at);

-- Drop old columns
ALTER TABLE shares DROP COLUMN created_at;
ALTER TABLE shares DROP COLUMN expires_at;

-- Rename temporary columns to original names
ALTER TABLE shares RENAME COLUMN created_at_ts TO created_at;
ALTER TABLE shares RENAME COLUMN expires_at_ts TO expires_at;

-- Recreate index on expires_at
CREATE INDEX idx_shares_expires_at ON shares(expires_at);

-- ============================================================================
-- STEP 2: Recreate triggers with Unix timestamp functions
-- ============================================================================

-- Recreate users trigger with Unix timestamp
CREATE TRIGGER trg_users_set_updated_at_after_update
AFTER UPDATE ON users
FOR EACH ROW
BEGIN
    UPDATE users SET updated_at = unixepoch('now') WHERE id = NEW.id;
END;

-- Recreate devices trigger with Unix timestamp
CREATE TRIGGER trg_devices_set_updated_at_after_update
AFTER UPDATE ON devices
FOR EACH ROW
BEGIN
    UPDATE devices SET updated_at = unixepoch('now') WHERE device_id = NEW.device_id;
END;
