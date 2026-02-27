-- Migration: Optimize updated_at triggers to only fire on meaningful column updates
-- This migration fixes the overly broad triggers that fire on ANY column update,
-- which causes unnecessary recursive UPDATE operations for tracking columns like
-- last_activity and shares.

-- ============================================================================
-- TABLE: users - Only fire on actual data changes, not tracking/counters
-- ============================================================================

DROP TRIGGER IF EXISTS trg_users_set_updated_at_after_update;

CREATE TRIGGER trg_users_set_updated_at_after_update
AFTER UPDATE OF email, first_name, last_name, email_verified, password_hash, role, encryption_key, force_password_update ON users
FOR EACH ROW
WHEN OLD.updated_at = NEW.updated_at
BEGIN
    UPDATE users SET updated_at = unixepoch('now') WHERE id = NEW.id;
END;

-- ============================================================================
-- TABLE: devices - Only fire on device configuration changes
-- ============================================================================

DROP TRIGGER IF EXISTS trg_devices_set_updated_at_after_update;

CREATE TRIGGER trg_devices_set_updated_at_after_update
AFTER UPDATE OF name, device_type, device_key, device_key_fast_hash, encryption_key ON devices
FOR EACH ROW
WHEN OLD.updated_at = NEW.updated_at
BEGIN
    UPDATE devices SET updated_at = unixepoch('now') WHERE device_id = NEW.device_id;
END;
