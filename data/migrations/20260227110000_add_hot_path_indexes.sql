-- Add hot-path indexes for device ownership and verification code lookups.
-- These indexes target the most frequent WHERE clauses in repositories.

-- Speeds up:
-- - SELECT * FROM devices WHERE user_id = ?
-- - SELECT COUNT(*) FROM devices WHERE user_id = ?
CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);

-- Speeds up:
-- - SELECT * FROM verification_codes
--   WHERE email = ? AND purpose = ? AND verified_at IS NULL
-- - SELECT COUNT(*) FROM verification_codes
--   WHERE email = ? AND purpose = ? AND expires_at > ?
CREATE INDEX IF NOT EXISTS idx_verification_codes_lookup
ON verification_codes(email, purpose, verified_at, expires_at);

-- Speeds up:
-- - DELETE FROM verification_codes WHERE expires_at < ?
CREATE INDEX IF NOT EXISTS idx_verification_codes_expires_at
ON verification_codes(expires_at);
