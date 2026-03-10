-- PostgreSQL consolidated schema
-- Equivalent to all SQLite migrations combined
-- Timestamps use TIMESTAMPTZ (maps to OffsetDateTime via sqlx)

-- ============================================================================
-- USERS
-- ============================================================================

CREATE TABLE users (
    id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    email_verified BOOLEAN DEFAULT FALSE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'User',
    encryption_key TEXT NOT NULL DEFAULT '',
    last_activity TIMESTAMPTZ DEFAULT NOW(),
    shares INTEGER DEFAULT 0,
    force_password_update BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE OR REPLACE FUNCTION trg_fn_users_set_updated_at() RETURNS TRIGGER AS $$
BEGIN
    IF OLD.updated_at = NEW.updated_at THEN
        NEW.updated_at = NOW();
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_users_set_updated_at_after_update
    BEFORE UPDATE OF email, first_name, last_name, email_verified, password_hash,
                      role, encryption_key, force_password_update
    ON users
    FOR EACH ROW
    EXECUTE FUNCTION trg_fn_users_set_updated_at();

-- ============================================================================
-- DEVICES
-- ============================================================================

CREATE TABLE devices (
    id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL UNIQUE,
    device_key TEXT NOT NULL UNIQUE,
    device_key_fast_hash TEXT,
    name TEXT NOT NULL,
    device_type TEXT NOT NULL,
    encryption_key TEXT,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_api_keys_expires ON devices(expires_at);
CREATE UNIQUE INDEX idx_devices_key_fast_hash ON devices(device_key_fast_hash)
    WHERE device_key_fast_hash IS NOT NULL;
CREATE INDEX idx_devices_user_id ON devices(user_id);

CREATE OR REPLACE FUNCTION trg_fn_devices_set_updated_at() RETURNS TRIGGER AS $$
BEGIN
    IF OLD.updated_at = NEW.updated_at THEN
        NEW.updated_at = NOW();
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_devices_set_updated_at_after_update
    BEFORE UPDATE OF name, device_type, device_key, device_key_fast_hash, encryption_key
    ON devices
    FOR EACH ROW
    EXECUTE FUNCTION trg_fn_devices_set_updated_at();

-- ============================================================================
-- VERIFICATION CODES
-- ============================================================================

CREATE TABLE verification_codes (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    attempts INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    verified_at TIMESTAMPTZ,
    purpose TEXT DEFAULT 'registration'
);

CREATE INDEX idx_verification_codes_lookup
    ON verification_codes(email, purpose, verified_at, expires_at);
CREATE INDEX idx_verification_codes_expires_at
    ON verification_codes(expires_at);

-- ============================================================================
-- SHARES
-- ============================================================================

CREATE TABLE shares (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    source_device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    destination_device_id TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_size INTEGER NOT NULL CHECK(file_size <= 1048576),
    content TEXT NOT NULL,
    deduplication_hash TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX idx_shares_dedup
    ON shares(source_device_id, destination_device_id, deduplication_hash);
CREATE INDEX idx_shares_user_id ON shares(user_id);
CREATE INDEX idx_shares_expires_at ON shares(expires_at);
CREATE INDEX idx_shares_destination_device ON shares(destination_device_id);
