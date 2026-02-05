-- Add force_password_update flag to users table
-- When true, user must change password before accessing any other page
ALTER TABLE users ADD COLUMN force_password_update BOOLEAN NOT NULL DEFAULT FALSE;
