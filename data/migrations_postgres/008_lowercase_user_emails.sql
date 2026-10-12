-- Lowercase stored emails so they match the normalized address used by every lookup path.
-- Admin-created users previously kept their submitted casing and could never log in.
-- If two accounts differ only by case, the UNIQUE constraint on users.email aborts this
-- migration on purpose: resolve the duplicate manually before restarting the server.

UPDATE users SET email = lower(email) WHERE email <> lower(email);
