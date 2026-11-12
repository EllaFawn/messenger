-- Each user's exchange key must be signed by their identity key, so that a
-- client holding the right userID can verify the exchange key and the server
-- cannot substitute its own.
--
-- Accounts created before this have no signature, and only the holder of the
-- identity private key can make one, so they cannot be upgraded in place.
-- This is pre-release software with no real users: existing accounts and
-- their undelivered messages are removed and must be registered again.
DELETE FROM messages;
DELETE FROM auth_nonces;
DELETE FROM users;

ALTER TABLE users
  ADD COLUMN exchange_sig bytea NOT NULL CHECK (octet_length(exchange_sig) = 64);
