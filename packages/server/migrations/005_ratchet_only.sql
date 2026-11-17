-- Forward secrecy, the clean break (M2 design, section 5.7).
--
-- Every account now has a ratchet key and every message is a ratchet
-- message. A static-key account cannot be converted without its private
-- key, and this is pre-release software with no real users: existing
-- accounts, their keys and their undelivered messages are removed and must
-- be registered again. Browsers keep their identity key, so userIDs stay
-- the same. Invites are kept; "used_by" is cleared by its foreign key.
DELETE FROM messages;
DELETE FROM auth_nonces;
DELETE FROM one_time_keys;
DELETE FROM users;

ALTER TABLE users
  DROP CONSTRAINT users_ratchet_key_and_sig_together,
  DROP COLUMN exchange_pubkey,
  DROP COLUMN exchange_sig,
  ALTER COLUMN ratchet_pubkey SET NOT NULL,
  ALTER COLUMN ratchet_sig SET NOT NULL;

-- The ratchet message carries everything it needs, so there is no separate
-- nonce. The version column stays so a later format can be told apart.
ALTER TABLE messages
  DROP CONSTRAINT messages_shape_matches_version,
  DROP COLUMN nonce,
  ALTER COLUMN v SET DEFAULT 2,
  ALTER COLUMN msg_type SET NOT NULL,
  ADD CONSTRAINT messages_are_ratchet_messages CHECK (v = 2 AND msg_type IN (0, 1));
