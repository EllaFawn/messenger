-- Forward secrecy, server side (M2 design, section 5.5). Additive: the
-- static-key (v1) columns and messages keep working until the client has
-- moved over, and a later migration removes them.

-- Each user's long-term ratchet key, signed by their identity key.
-- Nullable only until v1 is removed.
ALTER TABLE users
  ADD COLUMN ratchet_pubkey bytea CHECK (octet_length(ratchet_pubkey) = 32),
  ADD COLUMN ratchet_sig    bytea CHECK (octet_length(ratchet_sig) = 64),
  -- Raised each time the ratchet key is replaced (account restore).
  ADD COLUMN key_epoch      integer NOT NULL DEFAULT 1,
  ADD CONSTRAINT users_ratchet_key_and_sig_together
    CHECK ((ratchet_pubkey IS NULL) = (ratchet_sig IS NULL));

-- Signed one-time keys waiting to be claimed by someone starting a
-- conversation. A claimed key is deleted. The fallback key is handed out,
-- and kept, when the others have run out.
CREATE TABLE one_time_keys (
  user_id     text NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
  key_id      text NOT NULL CHECK (length(key_id) BETWEEN 1 AND 64),
  pubkey      bytea NOT NULL CHECK (octet_length(pubkey) = 32),
  sig         bytea NOT NULL CHECK (octet_length(sig) = 64),
  is_fallback boolean NOT NULL DEFAULT false,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, key_id)
);

-- At most one fallback key per user.
CREATE UNIQUE INDEX one_time_keys_one_fallback_idx ON one_time_keys (user_id) WHERE is_fallback;
-- Claiming takes the oldest non-fallback key.
CREATE INDEX one_time_keys_claim_idx ON one_time_keys (user_id, created_at) WHERE NOT is_fallback;

-- Ratchet (v2) messages carry their own nonce inside the ciphertext and
-- have a type: 0 pre-key, 1 normal.
ALTER TABLE messages
  ADD COLUMN v smallint NOT NULL DEFAULT 1,
  ADD COLUMN msg_type smallint,
  ALTER COLUMN nonce DROP NOT NULL,
  -- "IS NOT NULL" is spelled out because a CHECK passes when its result is
  -- unknown, and "msg_type IN (0, 1)" is unknown, not false, for a NULL.
  ADD CONSTRAINT messages_shape_matches_version CHECK (
    (v = 1 AND nonce IS NOT NULL AND msg_type IS NULL) OR
    (v = 2 AND nonce IS NULL AND msg_type IS NOT NULL AND msg_type IN (0, 1))
  );
