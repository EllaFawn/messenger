-- Per-person, single-use invites, created only by the operator from the
-- command line. Replaces the single shared INVITE_CODE setting.
--
-- Only the SHA-256 of a code is stored, so reading this table does not
-- reveal a usable code.
CREATE TABLE invites (
  code_hash   bytea PRIMARY KEY CHECK (octet_length(code_hash) = 32),
  note        text NOT NULL DEFAULT '',
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz,
  -- Kept as a record of who used it; cleared if that account is removed.
  used_by     text REFERENCES users (user_id) ON DELETE SET NULL
);
