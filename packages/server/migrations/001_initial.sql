-- Initial schema, per design doc section 5.
-- Applied files must never be edited; add a new numbered file instead.

CREATE TABLE users (
  user_id          text PRIMARY KEY,
  identity_pubkey  bytea NOT NULL CHECK (octet_length(identity_pubkey) = 32),
  exchange_pubkey  bytea NOT NULL CHECK (octet_length(exchange_pubkey) = 32),
  created_at       timestamptz NOT NULL DEFAULT now()
);

-- Ciphertext is an opaque blob. Rows are deleted on ack, so the server
-- holds ciphertext only during the delivery window.
CREATE TABLE messages (
  message_id   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  from_user_id text NOT NULL REFERENCES users (user_id),
  to_user_id   text NOT NULL REFERENCES users (user_id),
  nonce        bytea NOT NULL CHECK (octet_length(nonce) = 24),
  ciphertext   bytea NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz
);

-- Inbox lookup: messages for one recipient, oldest first.
CREATE INDEX messages_to_user_id_created_at_idx ON messages (to_user_id, created_at);

-- Request-signing nonces. The primary key rejects replays; rows are swept
-- after expires_at.
CREATE TABLE auth_nonces (
  nonce      text PRIMARY KEY,
  user_id    text NOT NULL,
  expires_at timestamptz NOT NULL
);

CREATE INDEX auth_nonces_expires_at_idx ON auth_nonces (expires_at);
