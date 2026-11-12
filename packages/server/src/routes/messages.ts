import { Router } from "express";
import {
  authenticatedUserId,
  requireSignedRequest,
  USER_ID_PATTERN,
  type AuthDeps,
} from "../auth/signed-request.js";

/** Standard base64 of exactly 24 bytes (an XChaCha20 nonce); no padding needed at that length. */
const MESSAGE_NONCE_PATTERN = /^[A-Za-z0-9+/]{32}$/;
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
/** A ciphertext always carries a 16-byte Poly1305 tag, so nothing shorter can be genuine. */
const MIN_CIPHERTEXT_BYTES = 16;

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Most messages returned by one inbox fetch. Acknowledging them brings the next ones into view. */
export const INBOX_PAGE_SIZE = 100;

interface IncomingEnvelope {
  to: string;
  nonce: Buffer;
  ciphertext: Buffer;
}

/** Decodes standard base64, accepting only the one canonical spelling of the bytes. */
function decodeStrictBase64(text: string): Buffer | null {
  if (!BASE64_PATTERN.test(text)) {
    return null;
  }
  const bytes = Buffer.from(text, "base64");
  return bytes.toString("base64") === text ? bytes : null;
}

/** Checks shape only. The server never decrypts, so the ciphertext stays an opaque blob. */
function parseEnvelope(body: unknown): IncomingEnvelope | null {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return null;
  }
  const { v, to, nonce, ciphertext } = body as Record<string, unknown>;
  if (
    v !== 1 ||
    typeof to !== "string" ||
    typeof nonce !== "string" ||
    typeof ciphertext !== "string" ||
    !USER_ID_PATTERN.test(to) ||
    !MESSAGE_NONCE_PATTERN.test(nonce)
  ) {
    return null;
  }
  const nonceBytes = decodeStrictBase64(nonce);
  const ciphertextBytes = decodeStrictBase64(ciphertext);
  if (nonceBytes === null || ciphertextBytes === null || ciphertextBytes.length < MIN_CIPHERTEXT_BYTES) {
    return null;
  }
  return { to, nonce: nonceBytes, ciphertext: ciphertextBytes };
}

export function messagesRouter(deps: AuthDeps): Router {
  const router = Router();

  router.post("/messages", requireSignedRequest(deps), async (req, res) => {
    const envelope = parseEnvelope(req.body);
    if (envelope === null) {
      res.status(400).json({ error: "invalid_request" });
      return;
    }

    // The sender is whoever signed the request; a "from" in the body is never read.
    const from = authenticatedUserId(res);

    const inserted = await deps.pool.query<{ message_id: string; created_at: Date }>(
      `INSERT INTO messages (from_user_id, to_user_id, nonce, ciphertext)
       SELECT $1, $2, $3, $4
       WHERE EXISTS (SELECT 1 FROM users WHERE user_id = $2)
       RETURNING message_id, created_at`,
      [from, envelope.to, envelope.nonce, envelope.ciphertext],
    );
    const row = inserted.rows[0];
    if (row === undefined) {
      res.status(404).json({ error: "recipient_not_found" });
      return;
    }

    res.status(201).json({ message_id: row.message_id, created_at: row.created_at.toISOString() });
  });

  // Every message for the caller that has not been acknowledged yet, oldest first.
  // A message keeps coming back until it is acked, so a client that crashes
  // between fetching and saving does not lose it; the client's counter check
  // discards repeats. delivered_at only records the first fetch.
  router.get("/messages/inbox", requireSignedRequest(deps), async (_req, res) => {
    const caller = authenticatedUserId(res);

    const result = await deps.pool.query<{
      message_id: string;
      from_user_id: string;
      nonce: Buffer;
      ciphertext: Buffer;
      created_at: Date;
    }>(
      `WITH page AS (
         SELECT message_id FROM messages
         WHERE to_user_id = $1
         ORDER BY created_at, message_id
         LIMIT $2
       ), marked AS (
         UPDATE messages SET delivered_at = now()
         WHERE message_id IN (SELECT message_id FROM page) AND delivered_at IS NULL
       )
       SELECT m.message_id, m.from_user_id, m.nonce, m.ciphertext, m.created_at
       FROM messages m JOIN page USING (message_id)
       ORDER BY m.created_at, m.message_id`,
      [caller, INBOX_PAGE_SIZE],
    );

    res.json(
      result.rows.map((row) => ({
        message_id: row.message_id,
        from: row.from_user_id,
        v: 1,
        nonce: row.nonce.toString("base64"),
        ciphertext: row.ciphertext.toString("base64"),
        created_at: row.created_at.toISOString(),
      })),
    );
  });

  // Acknowledging deletes the row, so the server stops holding the ciphertext.
  // Only the recipient may do it. Someone else's message and a missing one get
  // the same 404, so the answer does not reveal whether an id exists.
  router.post("/messages/:id/ack", requireSignedRequest(deps), async (req, res) => {
    const messageId = req.params.id;
    if (typeof messageId !== "string" || !UUID_PATTERN.test(messageId)) {
      res.status(404).json({ error: "not_found" });
      return;
    }

    const deleted = await deps.pool.query(
      "DELETE FROM messages WHERE message_id = $1 AND to_user_id = $2",
      [messageId, authenticatedUserId(res)],
    );
    if (deleted.rowCount !== 1) {
      res.status(404).json({ error: "not_found" });
      return;
    }

    res.status(204).end();
  });

  return router;
}
