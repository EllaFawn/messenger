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

  return router;
}
